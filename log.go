package tcglog

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"unsafe"
)

type Format uint
type PCRIndex uint32
type EventType uint32
type AlgorithmId uint16
type Digest []byte
type DigestMap map[AlgorithmId]Digest

type InvalidLogError struct {
	s string
}

type Event struct {
	PCRIndex  PCRIndex
	EventType EventType
	Digests   DigestMap
	Data	  EventData
}

type stream interface {
	ReadNextEvent() (*Event, bool, error)
}

type Log struct {
	Format     Format
	Algorithms []AlgorithmId
	stream     stream
}

var knownAlgorithms = map[AlgorithmId]uint16{
	AlgorithmSha1:   20,
	AlgorithmSha256: 32,
	AlgorithmSha384: 48,
	AlgorithmSha512: 64,
}

func isZeroDigest(d []byte) bool {
	for _, b := range d {
		if b != 0 {
			return false
		}
	}
	return true
}

type nativeEndian_ struct{}

func (nativeEndian_) Uint16(b []byte) uint16 {
	_ = b[1]
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func (nativeEndian_) Uint32(b []byte) uint32 {
	_ = b[3]
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func (nativeEndian_) Uint64(b []byte) uint64 {
	_ = b[7]
	return *(*uint64)(unsafe.Pointer(&b[0]))
}

func (nativeEndian_) PutUint16(b []byte, v uint16) {
	_ = b[1]
	*(*uint16)(unsafe.Pointer(&b[0])) = v
}

func (nativeEndian_) PutUint32(b []byte, v uint32) {
	_ = b[3]
	*(*uint32)(unsafe.Pointer(&b[0])) = v
}

func (nativeEndian_) PutUint64(b []byte, v uint64) {
	_ = b[7]
	*(*uint64)(unsafe.Pointer(&b[0])) = v
}

func (nativeEndian_) String() string {
	return "nativeEndian"
}

var nativeEndian nativeEndian_

const maxPCRIndex PCRIndex = 31

type stream_1_2 struct {
	r io.ReadSeeker
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.1.1, "TCG_PCClientPCREventStruct Structure")
func (s *stream_1_2) ReadNextEvent() (*Event, bool, error) {
	var pcrIndex PCRIndex
	if err := binary.Read(s.r, nativeEndian, &pcrIndex); err != nil {
		return nil, false, err
	}

	if pcrIndex > maxPCRIndex {
		err := &InvalidLogError{fmt.Sprintf("Invalid PCR index '%d'", pcrIndex)}
		return nil, true, err
	}

	var eventType EventType
	if err := binary.Read(s.r, nativeEndian, &eventType); err != nil {
		return nil, true, err
	}

	digest := make(Digest, knownAlgorithms[AlgorithmSha1])
	if _, err := s.r.Read(digest); err != nil {
		return nil, true, err
	}
	digests := make(DigestMap)
	digests[AlgorithmSha1] = digest

	var eventSize uint32
	if err := binary.Read(s.r, nativeEndian, &eventSize); err != nil {
		return nil, true, err
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, true, err
	}

	return &Event{
		PCRIndex:  pcrIndex,
		EventType: eventType,
		Digests:   digests,
		Data:      makeEventData(pcrIndex, eventType, event),
	}, false, nil
}

type stream_2 struct {
	r              io.ReadSeeker
	efiSpec	       *EFISpecIdEventData
	readFirstEvent bool
}

// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf (section 9.2.2, "TCG_PCR_EVENT2 Structure")
func (s *stream_2) ReadNextEvent() (*Event, bool, error) {
	if !s.readFirstEvent {
		s.readFirstEvent = true
		stream := stream_1_2{s.r}
		return stream.ReadNextEvent()
	}

	var pcrIndex PCRIndex
	if err := binary.Read(s.r, nativeEndian, &pcrIndex); err != nil {
		return nil, false, err
	}

	if pcrIndex > maxPCRIndex {
		err := &InvalidLogError{fmt.Sprintf("Invalid PCR index '%d'", pcrIndex)}
		return nil, true, err
	}

	var eventType EventType
	if err := binary.Read(s.r, nativeEndian, &eventType); err != nil {
		return nil, true, err
	}

	var count uint32
	if err := binary.Read(s.r, nativeEndian, &count); err != nil {
		return nil, true, err
	}

	digests := make(DigestMap)

	for i := uint32(0); i < count; i++ {
		var algorithmId AlgorithmId
		if err := binary.Read(s.r, nativeEndian, &algorithmId); err != nil {
			return nil, true, err
		}

		var digestSize uint16
		var j int
		for j = 0; j < len(s.efiSpec.DigestSizes); j++ {
			if s.efiSpec.DigestSizes[j].AlgorithmId == algorithmId {
				digestSize = s.efiSpec.DigestSizes[j].DigestSize
				break
			}
		}

		if j == len(s.efiSpec.DigestSizes) {
			err := &InvalidLogError{
				fmt.Sprintf("Entry for algorithm '%04x' not found in log header", algorithmId)}
			return nil, true, err
		}

		digest := make(Digest, digestSize)
		if _, err := io.ReadFull(s.r, digest); err != nil {
			return nil, true, err
		}

		if _, known := knownAlgorithms[algorithmId]; known {
			digests[algorithmId] = digest
		}
	}

	var eventSize uint32
	if err := binary.Read(s.r, nativeEndian, &eventSize); err != nil {
		return nil, true, err
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, true, err
	}

	return &Event{
		PCRIndex:  pcrIndex,
		EventType: eventType,
		Digests:   digests,
		Data:      makeEventData(pcrIndex, eventType, event),
	}, false, nil
}

func checkEvent(e *Event) (*Event, error) {
	switch e.EventType {
	case EventTypeNoAction:
	    if e.PCRIndex != 0 && e.PCRIndex != 6 {
		    err := &InvalidLogError{fmt.Sprintf("%s event measured to index %d", e.EventType, e.PCRIndex)}
		    return nil, err
	    }
	    for _, digest := range e.Digests {
		    if !isZeroDigest(digest) {
			    err := &InvalidLogError{
				    fmt.Sprintf("%s event contains non-zero digest", e.EventType)}
			    return nil, err
		    }
	    }
	default:
	}
	return e, nil
}

func newLogFromReader(r io.ReadSeeker) (*Log, error) {
	start, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	var stream stream = &stream_1_2{r}
	event, _, err := stream.ReadNextEvent()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	_, err = r.Seek(start, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var format Format
	var algorithms []AlgorithmId
	if efiSpec, isEfiSpec := event.Data.(*EFISpecIdEventData); isEfiSpec {
		format = Format2
		algorithms = make([]AlgorithmId, 0, len(efiSpec.DigestSizes))
		for _, specAlgSize := range efiSpec.DigestSizes {
			knownSize, known := knownAlgorithms[specAlgSize.AlgorithmId]
			if known {
				if knownSize != specAlgSize.DigestSize {
					err := &InvalidLogError{
						fmt.Sprintf("Digest size in log header for algorithm '%04x' " +
							"doesn't match expected size (size: %d, expected %d)",
							specAlgSize.AlgorithmId, specAlgSize.DigestSize,
							knownSize)}
					return nil, err
				}
				algorithms = append(algorithms, specAlgSize.AlgorithmId)

			}
		}
		stream = &stream_2{r, efiSpec, false}
	} else {
		format = Format1_2
		algorithms = []AlgorithmId{AlgorithmSha1}
	}

	return &Log{format, algorithms, stream}, nil
}

func (e EventType) Label() string {
	switch e {
	case EventTypePrebootCert:
		return "EV_PREBOOT_CERT"
	case EventTypePostCode:
		return "EV_POST_CODE"
	case EventTypeNoAction:
		return "EV_NO_ACTION"
	case EventTypeSeparator:
		return "EV_SEPARATOR"
	case EventTypeAction:
		return "EV_ACTION"
	case EventTypeEventTag:
		return "EV_EVENT_TAG"
	case EventTypeSCRTMContents:
		return "EV_S_CRTM_CONTENTS"
	case EventTypeSCRTMVersion:
		return "EV_S_CRTM_VERSION"
	case EventTypeCPUMicrocode:
		return "EV_CPU_MICROCODE"
	case EventTypePlatformConfigFlags:
		return "EV_PLATFORM_CONFIG_FLAGS"
	case EventTypeTableOfDevices:
		return "EV_TABLE_OF_DEVICES"
	case EventTypeCompactHash:
		return "EV_COMPACT_HASH"
	case EventTypeIPL:
		return "EV_IPL"
	case EventTypeIPLPartitionData:
		return "EV_IPL_PARTITION_DATA"
	case EventTypeNonhostCode:
		return "EV_NONHOST_CODE"
	case EventTypeNonhostConfig:
		return "EV_NONHOST_CONFIG"
	case EventTypeNonhostInfo:
		return "EV_NONHOST_INFO"
	case EventTypeOmitBootDeviceEvents:
		return "EV_OMIT_BOOT_DEVICE_EVENTS"
	case EventTypeEFIVariableDriverConfig:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case EventTypeEFIVariableBoot:
		return "EV_EFI_VARIABLE_BOOT"
	case EventTypeEFIBootServicesApplication:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case EventTypeEFIBootServicesDriver:
		return "EV_EFI_BOOT_SERVICES_DRIVER"
	case EventTypeEFIRuntimeServicesDriver:
		return "EV_EFI_RUNTIME_SERVICES_DRIVER"
	case EventTypeEFIGPTEvent:
		return "EF_EFI_GPT_EVENT"
	case EventTypeEFIAction:
		return "EV_EFI_ACTION"
	case EventTypeEFIPlatformFirmwareBlob:
		return "EV_EFI_PLATFORM_FIRMWARE_BLOB"
	case EventTypeEFIHandoffTables:
		return "EV_EFI_HANDOFF_TABLES"
	case EventTypeEFIHCRTMEvent:
		return "EV_EFI_HCRTM_EVENT"
	case EventTypeEFIVariableAuthority:
		return "EV_EFI_VARIABLE_AUTHORITY"
	default:
		return fmt.Sprintf("%08x", uint32(e))
	}
}

func (e EventType) Format(s fmt.State, f rune) {
	switch f {
	case 's':
		fmt.Fprintf(s, "%s", e.Label())
	// case 'x':
	//     TODO
	// case 'X':
	//     TODO
	default:
		fmt.Fprintf(s, "%%!%c(tcglog.EventType=%08x)", f, uint32(e))
	}
}

func (d Digest) Format(s fmt.State, f rune) {
	switch f {
	case 's':
		fmt.Fprintf(s, "%s", hex.EncodeToString([]byte(d)))
	default:
		fmt.Fprintf(s, "%%!%c(tcglog.Digest=%s)", f, hex.EncodeToString([]byte(d)))
	}
}

func (e *InvalidLogError) Error() string {
	return fmt.Sprintf("Error whilst parsing event log: %s", e.s)
}

func (l *Log) HasAlgorithm(alg AlgorithmId) bool {
	for _, a := range l.Algorithms {
		if a == alg {
			return true
		}
	}

	return false
}

func (l *Log) NextEvent() (*Event, error) {
	event, partial, err := l.stream.ReadNextEvent()
	if partial && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return nil, err
	}
	return checkEvent(event)
}

func NewLogFromByteReader(reader *bytes.Reader) (*Log, error) {
	return newLogFromReader(reader)
}

func NewLogFromFile(file *os.File) (*Log, error) {
	return newLogFromReader(file)
}

func DigestLength(alg AlgorithmId) uint16 {
	return knownAlgorithms[alg]
}
