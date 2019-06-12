package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"unsafe"
)

type Spec uint

type InvalidLogError struct {
	s string
}

type stream interface {
	ReadNextEvent() (*Event, bool, error)
}

type Log struct {
	Spec       Spec
	Algorithms []AlgorithmId
	stream     stream
}

var knownAlgorithms = map[AlgorithmId]uint16{
	AlgorithmSha1:   20,
	AlgorithmSha256: 32,
	AlgorithmSha384: 48,
	AlgorithmSha512: 64,
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

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.1.1 "TCG_PCClientPCREventStruct Structure")
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
	algSizes       []EFISpecIdEventAlgorithmSize
	readFirstEvent bool
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.2.2 "TCG_PCR_EVENT2 Structure")
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
		for j = 0; j < len(s.algSizes); j++ {
			if s.algSizes[j].AlgorithmId == algorithmId {
				digestSize = s.algSizes[j].DigestSize
				break
			}
		}

		if j == len(s.algSizes) {
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

	var spec Spec = SpecUnknown
	var algorithms []AlgorithmId
	specData, isSpecData := event.Data.(*SpecIdEventData)
	if isSpecData {
		spec = specData.Spec
	}
	if spec == SpecEFI_2 {
		algorithms = make([]AlgorithmId, 0, len(specData.DigestSizes))
		for _, specAlgSize := range specData.DigestSizes {
			knownSize, known := knownAlgorithms[specAlgSize.AlgorithmId]
			if known {
				if knownSize != specAlgSize.DigestSize {
					err := &InvalidLogError{
						fmt.Sprintf("Digest size in log header for algorithm '%04x' "+
							"doesn't match expected size (got: %d, expected %d)",
							specAlgSize.AlgorithmId, specAlgSize.DigestSize,
							knownSize)}
					return nil, err
				}
				algorithms = append(algorithms, specAlgSize.AlgorithmId)

			}
		}
		stream = &stream_2{r, specData.DigestSizes, false}
	} else {
		algorithms = []AlgorithmId{AlgorithmSha1}
	}

	return &Log{spec, algorithms, stream}, nil
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
	err = checkEvent(event, l.Spec)
	return event, err
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
