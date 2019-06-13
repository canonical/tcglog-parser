package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type Spec uint

var knownAlgorithms = map[AlgorithmId]uint16{
	AlgorithmSha1:   20,
	AlgorithmSha256: 32,
	AlgorithmSha384: 48,
	AlgorithmSha512: 64,
}

type InvalidLogError struct {
	s string
}

func (e *InvalidLogError) Error() string {
	return fmt.Sprintf("Error whilst parsing event log: %s", e.s)
}

type stream interface {
	ReadNextEvent() (*Event, bool, error)
}

const maxPCRIndex PCRIndex = 31

type stream_1_2 struct {
	r         io.ReadSeeker
	byteOrder binary.ByteOrder
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.1.1 "TCG_PCClientPCREventStruct Structure")
func (s *stream_1_2) ReadNextEvent() (*Event, bool, error) {
	var pcrIndex PCRIndex
	if err := binary.Read(s.r, s.byteOrder, &pcrIndex); err != nil {
		return nil, false, err
	}

	if pcrIndex > maxPCRIndex {
		err := &InvalidLogError{fmt.Sprintf("Invalid PCR index '%d'", pcrIndex)}
		return nil, true, err
	}

	var eventType EventType
	if err := binary.Read(s.r, s.byteOrder, &eventType); err != nil {
		return nil, true, err
	}

	digest := make(Digest, knownAlgorithms[AlgorithmSha1])
	if _, err := s.r.Read(digest); err != nil {
		return nil, true, err
	}
	digests := make(DigestMap)
	digests[AlgorithmSha1] = digest

	var eventSize uint32
	if err := binary.Read(s.r, s.byteOrder, &eventSize); err != nil {
		return nil, true, err
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, true, err
	}

	data, _ := makeEventData(pcrIndex, eventType, event, s.byteOrder)

	return &Event{
		PCRIndex:  pcrIndex,
		EventType: eventType,
		Digests:   digests,
		Data:      data,
	}, false, nil
}

type stream_2 struct {
	r              io.ReadSeeker
	byteOrder      binary.ByteOrder
	algSizes       []EFISpecIdEventAlgorithmSize
	readFirstEvent bool
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.2.2 "TCG_PCR_EVENT2 Structure")
func (s *stream_2) ReadNextEvent() (*Event, bool, error) {
	if !s.readFirstEvent {
		s.readFirstEvent = true
		stream := stream_1_2{r: s.r, byteOrder: s.byteOrder}
		return stream.ReadNextEvent()
	}

	var pcrIndex PCRIndex
	if err := binary.Read(s.r, s.byteOrder, &pcrIndex); err != nil {
		return nil, false, err
	}

	if pcrIndex > maxPCRIndex {
		err := &InvalidLogError{fmt.Sprintf("Invalid PCR index '%d'", pcrIndex)}
		return nil, true, err
	}

	var eventType EventType
	if err := binary.Read(s.r, s.byteOrder, &eventType); err != nil {
		return nil, true, err
	}

	var count uint32
	if err := binary.Read(s.r, s.byteOrder, &count); err != nil {
		return nil, true, err
	}

	digests := make(DigestMap)

	for i := uint32(0); i < count; i++ {
		var algorithmId AlgorithmId
		if err := binary.Read(s.r, s.byteOrder, &algorithmId); err != nil {
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
	if err := binary.Read(s.r, s.byteOrder, &eventSize); err != nil {
		return nil, true, err
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, true, err
	}

	data, _ := makeEventData(pcrIndex, eventType, event, s.byteOrder)

	return &Event{
		PCRIndex:  pcrIndex,
		EventType: eventType,
		Digests:   digests,
		Data:      data,
	}, false, nil
}

type Log struct {
	Spec       Spec
	Algorithms []AlgorithmId
	byteOrder  binary.ByteOrder
	stream     stream
}

func newLogFromReader(r io.ReadSeeker) (*Log, error) {
	start, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	// XXX: Support changing this
	var byteOrder binary.ByteOrder = binary.LittleEndian

	var stream stream = &stream_1_2{r: r, byteOrder: byteOrder}
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
		stream = &stream_2{r: r,
			byteOrder:      byteOrder,
			algSizes:       specData.DigestSizes,
			readFirstEvent: false}
	} else {
		algorithms = []AlgorithmId{AlgorithmSha1}
	}

	return &Log{Spec: spec, Algorithms: algorithms, byteOrder: byteOrder, stream: stream}, nil
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
	err = checkEvent(event, l.Spec, l.byteOrder)
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
