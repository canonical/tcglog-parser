package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
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

type stream interface {
	ReadNextEvent() (*Event, error, error)
}

const maxPCRIndex PCRIndex = 31

func isPCRIndexInRange(index PCRIndex) bool {
	return index <= maxPCRIndex
}

func wrapLogReadError(origErr error, partial bool) error {
	if origErr == io.EOF {
		if !partial {
			return origErr
		}
		origErr = io.ErrUnexpectedEOF
	}

	return &LogReadError{origErr}
}

type stream_1_2 struct {
	r         io.ReadSeeker
	byteOrder binary.ByteOrder
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.1.1 "TCG_PCClientPCREventStruct Structure")
func (s *stream_1_2) ReadNextEvent() (*Event, error, error) {
	var pcrIndex PCRIndex
	if err := binary.Read(s.r, s.byteOrder, &pcrIndex); err != nil {
		return nil, wrapLogReadError(err, false), nil
	}

	if !isPCRIndexInRange(pcrIndex) {
		return nil, &PCRIndexOutOfRangeError{pcrIndex}, nil
	}

	var eventType EventType
	if err := binary.Read(s.r, s.byteOrder, &eventType); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	digest := make(Digest, knownAlgorithms[AlgorithmSha1])
	if _, err := s.r.Read(digest); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}
	digests := make(DigestMap)
	digests[AlgorithmSha1] = digest

	var eventSize uint32
	if err := binary.Read(s.r, s.byteOrder, &eventSize); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	data, dataErr := makeEventData(pcrIndex, eventType, event, s.byteOrder)

	return &Event{
		PCRIndex:  pcrIndex,
		EventType: eventType,
		Digests:   digests,
		Data:      data,
	}, nil, dataErr
}

type stream_2 struct {
	r              io.ReadSeeker
	byteOrder      binary.ByteOrder
	algSizes       []EFISpecIdEventAlgorithmSize
	readFirstEvent bool
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.2.2 "TCG_PCR_EVENT2 Structure")
func (s *stream_2) ReadNextEvent() (*Event, error, error) {
	if !s.readFirstEvent {
		s.readFirstEvent = true
		stream := stream_1_2{r: s.r, byteOrder: s.byteOrder}
		return stream.ReadNextEvent()
	}

	var pcrIndex PCRIndex
	if err := binary.Read(s.r, s.byteOrder, &pcrIndex); err != nil {
		return nil, wrapLogReadError(err, false), nil
	}

	if !isPCRIndexInRange(pcrIndex) {
		return nil, &PCRIndexOutOfRangeError{pcrIndex}, nil
	}

	var eventType EventType
	if err := binary.Read(s.r, s.byteOrder, &eventType); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	var count uint32
	if err := binary.Read(s.r, s.byteOrder, &count); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	digests := make(DigestMap)

	for i := uint32(0); i < count; i++ {
		var algorithmId AlgorithmId
		if err := binary.Read(s.r, s.byteOrder, &algorithmId); err != nil {
			return nil, wrapLogReadError(err, true), nil
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
			return nil, &UnrecognizedAlgorithmError{algorithmId}, nil
		}

		digest := make(Digest, digestSize)
		if _, err := io.ReadFull(s.r, digest); err != nil {
			return nil, wrapLogReadError(err, true), nil
		}

		if _, known := knownAlgorithms[algorithmId]; known {
			digests[algorithmId] = digest
		}
	}

	var eventSize uint32
	if err := binary.Read(s.r, s.byteOrder, &eventSize); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, wrapLogReadError(err, true), nil
	}

	data, dataErr := makeEventData(pcrIndex, eventType, event, s.byteOrder)

	return &Event{
		PCRIndex:  pcrIndex,
		EventType: eventType,
		Digests:   digests,
		Data:      data,
	}, nil, dataErr
}

type Log struct {
	Spec       Spec
	Algorithms []AlgorithmId
	byteOrder  binary.ByteOrder
	stream     stream
	failed     bool
}

func newLogFromReader(r io.ReadSeeker) (*Log, error) {
	start, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	var byteOrder binary.ByteOrder = binary.LittleEndian

	var stream stream = &stream_1_2{r: r, byteOrder: byteOrder}
	event, err, _ := stream.ReadNextEvent()
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
			if _, known := knownAlgorithms[specAlgSize.AlgorithmId]; known {
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

	return &Log{Spec: spec, Algorithms: algorithms, byteOrder: byteOrder, stream: stream, failed: false}, nil
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
	if l.failed {
		return nil, &LogReadError{errors.New("log status inconsistent due to a previous error")}
	}

	event, err, dataErr := l.stream.ReadNextEvent()
	if err != nil {
		l.failed = true
		return nil, err
	}

	err = checkEvent(event, l.Spec, l.byteOrder)

	if err == nil {
		err = dataErr
	}

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
