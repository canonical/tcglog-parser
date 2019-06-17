package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
)

type Spec uint

var knownAlgorithms = map[AlgorithmId]uint16{
	AlgorithmSha1:   20,
	AlgorithmSha256: 32,
	AlgorithmSha384: 48,
	AlgorithmSha512: 64,
}

func isKnownAlgorithm(alg AlgorithmId) (out bool) {
	_, out = knownAlgorithms[alg]
	return
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

		if _, exists := digests[algorithmId]; exists {
			return nil, &DuplicateDigestValueError{algorithmId}, nil
		}
		digests[algorithmId] = digest
	}

	for _, algSize := range s.algSizes {
		if _, exists := digests[algSize.AlgorithmId]; !exists {
			return nil, &MissingDigestValueError{algSize.AlgorithmId}, nil
		}
	}

	for alg, _ := range digests {
		if isKnownAlgorithm(alg) {
			continue
		}
		delete(digests, alg)
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

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//  (section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//   "Procedure for Pre-OS to OS-Present Transition")
var (
	separatorEventErrorValue   uint32 = 1
	separatorEventNormalValues        = [...]uint32{0, math.MaxUint32}
)

func classifySeparatorEvent(event *Event, order binary.ByteOrder) {
	errorValue := make([]byte, 4)
	order.PutUint32(errorValue, separatorEventErrorValue)

	var errorEvent = false
	for alg, digest := range event.Digests {
		if bytes.Compare(digest, hash(errorValue, alg)) == 0 {
			errorEvent = true
		}
		break
	}
	// If this is not an error event, the event data is what was measured. For an error event,
	// the event data is platform defined (and what is measured is 0x00000001)
	event.Data.(*opaqueEventData).informational = errorEvent
}

func fixupSpecIdEvent(event *Event, algorithms []AlgorithmId) {
	if event.Data.(*SpecIdEventData).Spec != SpecEFI_2 {
		return
	}

	for _, alg := range algorithms {
		if alg == AlgorithmSha1 {
			continue
		}

		if _, ok := event.Digests[alg]; ok {
			continue
		}

		event.Digests[alg] = zeroDigests[alg]
	}
}

func isMissingDigestValueError(err error) (out bool) {
	_, out = err.(*MissingDigestValueError)
	return
}

func isSpecIdEvent(event *Event) (out bool) {
	_, out = event.Data.(*SpecIdEventData)
	return
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
	event, err, dataErr := stream.ReadNextEvent()
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
	} else if _, isSpecErr := dataErr.(*InvalidSpecIdEventError); isSpecErr {
		return nil, dataErr
	}

	if spec == SpecEFI_2 {
		algorithms = make([]AlgorithmId, 0, len(specData.DigestSizes))
		for _, specAlgSize := range specData.DigestSizes {
			if isKnownAlgorithm(specAlgSize.AlgorithmId) {
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

	switch {
	case event.EventType == EventTypeSeparator:
		classifySeparatorEvent(event, l.byteOrder)
	case isSpecIdEvent(event):
		fixupSpecIdEvent(event, l.Algorithms)
	}

	err = checkEvent(event, l.Spec, l.byteOrder, l.Algorithms)

	if err != nil && isMissingDigestValueError(err) {
		l.failed = true
		return nil, err
	}

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
