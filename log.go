package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// LogOptions allows the behaviour of Log to be controlled.
type LogOptions struct {
	EnableGrub bool // Enable support for interpreting events recorded by GRUB
}

var zeroDigests = map[AlgorithmId][]byte{
	AlgorithmSha1:   make([]byte, AlgorithmSha1.size()),
	AlgorithmSha256: make([]byte, AlgorithmSha256.size()),
	AlgorithmSha384: make([]byte, AlgorithmSha384.size()),
	AlgorithmSha512: make([]byte, AlgorithmSha512.size())}

type stream interface {
	readNextEvent() (*Event, int, error)
}

func isPCRIndexInRange(index PCRIndex) bool {
	const maxPCRIndex PCRIndex = 31
	return index <= maxPCRIndex
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 3.3.2.2 2 Error Conditions" , section 8.2.3 "Measuring Boot Events")
// https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf:
//  (section 2.3.2 "Error Conditions", section 2.3.4 "PCR Usage", section 7.2
//   "Procedure for Pre-OS to OS-Present Transition")
func isDigestOfSeparatorErrorValue(digest Digest, alg AlgorithmId) bool {
	errorValue := make([]byte, 4)
	binary.LittleEndian.PutUint32(errorValue, separatorEventErrorValue)

	return bytes.Compare(digest, alg.hash(errorValue)) == 0
}

func wrapLogReadError(origErr error, partial bool) error {
	if origErr == io.EOF {
		if !partial {
			return origErr
		}
		origErr = io.ErrUnexpectedEOF
	}

	return fmt.Errorf("error when reading from log stream (%v)", origErr)
}

func wrapPCRIndexOutOfRangeError(pcrIndex PCRIndex) error {
	return fmt.Errorf("log entry has an out-of-range PCR index (%d)", pcrIndex)
}

type eventHeader_1_2 struct {
	PCRIndex  PCRIndex
	EventType EventType
}

type stream_1_2 struct {
	r       io.ReadSeeker
	options LogOptions
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
//  (section 11.1.1 "TCG_PCClientPCREventStruct Structure")
func (s *stream_1_2) readNextEvent() (*Event, int, error) {
	var header eventHeader_1_2
	if err := binary.Read(s.r, binary.LittleEndian, &header); err != nil {
		return nil, 0, wrapLogReadError(err, false)
	}

	if !isPCRIndexInRange(header.PCRIndex) {
		return nil, 0, wrapPCRIndexOutOfRangeError(header.PCRIndex)
	}

	digest := make(Digest, AlgorithmSha1.size())
	if _, err := s.r.Read(digest); err != nil {
		return nil, 0, wrapLogReadError(err, true)
	}
	digests := make(DigestMap)
	digests[AlgorithmSha1] = digest

	var eventSize uint32
	if err := binary.Read(s.r, binary.LittleEndian, &eventSize); err != nil {
		return nil, 0, wrapLogReadError(err, true)
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, 0, wrapLogReadError(err, true)
	}

	data, trailing := decodeEventData(header.PCRIndex, header.EventType, event, &s.options,
		isDigestOfSeparatorErrorValue(digest, AlgorithmSha1))

	return &Event{
		PCRIndex:  header.PCRIndex,
		EventType: header.EventType,
		Digests:   digests,
		Data:      data,
	}, trailing, nil
}

type eventHeader_2 struct {
	PCRIndex  PCRIndex
	EventType EventType
	Count     uint32
}

type stream_2 struct {
	r              io.ReadSeeker
	options        LogOptions
	algSizes       []EFISpecIdEventAlgorithmSize
	readFirstEvent bool
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.2.2 "TCG_PCR_EVENT2 Structure")
func (s *stream_2) readNextEvent() (*Event, int, error) {
	if !s.readFirstEvent {
		s.readFirstEvent = true
		stream := stream_1_2{r: s.r}
		return stream.readNextEvent()
	}

	var header eventHeader_2
	if err := binary.Read(s.r, binary.LittleEndian, &header); err != nil {
		return nil, 0, wrapLogReadError(err, false)
	}

	if !isPCRIndexInRange(header.PCRIndex) {
		return nil, 0, wrapPCRIndexOutOfRangeError(header.PCRIndex)
	}

	digests := make(DigestMap)

	for i := uint32(0); i < header.Count; i++ {
		var algorithmId AlgorithmId
		if err := binary.Read(s.r, binary.LittleEndian, &algorithmId); err != nil {
			return nil, 0, wrapLogReadError(err, true)
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
			return nil, 0, fmt.Errorf("crypto-agile log entry contains a digest for an unrecognized "+
				"algorithm (%s)", algorithmId)
		}

		digest := make(Digest, digestSize)
		if _, err := io.ReadFull(s.r, digest); err != nil {
			return nil, 0, wrapLogReadError(err, true)
		}

		if _, exists := digests[algorithmId]; exists {
			return nil, 0, fmt.Errorf("crypto-agile log entry contains more than one digest value "+
				"for algorithm %s", algorithmId)
		}
		digests[algorithmId] = digest
	}

	for _, algSize := range s.algSizes {
		if _, exists := digests[algSize.AlgorithmId]; !exists {
			return nil, 0,
				fmt.Errorf("crypto-agile log entry is missing a digest value for algorithm %s "+
					"that was present in the Spec ID Event", algSize.AlgorithmId)
		}
	}

	for alg, _ := range digests {
		if alg.supported() {
			continue
		}
		delete(digests, alg)
	}

	var eventSize uint32
	if err := binary.Read(s.r, binary.LittleEndian, &eventSize); err != nil {
		return nil, 0, wrapLogReadError(err, true)
	}

	event := make([]byte, eventSize)
	if _, err := io.ReadFull(s.r, event); err != nil {
		return nil, 0, wrapLogReadError(err, true)
	}

	data, trailing := decodeEventData(header.PCRIndex, header.EventType, event, &s.options,
		isDigestOfSeparatorErrorValue(digests[s.algSizes[0].AlgorithmId], s.algSizes[0].AlgorithmId))

	return &Event{
		PCRIndex:  header.PCRIndex,
		EventType: header.EventType,
		Digests:   digests,
		Data:      data,
	}, trailing, nil
}

func fixupSpecIdEvent(event *Event, algorithms AlgorithmIdList) {
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

func isSpecIdEvent(event *Event) (out bool) {
	_, out = event.Data.(*SpecIdEventData)
	return
}

// Log corresponds to an event log parser instance, and allows the consumer to iterate over log entries.
type Log struct {
	Spec         Spec            // The specification to which this log conforms
	Algorithms   AlgorithmIdList // The digest algorithms that appear in the log
	stream       stream
	failed       bool
	indexTracker map[PCRIndex]uint
}

func (l *Log) nextEventInternal() (*Event, int, error) {
	if l.failed {
		return nil, 0,
			errors.New("cannot read next event: log status inconsistent due to a previous error")
	}

	event, trailing, err := l.stream.readNextEvent()
	if err != nil {
		if err != io.EOF {
			l.failed = true
		}
		return nil, 0, err
	}

	if i, exists := l.indexTracker[event.PCRIndex]; exists {
		event.Index = i
		l.indexTracker[event.PCRIndex] = i + 1
	} else {
		event.Index = 0
		l.indexTracker[event.PCRIndex] = 1
	}

	if isSpecIdEvent(event) {
		fixupSpecIdEvent(event, l.Algorithms)
	}

	return event, trailing, nil
}

// NextEvent returns an Event structure that corresponds to the next event in the log. Upon successful completion,
// the Log instance will advance to the next event. If there are no more events in the log, it will return io.EOF.
func (l *Log) NextEvent() (event *Event, err error) {
	event, _, err = l.nextEventInternal()
	return
}

// NewLog creates a new Log instance that reads an event log from r
func NewLog(r io.ReaderAt, options LogOptions) (*Log, error) {
	var stream stream = &stream_1_2{r: io.NewSectionReader(r, 0, (1<<63)-1), options: options}
	event, _, err := stream.readNextEvent()
	if err != nil {
		return nil, wrapLogReadError(err, true)
	}

	var spec Spec = SpecUnknown
	var digestSizes []EFISpecIdEventAlgorithmSize
	var algorithms AlgorithmIdList

	switch d := event.Data.(type) {
	case *SpecIdEventData:
		spec = d.Spec
		digestSizes = d.DigestSizes
	case *BrokenEventData:
		if _, isSpecErr := d.Error.(invalidSpecIdEventError); isSpecErr {
			return nil, d.Error
		}
	}

	if spec == SpecEFI_2 {
		algorithms = make(AlgorithmIdList, 0, len(digestSizes))
		for _, specAlgSize := range digestSizes {
			if specAlgSize.AlgorithmId.supported() {
				algorithms = append(algorithms, specAlgSize.AlgorithmId)
			}
		}
		stream = &stream_2{r: io.NewSectionReader(r, 0, (1<<63)-1),
			options:        options,
			algSizes:       digestSizes,
			readFirstEvent: false}
	} else {
		algorithms = AlgorithmIdList{AlgorithmSha1}
		stream.(*stream_1_2).r.Seek(0, io.SeekStart)
	}

	return &Log{Spec: spec,
		Algorithms:   algorithms,
		stream:       stream,
		failed:       false,
		indexTracker: map[PCRIndex]uint{}}, nil
}
