package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

type IncorrectDigestValue struct {
	Algorithm AlgorithmId
	Expected  Digest
}

type ValidatedEvent struct {
	Event                   *Event
	MeasuredTrailingBytes   int
	UnmeasuredTrailingBytes int
	IncorrectDigestValues   []IncorrectDigestValue
}

type LogValidateResult struct {
	EfiBootVariableDigestsContainFullVariableStruct bool
	ValidatedEvents                                 []*ValidatedEvent
	Spec                                            Spec
	Algorithms                                      AlgorithmIdList
	ExpectedPCRValues                               map[PCRIndex]DigestMap
}

type efiBootVariableQuirkState int

const (
	efiBootVariableQuirkStateUnknown efiBootVariableQuirkState = iota
	efiBootVariablesCorrect
	efiBootVariablesContainFullVariableStruct
)

func doesEventTypeExtendPCR(t EventType) bool {
	if t == EventTypeNoAction {
		return false
	}
	return true
}

func performHashExtendOperation(alg AlgorithmId, initial Digest, event Digest) Digest {
	hash := hasher(alg)
	hash.Write(initial)
	hash.Write(event)
	return hash.Sum(nil)
}

func determineMeasuredBytes(event *Event, efiBootVariableQuirk bool) ([]byte, bool) {
	switch d := event.Data.(type) {
	case *opaqueEventData:
		switch event.EventType {
		case EventTypeEventTag, EventTypeSCRTMVersion, EventTypePlatformConfigFlags,
			EventTypeTableOfDevices, EventTypeNonhostInfo, EventTypeOmitBootDeviceEvents:
			return event.Data.Bytes(), true
		}
	case *separatorEventData:
		if !d.isError {
			return event.Data.Bytes(), true
		} else {
			out := make([]byte, 4)
			binary.LittleEndian.PutUint32(out, separatorEventErrorValue)
			return out, false
		}
	case *asciiStringEventData:
		switch event.EventType {
		case EventTypeAction, EventTypeEFIAction:
			return event.Data.Bytes(), true
		}
	case *EFIVariableEventData:
		if event.EventType == EventTypeEFIVariableBoot && !efiBootVariableQuirk {
			return d.VariableData, false
		} else {
			return event.Data.Bytes(), true
		}
	case *efiGPTEventData:
		return event.Data.Bytes(), true
	case *GrubStringEventData:
		return d.measuredData, false
	}

	return nil, false
}

func isExpectedDigestValue(digest Digest, alg AlgorithmId, measuredBytes []byte) (bool, []byte) {
	expected := hashSum(measuredBytes, alg)
	return bytes.Equal(digest, expected), expected
}

type logValidator struct {
	log                       *Log
	expectedPCRValues         map[PCRIndex]DigestMap
	efiBootVariableQuirkState efiBootVariableQuirkState
	validatedEvents           []*ValidatedEvent
}

func (v *logValidator) checkEventDigests(e *ValidatedEvent, trailingBytes int) {
	var measuredBytes []byte

	for alg, digest := range e.Event.Digests {
		if len(measuredBytes) > 0 {
			if ok, expected := isExpectedDigestValue(digest, alg, measuredBytes); !ok {
				e.IncorrectDigestValues = append(e.IncorrectDigestValues,
					IncorrectDigestValue{Algorithm: alg, Expected: expected})
			}
			continue
		}

		efiBootVariableQuirk := v.efiBootVariableQuirkState == efiBootVariablesContainFullVariableStruct

	Loop:
		for {
			t := trailingBytes
			expectedMeasuredBytes, eventDataIsMeasured :=
				determineMeasuredBytes(e.Event, efiBootVariableQuirk)
			if expectedMeasuredBytes == nil {
				return
			}

			bytes := expectedMeasuredBytes

			for {
				ok, _ := isExpectedDigestValue(digest, alg, bytes)
				switch {
				case ok:
					measuredBytes = bytes
					if eventDataIsMeasured && trailingBytes > 0 {
						e.MeasuredTrailingBytes = t
						e.UnmeasuredTrailingBytes = trailingBytes - t
					}
					if e.Event.EventType == EventTypeEFIVariableBoot &&
						v.efiBootVariableQuirkState == efiBootVariableQuirkStateUnknown {
						if efiBootVariableQuirk {
							v.efiBootVariableQuirkState =
								efiBootVariablesContainFullVariableStruct
						} else {
							v.efiBootVariableQuirkState = efiBootVariablesCorrect
						}
					}
					break Loop
				case t > 0 && len(bytes) > 1 && eventDataIsMeasured:
					bytes = bytes[0 : len(bytes)-1]
					t -= 1
				case !ok:
					if e.Event.EventType == EventTypeEFIVariableBoot &&
						v.efiBootVariableQuirkState == efiBootVariableQuirkStateUnknown &&
						efiBootVariableQuirk == false {
						efiBootVariableQuirk = true
						continue Loop
					}
					expectedMeasuredBytes, _ = determineMeasuredBytes(e.Event, false)
					e.IncorrectDigestValues = append(e.IncorrectDigestValues,
						IncorrectDigestValue{Algorithm: alg,
							Expected: hashSum(expectedMeasuredBytes, alg)})
					break Loop
				}
			}
		}
	}
}

func (v *logValidator) processEvent(event *Event, trailingBytes int) {
	if _, exists := v.expectedPCRValues[event.PCRIndex]; !exists {
		v.expectedPCRValues[event.PCRIndex] = DigestMap{}
		for _, alg := range v.log.Algorithms {
			v.expectedPCRValues[event.PCRIndex][alg] = make(Digest, knownAlgorithms[alg])
		}
	}

	ve := &ValidatedEvent{Event: event}
	v.validatedEvents = append(v.validatedEvents, ve)

	if !doesEventTypeExtendPCR(event.EventType) {
		return
	}

	for alg, digest := range event.Digests {
		v.expectedPCRValues[event.PCRIndex][alg] =
			performHashExtendOperation(alg, v.expectedPCRValues[event.PCRIndex][alg], digest)
	}

	v.checkEventDigests(ve, trailingBytes)
}

func (v *logValidator) run() (*LogValidateResult, error) {
	for {
		event, trailingBytes, err := v.log.nextEventInternal()
		if err != nil {
			if err == io.EOF {
				return &LogValidateResult{
					EfiBootVariableDigestsContainFullVariableStruct: v.efiBootVariableQuirkState == efiBootVariablesContainFullVariableStruct,
					ValidatedEvents:   v.validatedEvents,
					Spec:              v.log.Spec,
					Algorithms:        v.log.Algorithms,
					ExpectedPCRValues: v.expectedPCRValues}, nil
			}
			return nil, err
		}
		v.processEvent(event, trailingBytes)
	}
}

func ReplayAndValidateLog(logPath string, options LogOptions) (*LogValidateResult, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file: %v", err)
	}

	log, err := NewLog(file, options)
	if err != nil {
		return nil, err
	}

	v := &logValidator{log: log, expectedPCRValues: make(map[PCRIndex]DigestMap)}
	return v.run()
}
