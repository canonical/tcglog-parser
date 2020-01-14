package tcglog

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
)

type EFIBootVariableBehaviour int

const (
	EFIBootVariableBehaviourUnknown EFIBootVariableBehaviour = iota
	EFIBootVariableBehaviourFull
	EFIBootVariableBehaviourVarDataOnly
)

type IncorrectDigestValue struct {
	Algorithm AlgorithmId
	Expected  Digest
}

type ValidatedEvent struct {
	Event                      *Event
	MeasuredBytes              []byte
	MeasuredTrailingBytesCount int
	IncorrectDigestValues      []IncorrectDigestValue
}

type LogValidateResult struct {
	EfiBootVariableBehaviour EFIBootVariableBehaviour
	ValidatedEvents          []*ValidatedEvent
	Spec                     Spec
	Algorithms               AlgorithmIdList
	ExpectedPCRValues        map[PCRIndex]DigestMap
}

func doesEventTypeExtendPCR(t EventType) bool {
	if t == EventTypeNoAction {
		return false
	}
	return true
}

func performHashExtendOperation(alg AlgorithmId, initial Digest, event Digest) Digest {
	hash := alg.newHash()
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
			return event.Data.Bytes(), false
		}
	case *separatorEventData:
		if !d.isError {
			return event.Data.Bytes(), false
		} else {
			out := make([]byte, 4)
			binary.LittleEndian.PutUint32(out, separatorEventErrorValue)
			return out, false
		}
	case *asciiStringEventData:
		switch event.EventType {
		case EventTypeAction, EventTypeEFIAction:
			return event.Data.Bytes(), false
		}
	case *EFIVariableEventData:
		if event.EventType == EventTypeEFIVariableBoot && efiBootVariableQuirk {
			return d.VariableData, false
		} else {
			return event.Data.Bytes(), true
		}
	case *efiGPTEventData:
		return event.Data.Bytes(), true
	case *GrubStringEventData:
		return []byte(d.Str), false
	}

	return nil, false
}

func isExpectedDigestValue(digest Digest, alg AlgorithmId, measuredBytes []byte) (bool, []byte) {
	expected := alg.hash(measuredBytes)
	return bytes.Equal(digest, expected), expected
}

type logValidator struct {
	log                      *Log
	expectedPCRValues        map[PCRIndex]DigestMap
	efiBootVariableBehaviour EFIBootVariableBehaviour
	validatedEvents          []*ValidatedEvent
}

func (v *logValidator) checkEventDigests(e *ValidatedEvent, trailingBytes int) {
	for alg, digest := range e.Event.Digests {
		if len(e.MeasuredBytes) > 0 {
			// We've already determined the bytes measured for this event for a previous digest
			if ok, expected := isExpectedDigestValue(digest, alg, e.MeasuredBytes); !ok {
				e.IncorrectDigestValues = append(e.IncorrectDigestValues,
					IncorrectDigestValue{Algorithm: alg, Expected: expected})
			}
			continue
		}

		efiBootVariableBehaviourTry := v.efiBootVariableBehaviour

	Loop:
		for {
			// Determine what we expect to be measured
			provisionalMeasuredBytes, checkTrailingBytes := determineMeasuredBytes(e.Event, efiBootVariableBehaviourTry == EFIBootVariableBehaviourVarDataOnly)
			if provisionalMeasuredBytes == nil {
				return
			}

			var provisionalMeasuredTrailingBytes int
			if checkTrailingBytes {
				provisionalMeasuredTrailingBytes = trailingBytes
			}

			for {
				// Determine whether the digest is consistent with the current provisional measured bytes
				ok, _ := isExpectedDigestValue(digest, alg, provisionalMeasuredBytes)
				switch {
				case ok:
					// All good
					e.MeasuredBytes = provisionalMeasuredBytes
					e.MeasuredTrailingBytesCount = provisionalMeasuredTrailingBytes
					if e.Event.EventType == EventTypeEFIVariableBoot && v.efiBootVariableBehaviour == EFIBootVariableBehaviourUnknown {
						// This is the first EV_EFI_VARIABLE_BOOT event, so record the measurement behaviour.
						v.efiBootVariableBehaviour = efiBootVariableBehaviourTry
						if efiBootVariableBehaviourTry == EFIBootVariableBehaviourUnknown {
							v.efiBootVariableBehaviour = EFIBootVariableBehaviourFull
						}
					}
					break Loop
				case provisionalMeasuredTrailingBytes > 0:
					// Invalid digest, the event data decoder determined there were trailing bytes, and we were expecting the measured
					// bytes to match the event data. Test if any of the trailing bytes only appear in the event data by truncating
					// the provisional measured bytes one byte at a time and re-testing.
					provisionalMeasuredBytes = provisionalMeasuredBytes[0 : len(provisionalMeasuredBytes)-1]
					provisionalMeasuredTrailingBytes -= 1
				default:
					// Invalid digest
					if e.Event.EventType == EventTypeEFIVariableBoot && efiBootVariableBehaviourTry == EFIBootVariableBehaviourUnknown {
						// This is the first EV_EFI_VARIABLE_BOOT event, and this test was done assuming that the measured bytes
						// would include the entire EFI_VARIABLE_DATA structure. Repeat the test with only the variable data.
						efiBootVariableBehaviourTry = EFIBootVariableBehaviourVarDataOnly
						continue Loop
					}
					// Record the expected digest on the event
					expectedMeasuredBytes, _ := determineMeasuredBytes(e.Event, false)
					e.IncorrectDigestValues = append(
						e.IncorrectDigestValues,
						IncorrectDigestValue{Algorithm: alg, Expected: alg.hash(expectedMeasuredBytes)})
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
			v.expectedPCRValues[event.PCRIndex][alg] = make(Digest, alg.size())
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
					EfiBootVariableBehaviour: v.efiBootVariableBehaviour,
					ValidatedEvents:          v.validatedEvents,
					Spec:                     v.log.Spec,
					Algorithms:               v.log.Algorithms,
					ExpectedPCRValues:        v.expectedPCRValues}, nil
			}
			return nil, err
		}
		v.processEvent(event, trailingBytes)
	}
}

func ReplayAndValidateLog(logPath string, options LogOptions) (*LogValidateResult, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	log, err := NewLog(file, options)
	if err != nil {
		return nil, err
	}

	v := &logValidator{log: log, expectedPCRValues: make(map[PCRIndex]DigestMap)}
	return v.run()
}
