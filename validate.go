package tcglog

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
)

type UnexpectedDigestValue struct {
	Algorithm AlgorithmId
	Expected  Digest
}

type ValidatedEvent struct {
	Event                                 *Event
	ExcessMeasuredBytes                   []byte
	EfiVariableAuthorityHasUnmeasuredByte bool
	UnexpectedDigestValues                []UnexpectedDigestValue
}

type LogValidateResult struct {
	EfiVariableBootDigestsContainFullVariableStruct bool
	ValidatedEvents                                 []*ValidatedEvent
	Spec                                            Spec
	Algorithms                                      AlgorithmIdList
	LogPCRValues                                    map[PCRIndex]DigestMap
}

type efiVarBootQuirkState uint

const (
	efiVarBootQuirkIndeterminate efiVarBootQuirkState = iota
	efiVarBootQuirkInactive
	efiVarBootQuirkActive
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

func determineMeasuredBytes(event *Event, efiVarBootQuirk bool) []byte {
	switch d := event.Data.(type) {
	case *opaqueEventData:
		switch event.EventType {
		case EventTypeEventTag, EventTypeSCRTMVersion, EventTypePlatformConfigFlags,
			EventTypeTableOfDevices, EventTypeNonhostInfo, EventTypeOmitBootDeviceEvents:
			return event.Data.Bytes()
		}
	case *separatorEventData:
		if !d.isError {
			return event.Data.Bytes()
		} else {
			out := make([]byte, 4)
			binary.LittleEndian.PutUint32(out, separatorEventErrorValue)
			return out
		}
	case *AsciiStringEventData:
		switch event.EventType {
		case EventTypeAction, EventTypeEFIAction:
			return event.Data.Bytes()
		}
	case *EFIVariableEventData:
		if event.EventType == EventTypeEFIVariableBoot && !efiVarBootQuirk {
			return d.VariableData
		} else {
			return event.Data.Bytes()
		}
	case *EFIGPTEventData:
		return event.Data.Bytes()
	case *KernelCmdlineEventData:
		return d.cmdline
	case *GrubCmdEventData:
		return d.cmd
	}

	return nil
}

func isExpectedDigestValue(digest Digest, alg AlgorithmId, measuredBytes []byte) (bool, []byte) {
	expected := hashSum(measuredBytes, alg)
	return bytes.Equal(digest, expected), expected
}

type logValidator struct {
	log                  *Log
	logPCRValues         map[PCRIndex]DigestMap
	efiVarBootQuirkState efiVarBootQuirkState
	validatedEvents      []*ValidatedEvent
}

func (v *logValidator) checkDigestForEvent(alg AlgorithmId, digest Digest, ve *ValidatedEvent) bool {
	efiVarBootQuirk := v.efiVarBootQuirkState == efiVarBootQuirkActive

	measuredBytes := determineMeasuredBytes(ve.Event, efiVarBootQuirk)
	if measuredBytes == nil {
		return false
	}

	if ok, exp := isExpectedDigestValue(digest, alg, measuredBytes); !ok {
		if ve.Event.EventType == EventTypeEFIVariableBoot &&
			v.efiVarBootQuirkState == efiVarBootQuirkIndeterminate {
			measuredBytes = determineMeasuredBytes(ve.Event, true)
			ok, _ = isExpectedDigestValue(digest, alg, measuredBytes)
			if ok {
				v.efiVarBootQuirkState = efiVarBootQuirkActive
			}
		} else if ve.Event.EventType == EventTypeEFIVariableAuthority {
			measuredBytes = measuredBytes[0 : len(measuredBytes)-1]
			ok, _ = isExpectedDigestValue(digest, alg, measuredBytes)
			if ok {
				ve.EfiVariableAuthorityHasUnmeasuredByte = true
			}
		}

		if !ok {
			ve.UnexpectedDigestValues = append(ve.UnexpectedDigestValues,
				UnexpectedDigestValue{Algorithm: alg, Expected: exp})
		}
	} else if ve.Event.EventType == EventTypeEFIVariableBoot &&
		v.efiVarBootQuirkState == efiVarBootQuirkIndeterminate {
		v.efiVarBootQuirkState = efiVarBootQuirkInactive
	}

	return true
}

func (v *logValidator) processEvent(event *Event, remaining int) {
	if _, exists := v.logPCRValues[event.PCRIndex]; !exists {
		v.logPCRValues[event.PCRIndex] = DigestMap{}
		for _, alg := range v.log.Algorithms {
			v.logPCRValues[event.PCRIndex][alg] = make(Digest, knownAlgorithms[alg])
		}
	}

	ve := &ValidatedEvent{Event: event}
	v.validatedEvents = append(v.validatedEvents, ve)

	if !doesEventTypeExtendPCR(event.EventType) {
		return
	}

	informational := false
	for alg, digest := range event.Digests {
		v.logPCRValues[event.PCRIndex][alg] =
			performHashExtendOperation(alg, v.logPCRValues[event.PCRIndex][alg], digest)

		if informational {
			continue
		}

		informational = !v.checkDigestForEvent(alg, digest, ve)
	}

	if remaining > 0 && !informational {
		end := len(event.Data.Bytes())
		if ve.EfiVariableAuthorityHasUnmeasuredByte {
			end -= 1
		}
		ve.ExcessMeasuredBytes = event.Data.Bytes()[len(event.Data.Bytes())-remaining : end]
	}
}

func (v *logValidator) run() (*LogValidateResult, error) {
	for {
		event, remaining, err := v.log.nextEventInternal()
		if err != nil {
			if err == io.EOF {
				return &LogValidateResult{
					EfiVariableBootDigestsContainFullVariableStruct: v.efiVarBootQuirkState == efiVarBootQuirkActive,
					ValidatedEvents: v.validatedEvents,
					Spec:            v.log.Spec,
					Algorithms:      v.log.Algorithms,
					LogPCRValues:    v.logPCRValues}, nil
			}
			return nil, err
		}
		v.processEvent(event, remaining)
	}
}

func ReplayAndValidateLog(logPath string, options LogOptions) (*LogValidateResult, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, LogReadError{OrigError: err}
	}

	log, err := NewLogFromFile(file, options)
	if err != nil {
		return nil, err
	}

	v := &logValidator{log: log, logPCRValues: make(map[PCRIndex]DigestMap)}
	return v.run()
}
