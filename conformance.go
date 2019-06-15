package tcglog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"math"
	"unsafe"
)

func hash(data []byte, alg AlgorithmId) []byte {
	switch alg {
	case AlgorithmSha1:
		h := sha1.Sum(data)
		return h[:]
	case AlgorithmSha256:
		h := sha256.Sum256(data)
		return h[:]
	case AlgorithmSha384:
		h := sha512.Sum384(data)
		return h[:]
	case AlgorithmSha512:
		h := sha512.Sum512(data)
		return h[:]
	default:
		panic("Unhandled algorithm")
	}
}

var zeroDigests = map[AlgorithmId][]byte{
	AlgorithmSha1:   make([]byte, knownAlgorithms[AlgorithmSha1]),
	AlgorithmSha256: make([]byte, knownAlgorithms[AlgorithmSha256]),
	AlgorithmSha384: make([]byte, knownAlgorithms[AlgorithmSha384]),
	AlgorithmSha512: make([]byte, knownAlgorithms[AlgorithmSha512])}

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

func isExpectedEventTypeForIndex(t EventType, i PCRIndex, spec Spec) bool {
	switch t {
	case EventTypePostCode, EventTypeSCRTMContents, EventTypeSCRTMVersion, EventTypeNonhostCode,
		EventTypeNonhostInfo, EventTypeEFIHCRTMEvent:
		return i == 0
	case EventTypeNoAction:
		return i == 0 || i == 6
	case EventTypeSeparator:
		return i <= 7
	case EventTypeAction, EventTypeEFIAction:
		return i >= 1 && i <= 6
	case EventTypeEventTag:
		return (i <= 4 && spec < SpecPCClient) || i >= 8
	case EventTypeCPUMicrocode, EventTypePlatformConfigFlags, EventTypeTableOfDevices, EventTypeNonhostConfig,
		EventTypeEFIVariableBoot, EventTypeEFIHandoffTables:
		return i == 1
	case EventTypeCompactHash:
		return i == 4 || i == 5 || i == 7
	case EventTypeIPL:
		return (i == 4 && spec < SpecPCClient) || i >= 8
	case EventTypeIPLPartitionData:
		return i == 5 && spec < SpecPCClient
	case EventTypeOmitBootDeviceEvents:
		return i == 4
	case EventTypeEFIVariableDriverConfig:
		return i == 1 || i == 3 || i == 5 || i == 7
	case EventTypeEFIBootServicesApplication:
		return i == 2 || i == 4
	case EventTypeEFIBootServicesDriver, EventTypeEFIRuntimeServicesDriver:
		return i == 0 || i == 2
	case EventTypeEFIGPTEvent:
		return i == 5
	case EventTypeEFIPlatformFirmwareBlob:
		return i == 0 || i == 2 || i == 4
	case EventTypeEFIVariableAuthority:
		return i == 7
	default:
		return true
	}
}

func isValidEventData(data EventData, t EventType) bool {
	switch t {
	case EventTypeSeparator:
		if data.MeasuredBytes() == nil {
			return true
		}
		if len(data.RawBytes()) != 4 {
			return false
		}
		for _, v := range separatorEventNormalValues {
			if v == *(*uint32)(unsafe.Pointer(&data.RawBytes()[0])) {
				return true
			}
		}
		return false
	case EventTypeCompactHash:
		return len(data.RawBytes()) == 4
	case EventTypeOmitBootDeviceEvents:
		return string(data.RawBytes()) == "BOOT ATTEMPTS OMITTED"
	case EventTypeEFIHCRTMEvent:
		return string(data.RawBytes()) == "HCRTM"
	default:
		return true
	}
}

func isExpectedDigestValue(digest Digest, t EventType, data EventData, alg AlgorithmId,
	order binary.ByteOrder) (bool, []byte) {
	buf := data.MeasuredBytes()
	var expected []byte

	switch t {
	case EventTypeSeparator:
		if buf == nil {
			buf = make([]byte, 4)
			order.PutUint32(buf, separatorEventErrorValue)
		}
	case EventTypeNoAction:
		expected = zeroDigests[alg]
	}

	switch {
	case buf == nil && expected == nil:
		return true, nil
	case expected == nil:
		expected = hash(buf, alg)
	}

	return bytes.Compare(digest, expected) == 0, expected
}

func checkForUnexpectedDigestValues(event *Event, algorithms []AlgorithmId,
	order binary.ByteOrder) error {
	for alg, digest := range event.Digests {
		if ok, expected := isExpectedDigestValue(digest, event.EventType, event.Data, alg, order); !ok {
			return &UnexpectedDigestValueError{event.EventType, alg, digest, expected}
		}
	}

	return nil
}

func isSpecIdEvent(event *Event) (out bool) {
	_, out = event.Data.(*SpecIdEventData)
	return
}

func checkEvent(event *Event, spec Spec, order binary.ByteOrder, algorithms []AlgorithmId) error {
	switch {
	case event.EventType == EventTypeSeparator:
		classifySeparatorEvent(event, order)
	case isSpecIdEvent(event):
		fixupSpecIdEvent(event, algorithms)
	}

	switch {
	case !isExpectedEventTypeForIndex(event.EventType, event.PCRIndex, spec):
		return &UnexpectedEventTypeError{event.EventType, event.PCRIndex}
	case !isValidEventData(event.Data, event.EventType):
		return &InvalidEventDataError{event.EventType, event.Data}
	}

	return checkForUnexpectedDigestValues(event, algorithms, order)
}
