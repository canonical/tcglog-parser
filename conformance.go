package tcglog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
)

type UnexpectedEventTypeError struct {
	EventType EventType
	PCRIndex  PCRIndex
}

func (e *UnexpectedEventTypeError) Error() string {
	return fmt.Sprintf("Unexpected %s event type measured to PCR index %d", e.EventType, e.PCRIndex)
}

type UnexpectedDigestValueError struct {
	EventType      EventType
	Alg            AlgorithmId
	Digest         Digest
	ExpectedDigest Digest
}

func (e *UnexpectedDigestValueError) Error() string {
	return fmt.Sprintf("Unexpected digest value for event type %s (got %s, expected %s)",
		e.EventType, e.Digest, e.ExpectedDigest)
}

type InvalidEventDataError struct {
	EventType EventType
	Data      EventData
}

func (e *InvalidEventDataError) Error() string {
	return fmt.Sprintf("Invalid data for event type %s", e.EventType)
}

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

func isZeroDigest(d []byte, a AlgorithmId) bool {
	return bytes.Compare(d, zeroDigests[a]) == 0
}

func isExpectedEventType(t EventType, i PCRIndex, spec Spec) bool {
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
	default:
		return true
	}
}

func isValidEventData(data EventData, t EventType) bool {
	var ok bool
	switch t {
	case EventTypeSeparator:
		_, ok = data.(*SeparatorEventData)
	case EventTypeCompactHash:
		ok = len(data.Bytes()) == 4
	case EventTypeOmitBootDeviceEvents:
		var builder strings.Builder
		builder.Write(data.Bytes())
		ok = builder.String() == "BOOT ATTEMPTS OMITTED"
	case EventTypeEFIVariableDriverConfig, EventTypeEFIVariableBoot:
		_, ok = data.(*EFIVariableEventData)
	case EventTypeEFIHCRTMEvent:
		var builder strings.Builder
		builder.Write(data.Bytes())
		ok = builder.String() == "HCRTM"
	default:
		ok = true
	}
	return ok
}

func isExpectedDigest(digest Digest, t EventType, data EventData, alg AlgorithmId,
	order binary.ByteOrder) (bool, []byte) {
	buf := data.Bytes()
	switch t {
	case EventTypeSeparator:
		se := data.(*SeparatorEventData)
		if se.Type == SeparatorEventTypeError {
			buf = make([]byte, 4)
			order.PutUint32(buf, uint32(1))
		}
	case EventTypeIPL:
		switch v := data.(type) {
		case GrubEventData:
			buf = v.HashedData()
		default:
			return true, nil
		}
	default:
	}

	expected := hash(buf, alg)
	return bytes.Compare(digest, expected) == 0, expected
}

func checkForUnexpectedDigestValues(event *Event, order binary.ByteOrder) error {
	switch event.EventType {
	case EventTypeSeparator:
	case EventTypeAction:
	case EventTypeEventTag:
	case EventTypeSCRTMVersion:
	case EventTypePlatformConfigFlags:
	case EventTypeTableOfDevices:
	case EventTypeIPL:
	case EventTypeIPLPartitionData:
	case EventTypeNonhostInfo:
	case EventTypeOmitBootDeviceEvents:
	case EventTypeEFIVariableDriverConfig:
	case EventTypeEFIVariableBoot:
	case EventTypeEFIGPTEvent:
	case EventTypeEFIAction:
	default:
		return nil
	}

	for alg, digest := range event.Digests {
		if ok, expected := isExpectedDigest(digest, event.EventType, event.Data, alg, order); !ok {
			return &UnexpectedDigestValueError{event.EventType, alg, digest, expected}
		}
	}

	return nil
}

func checkEvent(event *Event, spec Spec, order binary.ByteOrder) error {
	if !isExpectedEventType(event.EventType, event.PCRIndex, spec) {
		return &UnexpectedEventTypeError{event.EventType, event.PCRIndex}
	}

	if !isValidEventData(event.Data, event.EventType) {
		return &InvalidEventDataError{event.EventType, event.Data}
	}

	switch event.EventType {
	case EventTypeNoAction:
		for alg, digest := range event.Digests {
			if !isZeroDigest(digest, alg) {
				return &UnexpectedDigestValueError{event.EventType, alg, digest, zeroDigests[alg]}
			}
		}
	default:
	}

	return checkForUnexpectedDigestValues(event, order)
}
