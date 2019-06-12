package tcglog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"unsafe"
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

func isExpectedEventType(t EventType, i PCRIndex, s Spec) bool {
	switch t {
	case EventTypePostCode, EventTypeSCRTMContents, EventTypeSCRTMVersion:
		return i == 0
	case EventTypeNoAction:
		return i == 0 || i == 6
	case EventTypeSeparator:
		return i <= 7
	case EventTypeAction:
		return i >= 1 && i <= 6
	case EventTypeEventTag:
		return (i <= 4 && s < SpecPCClient) || i >= 8
	case EventTypeCPUMicrocode, EventTypePlatformConfigFlags, EventTypeTableOfDevices:
		return i == 1
	case EventTypeCompactHash:
		return i == 4 || i == 5 || i == 7
	case EventTypeIPL:
		return (i == 4 && s < SpecPCClient) || i >= 8
	case EventTypeIPLPartitionData:
		return i == 5 && s < SpecPCClient
	default:
		return true
	}
}

func isValidEventDataType(d EventData, t EventType) bool {
	var ok bool
	switch t {
	case EventTypeSeparator:
		_, ok = d.(*SeparatorEventData)
	case EventTypeCompactHash:
		ok = len(d.Bytes()) == 4
	default:
		ok = true
	}
	return ok
}

func isExpectedDigest(digest Digest, t EventType, data EventData, a AlgorithmId) (bool, []byte) {
	buf := data.Bytes()
	switch t {
	case EventTypeSeparator:
		se := data.(*SeparatorEventData)
		if se.Type == SeparatorEventTypeError {
			buf = make([]byte, 4)
			*(*uint32)(unsafe.Pointer(&buf[0])) = uint32(1)
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

	expected := hash(buf, a)
	return bytes.Compare(digest, expected) == 0, expected
}

func checkForUnexpectedDigestValues(e *Event) error {
	switch e.EventType {
	case EventTypeSeparator:
	case EventTypeAction:
	case EventTypeEventTag:
	case EventTypeSCRTMVersion:
	case EventTypePlatformConfigFlags:
	case EventTypeTableOfDevices:
	case EventTypeIPL:
	case EventTypeIPLPartitionData:
	default:
		return nil
	}

	for alg, digest := range e.Digests {
		if ok, expected := isExpectedDigest(digest, e.EventType, e.Data, alg); !ok {
			return &UnexpectedDigestValueError{e.EventType, alg, digest, expected}
		}
	}

	return nil
}

func checkEvent(e *Event, s Spec) error {
	if !isExpectedEventType(e.EventType, e.PCRIndex, s) {
		return &UnexpectedEventTypeError{e.EventType, e.PCRIndex}
	}

	if !isValidEventDataType(e.Data, e.EventType) {
		return &InvalidEventDataError{e.EventType, e.Data}
	}

	switch e.EventType {
	case EventTypeNoAction:
		for alg, digest := range e.Digests {
			if !isZeroDigest(digest, alg) {
				return &UnexpectedDigestValueError{e.EventType, alg, digest, zeroDigests[alg]}
			}
		}
	default:
	}

	return checkForUnexpectedDigestValues(e)
}
