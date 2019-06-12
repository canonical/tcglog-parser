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

type UnexpectedDigestValueError struct {
	EventType      EventType
	Alg            AlgorithmId
	Digest         Digest
	ExpectedDigest Digest
}

type InvalidEventDataError struct {
	EventType EventType
	Data      EventData
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

func checkEvent(e *Event, f Format) error {
	switch e.EventType {
	case EventTypePostCode:
		if e.PCRIndex != 0 {
			return &UnexpectedEventTypeError{e.EventType, e.PCRIndex}
		}
	case EventTypeNoAction:
		if e.PCRIndex != 0 && e.PCRIndex != 6 {
			return &UnexpectedEventTypeError{e.EventType, e.PCRIndex}
		}
		for alg, digest := range e.Digests {
			if !isZeroDigest(digest, alg) {
				return &UnexpectedDigestValueError{e.EventType, alg, digest, zeroDigests[alg]}
			}
		}
	case EventTypeSeparator:
		if e.PCRIndex > 7 {
			return &UnexpectedEventTypeError{e.EventType, e.PCRIndex}
		}
		se, ok := e.Data.(*SeparatorEventData)
		if !ok {
			return &InvalidEventDataError{e.EventType, e.Data}
		}
		d := e.Data.Bytes()
		if se.Type == SeparatorEventTypeError {
			d = make([]byte, 4)
			*(*uint32)(unsafe.Pointer(&d[0])) = uint32(1)
		}
		for alg, digest := range e.Digests {
			if expected := hash(d, alg); bytes.Compare(digest, expected) != 0 {
				return &UnexpectedDigestValueError{e.EventType, alg, digest, expected}
			}
		}
	case EventTypeEventTag:
		if e.PCRIndex > 4 || (e.PCRIndex < 4 && f == Format2) {
			return &UnexpectedEventTypeError{e.EventType, e.PCRIndex}
		}
	default:
	}

	return nil
}

func (e *UnexpectedEventTypeError) Error() string {
	return fmt.Sprintf("Unexpected %s event type measured to PCR index %d", e.EventType, e.PCRIndex)
}

func (e *UnexpectedDigestValueError) Error() string {
	return fmt.Sprintf("Unexpected digest value for event type %s (got %s, expected %s)",
		e.EventType, e.Digest, e.ExpectedDigest)
}

func (e *InvalidEventDataError) Error() string {
	return fmt.Sprintf("Invalid data for event type %s", e.EventType)
}
