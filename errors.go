package tcglog

import (
	"fmt"
)

type PCRIndexOutOfRangeError struct {
	Index PCRIndex
}

func (e *PCRIndexOutOfRangeError) Error() string {
	return fmt.Sprintf("log entry has an out-of-range PCR index (%d)", e.Index)
}

type LogReadError struct {
	OrigError error
}

func (e *LogReadError) Error() string {
	return fmt.Sprintf("encountered error when reading from log (%v)", e.OrigError)
}

type UnrecognizedAlgorithmError struct {
	Algorithm AlgorithmId
}

func (e *UnrecognizedAlgorithmError) Error() string {
	return fmt.Sprintf("crypto-agile log entry contains a digest for an unrecognized algorithm (%s)",
		e.Algorithm)
}

type InvalidSpecIdEventError struct {
	s string
}

func (e *InvalidSpecIdEventError) Error() string {
	return fmt.Sprintf("invalid SpecIdEvent: %s", e.s)
}

type UnexpectedEventTypeError struct {
	EventType EventType
	PCRIndex  PCRIndex
}

func (e *UnexpectedEventTypeError) Error() string {
	return fmt.Sprintf("unexpected %s event type measured to PCR index %d", e.EventType, e.PCRIndex)
}

type UnexpectedDigestValueError struct {
	EventType      EventType
	Alg            AlgorithmId
	Digest         Digest
	ExpectedDigest Digest
}

func (e *UnexpectedDigestValueError) Error() string {
	return fmt.Sprintf("unexpected digest value for event type %s (got %x, expected %x)",
		e.EventType, e.Digest, e.ExpectedDigest)
}

type InvalidEventDataError struct {
	EventType EventType
	Data      EventData
}

func (e *InvalidEventDataError) Error() string {
	return fmt.Sprintf("invalid data for event type %s", e.EventType)
}
