package tcglog

import (
	"fmt"
)

type PCRIndexOutOfRangeError struct {
	Index PCRIndex
}

func (e PCRIndexOutOfRangeError) Error() string {
	return fmt.Sprintf("log entry has an out-of-range PCR index (%d)", e.Index)
}

type LogReadError struct {
	OrigError error
}

func (e LogReadError) Error() string {
	return fmt.Sprintf("error when reading from log stream (%v)", e.OrigError)
}

type UnrecognizedAlgorithmError struct {
	Algorithm AlgorithmId
}

func (e UnrecognizedAlgorithmError) Error() string {
	return fmt.Sprintf("crypto-agile log entry contains a digest for an unrecognized algorithm (%s)",
		e.Algorithm)
}

type InvalidSpecIdEventError struct {
	s string
}

func (e InvalidSpecIdEventError) Error() string {
	return fmt.Sprintf("invalid SpecIdEvent (%s)", e.s)
}

type MissingDigestValueError struct {
	Algorithm AlgorithmId
}

func (e MissingDigestValueError) Error() string {
	return fmt.Sprintf("crypto-agile log entry is missing a digest value for algorithm %s that was present "+
		"in the Spec ID Event", e.Algorithm)
}

type DuplicateDigestValueError struct {
	Algorithm AlgorithmId
}

func (e DuplicateDigestValueError) Error() string {
	return fmt.Sprintf("crypto-agile log entry contains more than one digest value for algorithm %s",
		e.Algorithm)
}

type InvalidOptionError struct {
	msg string
}

func (e InvalidOptionError) Error() string {
	return fmt.Sprintf("invalid option (%s)", e.msg)
}

type TPMCommError struct {
	OrigError error
}

func (e TPMCommError) Error() string {
	return fmt.Sprintf("error whilst communicating with TPM (%v)", e.OrigError)
}
