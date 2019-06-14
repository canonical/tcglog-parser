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
