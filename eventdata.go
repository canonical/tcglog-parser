// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"crypto"
	"fmt"
)

type DecodedEventData interface {
	fmt.Stringer
}

// EventData represents all event data types that appear in a log. Some implementations of this are exported so that event data
// contents can be inspected programatically.
//
// If an error is encountered when decoding the data associated with an event, the event data will implement the error interface
// which can be used for obtaining information about the decoding error.
type EventData struct {
	bytes   []byte
	decoded DecodedEventData
}

// Bytes is the raw event data bytes as they appear in the event log.
func (e *EventData) Bytes() []byte {
	return e.bytes
}

func (e *EventData) Decoded() DecodedEventData {
	return e.decoded
}

func (e *EventData) String() string {
	return e.decoded.String()
}

// invalidEventData corresponds to an event data blob that failed to decode correctly.
type invalidEventData struct {
	err error
}

func (e *invalidEventData) String() string {
	return fmt.Sprintf("Invalid event data: %v", e.err)
}

func (e *invalidEventData) Error() string {
	return e.err.Error()
}

func (e *invalidEventData) Unwrap() error {
	return e.err
}

// opaqueEventData is event data whose format is unknown or implementation defined.
type opaqueEventData struct{}

func (d opaqueEventData) String() string {
	return ""
}

// ComputeEventDigest computes the digest associated with the supplied event data bytes.
func ComputeEventDigest(alg crypto.Hash, data []byte) []byte {
	h := alg.New()
	h.Write(data)
	return h.Sum(nil)
}

func decodeEventData(data []byte, pcrIndex PCRIndex, eventType EventType, digests DigestMap, options *LogOptions) DecodedEventData {
	if options.EnableGrub && (pcrIndex == 8 || pcrIndex == 9) {
		if out := decodeEventDataGRUB(data, pcrIndex, eventType); out != nil {
			return out
		}
	}

	if options.EnableSystemdEFIStub && pcrIndex == options.SystemdEFIStubPCR {
		if out := decodeEventDataSystemdEFIStub(data, eventType); out != nil {
			return out
		}

	}

	out, err := decodeEventDataTCG(data, pcrIndex, eventType, digests)
	if err != nil {
		return &invalidEventData{err: err}
	}

	if out != nil {
		return out
	}

	return opaqueEventData{}
}
