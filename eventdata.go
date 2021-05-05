// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"fmt"
)

// EventData represents all event data types that appear in a log. Some implementations of this are exported so that event data
// contents can be inspected programatically.
//
// If an error is encountered when decoding the data associated with an event, the event data will implement the error interface
// which can be used for obtaining information about the decoding error.
type EventData interface {
	fmt.Stringer

	// Bytes returns the raw event data bytes as they appear in the event log from which this event data was decoded.
	Bytes() []byte
}

// invalidEventData corresponds to an event data blob that failed to decode correctly.
type invalidEventData struct {
	data []byte
	err  error
}

func (e *invalidEventData) String() string {
	return fmt.Sprintf("Invalid event data: %v", e.err)
}

func (e *invalidEventData) Bytes() []byte {
	return e.data
}

func (e *invalidEventData) Error() string {
	return e.err.Error()
}

func (e *invalidEventData) Unwrap() error {
	return e.err
}

// opaqueEventData is event data whose format is unknown or implementation defined.
type opaqueEventData []byte

func (d opaqueEventData) String() string {
	return ""
}

func (d opaqueEventData) Bytes() []byte {
	return []byte(d)
}

func decodeEventData(data []byte, pcrIndex PCRIndex, eventType EventType, digests DigestMap, options *LogOptions) EventData {
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
		return &invalidEventData{data: data, err: err}
	}

	if out != nil {
		return out
	}

	return opaqueEventData(data)
}
