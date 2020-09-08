package tcglog

import (
	"fmt"
	"io"
)

// EventData represents all event data types that appear in a log. Some implementations of this are exported so that event data
// contents can be inspected programatically.
//
// If an error is encountered when decoding the data associated with an event, the event data will implement the error interface
// which can be used for obtaining information about the decoding error.
type EventData interface {
	fmt.Stringer
	Bytes() []byte // The raw event data bytes
}

// MeasuredEventData is implemented by event data types that provide all of the data necessary to construct or precompute a
// measurement. Some event data types are "informational" in the sense that they don't contain all of the information necessary
// to precompute a measurement, but may provide enough information to gather the data required to precompute a measurement (eg,
// the data associated with EV_EFI_BOOT_SERVICES_APPLICATION events). This package doesn't currently support pre-computing
// measurements for all data types where that should be possible (eg, EV_EFI_GPT_EVENT is an omission).
type MeasuredEventData interface {
	// EncodeMeasuredBytes encodes the event data to a form that can be hashed in order to compute a measurement associated
	// with this data.
	EncodeMeasuredBytes(io.Writer) error
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
type opaqueEventData struct {
	data []byte
}

func (e *opaqueEventData) String() string {
	return ""
}

func (e *opaqueEventData) Bytes() []byte {
	return e.data
}

func decodeEventData(pcrIndex PCRIndex, eventType EventType, digests DigestMap, data []byte, options *LogOptions) EventData {
	if options.EnableGrub && (pcrIndex == 8 || pcrIndex == 9) {
		if out := decodeEventDataGRUB(pcrIndex, eventType, data); out != nil {
			return out
		}
	}

	if options.EnableSystemdEFIStub && pcrIndex == options.SystemdEFIStubPCR {
		if out := decodeEventDataSystemdEFIStub(eventType, data); out != nil {
			return out
		}

	}

	out, err := decodeEventDataTCG(eventType, digests, data)
	if err != nil {
		return &invalidEventData{data: data, err: err}
	}

	if out != nil {
		return out
	}

	return &opaqueEventData{data: data}
}
