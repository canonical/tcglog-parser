package tcglog

import (
	"fmt"
)

// EventData is an interface that represents all event data types that appear in a log. Most implementations of
// this are private to this module.
type EventData interface {
	fmt.Stringer
	Bytes() []byte // The raw event data bytes
}

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
