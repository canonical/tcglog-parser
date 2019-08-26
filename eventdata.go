package tcglog

import (
	"bytes"
	"fmt"
	"io"
)

type EventData interface {
	String() string
	Bytes() []byte
}

type BrokenEventData struct {
	data  []byte
	Error error
}

func (e *BrokenEventData) String() string {
	if e.Error == io.ErrUnexpectedEOF {
		return "Invalid event data: event data smaller than expected"
	}
	return fmt.Sprintf("Invalid event data: %v", e.Error)
}

func (e *BrokenEventData) Bytes() []byte {
	return e.data
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

func bytesRead(stream *bytes.Reader) int {
	return int(stream.Size()) - stream.Len()
}

func decodeEventDataImpl(pcrIndex PCRIndex, eventType EventType, data []byte, options *LogOptions,
	hasDigestOfSeparatorError bool) (EventData, int, error) {
	switch {
	case options.EnableGrub && (pcrIndex == 8 || pcrIndex == 9):
		if d, n, e := decodeEventDataGRUB(pcrIndex, eventType, data); d != nil {
			return d, n, e
		}
		fallthrough
	default:
		return decodeEventDataTCG(eventType, data, hasDigestOfSeparatorError)
	}
}

func decodeEventData(pcrIndex PCRIndex, eventType EventType, data []byte, options *LogOptions,
	hasDigestOfSeparatorError bool) (EventData, int) {
	event, n, err := decodeEventDataImpl(pcrIndex, eventType, data, options, hasDigestOfSeparatorError)

	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return &BrokenEventData{data: data, Error: err}, 0
	}

	if event != nil {
		return event, len(data) - n
	}

	return &opaqueEventData{data: data}, 0
}
