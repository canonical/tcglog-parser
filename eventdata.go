package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type EventData interface {
	String() string
	Bytes() []byte
}

type BrokenEventData struct {
	data []byte
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

func makeEventDataImpl(pcrIndex PCRIndex, eventType EventType, data []byte,
	order binary.ByteOrder, options *LogOptions) (EventData, int, error) {
	switch {
	case options.EnableGrub && (pcrIndex == 8 || pcrIndex == 9):
		if d, n, e := makeEventDataGRUB(pcrIndex, eventType, data); d != nil {
			return d, n, e
		}
		fallthrough
	default:
		return makeEventDataTCG(eventType, data, order)
	}
}

func makeEventData(pcrIndex PCRIndex, eventType EventType, data []byte,
	order binary.ByteOrder, options *LogOptions) (EventData, error) {
	event, n, err := makeEventDataImpl(pcrIndex, eventType, data, order, options)

	if event != nil {
		if err == nil && n < len(data) {
			err = fmt.Errorf("event data contains %d bytes more than expected", len(data)-n)
		}
		return event, err
	}

	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return &BrokenEventData{data: data, Error: err}, nil
	}

	return &opaqueEventData{data: data}, nil
}
