package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type EventData interface {
	String() string
	Bytes() []byte
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
	if event == nil {
		if err == io.EOF {
			err = errors.New("event data smaller than expected")
		}
		return &opaqueEventData{data: data}, err
	}
	if n < len(data) {
		err = fmt.Errorf("event data contains %d bytes more than expected", len(data)-n)
	}
	return event, err
}
