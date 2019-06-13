package tcglog

import (
	"encoding/binary"
)

type EventData interface {
	String() string
	RawBytes() []byte
	MeasuredBytes() []byte
}

type opaqueEventData struct {
	data          []byte
	informational bool
}

func (e *opaqueEventData) String() string {
	return ""
}

func (e *opaqueEventData) RawBytes() []byte {
	return e.data
}

func (e *opaqueEventData) MeasuredBytes() []byte {
	if !e.informational {
		return e.data
	}
	return nil
}

func makeEventDataImpl(pcrIndex PCRIndex, eventType EventType, data []byte, order binary.ByteOrder) EventData {
	switch {
	case eventType == EventTypeIPL && (pcrIndex == 8 || pcrIndex == 9):
		return makeEventDataGRUB(pcrIndex, data)
	default:
		return makeEventDataTCG(pcrIndex, eventType, data, order)
	}
}

func makeOpaqueEventData(eventType EventType, data []byte) *opaqueEventData {
	switch eventType {
	case EventTypeEventTag, EventTypeSCRTMVersion, EventTypePlatformConfigFlags, EventTypeTableOfDevices,
		EventTypeNonhostInfo, EventTypeOmitBootDeviceEvents, EventTypeEFIGPTEvent:
		return &opaqueEventData{data: data, informational: false}
	default:
		return &opaqueEventData{data: data, informational: true}
	}
}

func makeEventData(pcrIndex PCRIndex, eventType EventType, data []byte, order binary.ByteOrder) EventData {
	if event := makeEventDataImpl(pcrIndex, eventType, data, order); event != nil {
		return event
	}
	return makeOpaqueEventData(eventType, data)
}
