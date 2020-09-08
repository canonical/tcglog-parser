package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// SystemdEFIStubEventData represents the data associated with an event measured by the systemd EFI stub linux loader.
type SystemdEFIStubEventData struct {
	data []byte
	Str  string
}

func (e *SystemdEFIStubEventData) String() string {
	return fmt.Sprintf("%s", e.Str)
}

func (e *SystemdEFIStubEventData) Bytes() []byte {
	return e.data
}

func (e *SystemdEFIStubEventData) EncodeMeasuredBytes(buf io.Writer) error {
	// Both GRUB's chainloader and systemd's EFI bootloader include a UTF-16 NULL terminator at the end of LoadOptions and
	// set LoadOptionsSize to StrLen(LoadOptions)+1. The EFI stub loader measures LoadOptionsSize number of bytes, meaning that
	// the 2 NULL bytes are measured. Include those here.
	return binary.Write(buf, binary.LittleEndian, append(convertStringToUtf16(e.Str), 0))
}

func decodeEventDataSystemdEFIStub(eventType EventType, data []byte) EventData {
	if eventType != EventTypeIPL {
		return nil
	}

	// data is a UTF-16 string in little-endian form terminated with a single zero byte.
	// Omit the zero byte added by the EFI stub and then convert to native byte order.
	reader := bytes.NewReader(data[:len(data)-1])

	utf16Str := make([]uint16, len(data)/2)
	binary.Read(reader, binary.LittleEndian, &utf16Str)

	return &SystemdEFIStubEventData{data: data, Str: convertUtf16ToString(utf16Str)}
}
