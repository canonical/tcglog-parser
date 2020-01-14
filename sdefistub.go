package tcglog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

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

func (e *SystemdEFIStubEventData) Encode(buf io.Writer) error {
	str := e.Str
	var unicodePoints []rune
	for len(str) > 0 {
		r, s := utf8.DecodeRuneInString(str)
		unicodePoints = append(unicodePoints, r)
		str = str[s:]
	}
	utf16Str := utf16.Encode(unicodePoints)
	utf16Str = append(utf16Str, 0)
	return binary.Write(buf, binary.LittleEndian, utf16Str)
}

func decodeEventDataSystemdEFIStub(data []byte) (EventData, int, error) {
	// data is a UTF-16 string in little-endian form terminated with a single zero byte.
	// Omit the zero byte added by the EFI stub.
	reader := bytes.NewReader(data[:len(data)-1])

	// reader now contains a UTF-16 string in little-endian form without a terminating zero byte.
	// Convert it to native byte order.
	utf16Str := make([]uint16, len(data)/2)
	binary.Read(reader, binary.LittleEndian, &utf16Str)

	// utf16Str contains a UTF-16 string in native byte order. Convert this to code points and then to UTF-8
	var utf8Str []byte
	for _, r := range utf16.Decode(utf16Str) {
		utf8Char := make([]byte, utf8.RuneLen(r))
		utf8.EncodeRune(utf8Char, r)
		utf8Str = append(utf8Str, utf8Char...)
	}

	// utf8Str now contains the UTF-8 encoded string, without a null terminator
	return &SystemdEFIStubEventData{data: data, Str: string(utf8Str)}, 0, nil
}
