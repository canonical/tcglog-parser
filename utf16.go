package tcglog

import (
	"encoding/binary"
	"io"
	"strings"
)

var (
	surr1 uint16 = 0xd800
	surr2 uint16 = 0xdc00
	surr3 uint16 = 0xe000
	surr4 rune   = 0x10000
)

// UEFI_VARIABLE_DATA specifies the number of *characters* for a UTF-16 rather than the size of
// the buffer, which makes it difficult for us to use go's utf16 module
func decodeUTF16ToString(stream io.Reader, count uint64, order binary.ByteOrder) (string, error) {
	var builder strings.Builder

	for i := uint64(0); i < count; i++ {
		var c1 uint16
		if err := binary.Read(stream, order, &c1); err != nil {
			return "", err
		}
		if c1 < surr1 || c1 >= surr3 {
			builder.WriteRune(rune(c1))
			continue
		}
		if c1 >= surr1 && c1 < surr2 {
			var c2 uint16
			if err := binary.Read(stream, order, &c2); err != nil {
				return "", err
			}
			if c2 >= surr2 && c2 < surr3 {
				builder.WriteRune(rune((c1-surr1)<<10|(c2-surr2)) + surr4)
				i++
				continue
			}
		}
		builder.WriteRune(rune(0xfffd))
	}

	return builder.String(), nil
}
