// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/exp/constraints"
)

func ptrSize() int {
	sz := unsafe.Sizeof(uintptr(0))
	switch sz {
	case 4, 8:
		return int(sz)
	default:
		panic("unexpected pointer size")
	}
}

func isPrintableASCII(data []byte, nullTerminated bool) bool {
	if nullTerminated && len(data) == 0 {
		return false
	}
	for len(data) > 0 {
		// Pop the next bytee
		c := data[0]
		data = data[1:]

		// If we're expecting a NULL terminated string, make sure the
		// final character is actually NULL
		if nullTerminated && len(data) == 0 && c == 0x00 {
			// Should terminate the loop and we return true
			continue
		}

		// Try to decode the single byte. This will return RuneError
		// if the supplied byte isn't ASCII.
		r, _ := utf8.DecodeRune([]byte{c})
		if r == utf8.RuneError {
			return false
		}
		// Check printable
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func isPrintableUCS2(data []byte, nullTerminated bool) bool {
	if len(data)%2 != 0 {
		return false
	}
	if nullTerminated && len(data) == 0 {
		return false
	}
	r := bytes.NewReader(data)
	ucs2Data := make([]uint16, len(data)/2)
	if err := binary.Read(r, binary.LittleEndian, &ucs2Data); err != nil {
		return false
	}

	for len(ucs2Data) > 0 {
		// Pop the next character
		c := ucs2Data[0]
		ucs2Data = ucs2Data[1:]

		// If we're expecting a NULL terminated string, make sure the
		// final character is actually NULL
		if nullTerminated && len(ucs2Data) == 0 && c == 0 {
			// Should terminate the loop and we return true
			continue
		}

		// Try to decode the single character. If this is the start of a surrogate
		// pair, it will return a single rune equal to unicode.ReplacementChar
		rs := utf16.Decode([]uint16{c})
		if len(rs) != 1 {
			// Should have returned at least one rune
			return false
		}
		r := rs[0]
		if r == unicode.ReplacementChar {
			// Not valid UCS2, but probably UTF-16
			return false
		}
		// Check printable
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func readLengthPrefixed[T constraints.Unsigned, V any](r io.Reader) ([]V, error) {
	var n T
	if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
		return nil, err
	}

	data := make([]V, n)
	if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func writeLengthPrefixed[T constraints.Unsigned, V any](w io.Writer, data []V) error {
	n := uint64(len(data))
	if n != uint64(T(n)) {
		return errors.New("size overflow")
	}

	if err := binary.Write(w, binary.LittleEndian, T(n)); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, data)
}

func mustSucceed[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

type stringer string

func (s stringer) String() string {
	return string(s)
}

type indentStringer struct {
	src    fmt.Stringer
	indent int
}

func (s *indentStringer) String() string {
	indent := make([]byte, s.indent)
	for i := range indent {
		indent[i] = '\t'
	}
	return strings.Replace(s.src.String(), "\n", "\n"+string(indent), -1)
}

func indent(src fmt.Stringer, indent int) fmt.Stringer {
	return &indentStringer{src: src, indent: indent}
}
