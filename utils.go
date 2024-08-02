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
	"unicode"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/exp/constraints"
)

func makeDefaultFormatter(s fmt.State, f rune) string {
	var builder bytes.Buffer
	builder.WriteString("%%")
	for _, flag := range [...]int{'+', '-', '#', ' ', '0'} {
		if s.Flag(flag) {
			fmt.Fprintf(&builder, "%c", flag)
		}
	}
	if width, ok := s.Width(); ok {
		fmt.Fprintf(&builder, "%d", width)
	}
	if prec, ok := s.Precision(); ok {
		fmt.Fprintf(&builder, ".%d", prec)
	}
	fmt.Fprintf(&builder, "%c", f)
	return builder.String()
}

func ptrSize() int {
	sz := unsafe.Sizeof(uintptr(0))
	switch sz {
	case 4, 8:
		return int(sz)
	default:
		panic("unexpected pointer size")
	}
}

func isPrintableASCII(data []byte) bool {
	for len(data) > 0 {
		// Pop the next bytee
		c := data[0]
		data = data[1:]

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
