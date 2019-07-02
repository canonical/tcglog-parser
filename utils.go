package tcglog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"strings"
)

func makeDefaultFormatter(s fmt.State, f rune) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%%")
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

func hash(data []byte, alg AlgorithmId) []byte {
	switch alg {
	case AlgorithmSha1:
		h := sha1.Sum(data)
		return h[:]
	case AlgorithmSha256:
		h := sha256.Sum256(data)
		return h[:]
	case AlgorithmSha384:
		h := sha512.Sum384(data)
		return h[:]
	case AlgorithmSha512:
		h := sha512.Sum512(data)
		return h[:]
	default:
		panic("Unhandled algorithm")
	}
}

func isSeparatorEventError(event *Event, order binary.ByteOrder) bool {
	if event.EventType != EventTypeSeparator {
		panic("Invalid event type")
	}

	errorValue := make([]byte, 4)
	order.PutUint32(errorValue, separatorEventErrorValue)

	for alg, digest := range event.Digests {
		if bytes.Compare(digest, hash(errorValue, alg)) == 0 {
			return true
		}
		break
	}
	return false
}
