package tcglog

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"reflect"
	"strconv"
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

func hasher(alg AlgorithmId) hash.Hash {
	switch alg {
	case AlgorithmSha1:
		return sha1.New()
	case AlgorithmSha256:
		return sha256.New()
	case AlgorithmSha384:
		return sha512.New384()
	case AlgorithmSha512:
		return sha512.New()
	default:
		panic("Unhandled algorithm")
	}
}

func hashSum(data []byte, alg AlgorithmId) []byte {
	h := hasher(alg)
	h.Write(data)
	return h.Sum(nil)
}

type PCRArgList []PCRIndex

func (l *PCRArgList) String() string {
	var builder bytes.Buffer
	for i, pcr := range *l {
		if i > 0 {
			builder.WriteString(", ")
		}
		fmt.Fprintf(&builder, "%d", pcr)
	}
	return builder.String()
}

func (l *PCRArgList) Set(value string) error {
	v, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return err
	}
	*l = append(*l, PCRIndex(v))
	return nil
}

func contains(slice interface{}, elem interface{}) bool {
	sv := reflect.ValueOf(slice)
	if sv.Kind() != reflect.Slice {
		panic(fmt.Sprintf("Invalid kind - expected a slice (got %s)", sv.Kind()))
	}
	if sv.Type().Elem() != reflect.ValueOf(elem).Type() {
		panic(fmt.Sprintf("Type mismatch (%s vs %s)", sv.Type().Elem(), reflect.ValueOf(elem).Type()))
	}
	for i := 0; i < sv.Len(); i++ {
		if sv.Index(i).Interface() == elem {
			return true
		}
	}
	return false
}

func ParseAlgorithm(alg string) (AlgorithmId, error) {
	switch alg {
	case "sha1":
		return AlgorithmSha1, nil
	case "sha256":
		return AlgorithmSha256, nil
	case "sha384":
		return AlgorithmSha384, nil
	case "sha512":
		return AlgorithmSha512, nil
	default:
		return 0, fmt.Errorf("Unrecognized algorithm \"%s\"", alg)
	}
}

func isPCRIndexInRange(index PCRIndex) bool {
	const maxPCRIndex PCRIndex = 31
	return index <= maxPCRIndex
}
