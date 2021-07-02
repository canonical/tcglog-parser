// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package internal

import (
	"bytes"
	"fmt"

	"github.com/bsiegert/ranges"
	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser"
)

type PCRArgList []tcglog.PCRIndex

func (l *PCRArgList) String() string {
	var builder bytes.Buffer
	for i, pcr := range *l {
		if i > 0 {
			builder.WriteString(",")
		}
		fmt.Fprintf(&builder, "%d", pcr)
	}
	return builder.String()
}

func (l *PCRArgList) Set(value string) error {
	i, err := ranges.Parse(value)
	if err != nil {
		return err
	}
	for _, p := range i {
		*l = append(*l, tcglog.PCRIndex(p))
	}
	return nil
}

func (l *PCRArgList) Contains(index tcglog.PCRIndex) bool {
	for _, p := range *l {
		if p == index {
			return true
		}
	}
	return false
}

func ParseAlgorithm(alg string) (tpm2.HashAlgorithmId, error) {
	switch alg {
	case "sha1":
		return tpm2.HashAlgorithmSHA1, nil
	case "sha256":
		return tpm2.HashAlgorithmSHA256, nil
	case "sha384":
		return tpm2.HashAlgorithmSHA384, nil
	case "sha512":
		return tpm2.HashAlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("Unrecognized algorithm \"%s\"", alg)
	}
}
