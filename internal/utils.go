// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package internal

import (
	"bytes"
	"fmt"

	"github.com/bsiegert/ranges"
	"github.com/canonical/tcglog-parser"
)

type PCRArgList []tcglog.PCRIndex

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
	i, err := ranges.Parse(value)
	if err != nil {
		return err
	}
	for _, p := range i {
		*l = append(*l, tcglog.PCRIndex(p))
	}
	return nil
}

func ParseAlgorithm(alg string) (tcglog.AlgorithmId, error) {
	switch alg {
	case "sha1":
		return tcglog.AlgorithmSha1, nil
	case "sha256":
		return tcglog.AlgorithmSha256, nil
	case "sha384":
		return tcglog.AlgorithmSha384, nil
	case "sha512":
		return tcglog.AlgorithmSha512, nil
	default:
		return 0, fmt.Errorf("Unrecognized algorithm \"%s\"", alg)
	}
}
