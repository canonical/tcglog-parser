// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package flags

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bsiegert/ranges"
	"github.com/canonical/go-tpm2"
)

type HashAlgorithmId tpm2.HashAlgorithmId

func (h HashAlgorithmId) MarshalFlag() (string, error) {
	switch tpm2.HashAlgorithmId(h) {
	case tpm2.HashAlgorithmSHA1:
		return "sha1", nil
	case tpm2.HashAlgorithmSHA256:
		return "sha256", nil
	case tpm2.HashAlgorithmSHA384:
		return "sha384", nil
	case tpm2.HashAlgorithmSHA512:
		return "sha512", nil
	default:
		return "", fmt.Errorf("unrecognized algorithm %v", h)
	}
}

func (h *HashAlgorithmId) UnmarshalFlag(value string) error {
	switch value {
	case "sha1":
		*h = HashAlgorithmId(tpm2.HashAlgorithmSHA1)
	case "sha256":
		*h = HashAlgorithmId(tpm2.HashAlgorithmSHA256)
	case "sha384":
		*h = HashAlgorithmId(tpm2.HashAlgorithmSHA384)
	case "sha512":
		*h = HashAlgorithmId(tpm2.HashAlgorithmSHA512)
	case "auto":
		*h = HashAlgorithmId(tpm2.HashAlgorithmNull)
	default:
		return fmt.Errorf("unrecognized algorithm \"%s\"", value)
	}

	return nil
}

type PCRRange []tpm2.Handle

func (r PCRRange) MarshalFlag() (string, error) {
	var s []string
	for _, p := range r {
		s = append(s, strconv.FormatUint(uint64(p), 10))
	}
	return strings.Join(s, ","), nil
}

func (r *PCRRange) UnmarshalFlag(value string) error {
	i, err := ranges.Parse(value)
	if err != nil {
		return err
	}
	for _, p := range i {
		*r = append(*r, tpm2.Handle(p))
	}
	return nil
}

func (r *PCRRange) Contains(index tpm2.Handle) bool {
	for _, p := range *r {
		if p == index {
			return true
		}
	}
	return false
}
