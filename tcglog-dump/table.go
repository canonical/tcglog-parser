// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser"
)

const (
	minPcrWidth    = len("PCR")
	minDigestWidth = len("DIGEST")
	minTypeWidth   = len("TYPE")
)

type tableFormatter struct {
	dst io.Writer

	alg     tpm2.HashAlgorithmId
	verbose bool

	pcrWidth    int
	digestWidth int
	typeWidth   int
}

func (f *tableFormatter) printHeader() {
	fmt.Fprintf(f.dst, "%-*s %-*s %-*s", f.pcrWidth, "PCR", f.digestWidth, "DIGEST", f.typeWidth, "TYPE")
	if f.verbose {
		fmt.Fprintf(f.dst, " | DETAILS")
	}
	fmt.Fprintf(f.dst, "\n")
}

func (f *tableFormatter) printEvent(event *tcglog.Event) {
	fmt.Fprintf(f.dst, "%*d %-*x %-*s", f.pcrWidth, event.PCRIndex, f.digestWidth, event.Digests[f.alg], f.typeWidth, event.EventType.String())
	if f.verbose {
		fmt.Fprintf(f.dst, " | %s", eventDetailsStringer(event, false))
	}
	fmt.Fprintf(f.dst, "\n")
}

func newTableFormatter(f *os.File, alg tpm2.HashAlgorithmId, verbose bool, pcrWidth, digestWidth, typeWidth int) formatter {
	if pcrWidth < minPcrWidth {
		pcrWidth = minPcrWidth
	}
	if digestWidth < minDigestWidth {
		digestWidth = minDigestWidth
	}
	if typeWidth < minTypeWidth {
		typeWidth = minTypeWidth
	}

	return &tableFormatter{
		dst:         f,
		alg:         alg,
		verbose:     verbose,
		pcrWidth:    pcrWidth,
		digestWidth: digestWidth,
		typeWidth:   typeWidth}
}
