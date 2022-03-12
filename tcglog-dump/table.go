// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser"
)

type tableStringer struct {
	fmt.Stringer
}

func (s *tableStringer) String() string {
	str := s.Stringer.String()
	n := strings.IndexAny(str, "\n\t")
	if n == -1 {
		return str
	}
	return str[0:n] + " ..."
}

type tableFormatter struct {
	dst *tabwriter.Writer

	alg     tpm2.HashAlgorithmId
	verbose bool
}

func (f *tableFormatter) printHeader() {
	fmt.Fprint(f.dst, "PCR\tDIGEST\tTYPE")
	if f.verbose {
		fmt.Fprint(f.dst, "\tDETAILS")
	}
	fmt.Fprint(f.dst, "\n")
}

func (f *tableFormatter) printEvent(event *tcglog.Event) {
	fmt.Fprintf(f.dst, "%d\t%x\t%s", event.PCRIndex, event.Digests[f.alg], event.EventType)
	if f.verbose {
		fmt.Fprintf(f.dst, "\t%s", &tableStringer{eventDetailsStringer(event, false)})
	}
	fmt.Fprint(f.dst, "\n")
}

func (f *tableFormatter) flush() {
	f.dst.Flush()
}

func newTableFormatter(f *os.File, alg tpm2.HashAlgorithmId, verbose bool) formatter {
	return &tableFormatter{
		dst:     tabwriter.NewWriter(f, 0, 0, 2, ' ', 0),
		alg:     alg,
		verbose: verbose}
}
