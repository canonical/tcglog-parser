// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser"
)

type blockFormatter struct {
	dst io.Writer

	alg tpm2.HashAlgorithmId

	verbosity  int
	hexdump    bool
	varHexdump bool
}

func (f *blockFormatter) printHeader() {}

func (f *blockFormatter) printEvent(event *tcglog.Event) {
	fmt.Fprintf(f.dst, "\nPCR: %d\n", event.PCRIndex)
	fmt.Fprintf(f.dst, "TYPE: %s\n", event.EventType)
	fmt.Fprintf(f.dst, "DIGEST: %x\n", event.Digests[f.alg])

	verbose := false
	if f.verbosity > 1 {
		verbose = true
	}
	if f.verbosity > 0 {
		fmt.Fprintf(f.dst, "DETAILS: %s\n", eventDetailsStringer(event, verbose))
	}
	if f.hexdump {
		fmt.Fprintf(f.dst, "EVENT DATA:\n\t%s", strings.Replace(hex.Dump(event.Data.Bytes()), "\n", "\n\t", -1))
	}
	if f.varHexdump {
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if ok {
			fmt.Fprintf(f.dst, "EFI VARIABLE PAYLOAD:\n\t%s", strings.Replace(hex.Dump(varData.VariableData), "\n", "\n\t", -1))
		}
	}
}

func newBlockFormatter(f *os.File, alg tpm2.HashAlgorithmId, verbosity int, hexdump, varHexdump bool) formatter {
	return &blockFormatter{
		dst:        f,
		alg:        alg,
		verbosity:  verbosity,
		hexdump:    hexdump,
		varHexdump: varHexdump}
}
