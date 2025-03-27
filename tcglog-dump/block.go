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

	verbosity  int
	hexdump    bool
	varHexdump bool
}

func (*blockFormatter) printHeader() {}

func (f *blockFormatter) printEvent(event *tcglog.Event) {
	fmt.Fprintf(f.dst, "\nPCR: %d\n", event.PCRIndex)
	fmt.Fprintf(f.dst, "TYPE: %s\n", event.EventType)
	for _, alg := range []tpm2.HashAlgorithmId{
		tpm2.HashAlgorithmSHA1,
		tpm2.HashAlgorithmSHA256,
		tpm2.HashAlgorithmSHA384,
		tpm2.HashAlgorithmSHA512,
		tpm2.HashAlgorithmSM3_256,
		tpm2.HashAlgorithmSHA3_256,
		tpm2.HashAlgorithmSHA3_384,
		tpm2.HashAlgorithmSHA3_512} {
		digest, ok := event.Digests[alg]
		if !ok {
			continue
		}
		fmt.Fprintf(f.dst, "DIGEST(%s): %x\n", alg, digest)
	}

	verbose := false
	if f.verbosity > 1 {
		verbose = true
	}
	if f.verbosity > 0 {
		fmt.Fprintf(f.dst, "DETAILS: %s\n", eventDetailsStringer(event, verbose))
	}
	if f.hexdump {
		io.WriteString(f.dst, "EVENT DATA:\n\t")
		data, err := event.Data.Bytes()
		if err != nil {
			fmt.Fprintf(f.dst, "Cannot obtain event data: %v", err)
		} else {
			fmt.Fprintf(f.dst, "%s", strings.Replace(hex.Dump(data), "\n", "\n\t", -1))
		}
	}
	if f.varHexdump {
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if ok {
			fmt.Fprintf(f.dst, "EFI VARIABLE PAYLOAD:\n\t%s", strings.Replace(hex.Dump(varData.VariableData), "\n", "\n\t", -1))
		}
	}
}

func (*blockFormatter) flush() {}

func newBlockFormatter(f *os.File, verbosity int, hexdump, varHexdump bool) formatter {
	return &blockFormatter{
		dst:        f,
		verbosity:  verbosity,
		hexdump:    hexdump,
		varHexdump: varHexdump}
}
