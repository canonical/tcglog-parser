// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/canonical/tcglog-parser"
	"github.com/canonical/tcglog-parser/internal"
)

var (
	alg           string
	verbose       bool
	withGrub      bool
	withSdEfiStub bool
	sdEfiStubPcr  int
	pcrs          internal.PCRArgList
)

func init() {
	flag.StringVar(&alg, "alg", "sha1", "Name of the hash algorithm to display")
	flag.BoolVar(&verbose, "verbose", false, "Display details of event data")
	flag.BoolVar(&withGrub, "with-grub", false, "Interpret measurements made by GRUB to PCR's 8 and 9")
	flag.BoolVar(&withSdEfiStub, "with-systemd-efi-stub", false, "Interpret measurements made by systemd's EFI stub Linux loader")
	flag.IntVar(&sdEfiStubPcr, "systemd-efi-stub-pcr", 8, "Specify the PCR that systemd's EFI stub Linux loader measures to")
	flag.Var(&pcrs, "pcr", "Display events associated with the specified PCR. Can be specified multiple times")
}

func shouldDisplayEvent(event *tcglog.Event) bool {
	if len(pcrs) == 0 {
		return true
	}

	for _, pcr := range pcrs {
		if pcr == event.PCRIndex {
			return true
		}
	}

	return false
}

func main() {
	flag.Parse()

	algorithmId, err := internal.ParseAlgorithm(alg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	args := flag.Args()
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "Too many arguments\n")
		os.Exit(1)
	}

	var path string
	if len(args) == 1 {
		path = args[0]
	} else {
		path = "/sys/kernel/security/tpm0/binary_bios_measurements"
	}

	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}

	log, err := tcglog.ParseLog(file, &tcglog.LogOptions{EnableGrub: withGrub, EnableSystemdEFIStub: withSdEfiStub, SystemdEFIStubPCR: tcglog.PCRIndex(sdEfiStubPcr)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse log file: %v\n", err)
		os.Exit(1)
	}

	if !log.Algorithms.Contains(algorithmId) {
		fmt.Fprintf(os.Stderr,
			"The log doesn't contain entries for the %s digest algorithm\n", algorithmId)
		os.Exit(1)
	}

	for _, event := range log.Events {
		if !shouldDisplayEvent(event) {
			continue
		}

		var builder bytes.Buffer
		fmt.Fprintf(&builder, "%2d %x %s", event.PCRIndex, event.Digests[algorithmId], event.EventType)
		if verbose {
			data := event.Data.String()
			if data != "" {
				fmt.Fprintf(&builder, " [ %s ]", data)
			}

		}
		fmt.Println(builder.String())
	}
}
