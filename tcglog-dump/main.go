// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/jessevdk/go-flags"

	"github.com/canonical/tcglog-parser"
	internal_flags "github.com/canonical/tcglog-parser/internal/flags"
)

type options struct {
	Alg                internal_flags.HashAlgorithmId `long:"alg" description:"Hash algorithm to display" default:"sha1" choice:"sha1" choice:"sha256" choice:"sha384" choice:"sha512"`
	Verbose            []bool                         `short:"v" long:"verbose" description:"Display summary of event data"`
	Hexdump            bool                           `long:"hexdump" description:"Display hexdump of event data associated with each event"`
	VarHexdump         bool                           `long:"varhexdump" description:"Display hexdump of variable data for events associated with the measurement of EFI variables"`
	ExtractData        string                         `long:"extract-data" description:"Extract event data associated with each event to individual files named with the supplied prefix (format: <prefix>-<num>)" optional:"true" optional-value:"data"`
	ExtractVars        string                         `long:"extract-vars" description:"Extract variable data for events associated with the measurement of EFI variables to individual files named with the supplied prefix (format: <prefix>-<num>)" optional:"true" optional-value:"var"`
	WithGrub           bool                           `long:"with-grub" description:"Decode event data measured by GRUB to PCRs 8 and 9"`
	WithSystemdEFIStub *tcglog.PCRIndex               `long:"with-systemd-efi-stub" description:"Decode event data measured by systemd's EFI stub Linux loader to the specified PCR" optional:"true" optional-value:"8"`
	Pcrs               internal_flags.PCRRange        `short:"p" long:"pcrs" description:"Display events associated with the specified PCRs. Can be specified multiple times"`

	Positional struct {
		LogPath string `positional-arg-name:"log-path"`
	} `positional-args:"true"`
}

var opts options

func shouldDisplayEvent(event *tcglog.Event) bool {
	if len(opts.Pcrs) == 0 {
		return true
	}
	return opts.Pcrs.Contains(event.PCRIndex)
}

func run() error {
	if _, err := flags.Parse(&opts); err != nil {
		return err
	}

	path := opts.Positional.LogPath
	if path == "" {
		path = "/sys/kernel/security/tpm0/binary_bios_measurements"
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	logOpts := tcglog.LogOptions{EnableGrub: opts.WithGrub}
	if opts.WithSystemdEFIStub != nil {
		logOpts.EnableSystemdEFIStub = true
		logOpts.SystemdEFIStubPCR = *opts.WithSystemdEFIStub
	}

	log, err := tcglog.ReadLog(f, &logOpts)
	if err != nil {
		return fmt.Errorf("cannot read log: %v", err)
	}

	alg := tpm2.HashAlgorithmId(opts.Alg)
	if !log.Algorithms.Contains(alg) {
		return fmt.Errorf("the log does not contain entries for the %v digest algorithm", alg)
	}

	var formatter formatter
	if len(opts.Verbose) < 2 && !opts.Hexdump && !opts.VarHexdump {
		var err error
		formatter, err = newTableFormatter(os.Stdout, alg, len(opts.Verbose) > 0)
		if err != nil {
			return err
		}
	} else {
		formatter = newBlockFormatter(os.Stdout, alg, len(opts.Verbose), opts.Hexdump, opts.VarHexdump)
	}

	formatter.printHeader()

	for i, event := range log.Events {
		if !shouldDisplayEvent(event) {
			continue
		}

		formatter.printEvent(event)

		if opts.ExtractData != "" {
			ioutil.WriteFile(fmt.Sprintf("%s-%d", opts.ExtractData, i), event.Data.Bytes(), 0644)
		}

		if opts.ExtractVars != "" {
			varData, ok := event.Data.(*tcglog.EFIVariableData)
			if ok {
				ioutil.WriteFile(fmt.Sprintf("%s-%d", opts.ExtractVars, i), varData.VariableData, 0644)
			}
		}
	}

	formatter.flush()

	return nil
}

func main() {
	if err := run(); err != nil {
		switch e := err.(type) {
		case *flags.Error:
			// flags already prints this
			if e.Type != flags.ErrHelp {
				os.Exit(1)
			}
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
