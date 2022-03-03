// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/jessevdk/go-flags"

	"github.com/canonical/tcglog-parser"
	internal_flags "github.com/canonical/tcglog-parser/internal/flags"
)

type options struct {
	Alg                internal_flags.HashAlgorithmId `long:"alg" description:"Hash algorithm to display" default:"sha1" choice:"sha1" choice:"sha256" choice:"sha384" choice:"sha512"`
	Verbose            bool                           `short:"v" long:"verbose" description:"Display summary of event data"`
	Hexdump            bool                           `long:"hexdump" description:"Display hexdump of event data associated with each event"`
	VarHexdump         bool                           `long:"varhexdump" description:"Display hexdump of variable data for events associated with the measurement of EFI variables"`
	EslSummary         bool                           `long:"eslsummary" description:"Display a summary of EFI signature lists for EV_EFI_VARIABLE_DRIVER_CONFIG events"`
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

	longestEventType := len("TYPE")
	if opts.Verbose || opts.Hexdump {
		for _, event := range log.Events {
			if !shouldDisplayEvent(event) {
				continue
			}

			n := len(event.EventType.String())
			if n > longestEventType {
				longestEventType = n
			}
		}
	}

	fmt.Printf("PCR %-*s %-*s", alg.Size()*2, "DIGEST", longestEventType, "TYPE")
	if opts.Verbose || opts.Hexdump {
		fmt.Printf(" DETAILS")
	}
	fmt.Printf("\n")

	for i, event := range log.Events {
		if !shouldDisplayEvent(event) {
			continue
		}

		str := new(bytes.Buffer)
		fmt.Fprintf(str, "%3d %x %-*s", event.PCRIndex, event.Digests[alg], longestEventType, event.EventType.String())
		if opts.Verbose || opts.Hexdump {
			switch {
			case event.EventType == tcglog.EventTypeEFIVariableBoot || event.EventType == tcglog.EventTypeEFIVariableBoot2:
				varData, ok := event.Data.(*tcglog.EFIVariableData)
				if ok && varData.VariableName == efi.GlobalVariable {
					if varData.UnicodeName == "BootOrder" {
						r := bytes.NewReader(varData.VariableData)
						var order []string
						var err error
						for {
							var n uint16
							err = binary.Read(r, binary.LittleEndian, &n)
							if err != nil {
								break
							}
							order = append(order, fmt.Sprintf("%04x", n))
						}
						if err != nil && err != io.EOF {
							fmt.Fprintf(str, " [ Invalid BootOrder: %v ]", err)
						} else {
							fmt.Fprintf(str, " [ BootOrder: %s ]", strings.Join(order, ","))
						}
					} else {
						opt, err := efi.ReadLoadOption(bytes.NewReader(varData.VariableData))
						if err != nil {
							fmt.Fprintf(str, " [ Invalid load option for %s: %v ]", varData.UnicodeName, err)
						} else {
							fmt.Fprintf(str, " [ %s: %s ]", varData.UnicodeName, opt)
						}
					}
				} else {
					fmt.Fprintf(str, " [ %s ]", event.Data.String())
				}
			default:
				data := event.Data.String()
				if data != "" {
					fmt.Fprintf(str, " [ %s ]", data)
				}
			}
		}

		if opts.Hexdump {
			fmt.Fprintf(str, "\n\tEvent data:\n\t%s", strings.Replace(hex.Dump(event.Data.Bytes()), "\n", "\n\t", -1))
		}

		if opts.VarHexdump {
			varData, ok := event.Data.(*tcglog.EFIVariableData)
			if ok {
				fmt.Fprintf(str, "\n\tEFI variable data:\n\t%s", strings.Replace(hex.Dump(varData.VariableData), "\n", "\n\t", -1))
			}
		}

		if opts.EslSummary && event.EventType == tcglog.EventTypeEFIVariableDriverConfig {
			varData, ok := event.Data.(*tcglog.EFIVariableData)
			if ok {
				db, err := efi.ReadSignatureDatabase(bytes.NewReader(varData.VariableData))
				if err == nil {
					fmt.Fprintf(str, "\n\tSignature database contents:%s", strings.Replace(db.String(), "\n", "\n\t", -1))
				}
			}
		}

		fmt.Println(str.String())

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
