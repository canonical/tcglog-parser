package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrisccoulson/tcglog-parser"
)

var (
	efiVariableBootQuirk bool
)

func init() {
	flag.BoolVar(&efiVariableBootQuirk, "efi-variable-boot-quirk", false,
		"Consider that some firmware measures the entire UEFI_VARIABLE_DATA structure rather " +
		"than just the variable data for EV_EFI_VARIABLE_BOOT events")
}

func main() {
	flag.Parse()

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

	report, err := tcglog.CheckLogFromFile(file, tcglog.Options{EfiVariableBootQuirk: efiVariableBootQuirk})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to check log file: %v\n", err)
		os.Exit(1)
	}

	for _, entry := range report.Entries {
		fmt.Printf("For event %d in PCR %d:\n", entry.Event().Index, entry.Event().PCRIndex)
		fmt.Printf(" %s\n", entry)
	}
}
