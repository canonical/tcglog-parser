package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/chrisccoulson/tcglog-parser"
)

var (
	withGrub      bool
	noDefaultPcrs bool
	pcrs          tcglog.PCRList
)

func init() {
	flag.BoolVar(&withGrub, "with-grub", false, "Validate log entries made by GRUB in to PCR's 8 and 9")
	flag.BoolVar(&noDefaultPcrs, "no-default-pcrs", false, "Don't validate log entries for PCRs 0 - 7")
	flag.Var(&pcrs, "pcr", "Validate log entries for the specified PCR. Can be specified multiple times")
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "Too many arguments\n")
		os.Exit(1)
	}

	if !noDefaultPcrs {
		pcrs = append(pcrs, 0, 1, 2, 3, 4, 5, 6, 7)
		if withGrub {
			pcrs = append(pcrs, 8, 9)
		}
	}

	result, err := tcglog.ValidateLog(tcglog.LogValidateOptions{
		PCRList:    pcrs,
		EnableGrub: withGrub})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to validate log file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("*** QUIRKS ***\n")

	if result.EfiVariableBootQuirk {
		fmt.Printf("EV_EFI_VARIABLE_BOOT events measure entire UEFI_VARIABLE_DATA structure rather " +
			"than just the variable contents\n")
	}

	seenExcessMeasuredBytes := false
	for _, e := range result.ValidatedEvents {
		if len(e.ExcessMeasuredBytes) == 0 {
			continue
		}

		if !seenExcessMeasuredBytes {
			seenExcessMeasuredBytes = true
			fmt.Printf("The following events have padding at the end of their event data that was " +
				"hashed and measured:\n")
		}

		fmt.Printf("- Event %d in PCR %d (type: %s): %x (%d bytes)\n", e.Event.Index, e.Event.PCRIndex,
			e.Event.EventType, e.ExcessMeasuredBytes, len(e.ExcessMeasuredBytes))
	}

	seenEVAWithUnmeasuredByte := false
	for _, e := range result.ValidatedEvents {
		if !e.EfiVariableAuthorityHasUnmeasuredByte {
			continue
		}

		if !seenEVAWithUnmeasuredByte {
			seenEVAWithUnmeasuredByte = true
			fmt.Printf("The following events have one extra byte at the end of their event data " +
				"that was not hashed and measured:\n")
		}
		v := e.Event.Data.(*tcglog.EFIVariableEventData)
		fmt.Printf("- Event %d in PCR %d [ VariableName: %s, UnicodeName: \"%s\" ] (byte: 0x%x)\n",
			e.Event.Index, e.Event.PCRIndex, &v.VariableName, v.UnicodeName,
			v.Bytes()[len(v.Bytes())-1])
	}

	fmt.Printf("*** END QUIRKS ***\n\n")

	fmt.Printf("*** UNEXPECTED EVENT DIGESTS ***\n")
	for _, e := range result.ValidatedEvents {
		if len(e.UnexpectedDigestValues) == 0 {
			continue
		}
		for _, v := range e.UnexpectedDigestValues {
			fmt.Printf("Event %d in PCR %d (type: %s, alg: %s) - expected: %x, got: %x\n",
				e.Event.Index, e.Event.PCRIndex, e.Event.EventType, v.Algorithm, v.Expected,
				e.Event.Digests[v.Algorithm])
		}
	}
	fmt.Printf("*** END UNEXPECTED EVENT DIGESTS ***\n\n")

	fmt.Printf("*** LOG CONSISTENCY ERRORS ***\n")
	for _, v := range result.LogConsistencyErrors {
		fmt.Printf("PCR %d, bank %s - actual PCR value: %x, expected PCR value from event log: %x\n",
			v.Index, v.Algorithm, v.PCRDigest, v.ExpectedPCRDigest)
	}
	fmt.Printf("*** END LOG CONSISTENCY ERRORS ***\n")
}
