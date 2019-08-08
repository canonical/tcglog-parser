package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/chrisccoulson/tcglog-parser"
)

type AlgorithmIdArgList []tcglog.AlgorithmId

func (l *AlgorithmIdArgList) String() string {
	var builder strings.Builder
	for i, alg := range *l {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "%s", alg)
	}
	return builder.String()
}

func (l *AlgorithmIdArgList) Set(value string) error {
	algorithmId, err := tcglog.ParseAlgorithm(value)
	if err != nil {
		return err
	}
	*l = append(*l, algorithmId)
	return nil
}

var (
	withGrub      bool
	noDefaultPcrs bool
	tpmPath       string
	pcrs          tcglog.PCRArgList
	algorithms    AlgorithmIdArgList
)

func init() {
	flag.BoolVar(&withGrub, "with-grub", false, "Validate log entries made by GRUB in to PCR's 8 and 9")
	flag.BoolVar(&noDefaultPcrs, "no-default-pcrs", false, "Don't validate log entries for PCRs 0 - 7")
	flag.StringVar(&tpmPath, "tpm-path", "/dev/tpm0", "Validate log entries associated with the specified TPM")
	flag.Var(&pcrs, "pcr", "Validate log entries for the specified PCR. Can be specified multiple times")
	flag.Var(&algorithms, "alg", "Validate log entries for the specified algorithm. Can be specified "+
		"multiple times")
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

	result, err := tcglog.ValidateLogAgainstTPMByPath(
		tpmPath,
		tcglog.LogValidateOptions{
			PCRs:       []tcglog.PCRIndex(pcrs),
			Algorithms: algorithms,
			EnableGrub: withGrub})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to validate log file: %v\n", err)
		os.Exit(1)
	}

	if result.EfiVariableBootQuirk {
		fmt.Printf("- EV_EFI_VARIABLE_BOOT events measure entire UEFI_VARIABLE_DATA structure rather " +
			"than just the variable contents\n\n")
	}

	seenExcessMeasuredBytes := false
	for _, e := range result.ValidatedEvents {
		if len(e.ExcessMeasuredBytes) == 0 {
			continue
		}

		if !seenExcessMeasuredBytes {
			seenExcessMeasuredBytes = true
			fmt.Printf("- The following events have padding at the end of their event data that was " +
				"hashed and measured:\n")
		}

		fmt.Printf("  - Event %d in PCR %d (type: %s): %x (%d bytes)\n", e.Event.Index, e.Event.PCRIndex,
			e.Event.EventType, e.ExcessMeasuredBytes, len(e.ExcessMeasuredBytes))
	}
	if seenExcessMeasuredBytes {
		fmt.Printf("  This extra padding should be taken in to account when calculating updated digests " +
			"for these events when the components that are being measured are upgraded or changed " +
			"in some way.\n\n")
	}

	seenEVAWithUnmeasuredByte := false
	for _, e := range result.ValidatedEvents {
		if !e.EfiVariableAuthorityHasUnmeasuredByte {
			continue
		}

		if !seenEVAWithUnmeasuredByte {
			seenEVAWithUnmeasuredByte = true
			fmt.Printf("- The following events have one extra byte at the end of their event data " +
				"that was not hashed and measured:\n")
		}

		v := e.Event.Data.(*tcglog.EFIVariableEventData)
		fmt.Printf("  - Event %d in PCR %d [ VariableName: %s, UnicodeName: \"%s\" ] (byte: 0x%x)\n",
			e.Event.Index, e.Event.PCRIndex, &v.VariableName, v.UnicodeName,
			v.Bytes()[len(v.Bytes())-1])
	}
	if seenEVAWithUnmeasuredByte {
		fmt.Printf("\n")
	}

	seenUnexpectedDigests := false
	for _, e := range result.ValidatedEvents {
		if len(e.UnexpectedDigestValues) == 0 {
			continue
		}

		if !seenUnexpectedDigests {
			seenUnexpectedDigests = true
			fmt.Printf("- The following events have digests that aren't generated from the data " +
				"recorded with them in the log:\n")
		}

		for _, v := range e.UnexpectedDigestValues {
			fmt.Printf("  - Event %d in PCR %d (type: %s, alg: %s) - expected (from data): %x, "+
				"got: %x\n", e.Event.Index, e.Event.PCRIndex, e.Event.EventType, v.Algorithm,
				v.Expected, e.Event.Digests[v.Algorithm])
		}
	}
	if seenUnexpectedDigests {
		fmt.Printf("  This is unexpected for these event types. Knowledge of the format of the data " +
			"being measured is required in order to calculate updated digests for these events " +
			"when the components being measured are upgraded or changed in some way.\n\n")
	}

	if len(result.LogConsistencyErrors) != 0 {
		fmt.Printf("- The log is not consistent with what was measured in to the TPM for some PCRs:\n")
	}
	for _, v := range result.LogConsistencyErrors {
		fmt.Printf("  - PCR %d, bank %s - actual PCR value: %x, expected PCR value from log: %x\n",
			v.Index, v.Algorithm, v.PCRDigest, v.ExpectedPCRDigest)
	}
	if len(result.LogConsistencyErrors) != 0 {
		fmt.Printf("*** The event log is broken! ***\n")
	}
}
