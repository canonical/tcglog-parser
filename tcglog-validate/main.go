package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/tcglog-parser"
)

type AlgorithmIdArgList tcglog.AlgorithmIdList

func (l *AlgorithmIdArgList) String() string {
	var builder bytes.Buffer
	for i, alg := range *l {
		if i > 0 {
			builder.WriteString(", ")
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

func pcrIndexListToSelectionData(l []tcglog.PCRIndex) (out tpm2.PCRSelectionData) {
	for _, i := range l {
		out = append(out, int(i))
	}
	return
}

func readPCRsFromTPM2Device(tpm *tpm2.TPMContext) (map[tcglog.PCRIndex]tcglog.DigestMap, error) {
	result := make(map[tcglog.PCRIndex]tcglog.DigestMap)

	var selections tpm2.PCRSelectionList
	for _, alg := range algorithms {
		selections = append(selections,
			tpm2.PCRSelection{Hash: tpm2.AlgorithmId(alg), Select: pcrIndexListToSelectionData(pcrs)})
	}

	for _, i := range pcrs {
		result[i] = tcglog.DigestMap{}
	}

	_, digests, err := tpm.PCRRead(selections)
	if err != nil {
		return nil, fmt.Errorf("cannot read PCR values: %v", err)
	}

	j := 0
	for _, s := range selections {
		for _, i := range s.Select {
			result[tcglog.PCRIndex(i)][tcglog.AlgorithmId(s.Hash)] = tcglog.Digest(digests[j])
			j++
		}
	}
	return result, nil
}

func readPCRsFromTPM1Device(tpm *tpm2.TPMContext) (map[tcglog.PCRIndex]tcglog.DigestMap, error) {
	result := make(map[tcglog.PCRIndex]tcglog.DigestMap)
	for _, i := range pcrs {
		in, err := tpm2.MarshalToBytes(uint32(i))
		if err != nil {
			return nil, fmt.Errorf("cannot read PCR values due to a marshalling error: %v", err)
		}
		rc, _, out, err := tpm.RunCommandBytes(tpm2.StructTag(0x00c1), tpm2.CommandCode(0x00000015), in)
		if err != nil {
			return nil, fmt.Errorf("cannot read PCR values: %v", err)
		}
		if rc != tpm2.Success {
			return nil, fmt.Errorf("cannot read PCR values: unexpected response code (0x%08x)", rc)
		}
		result[i] = tcglog.DigestMap{}
		result[i][tcglog.AlgorithmSha1] = out
	}
	return result, nil
}

func getTPMDeviceVersion(tpm *tpm2.TPMContext) int {
	if _, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyManufacturer, 1); err == nil {
		return 2
	}

	in, err := tpm2.MarshalToBytes(uint32(0x00000005), uint32(4), uint32(0x00000103))
	if err != nil {
		return 0
	}
	if rc, _, _, err := tpm.RunCommandBytes(tpm2.StructTag(0x00c1), tpm2.CommandCode(0x00000065),
		in); err == nil && rc == tpm2.Success {
		return 1
	}

	return 0
}

func readPCRs() (map[tcglog.PCRIndex]tcglog.DigestMap, error) {
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("could not open TPM device: %v", err)
	}
	tpm, _ := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	switch getTPMDeviceVersion(tpm) {
	case 2:
		return readPCRsFromTPM2Device(tpm)
	case 1:
		return readPCRsFromTPM1Device(tpm)
	}

	return nil, errors.New("not a valid TPM device")
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

	sort.SliceStable(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })

	if filepath.Dir(tpmPath) != "/dev" {
		fmt.Fprintf(os.Stderr, "Expected TPM path to be a device node in /dev")
		os.Exit(1)
	}

	logPath := fmt.Sprintf("/sys/kernel/security/%s/binary_bios_measurements", filepath.Base(tpmPath))

	result, err := tcglog.ReplayAndValidateLog(logPath, tcglog.LogOptions{EnableGrub: withGrub})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to replay and validate log file: %v\n", err)
		os.Exit(1)
	}

	if len(algorithms) == 0 {
		algorithms = AlgorithmIdArgList(result.Algorithms)
	}
	for _, alg := range algorithms {
		if !result.Algorithms.Contains(alg) {
			fmt.Fprintf(os.Stderr, "Log doesn't contain entries for %s algorithm", alg)
			os.Exit(1)
		}
	}

	tpmPCRValues, err := readPCRs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read PCR values from TPM: %v", err)
		os.Exit(1)
	}

	if result.EfiVariableBootDigestsContainFullVariableStruct {
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

	seenLogConsistencyError := false
	for _, i := range pcrs {
		for _, alg := range algorithms {
			if bytes.Equal(result.LogPCRValues[i][alg], tpmPCRValues[i][alg]) {
				continue
			}
			if !seenLogConsistencyError {
				seenLogConsistencyError = true
				fmt.Printf("- The log is not consistent with what was measured in to the TPM " +
					"for some PCRs:\n")
			}
			fmt.Printf("  - PCR %d, bank %s - actual PCR value: %x, expected PCR value from log: %x\n",
				i, alg, tpmPCRValues[i][alg], result.LogPCRValues[i][alg])
		}
	}

	if seenLogConsistencyError {
		fmt.Printf("*** The event log is broken! ***\n")
	}
}
