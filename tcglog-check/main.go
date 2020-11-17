// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/tcglog-parser"
	"github.com/canonical/tcglog-parser/internal"
	"github.com/chrisccoulson/go-efilib"
)

type efiBootVariableBehaviourArg string

func (a *efiBootVariableBehaviourArg) String() string {
	return string(*a)
}

func (a *efiBootVariableBehaviourArg) Set(value string) error {
	switch value {
	case "full", "data-only":
	default:
		return errors.New("invalid value (must be \"full\" or \"data-only\"")
	}
	*a = efiBootVariableBehaviourArg(value)
	return nil
}

var (
	withGrub      bool
	withSdEfiStub bool
	sdEfiStubPcr  int
	noDefaultPcrs bool
	tpmPath       string
	pcrs          internal.PCRArgList

	efiBootVarBehaviour         efiBootVariableBehaviourArg
	ignoreDataDecodeErrors      bool
	ignoreMeasuredTrailingBytes bool
	requirePeImageDigests       bool
)

func init() {
	flag.BoolVar(&withGrub, "with-grub", false, "Validate log entries made by GRUB in to PCR's 8 and 9")
	flag.BoolVar(&withSdEfiStub, "with-systemd-efi-stub", false, "Interpret measurements made by systemd's EFI stub Linux loader")
	flag.IntVar(&sdEfiStubPcr, "systemd-efi-stub-pcr", 8, "Specify the PCR that systemd's EFI stub Linux loader measures to")
	flag.BoolVar(&noDefaultPcrs, "no-default-pcrs", false, "Don't validate log entries for PCRs 0 - 7")
	flag.StringVar(&tpmPath, "tpm-path", "/dev/tpm0", "Validate log entries associated with the specified TPM")
	flag.Var(&pcrs, "pcrs", "Validate log entries for the specified PCRs. Can be specified multiple times")

	flag.Var(&efiBootVarBehaviour, "efi-bootvar-behaviour", "Require that EV_EFI_VARIABLE_BOOT events are associated with "+
		"either the full UEFI_VARIABLE_DATA structure (full) or the variable data only (data-only)")
	flag.BoolVar(&ignoreDataDecodeErrors, "ignore-data-decode-errors", false,
		"Don't exit with an error if any event data fails to decode correctly")
	flag.BoolVar(&ignoreMeasuredTrailingBytes, "ignore-meaured-trailing-bytes", false,
		"Don't exit with an error if any event data contains trailing bytes that were hashed and measured")
	flag.BoolVar(&requirePeImageDigests, "require-pe-image-digests", false, "Require that the digests associated with "+
		"EV_EFI_BOOT_SERVICES_APPLICATION events are PE image digests rather than file digests")
}

type peImageData struct {
	path     string
	peHash   []byte
	fileHash []byte
}

var peImageDataCache map[tcglog.AlgorithmId][]*peImageData

func populatePeImageDataCache(algorithms tcglog.AlgorithmIdList) {
	peImageDataCache = make(map[tcglog.AlgorithmId][]*peImageData)

	dirs := []string{"/boot"}
	for len(dirs) > 0 {
		dir := dirs[0]
		dirs = dirs[1:]

		f, err := os.Open(dir)
		if err != nil {
			continue
		}
		func() {
			defer f.Close()
			dirInfo, err := f.Readdir(-1)
			if err != nil {
				return
			}

			for _, fi := range dirInfo {
				path := filepath.Join(dir, fi.Name())
				switch {
				case fi.IsDir():
					dirs = append(dirs, path)
				case fi.Mode().IsRegular():
					f, err := os.Open(path)
					if err != nil {
						continue
					}
					func() {
						defer f.Close()
						fi, err := f.Stat()
						if err != nil {
							return
						}
						for _, alg := range algorithms {
							peHash, err := efi.ComputePeImageDigest(alg.GetHash(), f, fi.Size())
							if err != nil {
								continue
							}
							h := alg.GetHash().New()
							if _, err := io.Copy(h, f); err != nil {
								continue
							}
							peImageDataCache[alg] = append(peImageDataCache[alg], &peImageData{path: path, peHash: peHash, fileHash: h.Sum(nil)})
						}
					}()
				}
			}
		}()
	}
}

type efiBootVariableBehaviour int

const (
	efiBootVariableBehaviourUnknown efiBootVariableBehaviour = iota
	efiBootVariableBehaviourFull
	efiBootVariableBehaviourVarDataOnly
)

type peImageDigestType int

const (
	peImageDigestTypeUnknown peImageDigestType = iota
	peImageDigestTypePe
	peImageDigestTypeFile
)

func pcrIndexListToSelect(l []tcglog.PCRIndex) (out tpm2.PCRSelect) {
	for _, i := range l {
		out = append(out, int(i))
	}
	return
}

func readPCRsFromTPM2Device(tpm *tpm2.TPMContext, algorithms tcglog.AlgorithmIdList) (map[tcglog.PCRIndex]tcglog.DigestMap, error) {
	result := make(map[tcglog.PCRIndex]tcglog.DigestMap)

	var selections tpm2.PCRSelectionList
	for _, alg := range algorithms {
		selections = append(selections, tpm2.PCRSelection{Hash: tpm2.HashAlgorithmId(alg), Select: pcrIndexListToSelect(pcrs)})
	}

	for _, i := range pcrs {
		result[i] = tcglog.DigestMap{}
	}

	_, digests, err := tpm.PCRRead(selections)
	if err != nil {
		return nil, fmt.Errorf("cannot read PCR values: %v", err)
	}

	for _, s := range selections {
		for _, i := range s.Select {
			result[tcglog.PCRIndex(i)][tcglog.AlgorithmId(s.Hash)] = tcglog.Digest(digests[s.Hash][i])
		}
	}
	return result, nil
}

func readPCRsFromTPM1Device(tpm *tpm2.TPMContext) (map[tcglog.PCRIndex]tcglog.DigestMap, error) {
	result := make(map[tcglog.PCRIndex]tcglog.DigestMap)
	for _, i := range pcrs {
		in, err := mu.MarshalToBytes(uint32(i))
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
	if isTpm2, _ := tpm.IsTPM2(); isTpm2 {
		return 2
	}

	payload, _ := mu.MarshalToBytes(uint32(0x00000005), uint32(4), uint32(0x00000103))
	if rc, _, _, err := tpm.RunCommandBytes(tpm2.StructTag(0x00c1), tpm2.CommandCode(0x00000065), payload); err == nil && rc == tpm2.Success {
		return 1
	}

	return 0
}

func readPCRs(algorithms tcglog.AlgorithmIdList) (map[tcglog.PCRIndex]tcglog.DigestMap, error) {
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return nil, fmt.Errorf("could not open TPM device: %v", err)
	}
	tpm, _ := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	switch getTPMDeviceVersion(tpm) {
	case 2:
		return readPCRsFromTPM2Device(tpm, algorithms)
	case 1:
		return readPCRsFromTPM1Device(tpm)
	}

	return nil, errors.New("not a valid TPM device")
}

type incorrectDigestValue struct {
	algorithm tcglog.AlgorithmId
	expected  tcglog.Digest
}

type checkedEvent struct {
	*tcglog.Event
	measuredBytes           []byte
	measuredTrailingBytes   []byte
	incorrectDigestValues   []incorrectDigestValue
	peImageDigestType       peImageDigestType
	peImagePath             string
	incorrectPeImageDigests tcglog.AlgorithmIdList
}

func (e *checkedEvent) extendsPCR() bool {
	if e.EventType == tcglog.EventTypeNoAction {
		return false
	}
	return true
}

func (e *checkedEvent) expectedMeasuredBytes(efiBootVariableQuirk bool) []byte {
	if err := e.dataDecoderErr(); err != nil {
		return nil
	}

	switch e.EventType {
	case tcglog.EventTypeEventTag, tcglog.EventTypeSCRTMVersion, tcglog.EventTypePlatformConfigFlags, tcglog.EventTypeTableOfDevices, tcglog.EventTypeNonhostInfo, tcglog.EventTypeOmitBootDeviceEvents:
		return e.Data.Bytes()
	case tcglog.EventTypeSeparator:
		if e.Data.(*tcglog.SeparatorEventData).IsError {
			var d [4]byte
			binary.LittleEndian.PutUint32(d[:], tcglog.SeparatorEventErrorValue)
			return d[:]
		}
		return e.Data.Bytes()
	case tcglog.EventTypeAction, tcglog.EventTypeEFIAction:
		return e.Data.Bytes()
	case tcglog.EventTypeEFIVariableDriverConfig, tcglog.EventTypeEFIVariableBoot, tcglog.EventTypeEFIVariableAuthority:
		if e.EventType == tcglog.EventTypeEFIVariableBoot && efiBootVariableQuirk {
			return e.Data.(*tcglog.EFIVariableData).VariableData
		}
		return e.Data.Bytes()
	case tcglog.EventTypeEFIGPTEvent:
		return e.Data.Bytes()
	case tcglog.EventTypeIPL:
		switch d := e.Data.(type) {
		case *tcglog.GrubStringEventData:
			var b bytes.Buffer
			d.EncodeMeasuredBytes(&b)
			return b.Bytes()
		case *tcglog.SystemdEFIStubEventData:
			var b bytes.Buffer
			d.EncodeMeasuredBytes(&b)
			return b.Bytes()
		}
	}

	return nil
}

func (e *checkedEvent) dataDecoderErr() error {
	if err, isErr := e.Data.(error); isErr {
		return err
	}
	return nil
}

func (e *checkedEvent) expectedDigest(alg tcglog.AlgorithmId) []byte {
	h := alg.GetHash().New()
	h.Write(e.measuredBytes)
	return h.Sum(nil)
}

func (e *checkedEvent) hasExpectedDigest(alg tcglog.AlgorithmId) bool {
	h := alg.GetHash().New()
	h.Write(e.measuredBytes)
	return bytes.Equal(e.Digests[alg], e.expectedDigest(alg))
}

func checkEvent(event *tcglog.Event, c *logChecker) (out *checkedEvent) {
	out = &checkedEvent{Event: event}

	for alg := range out.Digests {
		if len(out.measuredBytes) > 0 {
			// We've already determined the bytes measured for this event for a previous digest
			if !out.hasExpectedDigest(alg) {
				out.incorrectDigestValues = append(out.incorrectDigestValues, incorrectDigestValue{algorithm: alg, expected: out.expectedDigest(alg)})
			}
			continue
		}

		efiBootVariableBehaviourTry := c.efiBootVariableBehaviour

	Loop:
		for {
			// Determine what we expect to be measured
			out.measuredBytes = out.expectedMeasuredBytes(efiBootVariableBehaviourTry == efiBootVariableBehaviourVarDataOnly)
			if out.measuredBytes == nil {
				break Loop
			}

			if m, ok := out.Data.(interface{ TrailingBytes() []byte }); ok {
				out.measuredTrailingBytes = m.TrailingBytes()
			}

			for {
				// Determine whether the digest is consistent with the current provisional measured bytes
				switch {
				case out.hasExpectedDigest(alg):
					// All good
					if out.EventType == tcglog.EventTypeEFIVariableBoot && c.efiBootVariableBehaviour == efiBootVariableBehaviourUnknown {
						// This is the first EV_EFI_VARIABLE_BOOT event, so record the measurement behaviour.
						c.efiBootVariableBehaviour = efiBootVariableBehaviourTry
						if efiBootVariableBehaviourTry == efiBootVariableBehaviourUnknown {
							c.efiBootVariableBehaviour = efiBootVariableBehaviourFull
						}
					}
					break Loop
				case len(out.measuredTrailingBytes) > 0:
					// Invalid digest, the event data decoder determined there were trailing bytes, and we were expecting the measured
					// bytes to match the event data. Test if any of the trailing bytes only appear in the event data by truncating
					// the provisional measured bytes one byte at a time and re-testing.
					out.measuredBytes = out.measuredBytes[0 : len(out.measuredBytes)-1]
					out.measuredTrailingBytes = out.measuredTrailingBytes[0 : len(out.measuredTrailingBytes)-1]
				default:
					// Invalid digest
					if out.EventType == tcglog.EventTypeEFIVariableBoot && efiBootVariableBehaviourTry == efiBootVariableBehaviourUnknown {
						// This is the first EV_EFI_VARIABLE_BOOT event, and this test was done assuming that the measured bytes
						// would include the entire EFI_VARIABLE_DATA structure. Repeat the test with only the variable data.
						efiBootVariableBehaviourTry = efiBootVariableBehaviourVarDataOnly
						continue Loop
					}
					// Record the expected digest on the event
					expectedMeasuredBytes := out.expectedMeasuredBytes(false)
					h := alg.GetHash().New()
					h.Write(expectedMeasuredBytes)
					out.incorrectDigestValues = append(out.incorrectDigestValues, incorrectDigestValue{algorithm: alg, expected: h.Sum(nil)})

					out.measuredBytes = nil
					out.measuredTrailingBytes = nil

					break Loop
				}
			}
		}
	}

	if out.PCRIndex != 4 {
		return
	}
	if out.EventType != tcglog.EventTypeEFIBootServicesApplication {
		return
	}

	for alg, digest := range out.Digests {
		var foundData *peImageData
		for _, f := range peImageDataCache[alg] {
			var found bool
			switch {
			case out.peImageDigestType == peImageDigestTypePe && bytes.Equal(digest, f.peHash):
				found = true
			case out.peImageDigestType == peImageDigestTypeFile && bytes.Equal(digest, f.fileHash):
				found = true
			case out.peImageDigestType != peImageDigestTypeUnknown:
			case bytes.Equal(digest, f.peHash):
				found = true
				out.peImageDigestType = peImageDigestTypePe
			case bytes.Equal(digest, f.fileHash):
				found = true
				out.peImageDigestType = peImageDigestTypeFile
			}
			if found {
				foundData = f
				break
			}
		}
		if foundData == nil {
			out.incorrectPeImageDigests = append(out.incorrectPeImageDigests, alg)
		} else {
			out.peImagePath = foundData.path
		}
	}
	return
}

type logChecker struct {
	algs                        tcglog.AlgorithmIdList
	expectedPCRValues           map[tcglog.PCRIndex]tcglog.DigestMap
	efiBootVariableBehaviour    efiBootVariableBehaviour
	events                      []*checkedEvent
	seenMeasuredTrailingBytes   bool
	seenIncorrectDigests        bool
	seenIncorrectPeImageDigests bool
}

func (c *logChecker) ensureExpectedPCRValuesInitialized(index tcglog.PCRIndex) {
	if _, exists := c.expectedPCRValues[index]; exists {
		return
	}

	c.expectedPCRValues[index] = tcglog.DigestMap{}

	for _, alg := range c.algs {
		c.expectedPCRValues[index][alg] = make(tcglog.Digest, alg.Size())
	}
}

func (c *logChecker) simulatePCRExtend(event *checkedEvent) {
	if !event.extendsPCR() {
		return
	}

	for alg, digest := range event.Digests {
		h := alg.GetHash().New()
		h.Write(c.expectedPCRValues[event.PCRIndex][alg])
		h.Write(digest)
		c.expectedPCRValues[event.PCRIndex][alg] = h.Sum(nil)
	}
}

func (c *logChecker) processEvent(event *tcglog.Event) {
	c.ensureExpectedPCRValuesInitialized(event.PCRIndex)

	ce := checkEvent(event, c)
	if len(ce.measuredTrailingBytes) > 0 {
		c.seenMeasuredTrailingBytes = true
	}
	if len(ce.incorrectDigestValues) > 0 {
		c.seenIncorrectDigests = true
	}
	if len(ce.incorrectPeImageDigests) > 0 {
		c.seenIncorrectPeImageDigests = true
	}

	c.simulatePCRExtend(ce)
	c.events = append(c.events, ce)
}

func (c *logChecker) run(log *tcglog.Log) {
	c.algs = log.Algorithms
	c.expectedPCRValues = make(map[tcglog.PCRIndex]tcglog.DigestMap)

	for _, event := range log.Events {
		c.processEvent(event)
	}
}

func run() int {
	flag.Parse()

	args := flag.Args()
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "Too many arguments\n")
		return 1
	}

	logPath := ""
	if len(args) == 1 {
		logPath = args[0]
	}

	if !noDefaultPcrs {
		pcrs = append(pcrs, 0, 1, 2, 3, 4, 5, 6, 7)
		if withGrub {
			pcrs = append(pcrs, 8, 9)
		}
	}

	sort.SliceStable(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })

	if logPath == "" {
		if filepath.Dir(tpmPath) != "/dev" {
			fmt.Fprintf(os.Stderr, "Expected TPM path to be a device node in /dev")
			os.Exit(1)
		}
		logPath = fmt.Sprintf("/sys/kernel/security/%s/binary_bios_measurements", filepath.Base(tpmPath))
	} else {
		tpmPath = ""
	}

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log: %v\n", err)
		return 1
	}
	defer f.Close()

	log, err := tcglog.ParseLog(f, &tcglog.LogOptions{EnableGrub: withGrub, EnableSystemdEFIStub: withSdEfiStub, SystemdEFIStubPCR: tcglog.PCRIndex(sdEfiStubPcr)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse log: %v\n", err)
		return 1
	}

	populatePeImageDataCache(log.Algorithms)

	c := &logChecker{}
	c.run(log)

	failCount := 0

	switch efiBootVarBehaviour {
	case "data-only":
		if c.efiBootVariableBehaviour == efiBootVariableBehaviourFull {
			fmt.Printf("*** FAIL ***: EV_EFI_VARIABLE_BOOT events contain measurements of the entire UEFI_VARIABLE_DATA structure rather than just the event data\n\n")
			failCount++
		}
	case "full":
		if c.efiBootVariableBehaviour == efiBootVariableBehaviourVarDataOnly {
			fmt.Printf("*** FAIL ***: EV_EFI_VARIABLE_BOOT events only contain measurements of variable data rather than the entire UEFI_VARIABLE_DATA structure\n\n")
			failCount++
		}
	default:
		if c.efiBootVariableBehaviour == efiBootVariableBehaviourVarDataOnly {
			fmt.Printf("- INFO: EV_EFI_VARIABLE_BOOT events only contain measurements of variable data rather than the entire UEFI_VARIABLE_DATA structure\n\n")
		}
	}

	var dataDecoderErrs []string
	for _, e := range c.events {
		err := e.dataDecoderErr()
		if err == nil {
			continue
		}

		dataDecoderErrs = append(dataDecoderErrs, fmt.Sprintf("\t- Event %d in PCR %d (type: %s): %v\n", e.Index, e.PCRIndex, e.EventType, err))
	}
	if len(dataDecoderErrs) > 0 {
		if !ignoreDataDecodeErrors {
			fmt.Printf("*** FAIL ***")
			failCount++
		} else {
			fmt.Printf("- INFO")
		}
		fmt.Printf(": The following events contain event data that was not in the expected format and could not be decoded correctly:\n")
		for _, err := range dataDecoderErrs {
			fmt.Printf("%s", err)
		}
		fmt.Printf("This might be a bug in the firmware or bootloader code responsible for performing these measurements.\n\n")
	}

	if c.seenMeasuredTrailingBytes {
		if !ignoreMeasuredTrailingBytes {
			fmt.Printf("*** FAIL ***")
			failCount++
		} else {
			fmt.Printf("- INFO")
		}
		fmt.Printf(": The following events have trailing bytes at the end of their event data that was hashed and measured:\n")
		for _, e := range c.events {
			if len(e.measuredTrailingBytes) == 0 {
				continue
			}

			fmt.Printf("\t- Event %d in PCR %d (type: %s): %x (%d bytes)\n", e.Index, e.PCRIndex, e.EventType, e.measuredTrailingBytes, len(e.measuredTrailingBytes))
		}
		fmt.Printf("These trailing bytes might indicate a bug in the firmware or bootloader code responsible for performing the " +
			"measurements, and should be taken in to account when pre-computing digests for these events.\n\n")
	}

	if c.seenIncorrectDigests {
		failCount++
		fmt.Printf("*** FAIL ***: The following events have digests that aren't consistent with the data recorded with them in the log:\n")
		for _, e := range c.events {
			if len(e.incorrectDigestValues) == 0 {
				continue
			}

			for _, d := range e.incorrectDigestValues {
				fmt.Printf("\t- Event %d in PCR %d (type: %s, alg: %s) - expected (from data): %x, got: %x\n", e.Index, e.PCRIndex, e.EventType, d.algorithm, d.expected, e.Digests[d.algorithm])
			}
		}
		fmt.Printf("This is unexpected for these event types, and might indicate a bug in the firmware of bootloader code responsible " +
			"for performing these measurements. Knowledge of the format of the data being measured is required in order to pre-compute " +
			"digests for these events or by a remote verifier for attestation purposes.\n\n")
	}

	if requirePeImageDigests {
		seenFileDigest := false
		for _, e := range c.events {
			if e.peImageDigestType != peImageDigestTypeFile {
				continue
			}

			if !seenFileDigest {
				seenFileDigest = true
				failCount++
				fmt.Printf("*** FAIL ***: The following EV_EFI_BOOT_SERVICES_APPLICATION events contain file digests rather than PE image digests:\n")
			}

			fmt.Printf("\t- Event %d in PCR 4 (%s)\n", e.Index, e.peImagePath)
		}
		if seenFileDigest {
			fmt.Printf("The presence of file digests rather than PE image digests might be because the measuring bootloader " +
				"is using the 1.2 version of the TCG EFI Protocol Specification rather than the 2.0 version (which could be " +
				"because the firmware doesn't support the newer version). It could also be because the measuring bootloader " +
				"does not pass the appropriate flag to the firmware to indicate that what is being measured is a PE image\n")
		}
	}

	if c.seenIncorrectPeImageDigests {
		failCount++
		fmt.Printf("*** FAIL ***: The following EV_EFI_BOOT_SERVICES_APPLICATION events contain digests that might be invalid:\n")
		for _, e := range c.events {
			if len(e.incorrectPeImageDigests) == 0 {
				continue
			}

			if e.peImageDigestType == peImageDigestTypeUnknown {
				fmt.Printf("\t- Event %d in PCR 4 has digests that don't correspond to any PE images\n", e.Index)
			} else {
				for _, alg := range e.incorrectPeImageDigests {
					fmt.Printf("\t- Event %d in PCR 4 (%s) has an invalid digest for alg %s (got: %x) [almost certainly a firmware bug]\n", e.Index, e.peImagePath, alg, e.Digests[alg])
				}
			}
		}
		fmt.Printf("Event digests that don't correspond to any PE image might be caused by a bug in the firmware or bootloader " +
			"code responsible for performing the measurements, or might be because the image was loaded from a location " +
			"that is not currently mounted at the expected path (/boot), in which case it is not possible to determine if " +
			"the digests are correct.\n")
	}

	if tpmPath == "" {
		fmt.Printf("- INFO: Expected PCR values from log:\n")
		for _, i := range pcrs {
			for _, alg := range log.Algorithms {
				fmt.Printf("\tPCR %d, bank %s: %x\n", i, alg, c.expectedPCRValues[i][alg])
			}
		}
	} else {
		tpmPCRValues, err := readPCRs(log.Algorithms)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read PCR values from TPM: %v", err)
			return 1
		}

		seenLogConsistencyError := false
		for _, i := range pcrs {
			for _, alg := range log.Algorithms {
				if bytes.Equal(c.expectedPCRValues[i][alg], tpmPCRValues[i][alg]) {
					continue
				}
				if !seenLogConsistencyError {
					seenLogConsistencyError = true
					fmt.Printf("*** FAIL ***: The log is not consistent with what was measured in to the TPM for some PCRs:\n")
					failCount++
				}
				fmt.Printf("\t- PCR %d, bank %s - actual value from TPM: %x, expected value from log: %x\n",
					i, alg, tpmPCRValues[i][alg], c.expectedPCRValues[i][alg])
			}
		}

		if seenLogConsistencyError {
			fmt.Printf("This might be caused by a bug in the firmware or bootloader code participating in the measured boot chain, " +
				"a bug in the kernel's log handling code, or because events have been measured to the TPM by OS code. A " +
				"remote verifier will require consistency between the log and the TPM's PCR values for attestation.\n")
		}
	}

	if failCount > 0 {
		return 1
	}
	return 0

}
func main() {
	os.Exit(run())
}
