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
	"strings"

	"github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"

	"github.com/canonical/tcglog-parser"
	"github.com/canonical/tcglog-parser/internal"
)

type requiredAlgsArg tcglog.AlgorithmIdList

func (l *requiredAlgsArg) String() string {
	return fmt.Sprintf("%v", *l)
}

func (l *requiredAlgsArg) Set(value string) error {
	algs := strings.Split(value, ",")
	for _, alg := range algs {
		a, err := internal.ParseAlgorithm(alg)
		if err != nil {
			return err
		}
		*l = append(*l, a)
	}
	return nil
}

type bootImageSearchPathsArg []string

func (a *bootImageSearchPathsArg) String() string {
	return strings.Join(*a, ",")
}

func (a *bootImageSearchPathsArg) Set(value string) error {
	*a = append(*a, value)
	return nil
}

var (
	withGrub      bool
	withSdEfiStub bool
	sdEfiStubPcr  int
	noDefaultPcrs bool
	tpmPath       string
	pcrs          = internal.PCRArgList{0, 1, 2, 3, 4, 5, 6, 7}

	ignoreIncorrectEfiBootvar bool
	ignoreDataDecodeErrors    bool
	requiredAlgs              requiredAlgsArg
	requirePeImageDigests     bool
	bootImageSearchPaths      = bootImageSearchPathsArg{"/boot", "/cdrom/EFI", "/cdrom/casper"}
)

func init() {
	flag.BoolVar(&withGrub, "with-grub", false, "Validate log entries made by GRUB in to PCR's 8 and 9")
	flag.BoolVar(&withSdEfiStub, "with-systemd-efi-stub", false, "Interpret measurements made by systemd's EFI stub Linux loader")
	flag.IntVar(&sdEfiStubPcr, "systemd-efi-stub-pcr", 8, "Specify the PCR that systemd's EFI stub Linux loader measures to")
	flag.BoolVar(&noDefaultPcrs, "no-default-pcrs", false, "Omit the default PCRs")
	flag.StringVar(&tpmPath, "tpm-path", "/dev/tpm0", "Validate log entries associated with the specified TPM")
	flag.Var(&pcrs, "pcrs", "Validate log entries for the specified PCRs. Can be specified multiple times")

	flag.BoolVar(&ignoreIncorrectEfiBootvar, "ignore-incorrect-efi-bootvar", false,
		"Don't exit with an error if the EV_EFI_VARIABLE_BOOT events don't contain the entire corresponding "+
			"UEFI_VARIABLE_DATA structure, but instead only contain the variable payload")
	flag.BoolVar(&ignoreDataDecodeErrors, "ignore-data-decode-errors", false,
		"Don't exit with an error if any event data fails to decode correctly")
	flag.Var(&requiredAlgs, "required-algs", "Require the specified algorithms to be present in the log")
	flag.BoolVar(&requirePeImageDigests, "require-pe-image-digests", false, "Require that the digests for "+
		"EV_EFI_BOOT_SERVICES_APPLICATION events associated with PE images are PE image digests rather than "+
		"file digests")
	flag.Var(&bootImageSearchPaths, "boot-image-search-path", "Specify the path to search for images executed during "+
		"boot and measured to PCR 4 with EV_EFI_BOOT_SERVICES_APPLICATION events. Can be specified multiple "+
		"times. Default is /boot, /cdrom/EFI and /cdrom/casper")
}

type peImageData struct {
	path     string
	peHash   []byte
	fileHash []byte
}

var peImageDataCache map[tpm2.HashAlgorithmId][]*peImageData

func populatePeImageDataCache(algorithms tcglog.AlgorithmIdList) {
	peImageDataCache = make(map[tpm2.HashAlgorithmId][]*peImageData)

	dirs := make([]string, len(bootImageSearchPaths))
	copy(dirs, bootImageSearchPaths)
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
							fileHash := h.Sum(nil)
							fmt.Printf("Computed %v for PE image %s - file:%x, authenticode:%x\n", alg, path, fileHash, peHash)
							peImageDataCache[alg] = append(peImageDataCache[alg], &peImageData{path: path, peHash: peHash, fileHash: fileHash})
						}
					}()
				}
			}
		}()
	}

	fmt.Println("")
}

type efiBootVariableBehaviour int

const (
	efiBootVariableBehaviourUnknown efiBootVariableBehaviour = iota
	efiBootVariableBehaviourOK
	efiBootVariableBehaviourIncorrect
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
		selections = append(selections, tpm2.PCRSelection{Hash: alg, Select: pcrIndexListToSelect(pcrs)})
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
			result[tcglog.PCRIndex(i)][s.Hash] = tcglog.Digest(digests[s.Hash][i])
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
		result[i][tpm2.HashAlgorithmSHA1] = out
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
	algorithm tpm2.HashAlgorithmId
	expected  tcglog.Digest
}

type checkedEvent struct {
	*tcglog.Event
	index                   uint
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

func (e *checkedEvent) dataDecoderErr() error {
	if err, isErr := e.Data.Decoded().(error); isErr {
		return err
	}
	return nil
}

func (e *checkedEvent) expectedDigest(alg tpm2.HashAlgorithmId, efiBootVariableQuirk bool) []byte {
	if err := e.dataDecoderErr(); err != nil {
		return nil
	}

	switch e.EventType {
	case tcglog.EventTypeEventTag, tcglog.EventTypeSCRTMVersion, tcglog.EventTypePlatformConfigFlags, tcglog.EventTypeTableOfDevices, tcglog.EventTypeNonhostInfo, tcglog.EventTypeOmitBootDeviceEvents:
		return tcglog.ComputeEventDigest(alg.GetHash(), e.Data.Bytes())
	case tcglog.EventTypeSeparator:
		var value uint32
		if e.Data.Decoded().(*tcglog.SeparatorEventData).IsError {
			value = tcglog.SeparatorEventErrorValue
		} else {
			value = binary.LittleEndian.Uint32(e.Data.Bytes())
		}
		return tcglog.ComputeSeparatorEventDigest(alg.GetHash(), value)
	case tcglog.EventTypeAction, tcglog.EventTypeEFIAction:
		return tcglog.ComputeStringEventDigest(alg.GetHash(), string(e.Data.Decoded().(tcglog.StringEventData)))
	case tcglog.EventTypeEFIVariableDriverConfig, tcglog.EventTypeEFIVariableBoot, tcglog.EventTypeEFIVariableAuthority:
		data := e.Data.Decoded().(*tcglog.EFIVariableData)
		if e.EventType == tcglog.EventTypeEFIVariableBoot && efiBootVariableQuirk {
			h := alg.GetHash().New()
			h.Write(data.VariableData)
			return h.Sum(nil)
		}
		return tcglog.ComputeEFIVariableDataDigest(alg.GetHash(), data.UnicodeName, data.VariableName, data.VariableData)
	case tcglog.EventTypeEFIGPTEvent:
		return tcglog.ComputeEventDigest(alg.GetHash(), e.Data.Bytes())
	case tcglog.EventTypeIPL:
		switch d := e.Data.Decoded().(type) {
		case *tcglog.GrubStringEventData:
			return tcglog.ComputeStringEventDigest(alg.GetHash(), d.Str)
		case tcglog.SystemdEFIStubCommandline:
			return tcglog.ComputeSystemdEFIStubCommandlineDigest(alg.GetHash(), string(d))
		}
	}

	return nil
}

func checkEvent(event *tcglog.Event, c *logChecker) (out *checkedEvent) {
	out = &checkedEvent{Event: event}

Outer:
	for alg, digest := range out.Digests {
		efiBootVariableBehaviourTry := c.efiBootVariableBehaviour

	Inner:
		for {
			expectedDigest := out.expectedDigest(alg, efiBootVariableBehaviourTry == efiBootVariableBehaviourIncorrect)
			if expectedDigest == nil {
				break Outer
			}

			switch {
			case bytes.Equal(digest, expectedDigest) && out.EventType == tcglog.EventTypeEFIVariableBoot && c.efiBootVariableBehaviour == efiBootVariableBehaviourUnknown:
				// Valid digest, and this is the first EV_EFI_VARIABLE_BOOT event,
				// so record the measurement behaviour.
				c.efiBootVariableBehaviour = efiBootVariableBehaviourTry
				if efiBootVariableBehaviourTry == efiBootVariableBehaviourUnknown {
					c.efiBootVariableBehaviour = efiBootVariableBehaviourOK
				}
				fallthrough
			case bytes.Equal(digest, expectedDigest):
				// Valid digest
				break Inner
			case out.EventType == tcglog.EventTypeEFIVariableBoot && efiBootVariableBehaviourTry == efiBootVariableBehaviourUnknown:
				// Invalid digest
				// This is the first EV_EFI_VARIABLE_BOOT event, and this test was done assuming that the measured bytes
				// would include the entire EFI_VARIABLE_DATA structure. Repeat the test with only the variable data, which
				// is how EDK2 measures these.
				efiBootVariableBehaviourTry = efiBootVariableBehaviourIncorrect
			default:
				// Invalid digest. Record the expected digest on the event.
				out.incorrectDigestValues = append(out.incorrectDigestValues, incorrectDigestValue{algorithm: alg, expected: expectedDigest})
				break Inner
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
	indexTracker                map[tcglog.PCRIndex]uint
	expectedPCRValues           map[tcglog.PCRIndex]tcglog.DigestMap
	efiBootVariableBehaviour    efiBootVariableBehaviour
	events                      []*checkedEvent
	seenIncorrectDigests        bool
	seenIncorrectPeImageDigests bool
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
	if !pcrs.Contains(event.PCRIndex) {
		return
	}

	ce := checkEvent(event, c)
	if len(ce.incorrectDigestValues) > 0 {
		c.seenIncorrectDigests = true
	}
	if len(ce.incorrectPeImageDigests) > 0 {
		c.seenIncorrectPeImageDigests = true
	}

	c.simulatePCRExtend(ce)
	ce.index = c.indexTracker[ce.PCRIndex]
	c.events = append(c.events, ce)
	c.indexTracker[ce.PCRIndex] = ce.index + 1
}

func (c *logChecker) run(log *tcglog.Log) {
	c.indexTracker = make(map[tcglog.PCRIndex]uint)
	c.expectedPCRValues = make(map[tcglog.PCRIndex]tcglog.DigestMap)
	for _, pcr := range pcrs {
		c.expectedPCRValues[pcr] = tcglog.DigestMap{}

		for _, alg := range log.Algorithms {
			c.expectedPCRValues[pcr][alg] = make(tcglog.Digest, alg.Size())
		}
	}

	for _, event := range log.Events {
		c.processEvent(event)
	}
}

func run() error {
	flag.Parse()

	args := flag.Args()
	if len(args) > 1 {
		return errors.New("too many arguments")
	}

	logPath := ""
	if len(args) == 1 {
		logPath = args[0]
	}

	if !noDefaultPcrs {
		if withGrub {
			pcrs = append(pcrs, 8, 9)
		}
		if withSdEfiStub {
			pcrs = append(pcrs, tcglog.PCRIndex(sdEfiStubPcr))
		}
	} else {
		pcrs = pcrs[8:]
	}

	sort.SliceStable(pcrs, func(i, j int) bool { return pcrs[i] < pcrs[j] })

	if logPath == "" {
		if filepath.Dir(tpmPath) != "/dev" {
			return errors.New("expected TPM path to be a device node in /dev")
		}
		logPath = fmt.Sprintf("/sys/kernel/security/%s/binary_bios_measurements", filepath.Base(tpmPath))
	} else {
		tpmPath = ""
	}

	f, err := os.Open(logPath)
	if err != nil {
		return xerrors.Errorf("cannot open log: %w", err)
	}
	defer f.Close()

	failed := false

	options := tcglog.LogOptions{
		EnableGrub:           withGrub,
		EnableSystemdEFIStub: withSdEfiStub,
		SystemdEFIStubPCR:    tcglog.PCRIndex(sdEfiStubPcr)}
	log, err := tcglog.ParseLog(f, &options)
	if err != nil {
		return xerrors.Errorf("cannot parse log: %w", err)
	}

	missingAlg := false
	for _, alg := range requiredAlgs {
		if log.Algorithms.Contains(alg) {
			continue
		}

		if !missingAlg {
			missingAlg = true
			failed = true
			fmt.Printf("*** FAIL ***: The log is missing the following required algorithms:\n")
		}

		fmt.Printf("\t- %s\n", alg)
	}
	if missingAlg {
		fmt.Printf("\n")
	}

	populatePeImageDataCache(log.Algorithms)

	c := &logChecker{}
	c.run(log)

	switch {
	case c.efiBootVariableBehaviour == efiBootVariableBehaviourIncorrect && ignoreIncorrectEfiBootvar:
		fmt.Printf("- INFO: EV_EFI_VARIABLE_BOOT events only contain measurements of variable data rather than the entire UEFI_VARIABLE_DATA structure\n\n")
	case c.efiBootVariableBehaviour == efiBootVariableBehaviourIncorrect:
		fmt.Printf("*** FAIL ***: EV_EFI_VARIABLE_BOOT events only contain measurements of variable data rather than the entire UEFI_VARIABLE_DATA structure\n\n")
		failed = true
	}

	var dataDecoderErrs []string
	for _, e := range c.events {
		err := e.dataDecoderErr()
		if err == nil {
			continue
		}

		dataDecoderErrs = append(dataDecoderErrs, fmt.Sprintf("\t- Event %d in PCR %d (type: %s): %v\n", e.index, e.PCRIndex, e.EventType, err))
	}
	if len(dataDecoderErrs) > 0 {
		if !ignoreDataDecodeErrors {
			fmt.Printf("*** FAIL ***")
			failed = true
		} else {
			fmt.Printf("- INFO")
		}
		fmt.Printf(": The following events contain event data that was not in the expected format and could not be decoded correctly:\n")
		for _, err := range dataDecoderErrs {
			fmt.Printf("%s", err)
		}
		fmt.Printf("This might be a bug in the firmware or bootloader code responsible for performing these measurements.\n\n")
	}

	if c.seenIncorrectDigests {
		failed = true
		fmt.Printf("*** FAIL ***: The following events have digests that aren't consistent with the data recorded with them in the log:\n")
		for _, e := range c.events {
			if len(e.incorrectDigestValues) == 0 {
				continue
			}

			for _, d := range e.incorrectDigestValues {
				fmt.Printf("\t- Event %d in PCR %d (type: %s, alg: %s) - expected (from data): %x, got: %x\n", e.index, e.PCRIndex, e.EventType, d.algorithm, d.expected, e.Digests[d.algorithm])
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
				failed = true
				fmt.Printf("*** FAIL ***: The following EV_EFI_BOOT_SERVICES_APPLICATION events contain file digests rather than PE image digests:\n")
			}

			fmt.Printf("\t- Event %d in PCR 4 (%s)\n", e.index, e.peImagePath)
		}
		if seenFileDigest {
			fmt.Printf("The presence of file digests rather than PE image digests might be because the measuring bootloader " +
				"is using the 1.2 version of the TCG EFI Protocol Specification rather than the 2.0 version (which could be " +
				"because the firmware doesn't support the newer version). It could also be because the measuring bootloader " +
				"does not pass the appropriate flag to the firmware to indicate that what is being measured is a PE image\n")
		}
	}

	if c.seenIncorrectPeImageDigests {
		failed = true
		fmt.Printf("*** FAIL ***: The following EV_EFI_BOOT_SERVICES_APPLICATION events contain digests that might be invalid:\n")
		for _, e := range c.events {
			if len(e.incorrectPeImageDigests) == 0 {
				continue
			}

			if e.peImageDigestType == peImageDigestTypeUnknown {
				fmt.Printf("\t- Event %d in PCR 4 has digests that don't correspond to any PE images\n", e.index)
			} else {
				for _, alg := range e.incorrectPeImageDigests {
					fmt.Printf("\t- Event %d in PCR 4 (%s) has an invalid digest for alg %s (got: %x) [almost certainly a firmware bug]\n", e.index, e.peImagePath, alg, e.Digests[alg])
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
			return xerrors.Errorf("cannot read PCR values from TPM: %w", err)
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
					failed = true
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

	if failed {
		return errors.New("One or more failures were detected!")
	}
	return nil

}
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
