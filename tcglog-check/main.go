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

var (
	withGrub      bool
	withSdEfiStub bool
	sdEfiStubPcr  int
	noDefaultPcrs bool
	tpmPath       string
	logPath       string
	pcrs          internal.PCRArgList
)

func init() {
	flag.BoolVar(&withGrub, "with-grub", false, "Validate log entries made by GRUB in to PCR's 8 and 9")
	flag.BoolVar(&withSdEfiStub, "with-systemd-efi-stub", false, "Interpret measurements made by systemd's EFI stub Linux loader")
	flag.IntVar(&sdEfiStubPcr, "systemd-efi-stub-pcr", 8, "Specify the PCR that systemd's EFI stub Linux loader measures to")
	flag.BoolVar(&noDefaultPcrs, "no-default-pcrs", false, "Don't validate log entries for PCRs 0 - 7")
	flag.StringVar(&tpmPath, "tpm-path", "/dev/tpm0", "Validate log entries associated with the specified TPM")
	flag.StringVar(&logPath, "log-path", "", "")
	flag.Var(&pcrs, "pcrs", "Validate log entries for the specified PCRs. Can be specified multiple times")
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

func doesEventTypeExtendPCR(t tcglog.EventType) bool {
	if t == tcglog.EventTypeNoAction {
		return false
	}
	return true
}

func isExpectedDigestValue(digest tcglog.Digest, alg tcglog.AlgorithmId, measuredBytes []byte) (bool, []byte) {
	h := alg.GetHash().New()
	h.Write(measuredBytes)
	expected := h.Sum(nil)
	return bytes.Equal(digest, expected), expected
}

func determineMeasuredBytes(event *tcglog.Event, efiBootVariableQuirk bool) []byte {
	if _, isErr := event.Data.(error); isErr {
		return nil
	}

	switch event.EventType {
	case tcglog.EventTypeEventTag, tcglog.EventTypeSCRTMVersion, tcglog.EventTypePlatformConfigFlags, tcglog.EventTypeTableOfDevices, tcglog.EventTypeNonhostInfo, tcglog.EventTypeOmitBootDeviceEvents:
		return event.Data.Bytes()
	case tcglog.EventTypeSeparator:
		if event.Data.(*tcglog.SeparatorEventData).IsError {
			var d [4]byte
			binary.LittleEndian.PutUint32(d[:], tcglog.SeparatorEventErrorValue)
			return d[:]
		}
		return event.Data.Bytes()
	case tcglog.EventTypeAction, tcglog.EventTypeEFIAction:
		return event.Data.Bytes()
	case tcglog.EventTypeEFIVariableDriverConfig, tcglog.EventTypeEFIVariableBoot, tcglog.EventTypeEFIVariableAuthority:
		if event.EventType == tcglog.EventTypeEFIVariableBoot && efiBootVariableQuirk {
			return event.Data.(*tcglog.EFIVariableData).VariableData
		}
		return event.Data.Bytes()
	case tcglog.EventTypeEFIGPTEvent:
		return event.Data.Bytes()
	case tcglog.EventTypeIPL:
		switch d := event.Data.(type) {
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

type incorrectDigestValue struct {
	algorithm tcglog.AlgorithmId
	expected  tcglog.Digest
}

type validatedEvent struct {
	*tcglog.Event
	measuredTrailingBytes   []byte
	incorrectDigestValues   []incorrectDigestValue
	peImageDigestType       peImageDigestType
	peImagePath             string
	incorrectPeImageDigests tcglog.AlgorithmIdList
	dataDecoderErr          error
}

type logValidator struct {
	expectedPCRValues        map[tcglog.PCRIndex]tcglog.DigestMap
	efiBootVariableBehaviour efiBootVariableBehaviour
	validatedEvents          []*validatedEvent
}

func (v *logValidator) processEvent(log *tcglog.Log, event *tcglog.Event) {
	if _, exists := v.expectedPCRValues[event.PCRIndex]; !exists {
		v.expectedPCRValues[event.PCRIndex] = tcglog.DigestMap{}
		for _, alg := range log.Algorithms {
			v.expectedPCRValues[event.PCRIndex][alg] = make(tcglog.Digest, alg.Size())
		}
	}

	ve := &validatedEvent{Event: event}
	v.validatedEvents = append(v.validatedEvents, ve)

	if err, isErr := ve.Data.(error); isErr {
		ve.dataDecoderErr = err
	}

	if !doesEventTypeExtendPCR(ve.EventType) {
		return
	}

	for alg, digest := range ve.Digests {
		h := alg.GetHash().New()
		h.Write(v.expectedPCRValues[ve.PCRIndex][alg])
		h.Write(digest)
		v.expectedPCRValues[ve.PCRIndex][alg] = h.Sum(nil)
	}

	var measuredBytes []byte

	for alg, digest := range ve.Digests {
		if len(measuredBytes) > 0 {
			// We've already determined the bytes measured for this event for a previous digest
			if ok, expected := isExpectedDigestValue(digest, alg, measuredBytes); !ok {
				ve.incorrectDigestValues = append(ve.incorrectDigestValues, incorrectDigestValue{algorithm: alg, expected: expected})
			}
			continue
		}

		efiBootVariableBehaviourTry := v.efiBootVariableBehaviour

	Loop:
		for {
			// Determine what we expect to be measured
			provisionalMeasuredBytes := determineMeasuredBytes(ve.Event, efiBootVariableBehaviourTry == efiBootVariableBehaviourVarDataOnly)
			if provisionalMeasuredBytes == nil {
				break Loop
			}

			var provisionalMeasuredTrailingBytes []byte
			if m, ok := ve.Data.(interface{ TrailingBytes() []byte }); ok {
				provisionalMeasuredTrailingBytes = m.TrailingBytes()
			}

			for {
				// Determine whether the digest is consistent with the current provisional measured bytes
				ok, _ := isExpectedDigestValue(digest, alg, provisionalMeasuredBytes)
				switch {
				case ok:
					// All good
					measuredBytes = provisionalMeasuredBytes
					ve.measuredTrailingBytes = provisionalMeasuredTrailingBytes

					if ve.EventType == tcglog.EventTypeEFIVariableBoot && v.efiBootVariableBehaviour == efiBootVariableBehaviourUnknown {
						// This is the first EV_EFI_VARIABLE_BOOT event, so record the measurement behaviour.
						v.efiBootVariableBehaviour = efiBootVariableBehaviourTry
						if efiBootVariableBehaviourTry == efiBootVariableBehaviourUnknown {
							v.efiBootVariableBehaviour = efiBootVariableBehaviourFull
						}
					}
					break Loop
				case len(provisionalMeasuredTrailingBytes) > 0:
					// Invalid digest, the event data decoder determined there were trailing bytes, and we were expecting the measured
					// bytes to match the event data. Test if any of the trailing bytes only appear in the event data by truncating
					// the provisional measured bytes one byte at a time and re-testing.
					provisionalMeasuredBytes = provisionalMeasuredBytes[0 : len(provisionalMeasuredBytes)-1]
					provisionalMeasuredTrailingBytes = provisionalMeasuredTrailingBytes[0 : len(provisionalMeasuredTrailingBytes)-1]
				default:
					// Invalid digest
					if ve.EventType == tcglog.EventTypeEFIVariableBoot && efiBootVariableBehaviourTry == efiBootVariableBehaviourUnknown {
						// This is the first EV_EFI_VARIABLE_BOOT event, and this test was done assuming that the measured bytes
						// would include the entire EFI_VARIABLE_DATA structure. Repeat the test with only the variable data.
						efiBootVariableBehaviourTry = efiBootVariableBehaviourVarDataOnly
						continue Loop
					}
					// Record the expected digest on the event
					expectedMeasuredBytes := determineMeasuredBytes(ve.Event, false)
					h := alg.GetHash().New()
					h.Write(expectedMeasuredBytes)
					ve.incorrectDigestValues = append(ve.incorrectDigestValues, incorrectDigestValue{algorithm: alg, expected: h.Sum(nil)})
					break Loop
				}
			}
		}
	}

	if ve.PCRIndex != 4 {
		return
	}
	if ve.EventType != tcglog.EventTypeEFIBootServicesApplication {
		return
	}

	for alg, digest := range ve.Digests {
		var foundData *peImageData
		for _, f := range peImageDataCache[alg] {
			var found bool
			switch {
			case ve.peImageDigestType == peImageDigestTypePe && bytes.Equal(digest, f.peHash):
				found = true
			case ve.peImageDigestType == peImageDigestTypeFile && bytes.Equal(digest, f.fileHash):
				found = true
			case ve.peImageDigestType != peImageDigestTypeUnknown:
			case bytes.Equal(digest, f.peHash):
				found = true
				ve.peImageDigestType = peImageDigestTypePe
			case bytes.Equal(digest, f.fileHash):
				found = true
				ve.peImageDigestType = peImageDigestTypeFile
			}
			if found {
				foundData = f
				break
			}
		}
		if foundData == nil {
			ve.incorrectPeImageDigests = append(ve.incorrectPeImageDigests, alg)
		} else {
			ve.peImagePath = foundData.path
		}
	}
}

func (v *logValidator) run(log *tcglog.Log) {
	v.expectedPCRValues = make(map[tcglog.PCRIndex]tcglog.DigestMap)

	for _, event := range log.Events {
		v.processEvent(log, event)
	}
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
		os.Exit(1)
	}
	defer f.Close()

	log, err := tcglog.ParseLog(f, &tcglog.LogOptions{EnableGrub: withGrub, EnableSystemdEFIStub: withSdEfiStub, SystemdEFIStubPCR: tcglog.PCRIndex(sdEfiStubPcr)})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse log: %v\n", err)
		os.Exit(1)
	}

	populatePeImageDataCache(log.Algorithms)

	v := &logValidator{}
	v.run(log)

	if v.efiBootVariableBehaviour == efiBootVariableBehaviourVarDataOnly {
		fmt.Printf("- EV_EFI_VARIABLE_BOOT events only contain measurement of variable data rather than the entire UEFI_VARIABLE_DATA structure\n\n")
	}

	seenInvalidData := false
	for _, e := range v.validatedEvents {
		if e.dataDecoderErr == nil {
			continue
		}

		if !seenInvalidData {
			seenInvalidData = true
			fmt.Printf("- The following events contain event data that was not in the expected format and could not be decoded correctly:\n")
		}

		fmt.Printf("  - Event %d in PCR %d (type: %s): %v\n", e.Index, e.PCRIndex, e.EventType, e.dataDecoderErr)
	}
	if seenInvalidData {
		fmt.Printf("\n\n")
	}

	seenTrailingMeasuredBytes := false
	for _, e := range v.validatedEvents {
		if len(e.measuredTrailingBytes) == 0 {
			continue
		}

		if !seenTrailingMeasuredBytes {
			seenTrailingMeasuredBytes = true
			fmt.Printf("- The following events have trailing bytes at the end of their event data that was hashed and measured:\n")
		}

		fmt.Printf("  - Event %d in PCR %d (type: %s): %x (%d bytes)\n", e.Index, e.PCRIndex, e.EventType, e.measuredTrailingBytes, len(e.measuredTrailingBytes))
	}
	if seenTrailingMeasuredBytes {
		fmt.Printf("  This trailing bytes should be taken in to account when pre-computing digests for these events when the components " +
			"being measured are updated or changed in some way.\n\n")
	}

	seenIncorrectDigests := false
	for _, e := range v.validatedEvents {
		if len(e.incorrectDigestValues) == 0 {
			continue
		}

		if !seenIncorrectDigests {
			seenIncorrectDigests = true
			fmt.Printf("- The following events have digests that aren't consistent with the data recorded with them in the log:\n")
		}

		for _, d := range e.incorrectDigestValues {
			fmt.Printf("  - Event %d in PCR %d (type: %s, alg: %s) - expected (from data): %x, got: %x\n", e.Index, e.PCRIndex, e.EventType, d.algorithm, d.expected, e.Digests[d.algorithm])
		}
	}
	if seenIncorrectDigests {
		fmt.Printf("  This is unexpected for these event types. Knowledge of the format of the data being measured is required in order " +
			"to pre-compute digests for these events when the components being measured are updated or changed in some way.\n\n")
	}

	seenIncorrectBSApplicationEvent := false
	for _, e := range v.validatedEvents {
		if e.peImageDigestType != peImageDigestTypeFile {
			continue
		}

		if !seenIncorrectBSApplicationEvent {
			seenIncorrectBSApplicationEvent = true
			fmt.Printf("- The following EV_EFI_BOOT_SERVICES_APPLICATION events contain file digests rather than PE image digests:\n")
		}

		fmt.Printf("  - Event %d in PCR 4 (%s)\n", e.Index, e.peImagePath)
	}
	if seenIncorrectBSApplicationEvent {
		fmt.Printf("  The presence of file digests rather than PE image digests might be because the measuring bootloader " +
			"is using the 1.2 version of the TCG EFI Protocol Specification rather than the 2.0 version (which could be " +
			"because the firmware doesn't support the newer version). It could also be because the measuring bootloader " +
			"does not pass the appropriate flag to the firmware to indicate that what is being measured is a PE image\n")
	}

	seenIncorrectBSApplicationEvent = false
	for _, e := range v.validatedEvents {
		if len(e.incorrectPeImageDigests) == 0 {
			continue
		}

		if !seenIncorrectBSApplicationEvent {
			seenIncorrectBSApplicationEvent = true
			fmt.Printf("- The following EV_EFI_BOOT_SERVICES_APPLICATION events contain digests that might be invalid:\n")
		}

		if e.peImageDigestType == peImageDigestTypeUnknown {
			fmt.Printf("  - Event %d in PCR 4 has digests that don't correspond to any PE images\n", e.Index)
		} else {
			for _, alg := range e.incorrectPeImageDigests {
				fmt.Printf("  - Event %d in PCR 4 (%s) has an invalid digest for alg %s (got: %x) [almost certainly a firmware bug]\n", e.Index, e.peImagePath, alg, e.Digests[alg])
			}
		}
	}
	if seenIncorrectBSApplicationEvent {
		fmt.Printf("  Event digests that don't correspond to any PE image might be caused by a firmware bug (invalid digest), " +
			"or might be because the image was loaded from a location that is not currently mounted at the expected path " +
			"(/boot), in which case it is not possible to determine if the digests are correct\n")
	}

	if tpmPath == "" {
		fmt.Printf("- Expected PCR values from log:\n")
		for _, i := range pcrs {
			for _, alg := range log.Algorithms {
				fmt.Printf("PCR %d, bank %s: %x\n", i, alg, v.expectedPCRValues[i][alg])
			}
		}
		return
	}

	tpmPCRValues, err := readPCRs(log.Algorithms)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read PCR values from TPM: %v", err)
		os.Exit(1)
	}

	seenLogConsistencyError := false
	for _, i := range pcrs {
		for _, alg := range log.Algorithms {
			if bytes.Equal(v.expectedPCRValues[i][alg], tpmPCRValues[i][alg]) {
				continue
			}
			if !seenLogConsistencyError {
				seenLogConsistencyError = true
				fmt.Printf("- The log is not consistent with what was measured in to the TPM for some PCRs:\n")
			}
			fmt.Printf("  - PCR %d, bank %s - actual value from TPM: %x, expected value from log: %x\n",
				i, alg, tpmPCRValues[i][alg], v.expectedPCRValues[i][alg])
		}
	}

	if seenLogConsistencyError {
		fmt.Printf("*** The event log is broken! ***\n")
	}
}
