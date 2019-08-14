package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/chrisccoulson/go-tpm2"
)

type UnexpectedDigestValue struct {
	Algorithm AlgorithmId
	Expected  Digest
}

type ValidatedEvent struct {
	Event                                 *Event
	ExcessMeasuredBytes                   []byte
	EfiVariableAuthorityHasUnmeasuredByte bool
	UnexpectedDigestValues                []UnexpectedDigestValue
}

type LogConsistencyError struct {
	Index             PCRIndex
	Algorithm         AlgorithmId
	PCRDigest         Digest
	ExpectedPCRDigest Digest
}

type LogValidateResult struct {
	EfiVariableBootQuirk bool
	ValidatedEvents      []ValidatedEvent
	Spec                 Spec
	Algorithms           []AlgorithmId
	LogConsistencyErrors []LogConsistencyError
}

type LogValidateOptions struct {
	PCRs       []PCRIndex
	Algorithms []AlgorithmId
	EnableGrub bool
}

type efiVarBootQuirkState uint

const (
	efiVarBootQuirkIndeterminate efiVarBootQuirkState = iota
	efiVarBootQuirkInactive
	efiVarBootQuirkActive
)

func doesEventTypeExtendPCR(t EventType) bool {
	if t == EventTypeNoAction {
		return false
	}
	return true
}

func performHashExtendOperation(alg AlgorithmId, initial Digest, event Digest) Digest {
	hash := hasher(alg)
	hash.Write(initial)
	hash.Write(event)
	return hash.Sum(nil)
}

func determineMeasuredBytes(event *Event, efiVarBootQuirk bool) []byte {
	switch d := event.Data.(type) {
	case *opaqueEventData:
		switch event.EventType {
		case EventTypeEventTag, EventTypeSCRTMVersion, EventTypePlatformConfigFlags,
			EventTypeTableOfDevices, EventTypeNonhostInfo, EventTypeOmitBootDeviceEvents:
			return event.Data.Bytes()
		}
	case *separatorEventData:
		if !d.isError {
			return event.Data.Bytes()
		} else {
			out := make([]byte, 4)
			binary.LittleEndian.PutUint32(out, separatorEventErrorValue)
			return out
		}
	case *AsciiStringEventData:
		switch event.EventType {
		case EventTypeAction, EventTypeEFIAction:
			return event.Data.Bytes()
		}
	case *EFIVariableEventData:
		if event.EventType == EventTypeEFIVariableBoot && !efiVarBootQuirk {
			return d.VariableData
		} else {
			return event.Data.Bytes()
		}
	case *EFIGPTEventData:
		return event.Data.Bytes()
	case *KernelCmdlineEventData:
		return d.cmdline
	case *GrubCmdEventData:
		return d.cmd
	}

	return nil
}

func isExpectedDigestValue(digest Digest, alg AlgorithmId, measuredBytes []byte) (bool, []byte) {
	expected := hashSum(measuredBytes, alg)
	return bytes.Compare(digest, expected) == 0, expected
}

type logValidator struct {
	log                  *Log
	pcrs                 []PCRIndex
	algorithms           []AlgorithmId
	logPCRValues         map[PCRIndex]DigestMap
	tpmPCRValues         map[PCRIndex]DigestMap
	efiVarBootQuirkState efiVarBootQuirkState
	validatedEvents      []ValidatedEvent
}

func (v *logValidator) checkDigestForEvent(alg AlgorithmId, digest Digest, ve *ValidatedEvent) bool {
	efiVarBootQuirk := v.efiVarBootQuirkState == efiVarBootQuirkActive

	measuredBytes := determineMeasuredBytes(ve.Event, efiVarBootQuirk)
	if measuredBytes == nil {
		return false
	}

	if ok, exp := isExpectedDigestValue(digest, alg, measuredBytes); !ok {
		if ve.Event.EventType == EventTypeEFIVariableBoot &&
			v.efiVarBootQuirkState == efiVarBootQuirkIndeterminate {
			measuredBytes = determineMeasuredBytes(ve.Event, true)
			ok, _ = isExpectedDigestValue(digest, alg, measuredBytes)
			if ok {
				v.efiVarBootQuirkState = efiVarBootQuirkActive
			}
		} else if ve.Event.EventType == EventTypeEFIVariableAuthority {
			measuredBytes = measuredBytes[0 : len(measuredBytes)-1]
			ok, _ = isExpectedDigestValue(digest, alg, measuredBytes)
			if ok {
				ve.EfiVariableAuthorityHasUnmeasuredByte = true
			}
		}

		if !ok {
			ve.UnexpectedDigestValues = append(ve.UnexpectedDigestValues,
				UnexpectedDigestValue{Algorithm: alg, Expected: exp})
		}
	} else if ve.Event.EventType == EventTypeEFIVariableBoot &&
		v.efiVarBootQuirkState == efiVarBootQuirkIndeterminate {
		v.efiVarBootQuirkState = efiVarBootQuirkInactive
	}

	return true
}

func (v *logValidator) processEvent(event *Event, remaining int) {
	if _, exists := v.logPCRValues[event.PCRIndex]; !exists {
		return
	}

	ve := ValidatedEvent{Event: event}
	v.validatedEvents = append(v.validatedEvents, ve)

	if !doesEventTypeExtendPCR(event.EventType) {
		return
	}

	informational := false
	for alg, digest := range event.Digests {
		if !contains(v.algorithms, alg) {
			continue
		}

		v.logPCRValues[event.PCRIndex][alg] =
			performHashExtendOperation(alg, v.logPCRValues[event.PCRIndex][alg], digest)

		if informational {
			continue
		}

		informational = !v.checkDigestForEvent(alg, digest, &ve)
	}

	if remaining > 0 && !informational {
		end := len(event.Data.Bytes())
		if ve.EfiVariableAuthorityHasUnmeasuredByte {
			end -= 1
		}
		ve.ExcessMeasuredBytes = event.Data.Bytes()[len(event.Data.Bytes())-remaining : end]
	}
}

func (v *logValidator) createResult() (out *LogValidateResult) {
	out = new(LogValidateResult)

	out.EfiVariableBootQuirk = v.efiVarBootQuirkState == efiVarBootQuirkActive
	out.ValidatedEvents = v.validatedEvents
	out.Spec = v.log.Spec
	out.Algorithms = v.log.Algorithms

	for _, i := range v.pcrs {
		for _, alg := range v.log.Algorithms {
			if bytes.Compare(v.logPCRValues[i][alg], v.tpmPCRValues[i][alg]) == 0 {
				continue
			}

			out.LogConsistencyErrors = append(out.LogConsistencyErrors,
				LogConsistencyError{Index: i,
					Algorithm:         alg,
					PCRDigest:         v.tpmPCRValues[i][alg],
					ExpectedPCRDigest: v.logPCRValues[i][alg]})
		}
	}

	return
}

func (v *logValidator) run() (*LogValidateResult, error) {
	for {
		event, remaining, err := v.log.nextEventInternal()
		if err != nil {
			if err == io.EOF {
				return v.createResult(), nil
			}
			return nil, err
		}
		v.processEvent(event, remaining)
	}
}

func pcrIndexListToSelectionData(l []PCRIndex) (out tpm2.PCRSelectionData) {
	for _, i := range l {
		out = append(out, int(i))
	}
	return
}

func (v *logValidator) readPCRsFromTPM2Device(tpm tpm2.TPMContext) error {
	var selections tpm2.PCRSelectionList
	for _, alg := range v.algorithms {
		selections = append(selections,
			tpm2.PCRSelection{Hash: tpm2.AlgorithmId(alg),
				Select: pcrIndexListToSelectionData(v.pcrs)})
	}

	_, digests, err := tpm.PCRRead(selections)
	if err != nil {
		return fmt.Errorf("cannot read PCR values: %v", err)
	}

	j := 0
	for _, s := range selections {
		for _, i := range s.Select {
			v.tpmPCRValues[PCRIndex(i)][AlgorithmId(s.Hash)] = Digest(digests[j])
			j++
		}
	}
	return nil
}

func (v *logValidator) readPCRsFromTPM1Device(tpm tpm2.TPMContext) error {
	for _, i := range v.pcrs {
		in, err := tpm2.MarshalToBytes(uint32(i))
		if err != nil {
			return fmt.Errorf("cannot read PCR values due to a marshalling error: %v", err)
		}
		rc, _, out, err := tpm.RunCommandBytes(tpm2.StructTag(0x00c1), tpm2.CommandCode(0x00000015), in)
		if err != nil {
			return fmt.Errorf("cannot read PCR values: %v", err)
		}
		if rc != tpm2.Success {
			return fmt.Errorf("cannot read PCR values: unexpected response code (0x%08x)", rc)
		}
		v.tpmPCRValues[i][AlgorithmSha1] = out
	}
	return nil
}

func getTPMDeviceVersion(tpm tpm2.TPMContext) int {
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
	} else {
		fmt.Println("rc:", rc, "err:", err)
	}

	return 0
}

func (v *logValidator) readPCRs(tpm tpm2.TPMContext) error {
	switch getTPMDeviceVersion(tpm) {
	case 2:
		return v.readPCRsFromTPM2Device(tpm)
	case 1:
		return v.readPCRsFromTPM1Device(tpm)
	}

	return errors.New("not a valid TPM device")
}

func ValidateLogAgainstTPM(tpm tpm2.TPMContext, logPath string, options LogValidateOptions) (*LogValidateResult,
	error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, LogReadError{OrigError: err}
	}

	log, err := NewLogFromFile(file, LogOptions{EnableGrub: options.EnableGrub})
	if err != nil {
		return nil, err
	}

	tmp := options.PCRs
	sort.SliceStable(tmp, func(i, j int) bool { return tmp[i] < tmp[j] })
	var pcrs []PCRIndex
	for _, i := range tmp {
		if contains(pcrs, i) {
			return nil, InvalidOptionError{msg: fmt.Sprintf("duplicate entries for PCR %d", i)}
		}
		if !isPCRIndexInRange(i) {
			return nil, InvalidOptionError{msg: fmt.Sprintf("PCR index out-of-range (%d)", i)}
		}
		pcrs = append(pcrs, i)
	}

	algorithms := options.Algorithms
	if len(algorithms) == 0 {
		algorithms = log.Algorithms
	}
	for _, alg := range algorithms {
		if !contains(log.Algorithms, alg) {
			return nil, InvalidOptionError{
				msg: fmt.Sprintf("log doesn't contain entries for %s algorithm", alg)}
		}
	}

	v := &logValidator{log: log,
		pcrs:         pcrs,
		algorithms:   algorithms,
		logPCRValues: make(map[PCRIndex]DigestMap),
		tpmPCRValues: make(map[PCRIndex]DigestMap)}
	for _, i := range pcrs {
		v.logPCRValues[i] = DigestMap{}
		for _, alg := range algorithms {
			v.logPCRValues[i][alg] = make(Digest, knownAlgorithms[alg])
		}
		v.tpmPCRValues[i] = DigestMap{}
	}

	if err := v.readPCRs(tpm); err != nil {
		return nil, TPMCommError{OrigError: err}
	}

	return v.run()
}

func ValidateLogAgainstTPMByPath(tpmPath string, options LogValidateOptions) (*LogValidateResult, error) {
	if tpmPath == "" {
		return nil, InvalidOptionError{msg: fmt.Sprintf("missing TPM path")}
	}
	if filepath.Dir(tpmPath) != "/dev" {
		return nil, InvalidOptionError{msg: fmt.Sprintf("expected TPM path to be a device node in /dev")}
	}
	tcti, err := tpm2.OpenTPMDevice(tpmPath)
	if err != nil {
		return nil, TPMCommError{OrigError: fmt.Errorf("couldn't open TPM device: %v", err)}
	}
	tpm, _ := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	logPath := fmt.Sprintf("/sys/kernel/security/%s/binary_bios_measurements", filepath.Base(tpmPath))

	return ValidateLogAgainstTPM(tpm, logPath, options)
}
