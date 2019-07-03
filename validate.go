package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpm"
	"github.com/google/go-tpm/tpm2"
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
	ValidatedEvents      []*ValidatedEvent
	Spec                 Spec
	LogConsistencyErrors []LogConsistencyError
}

type LogValidateOptions struct {
	TPMId        int
	PCRSelection []PCRIndex
	EnableGrub   bool
}

type efiVarBootQuirkState uint

var (
	efiVarBootQuirkIndeterminate efiVarBootQuirkState = 0
	efiVarBootQuirkInactive      efiVarBootQuirkState = 1
	efiVarBootQuirkActive        efiVarBootQuirkState = 2
)

func doesEventTypeExtendPCR(t EventType) bool {
	if t == EventTypeNoAction {
		return false
	}
	return true
}

func performHashExtendOperation(alg AlgorithmId, dest Digest, src Digest) Digest {
	algLen := knownAlgorithms[alg]
	scratch := make([]byte, algLen*2)
	if len(dest) != 0 {
		copy(scratch, dest)
	}
	copy(scratch[algLen:], src)

	return hash(scratch, alg)
}

func determineMeasuredBytes(event *Event, order binary.ByteOrder, efiVarBootQuirk bool) (out []byte) {
	switch d := event.Data.(type) {
	case *opaqueEventData:
		switch event.EventType {
		case EventTypeEventTag, EventTypeSCRTMVersion, EventTypePlatformConfigFlags,
			EventTypeTableOfDevices, EventTypeNonhostInfo, EventTypeOmitBootDeviceEvents:
			out = event.Data.Bytes()
		case EventTypeSeparator:
			if !isSeparatorEventError(event, order) {
				out = event.Data.Bytes()
			}
		}
	case *AsciiStringEventData:
		switch event.EventType {
		case EventTypeAction, EventTypeEFIAction:
			out = event.Data.Bytes()
		}
	case *EFIVariableEventData:
		if event.EventType == EventTypeEFIVariableBoot && !efiVarBootQuirk {
			out = d.VariableData
		} else {
			out = event.Data.Bytes()
		}
	case *EFIGPTEventData:
		out = event.Data.Bytes()
	case *KernelCmdlineEventData:
		out = d.cmdline
	case *GrubCmdEventData:
		out = d.cmd
	}

	if out != nil {
		return
	}

	if event.EventType == EventTypeSeparator {
		out = make([]byte, 4)
		order.PutUint32(out, separatorEventErrorValue)
	}

	return
}

func isExpectedDigestValue(digest Digest, alg AlgorithmId, measuredBytes []byte) (bool, []byte) {
	expected := hash(measuredBytes, alg)
	return bytes.Compare(digest, expected) == 0, expected
}

type logValidator struct {
	log                  *Log
	options              LogValidateOptions
	logPCRValues         map[PCRIndex]DigestMap
	tpmPCRValues         map[PCRIndex]DigestMap
	efiVarBootQuirkState efiVarBootQuirkState
	validatedEvents      []*ValidatedEvent
}

func (v *logValidator) checkDigestForEvent(alg AlgorithmId, digest Digest, ve *ValidatedEvent) {
	efiVarBootQuirk := v.efiVarBootQuirkState == efiVarBootQuirkActive

	measuredBytes := determineMeasuredBytes(ve.Event, v.log.byteOrder, efiVarBootQuirk)
	if measuredBytes == nil {
		return
	}

	if ok, exp := isExpectedDigestValue(digest, alg, measuredBytes); !ok {
		if ve.Event.EventType == EventTypeEFIVariableBoot &&
			v.efiVarBootQuirkState == efiVarBootQuirkIndeterminate {
			measuredBytes = determineMeasuredBytes(ve.Event, v.log.byteOrder, true)
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
}

func (v *logValidator) processEvent(event *Event, remaining int) {
	if _, exists := v.logPCRValues[event.PCRIndex]; !exists {
		return
	}

	ve := &ValidatedEvent{Event: event}
	v.validatedEvents = append(v.validatedEvents, ve)

	if !doesEventTypeExtendPCR(event.EventType) {
		return
	}

	for alg, digest := range event.Digests {
		v.logPCRValues[event.PCRIndex][alg] =
			performHashExtendOperation(alg, v.logPCRValues[event.PCRIndex][alg], digest)

		v.checkDigestForEvent(alg, digest, ve)
	}

	if remaining > 0 {
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

	for _, i := range v.options.PCRSelection {
		for _, alg := range v.log.Algorithms {
			if bytes.Compare(v.logPCRValues[i][alg], v.tpmPCRValues[i][alg]) != 0 {
				out.LogConsistencyErrors = append(out.LogConsistencyErrors,
					LogConsistencyError{Index: i,
						Algorithm:         alg,
						PCRDigest:         v.tpmPCRValues[i][alg],
						ExpectedPCRDigest: v.logPCRValues[i][alg]})
			}
		}
	}
	return
}

func (v *logValidator) validateFull() (*LogValidateResult, error) {
	for {
		event, remaining, err := v.log.nextEventInternal()
		if event == nil {
			if err == io.EOF {
				return v.createResult(), nil
			}
			return nil, err
		}
		v.processEvent(event, remaining)
	}
}

func pcrIndexSliceToInts(s []PCRIndex) (out []int) {
	for _, i := range s {
		out = append(out, int(i))
	}
	return
}

func (v *logValidator) readPCRsFromTPM2Device(rw io.ReadWriter) error {
	for _, alg := range v.log.Algorithms {
		pcrSelection := tpm2.PCRSelection{
			Hash: tpm2.Algorithm(alg),
			PCRs: pcrIndexSliceToInts(v.options.PCRSelection)}
		res, err := tpm2.ReadPCRs(rw, pcrSelection)
		if err != nil {
			return err
		}
		for _, i := range v.options.PCRSelection {
			v.tpmPCRValues[i][alg] = res[int(i)]
		}
	}
	return nil
}

func (v *logValidator) readPCRsFromTPM1Device(rw io.ReadWriter) error {
	for _, i := range v.options.PCRSelection {
		res, err := tpm.ReadPCR(rw, uint32(i))
		if err != nil {
			return err
		}
		v.tpmPCRValues[i][AlgorithmSha1] = res
	}
	return nil
}

func (v *logValidator) readPCRs() error {
	path := fmt.Sprintf("/dev/tpm%d", v.options.TPMId)
	if rw, err := tpm2.OpenTPM(path); err == nil {
		defer rw.Close()
		return v.readPCRsFromTPM2Device(rw)
	} else if rw, err := tpm.OpenTPM(path); err == nil {
		defer rw.Close()
		return v.readPCRsFromTPM1Device(rw)
	}

	return errors.New("failed to read PCR contents - couldn't open any TPM device")
}

func ValidateLog(options LogValidateOptions) (*LogValidateResult, error) {
	path := fmt.Sprintf("/sys/kernel/security/tpm%d/binary_bios_measurements", options.TPMId)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	log, err := NewLogFromFile(file, LogOptions{EnableGrub: options.EnableGrub})
	if err != nil {
		return nil, err
	}

	v := &logValidator{log: log,
		options:      options,
		logPCRValues: make(map[PCRIndex]DigestMap),
		tpmPCRValues: make(map[PCRIndex]DigestMap)}
	for _, i := range options.PCRSelection {
		v.logPCRValues[i] = DigestMap{}
		for _, alg := range log.Algorithms {
			v.logPCRValues[i][alg] = make(Digest, knownAlgorithms[alg])
		}
		v.tpmPCRValues[i] = DigestMap{}
	}

	if err := v.readPCRs(); err != nil {
		return nil, err
	}

	return v.validateFull()
}
