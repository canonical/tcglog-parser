// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"

	"github.com/canonical/tcglog-parser"
)

var shimLockGuid = efi.MakeGUID(0x605dab50, 0xe046, 0x4300, 0xabb6, [...]uint8{0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23})

type indentStringer struct {
	src    fmt.Stringer
	indent int
}

func (s *indentStringer) String() string {
	indent := make([]byte, s.indent)
	for i := range indent {
		indent[i] = '\t'
	}
	return strings.Replace(s.src.String(), "\n", "\n"+string(indent), -1)
}

func indent(src fmt.Stringer, indent int) fmt.Stringer {
	return &indentStringer{src: src, indent: indent}
}

// nullStringer prints nothing.
type nullStringer struct{}

func (nullStringer) String() string { return "" }

// newlineStringer prints a newline.
type newlineStringer struct{}

func (newlineStringer) String() string { return "\n" }

// stringer prints a string.
type stringer string

func (s stringer) String() string {
	return string(s)
}

// catStringer concatenates the output from a slice of stringers.
type catStringer []fmt.Stringer

func (s catStringer) String() string {
	var b strings.Builder
	for _, str := range []fmt.Stringer(s) {
		b.WriteString(str.String())
	}
	return b.String()
}

// varDescriptor prints a variable descriptor.
type varDescriptor efi.VariableDescriptor

func (d varDescriptor) String() string {
	switch d.GUID {
	case efi.GlobalVariable, efi.ImageSecurityDatabaseGuid:
		return d.Name
	case shimLockGuid:
		return d.Name + " (Shim)"
	default:
		return fmt.Sprintf("%s-%s", d.Name, d.GUID)
	}
}

type variableStringer struct {
	data    *tcglog.EFIVariableData
	verbose bool
}

func (s *variableStringer) String() string {
	if s.verbose {
		return s.data.String()
	}

	desc := varDescriptor{s.data.UnicodeName, s.data.VariableName}
	return desc.String()
}

type stringVariableStringer struct {
	desc varDescriptor
	data []byte
}

func (s *stringVariableStringer) String() string {
	return fmt.Sprintf("%s: %s", s.desc, string(s.data))
}

// bootOrderVariableStringer prints a summary of the contents of BootOrder.
type bootOrderVariableStringer []byte

func (s bootOrderVariableStringer) String() string {
	data := []byte(s)

	if len(data)%2 != 0 {
		return fmt.Sprint("Invalid BootOrder payload length (", len(data), " bytes)")
	}

	var order []string
	for len(data) > 0 {
		order = append(order, fmt.Sprintf("%04x", binary.LittleEndian.Uint16(data)))
		data = data[2:]
	}

	return "BootOrder: " + strings.Join(order, ",")
}

// bootOptionVariableStringer prints a summary of the contents of a BootXXXX variable.
type bootOptionVariableStringer struct {
	name    string
	data    []byte
	verbose bool
}

func (s *bootOptionVariableStringer) String() string {
	opt, err := efi.ReadLoadOption(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid load option for %s: %v", s.name, err)
	}

	if s.verbose {
		return fmt.Sprintf("%s: %v", s.name, opt)
	}
	return fmt.Sprintf("%s: %s", s.name, opt.Description)
}

// boolVariableStringer prints a summary of the contents of an EFI variable containing a boolean.
type boolVariableStringer struct {
	desc varDescriptor
	data []byte
}

func (s *boolVariableStringer) String() string {
	switch {
	case bytes.Equal(s.data, []byte{0}):
		return fmt.Sprintf("%s: 0", s.desc)
	case bytes.Equal(s.data, []byte{1}):
		return fmt.Sprintf("%s: 1", s.desc)
	default:
		return fmt.Sprintf("Invalid %s boolean payload", s.desc)
	}
}

// dbVariableStringer prints a summary of the contents of an EFI variable.
type dbVariableStringer struct {
	desc    varDescriptor
	data    []byte
	verbose bool
}

func (s *dbVariableStringer) String() string {
	db, err := efi.ReadSignatureDatabase(bytes.NewReader(s.data))
	if err != nil {
		return fmt.Sprintf("Invalid signature database for %s: %v", s.desc, err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s: ", s.desc)

	if s.verbose {
		b.WriteString(db.String())
		return b.String()
	}

	counts := make(map[efi.GUID]int)
	for _, l := range db {
		if _, exists := counts[l.Type]; !exists {
			counts[l.Type] = 0
		}
		counts[l.Type] += len(l.Signatures)
	}

	var countsStrings []string
	for _, t := range []struct {
		guid efi.GUID
		desc string
	}{
		{efi.CertX509Guid, "x509"},
		{efi.CertSHA256Guid, "sha256"},
	} {
		countsStrings = append(countsStrings, fmt.Sprintf("entries(%s)=%d", t.desc, counts[t.guid]))
	}

	b.WriteString(strings.Join(countsStrings, ", "))
	return b.String()
}

type sbatlevelVariableStringer struct {
	data    []byte
	verbose bool
}

func (s *sbatlevelVariableStringer) String() string {
	desc := varDescriptor{"SbatLevel", shimLockGuid}
	if s.verbose {
		str := stringVariableStringer{desc, s.data}
		return str.String()
	}

	r := csv.NewReader(bytes.NewReader(s.data))
	record, err := r.Read()
	if err != nil {
		return fmt.Sprintf("Invalid %s: %v", desc, err)
	}
	if len(record) != 3 {
		return fmt.Sprintf("Invalid %s: not enough fields in first record", desc)
	}

	return fmt.Sprintf("%s: %s", desc, record[2])
}

type variableAuthorityStringer struct {
	desc    varDescriptor
	data    []byte
	verbose bool
}

func (s *variableAuthorityStringer) String() string {
	var owner efi.GUID
	data := s.data[copy(owner[:], s.data):]

	switch len(s.data) {
	case 36, 44, 48, 64, 80:
		return fmt.Sprintf("hash: %x, owner: %s, source: %s", data, owner, s.desc)
	default:
		cert, err := x509.ParseCertificate(data)
		switch {
		case err != nil && s.desc.GUID == shimLockGuid:
			// Shim doesn't log a EFI_SIGNATURE_DATA when doing verification
			// with its vendor cert.
			cert, err2 := x509.ParseCertificate(s.data)
			switch {
			case err2 != nil:
				// do nothing and fall through to the next leg.
			case !s.verbose:
				return fmt.Sprintf("subject: %q, source: %s", cert.Subject, s.desc)
			default:
				return fmt.Sprintf("subject: %q, fingerprint: %x, source: %s", cert.Subject, sha256.Sum256(cert.Raw), s.desc)
			}
			fallthrough
		case err != nil:
			return fmt.Sprintf("Invalid authority event for %s - not a hash or X509 certificate: %v", s.desc, err)
		case !s.verbose:
			return fmt.Sprintf("subject: %q, source: %s", cert.Subject, s.desc)
		default:
			return fmt.Sprintf("subject: %q, fingerprint: %x, owner: %s, source: %s", cert.Subject, sha256.Sum256(cert.Raw), owner, s.desc)
		}
	}
}

type simpleGptEventStringer struct {
	data *tcglog.EFIGPTData
}

func (s *simpleGptEventStringer) String() string {
	return fmt.Sprint("DiskGUID: ", s.data.Hdr.DiskGUID)
}

type startupLocalityStringer uint8

func (s startupLocalityStringer) String() string {
	return "Startup Locality: " + strconv.Itoa(int(s))
}

type simpleSpecIfEvent00Stringer struct {
	data *tcglog.SpecIdEvent00
}

func (s simpleSpecIfEvent00Stringer) String() string {
	return fmt.Sprintf("BIOS, Platform Class: %d, Spec: %d.%d (Errata: %d)", s.data.PlatformClass, s.data.SpecVersionMajor, s.data.SpecVersionMinor, s.data.SpecErrata)
}

type simpleSpecIdEvent02Stringer struct {
	data *tcglog.SpecIdEvent02
}

func (s simpleSpecIdEvent02Stringer) String() string {
	return fmt.Sprintf("EFI, Platform Class: %d, Spec: %d.%d (Errata: %d)", s.data.PlatformClass, s.data.SpecVersionMajor, s.data.SpecVersionMinor, s.data.SpecErrata)
}

type simpleSpecIdEvent03Stringer struct {
	data *tcglog.SpecIdEvent03
}

func (s simpleSpecIdEvent03Stringer) String() string {
	var digests []tpm2.HashAlgorithmId
	for _, digestSize := range s.data.DigestSizes {
		digests = append(digests, digestSize.AlgorithmId)
	}
	return fmt.Sprintf("EFI, Platform Class: %d, Spec: %d.%d (Errata: %d), Digests: %s", s.data.PlatformClass, s.data.SpecVersionMajor, s.data.SpecVersionMinor, s.data.SpecErrata, digests)
}

type devicePathStringer struct {
	path efi.DevicePath
}

func (s *devicePathStringer) String() string {
	return s.path.ToString(efi.DevicePathDisplayOnly | efi.DevicePathAllowVendorShortcuts | efi.DevicePathDisplayFWGUIDNames)
}

func customEventDetailsStringer(event *tcglog.Event, verbose bool) fmt.Stringer {
	switch {
	case event.EventType == tcglog.EventTypeNoAction && !verbose:
		switch data := event.Data.(type) {
		case *tcglog.SpecIdEvent00:
			return simpleSpecIfEvent00Stringer{data: data}
		case *tcglog.SpecIdEvent02:
			return simpleSpecIdEvent02Stringer{data: data}
		case *tcglog.SpecIdEvent03:
			return simpleSpecIdEvent03Stringer{data: data}
		case *tcglog.StartupLocalityEventData:
			return startupLocalityStringer(data.StartupLocality)
		}
	case (event.EventType == tcglog.EventTypeEFIPlatformFirmwareBlob || event.EventType == tcglog.EventTypePostCode) && !verbose:
		if _, ok := event.Data.(*tcglog.EFIPlatformFirmwareBlob); !ok {
			return nil
		}
		return nullStringer{}
	case (event.EventType == tcglog.EventTypeEFIPlatformFirmwareBlob2 || event.EventType == tcglog.EventTypePostCode2) && !verbose:
		data, ok := event.Data.(*tcglog.EFIPlatformFirmwareBlob2)
		if !ok {
			return nil
		}
		return stringer(data.BlobDescription)
	case event.EventType == tcglog.EventTypeEFIHandoffTables && !verbose:
		return nullStringer{}
	case event.EventType == tcglog.EventTypeEFIHandoffTables2 && !verbose:
		data, ok := event.Data.(*tcglog.EFIHandoffTablePointers2)
		if !ok {
			return nil
		}
		return stringer(data.TableDescription)
	case (event.EventType == tcglog.EventTypeEFIVariableBoot || event.EventType == tcglog.EventTypeEFIVariableBoot2):
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return nil
		}
		if varData.VariableName != efi.GlobalVariable {
			// Unexpected GUID
			return nil
		}

		var summary fmt.Stringer
		if varData.UnicodeName == "BootOrder" {
			summary = bootOrderVariableStringer(varData.VariableData)
		} else {
			summary = &bootOptionVariableStringer{varData.UnicodeName, varData.VariableData, verbose}
		}

		if !verbose {
			return summary
		}
		return catStringer{summary, newlineStringer{}, varData}
	case event.EventType == tcglog.EventTypeEFIVariableDriverConfig && event.PCRIndex == 7:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return nil
		}

		var summary fmt.Stringer
		switch {
		case varData.VariableName == efi.GlobalVariable:
			switch varData.UnicodeName {
			case "SecureBoot", "DeployedMode", "AuditMode":
				summary = &boolVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: efi.GlobalVariable}, varData.VariableData}
			default:
				summary = &dbVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: efi.GlobalVariable}, varData.VariableData, verbose}
			}
		default:
			summary = &dbVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData, verbose}
		}

		if !verbose {
			return summary
		}
		return catStringer{summary, newlineStringer{}, varData}
	case event.EventType == tcglog.EventTypeEFIVariableDriverConfig:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return nil
		}

		return &variableStringer{varData, verbose}
	case event.EventType == tcglog.EventTypeEFIVariableAuthority:
		varData, ok := event.Data.(*tcglog.EFIVariableData)
		if !ok {
			return nil
		}

		var summary fmt.Stringer
		switch {
		case varData.VariableName == shimLockGuid:
			// XXX: Ideally these events would have a type of EV_EFI_VARIABLE_DRIVER_CONFIG
			switch varData.UnicodeName {
			case "MokSBState":
				summary = &boolVariableStringer{varDescriptor{Name: varData.UnicodeName, GUID: shimLockGuid}, varData.VariableData}
			case "SbatLevel":
				summary = &sbatlevelVariableStringer{varData.VariableData, verbose}
			default:
				summary = &variableAuthorityStringer{varDescriptor{Name: varData.UnicodeName, GUID: shimLockGuid}, varData.VariableData, verbose}
			}
		default:
			summary = &variableAuthorityStringer{varDescriptor{Name: varData.UnicodeName, GUID: varData.VariableName}, varData.VariableData, verbose}
		}

		if !verbose {
			return summary
		}
		return catStringer{summary, newlineStringer{}, varData}
	case (event.EventType == tcglog.EventTypeEFIGPTEvent || event.EventType == tcglog.EventTypeEFIGPTEvent2) && !verbose:
		data, ok := event.Data.(*tcglog.EFIGPTData)
		if !ok {
			return nil
		}

		return &simpleGptEventStringer{data}
	case (event.EventType == tcglog.EventTypeEFIBootServicesApplication || event.EventType == tcglog.EventTypeEFIBootServicesDriver ||
		event.EventType == tcglog.EventTypeEFIRuntimeServicesDriver) && !verbose:
		data, ok := event.Data.(*tcglog.EFIImageLoadEvent)
		if !ok {
			return nil
		}
		return &devicePathStringer{data.DevicePath}
	}

	return nil
}

func eventDetailsStringer(event *tcglog.Event, verbose bool) fmt.Stringer {
	if _, isErr := event.Data.(error); isErr && !verbose {
		return nullStringer{}
	}
	if out := customEventDetailsStringer(event, verbose); out != nil {
		return out
	}
	return event.Data
}
