package tcglog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/xerrors"
)

var (
	surr1 uint16 = 0xd800
	surr2 uint16 = 0xdc00
	surr3 uint16 = 0xe000
)

// UEFI_VARIABLE_DATA specifies the number of *characters* for a UTF-16 sequence rather than the size of
// the buffer. Extract a UTF-16 sequence of the correct length, given a buffer and the number of characters.
// The returned buffer can be passed to utf16.Decode.
func extractUTF16Buffer(r io.ReadSeeker, nchars uint64) ([]uint16, error) {
	var out []uint16

	for i := nchars; i > 0; i-- {
		var c uint16
		if err := binary.Read(r, binary.LittleEndian, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
		if c >= surr1 && c < surr2 {
			if err := binary.Read(r, binary.LittleEndian, &c); err != nil {
				return nil, err
			}
			if c < surr2 || c >= surr3 {
				// Invalid surrogate sequence. utf16.Decode doesn't consume this
				// byte when inserting the replacement char
				if _, err := r.Seek(-1, io.SeekCurrent); err != nil {
					return nil, err
				}
				continue
			}
			// Valid surrogate sequence
			out = append(out, c)
		}
	}

	return out, nil
}

// EFIGUID corresponds to the EFI_GUID type
type EFIGUID [16]uint8

func (guid EFIGUID) String() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		binary.LittleEndian.Uint32(guid[0:4]),
		binary.LittleEndian.Uint16(guid[4:6]),
		binary.LittleEndian.Uint16(guid[6:8]),
		binary.BigEndian.Uint16(guid[8:10]),
		guid[10:16])
}

// MakeEFIGUID makes a new EFIGUID from the supplied arguments.
func MakeEFIGUID(a uint32, b, c, d uint16, e [6]uint8) (out EFIGUID) {
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint16(out[4:6], b)
	binary.LittleEndian.PutUint16(out[6:8], c)
	binary.BigEndian.PutUint16(out[8:10], d)
	copy(out[10:], e[:])
	return
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func parseEFI_1_2_SpecIdEvent(r io.Reader, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_1_2

	// TCG_EfiSpecIdEventStruct.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return xerrors.Errorf("cannot read vendor info size: %w", err)
	}

	// TCG_EfiSpecIdEventStruct.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(r, eventData.VendorInfo); err != nil {
		return xerrors.Errorf("cannot read vendor info: %w", err)
	}

	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (secion 9.4.5.1 "Specification ID Version Event")
func parseEFI_2_SpecIdEvent(r io.Reader, eventData *SpecIdEventData) error {
	eventData.Spec = SpecEFI_2

	// TCG_EfiSpecIdEvent.numberOfAlgorithms
	var numberOfAlgorithms uint32
	if err := binary.Read(r, binary.LittleEndian, &numberOfAlgorithms); err != nil {
		return xerrors.Errorf("cannot read number of digest algorithms: %w", err)
	}

	if numberOfAlgorithms < 1 {
		return errors.New("numberOfAlgorithms is zero")
	}

	// TCG_EfiSpecIdEvent.digestSizes
	eventData.DigestSizes = make([]EFISpecIdEventAlgorithmSize, numberOfAlgorithms)
	if err := binary.Read(r, binary.LittleEndian, eventData.DigestSizes); err != nil {
		return xerrors.Errorf("cannot read digest algorithm sizes: %w", err)
	}
	for _, d := range eventData.DigestSizes {
		if d.AlgorithmId.supported() && d.AlgorithmId.size() != int(d.DigestSize) {
			return fmt.Errorf("digestSize for algorithmId %v does not match expected size", d.AlgorithmId)
		}
	}

	// TCG_EfiSpecIdEvent.vendorInfoSize
	var vendorInfoSize uint8
	if err := binary.Read(r, binary.LittleEndian, &vendorInfoSize); err != nil {
		return xerrors.Errorf("cannot read vendor info size: %w", err)
	}

	// TCG_EfiSpecIdEvent.vendorInfo
	eventData.VendorInfo = make([]byte, vendorInfoSize)
	if _, err := io.ReadFull(r, eventData.VendorInfo); err != nil {
		return xerrors.Errorf("cannot read vendor info: %w", err)
	}

	return nil
}

type startupLocalityEventData struct {
	data     []byte
	locality uint8
}

func (e *startupLocalityEventData) String() string {
	return fmt.Sprintf("EfiStartupLocalityEvent{ StartupLocality: %d }", e.locality)
}

func (e *startupLocalityEventData) Bytes() []byte {
	return e.data
}

func (e *startupLocalityEventData) Type() NoActionEventType {
	return StartupLocality
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.3 "Startup Locality Event")
func decodeStartupLocalityEvent(r io.Reader, data []byte) (*startupLocalityEventData, error) {
	var locality uint8
	if err := binary.Read(r, binary.LittleEndian, &locality); err != nil {
		return nil, err
	}

	return &startupLocalityEventData{data: data, locality: locality}, nil
}

type bimReferenceManifestEventData struct {
	data     []byte
	vendorId uint32
	guid     EFIGUID
}

func (e *bimReferenceManifestEventData) String() string {
	return fmt.Sprintf("Sp800_155_PlatformId_Event{ VendorId: %d, ReferenceManifestGuid: %s }", e.vendorId, &e.guid)
}

func (e *bimReferenceManifestEventData) Bytes() []byte {
	return e.data
}

func (e *bimReferenceManifestEventData) Type() NoActionEventType {
	return BiosIntegrityMeasurement
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
//  (section 9.4.5.2 "BIOS Integrity Measurement Reference Manifest Event")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
//  (section 7.4 "EV_NO_ACTION Event Types")
func decodeBIMReferenceManifestEvent(r io.Reader, data []byte) (*bimReferenceManifestEventData, error) {
	var d struct {
		VendorId uint32
		Guid     EFIGUID
	}
	if err := binary.Read(r, binary.LittleEndian, &d); err != nil {
		return nil, err
	}

	return &bimReferenceManifestEventData{data: data, vendorId: d.VendorId, guid: d.Guid}, nil
}

// EFIVariableEventData corresponds to the EFI_VARIABLE_DATA type.
type EFIVariableEventData struct {
	data         []byte
	VariableName EFIGUID
	UnicodeName  string
	VariableData []byte
}

func (e *EFIVariableEventData) String() string {
	return fmt.Sprintf("UEFI_VARIABLE_DATA{ VariableName: %s, UnicodeName: \"%s\" }", e.VariableName, e.UnicodeName)
}

func (e *EFIVariableEventData) Bytes() []byte {
	return e.data
}

func (e *EFIVariableEventData) EncodeMeasuredBytes(w io.Writer) error {
	if _, err := w.Write(e.VariableName[:]); err != nil {
		return xerrors.Errorf("cannot write variable name: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(utf8.RuneCount([]byte(e.UnicodeName)))); err != nil {
		return xerrors.Errorf("cannot write unicode name length: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(len(e.VariableData))); err != nil {
		return xerrors.Errorf("cannot write variable data length: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, convertStringToUtf16(e.UnicodeName)); err != nil {
		return xerrors.Errorf("cannot write unicode name: %w", err)
	}
	if _, err := w.Write(e.VariableData); err != nil {
		return xerrors.Errorf("cannot write variable data: %w", err)
	}
	return nil
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 7.8 "Measuring EFI Variables")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.6 "Measuring UEFI Variables")
func decodeEventDataEFIVariable(data []byte, eventType EventType) (EventData, error) {
	r := bytes.NewReader(data)

	d := &EFIVariableEventData{data: data}

	if _, err := io.ReadFull(r, d.VariableName[:]); err != nil {
		return nil, xerrors.Errorf("cannot read variable name: %w", err)
	}

	var unicodeNameLength uint64
	if err := binary.Read(r, binary.LittleEndian, &unicodeNameLength); err != nil {
		return nil, xerrors.Errorf("cannot read unicode name length: %w", err)
	}

	var variableDataLength uint64
	if err := binary.Read(r, binary.LittleEndian, &variableDataLength); err != nil {
		return nil, xerrors.Errorf("cannot read variable data length: %w", err)
	}

	utf16Name, err := extractUTF16Buffer(r, unicodeNameLength)
	if err != nil {
		return nil, xerrors.Errorf("cannot extract unicode name buffer: %w", err)
	}
	d.UnicodeName = convertUtf16ToString(utf16Name)

	d.VariableData = make([]byte, variableDataLength)
	if _, err := io.ReadFull(r, d.VariableData); err != nil {
		return nil, xerrors.Errorf("cannot read variable data: %w", err)
	}

	return d, nil
}

type efiDevicePathNodeType uint8

func (t efiDevicePathNodeType) String() string {
	switch t {
	case efiDevicePathNodeHardware:
		return "HardwarePath"
	case efiDevicePathNodeACPI:
		return "AcpiPath"
	case efiDevicePathNodeMsg:
		return "Msg"
	case efiDevicePathNodeMedia:
		return "MediaPath"
	case efiDevicePathNodeBBS:
		return "BbsPath"
	default:
		return fmt.Sprintf("Path[%02x]", uint8(t))
	}
}

const (
	efiDevicePathNodeHardware efiDevicePathNodeType = 0x01
	efiDevicePathNodeACPI                           = 0x02
	efiDevicePathNodeMsg                            = 0x03
	efiDevicePathNodeMedia                          = 0x04
	efiDevicePathNodeBBS                            = 0x05
	efiDevicePathNodeEoH                            = 0x7f
)

const (
	efiHardwareDevicePathNodePCI = 0x01

	efiACPIDevicePathNodeNormal = 0x01

	efiMsgDevicePathNodeLU   = 0x11
	efiMsgDevicePathNodeSATA = 0x12

	efiMediaDevicePathNodeHardDrive      = 0x01
	efiMediaDevicePathNodeFilePath       = 0x04
	efiMediaDevicePathNodeFvFile         = 0x06
	efiMediaDevicePathNodeFv             = 0x07
	efiMediaDevicePathNodeRelOffsetRange = 0x08
)

func firmwareDevicePathNodeToString(subType uint8, data []byte) (string, error) {
	r := bytes.NewReader(data)

	var name EFIGUID
	if _, err := io.ReadFull(r, name[:]); err != nil {
		return "", xerrors.Errorf("cannot read name: %w", err)
	}

	var builder bytes.Buffer
	switch subType {
	case efiMediaDevicePathNodeFvFile:
		builder.WriteString("\\FvFile")
	case efiMediaDevicePathNodeFv:
		builder.WriteString("\\Fv")
	default:
		return "", fmt.Errorf("invalid sub type for firmware device path node: %d", subType)
	}

	fmt.Fprintf(&builder, "(%s)", name)
	return builder.String(), nil
}

func acpiDevicePathNodeToString(data []byte) (string, error) {
	r := bytes.NewReader(data)

	var hid uint32
	if err := binary.Read(r, binary.LittleEndian, &hid); err != nil {
		return "", xerrors.Errorf("cannot read HID: %w", err)
	}

	var uid uint32
	if err := binary.Read(r, binary.LittleEndian, &uid); err != nil {
		return "", xerrors.Errorf("cannot read UID: %w", err)
	}

	if hid&0xffff == 0x41d0 {
		switch hid >> 16 {
		case 0x0a03:
			return fmt.Sprintf("\\PciRoot(0x%x)", uid), nil
		case 0x0a08:
			return fmt.Sprintf("\\PcieRoot(0x%x)", uid), nil
		case 0x0604:
			return fmt.Sprintf("\\Floppy(0x%x)", uid), nil
		default:
			return fmt.Sprintf("\\Acpi(PNP%04x,0x%x)", hid>>16, uid), nil
		}
	} else {
		return fmt.Sprintf("\\Acpi(0x%08x,0x%x)", hid, uid), nil
	}
}

func pciDevicePathNodeToString(data []byte) (string, error) {
	r := bytes.NewReader(data)

	var function uint8
	if err := binary.Read(r, binary.LittleEndian, &function); err != nil {
		return "", xerrors.Errorf("cannot read function: %w", err)
	}

	var device uint8
	if err := binary.Read(r, binary.LittleEndian, &device); err != nil {
		return "", xerrors.Errorf("cannot read device: %w", err)
	}

	return fmt.Sprintf("\\Pci(0x%x,0x%x)", device, function), nil
}

func luDevicePathNodeToString(data []byte) (string, error) {
	r := bytes.NewReader(data)

	var lun uint8
	if err := binary.Read(r, binary.LittleEndian, &lun); err != nil {
		return "", xerrors.Errorf("cannot read LUN: %w", err)
	}

	return fmt.Sprintf("\\Unit(0x%x)", lun), nil
}

func hardDriveDevicePathNodeToString(data []byte) (string, error) {
	r := bytes.NewReader(data)

	var partNumber uint32
	if err := binary.Read(r, binary.LittleEndian, &partNumber); err != nil {
		return "", xerrors.Errorf("cannot read partition number: %w", err)
	}

	var partStart uint64
	if err := binary.Read(r, binary.LittleEndian, &partStart); err != nil {
		return "", xerrors.Errorf("cannot read partition start: %w", err)
	}

	var partSize uint64
	if err := binary.Read(r, binary.LittleEndian, &partSize); err != nil {
		return "", xerrors.Errorf("cannot read partition size: %w", err)
	}

	var sig EFIGUID
	if _, err := io.ReadFull(r, sig[:]); err != nil {
		return "", xerrors.Errorf("cannot read signature: %w", err)
	}

	var partFormat uint8
	if err := binary.Read(r, binary.LittleEndian, &partFormat); err != nil {
		return "", xerrors.Errorf("cannot read partition format: %w", err)
	}

	var sigType uint8
	if err := binary.Read(r, binary.LittleEndian, &sigType); err != nil {
		return "", xerrors.Errorf("cannot read signature type: %w", err)
	}

	var builder bytes.Buffer

	switch sigType {
	case 0x01:
		fmt.Fprintf(&builder, "\\HD(%d,MBR,0x%08x,", partNumber, binary.LittleEndian.Uint32(sig[:]))
	case 0x02:
		fmt.Fprintf(&builder, "\\HD(%d,GPT,%s,", partNumber, sig)
	default:
		fmt.Fprintf(&builder, "\\HD(%d,%d,0,", partNumber, sigType)
	}

	fmt.Fprintf(&builder, "0x%016x, 0x%016x)", partStart, partSize)
	return builder.String(), nil
}

func sataDevicePathNodeToString(data []byte) (string, error) {
	r := bytes.NewReader(data)

	var hbaPortNumber uint16
	if err := binary.Read(r, binary.LittleEndian, &hbaPortNumber); err != nil {
		return "", xerrors.Errorf("cannot read HBA port number: %w", err)
	}

	var portMultiplierPortNumber uint16
	if err := binary.Read(r, binary.LittleEndian, &portMultiplierPortNumber); err != nil {
		return "", xerrors.Errorf("cannot read port multiplier port number: %w", err)
	}

	var lun uint16
	if err := binary.Read(r, binary.LittleEndian, &lun); err != nil {
		return "", xerrors.Errorf("cannot read LUN: %w", err)
	}

	return fmt.Sprintf("\\Sata(0x%x,0x%x,0x%x)", hbaPortNumber, portMultiplierPortNumber, lun), nil
}

func filePathDevicePathNodeToString(data []byte) string {
	u16 := make([]uint16, len(data)/2)
	r := bytes.NewReader(data)
	binary.Read(r, binary.LittleEndian, &u16)

	var buf bytes.Buffer
	for _, r := range utf16.Decode(u16) {
		buf.WriteRune(r)
	}
	return buf.String()
}

func relOffsetRangePathNodeToString(data []byte) (string, error) {
	r := bytes.NewReader(data)

	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return "", err
	}

	var start uint64
	if err := binary.Read(r, binary.LittleEndian, &start); err != nil {
		return "", xerrors.Errorf("cannot read start: %w", err)
	}

	var end uint64
	if err := binary.Read(r, binary.LittleEndian, &end); err != nil {
		return "", xerrors.Errorf("cannot read end: %w", err)
	}

	return fmt.Sprintf("\\Offset(0x%x,0x%x)", start, end), nil
}

func decodeDevicePathNode(r io.Reader) (string, error) {
	var t efiDevicePathNodeType
	if err := binary.Read(r, binary.LittleEndian, &t); err != nil {
		return "", xerrors.Errorf("cannot read type: %w", err)
	}

	if t == efiDevicePathNodeEoH {
		return "", nil
	}

	var subType uint8
	if err := binary.Read(r, binary.LittleEndian, &subType); err != nil {
		return "", xerrors.Errorf("cannot read sub-type: %w", err)
	}

	var length uint16
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return "", xerrors.Errorf("cannot read length: %w", err)
	}

	if length < 4 {
		return "", errors.New("unexpected length")
	}

	data := make([]byte, length-4)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", xerrors.Errorf("cannot read data: %w", err)
	}

	switch t {
	case efiDevicePathNodeMedia:
		switch subType {
		case efiMediaDevicePathNodeFvFile, efiMediaDevicePathNodeFv:
			s, err := firmwareDevicePathNodeToString(subType, data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode Fv or FvFile node: %w", err)
			}
			return s, nil
		case efiMediaDevicePathNodeHardDrive:
			s, err := hardDriveDevicePathNodeToString(data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode HD node: %w", err)
			}
			return s, nil
		case efiMediaDevicePathNodeFilePath:
			return filePathDevicePathNodeToString(data), nil
		case efiMediaDevicePathNodeRelOffsetRange:
			s, err := relOffsetRangePathNodeToString(data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode Offset node: %w", err)
			}
			return s, nil
		}
	case efiDevicePathNodeACPI:
		switch subType {
		case efiACPIDevicePathNodeNormal:
			s, err := acpiDevicePathNodeToString(data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode Acpi node: %w", err)
			}
			return s, nil
		}
	case efiDevicePathNodeHardware:
		switch subType {
		case efiHardwareDevicePathNodePCI:
			s, err := pciDevicePathNodeToString(data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode Pci node: %w", err)
			}
			return s, nil
		}
	case efiDevicePathNodeMsg:
		switch subType {
		case efiMsgDevicePathNodeLU:
			s, err := luDevicePathNodeToString(data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode Unit node: %w", err)
			}
			return s, nil
		case efiMsgDevicePathNodeSATA:
			s, err := sataDevicePathNodeToString(data)
			if err != nil {
				return "", xerrors.Errorf("cannot decode Sata node: %w", err)
			}
			return s, nil
		}

	}

	var builder bytes.Buffer
	fmt.Fprintf(&builder, "\\%s(%d", t, subType)
	if len(data) > 0 {
		fmt.Fprintf(&builder, ", 0x")
		for _, b := range data {
			fmt.Fprintf(&builder, "%02x", b)
		}
	}
	fmt.Fprintf(&builder, ")")
	return builder.String(), nil
}

func decodeDevicePath(data []byte) (string, error) {
	r := bytes.NewReader(data)
	var builder bytes.Buffer

	for i := 0; ; i++ {
		node, err := decodeDevicePathNode(r)
		if err != nil {
			return "", xerrors.Errorf("cannot decode node %d: %w", i, err)
		}
		if node == "" {
			return builder.String(), nil
		}
		fmt.Fprintf(&builder, "%s", node)
	}
}

type efiImageLoadEventData struct {
	data             []byte
	locationInMemory uint64
	lengthInMemory   uint64
	linkTimeAddress  uint64
	path             string
}

func (e *efiImageLoadEventData) String() string {
	return fmt.Sprintf("UEFI_IMAGE_LOAD_EVENT{ ImageLocationInMemory: 0x%016x, ImageLengthInMemory: %d, "+
		"ImageLinkTimeAddress: 0x%016x, DevicePath: %s }", e.locationInMemory, e.lengthInMemory,
		e.linkTimeAddress, e.path)
}

func (e *efiImageLoadEventData) Bytes() []byte {
	return e.data
}

// https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf (section 4 "Measuring PE/COFF Image Files")
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.2.3 "UEFI_IMAGE_LOAD_EVENT Structure")
func decodeEventDataEFIImageLoad(data []byte) (*efiImageLoadEventData, error) {
	r := bytes.NewReader(data)

	var locationInMemory uint64
	if err := binary.Read(r, binary.LittleEndian, &locationInMemory); err != nil {
		return nil, xerrors.Errorf("cannot read location in memory: %w", err)
	}

	var lengthInMemory uint64
	if err := binary.Read(r, binary.LittleEndian, &lengthInMemory); err != nil {
		return nil, xerrors.Errorf("cannot read length in memory: %w", err)
	}

	var linkTimeAddress uint64
	if err := binary.Read(r, binary.LittleEndian, &linkTimeAddress); err != nil {
		return nil, xerrors.Errorf("cannot read link time address: %w", err)
	}

	var devicePathLength uint64
	if err := binary.Read(r, binary.LittleEndian, &devicePathLength); err != nil {
		return nil, xerrors.Errorf("cannot read device path length: %w", err)
	}

	devicePathBuf := make([]byte, devicePathLength)

	if _, err := io.ReadFull(r, devicePathBuf); err != nil {
		return nil, xerrors.Errorf("cannot read device path: %w", err)
	}

	path, err := decodeDevicePath(devicePathBuf)
	if err != nil {
		return nil, xerrors.Errorf("cannot decode device path: %w", err)
	}

	return &efiImageLoadEventData{data: data,
		locationInMemory: locationInMemory,
		lengthInMemory:   lengthInMemory,
		linkTimeAddress:  linkTimeAddress,
		path:             path}, nil
}

type efiGPTPartitionEntry struct {
	typeGUID   EFIGUID
	uniqueGUID EFIGUID
	name       string
}

func (p *efiGPTPartitionEntry) String() string {
	return fmt.Sprintf("PartitionTypeGUID: %s, UniquePartitionGUID: %s, Name: \"%s\"", p.typeGUID, p.uniqueGUID, p.name)
}

type efiGPTEventData struct {
	data       []byte
	diskGUID   EFIGUID
	partitions []*efiGPTPartitionEntry
}

func (e *efiGPTEventData) String() string {
	var builder bytes.Buffer
	fmt.Fprintf(&builder, "UEFI_GPT_DATA{ DiskGUID: %s, Partitions: [", e.diskGUID)
	for i, part := range e.partitions {
		if i > 0 {
			fmt.Fprintf(&builder, ", ")
		}
		fmt.Fprintf(&builder, "{ %s }", part)
	}
	fmt.Fprintf(&builder, "] }")
	return builder.String()
}

func (e *efiGPTEventData) Bytes() []byte {
	return e.data
}

func decodeEventDataEFIGPT(data []byte) (*efiGPTEventData, error) {
	r := bytes.NewReader(data)

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.{Header, MyLBA, AlternateLBA, FirstUsableLBA, LastUsableLBA}
	if _, err := r.Seek(56, io.SeekCurrent); err != nil {
		return nil, err
	}

	d := &efiGPTEventData{data: data}

	// UEFI_GPT_DATA.UEFIPartitionHeader.DiskGUID
	if _, err := io.ReadFull(r, d.diskGUID[:]); err != nil {
		return nil, xerrors.Errorf("cannot read disk GUID: %w", err)
	}

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.{PartitionEntryLBA, NumberOfPartitionEntries}
	if _, err := r.Seek(12, io.SeekCurrent); err != nil {
		return nil, err
	}

	// UEFI_GPT_DATA.UEFIPartitionHeader.SizeOfPartitionEntry
	var partEntrySize uint32
	if err := binary.Read(r, binary.LittleEndian, &partEntrySize); err != nil {
		return nil, xerrors.Errorf("cannot read SizeOfPartitionEntry: %w", err)
	}

	// Skip UEFI_GPT_DATA.UEFIPartitionHeader.PartitionEntryArrayCRC32
	if _, err := r.Seek(4, io.SeekCurrent); err != nil {
		return nil, err
	}

	// UEFI_GPT_DATA.NumberOfPartitions
	var numberOfParts uint64
	if err := binary.Read(r, binary.LittleEndian, &numberOfParts); err != nil {
		return nil, xerrors.Errorf("cannot read number of partitions: %w", err)
	}

	for i := uint64(0); i < numberOfParts; i++ {
		entryData := make([]byte, partEntrySize)
		if _, err := io.ReadFull(r, entryData); err != nil {
			return nil, xerrors.Errorf("cannot read partition entry data: %w", err)
		}

		er := bytes.NewReader(entryData)
		e := &efiGPTPartitionEntry{}

		if _, err := io.ReadFull(er, e.typeGUID[:]); err != nil {
			return nil, xerrors.Errorf("cannot read partition type GUID: %w", err)
		}

		if _, err := io.ReadFull(er, e.uniqueGUID[:]); err != nil {
			return nil, xerrors.Errorf("cannot read partition unique GUID: %w", err)
		}

		// Skip UEFI_GPT_DATA.Partitions[i].{StartingLBA, EndingLBA, Attributes}
		if _, err := er.Seek(24, io.SeekCurrent); err != nil {
			return nil, err
		}

		nameUtf16 := make([]uint16, er.Len()/2)
		if err := binary.Read(er, binary.LittleEndian, &nameUtf16); err != nil {
			return nil, xerrors.Errorf("cannot read partition name: %w", err)
		}

		var name bytes.Buffer
		for _, r := range utf16.Decode(nameUtf16) {
			if r == rune(0) {
				break
			}
			name.WriteRune(r)
		}
		e.name = name.String()

		d.partitions = append(d.partitions, e)
	}

	return d, nil
}
