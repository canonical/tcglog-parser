package tcglog

// Known event types
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf (section 11.3.1)
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf (section 9.4.1)
const (
	EventTypePrebootCert EventType = 0x00000000
	EventTypePostCode              = 0x00000001
	// EventTypeUnused = 0x00000002
	EventTypeNoAction             = 0x00000003
	EventTypeSeparator            = 0x00000004
	EventTypeAction               = 0x00000005
	EventTypeEventTag             = 0x00000006
	EventTypeSCRTMContents        = 0x00000007
	EventTypeSCRTMVersion         = 0x00000008
	EventTypeCPUMicrocode         = 0x00000009
	EventTypePlatformConfigFlags  = 0x0000000a
	EventTypeTableOfDevices       = 0x0000000b
	EventTypeCompactHash          = 0x0000000c
	EventTypeIPL                  = 0x0000000d
	EventTypeIPLPartitionData     = 0x0000000e
	EventTypeNonhostCode          = 0x0000000f
	EventTypeNonhostConfig        = 0x00000010
	EventTypeNonhostInfo          = 0x00000011
	EventTypeOmitBootDeviceEvents = 0x00000012

	EventTypeEFIEventBase               = 0x80000000
	EventTypeEFIVariableDriverConfig    = 0x80000001
	EventTypeEFIVariableBoot            = 0x80000002
	EventTypeEFIBootServicesApplication = 0x80000003
	EventTypeEFIBootServicesDriver      = 0x80000004
	EventTypeEFIRuntimeServicesDriver   = 0x80000005
	EventTypeEFIGPTEvent                = 0x80000006
	EventTypeEFIAction                  = 0x80000007
	EventTypeEFIPlatformFirmwareBlob    = 0x80000008
	EventTypeEFIHandoffTables           = 0x80000009
	EventTypeEFIHCRTMEvent              = 0x80000010
	EventTypeEFIVariableAuthority       = 0x800000e0
)

// The supported digest algorithms
// https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf (Table 9)
const (
	AlgorithmSha1   AlgorithmId = 0x0004
	AlgorithmSha256             = 0x000b
	AlgorithmSha384             = 0x000c
	AlgorithmSha512             = 0x000d
)

const (
	SeparatorEventTypeNormal SeparatorEventType = 0
	SeparatorEventTypeError  SeparatorEventType = 1
)

const (
	SpecUnknown  Spec = 0
	SpecPCClient      = 1
	SpecEFI_1_2       = 2
	SpecEFI_2         = 3
)

const (
	EFIDevicePathNodeHardware EFIDevicePathNodeType = 0x01
	EFIDevicePathNodeACPI     EFIDevicePathNodeType = 0x02
	EFIDevicePathNodeMsg      EFIDevicePathNodeType = 0x03
	EFIDevicePathNodeMedia    EFIDevicePathNodeType = 0x04
	EFIDevicePathNodeBBS      EFIDevicePathNodeType = 0x05

	efiDevicePathNodeEoH EFIDevicePathNodeType = 0x7f
)
