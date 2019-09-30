package tcglog

const (
	EventTypePrebootCert EventType = 0x00000000 // EV_PREBOOT_CERT
	EventTypePostCode              = 0x00000001 // EV_POST_CODE
	// EventTypeUnused = 0x00000002
	EventTypeNoAction             = 0x00000003 // EV_NO_ACTION
	EventTypeSeparator            = 0x00000004 // EV_SEPARATOR
	EventTypeAction               = 0x00000005 // EV_ACTION
	EventTypeEventTag             = 0x00000006 // EV_EVENT_TAG
	EventTypeSCRTMContents        = 0x00000007 // EV_S_CRTM_CONTENTS
	EventTypeSCRTMVersion         = 0x00000008 // EV_S_CRTM_VERSION
	EventTypeCPUMicrocode         = 0x00000009 // EV_CPU_MICROCODE
	EventTypePlatformConfigFlags  = 0x0000000a // EV_PLATFORM_CONFIG_FLAGS
	EventTypeTableOfDevices       = 0x0000000b // EV_TABLE_OF_DEVICES
	EventTypeCompactHash          = 0x0000000c // EV_COMPACT_HASH
	EventTypeIPL                  = 0x0000000d // EV_IPL
	EventTypeIPLPartitionData     = 0x0000000e // EV_IPL_PARTITION_DATA
	EventTypeNonhostCode          = 0x0000000f // EV_NONHOST_CODE
	EventTypeNonhostConfig        = 0x00000010 // EV_NONHOST_CONFIG
	EventTypeNonhostInfo          = 0x00000011 // EV_NONHOST_INFO
	EventTypeOmitBootDeviceEvents = 0x00000012 // EV_OMIT_BOOT_DEVICE_EVENTS

	EventTypeEFIEventBase               = 0x80000000 // EV_EFI_EVENT_BASE
	EventTypeEFIVariableDriverConfig    = 0x80000001 // EV_EFI_VARIABLE_DRIVER_CONFIG
	EventTypeEFIVariableBoot            = 0x80000002 // EV_EFI_VARIABLE_BOOT
	EventTypeEFIBootServicesApplication = 0x80000003 // EV_EFI_BOOT_SERVICES_APPLICATION
	EventTypeEFIBootServicesDriver      = 0x80000004 // EV_EFI_BOOT_SERVICES_DRIVER
	EventTypeEFIRuntimeServicesDriver   = 0x80000005 // EV_EFI_RUNTIME_SERVICES_DRIVER
	EventTypeEFIGPTEvent                = 0x80000006 // EV_EFI_GPT_EVENT
	EventTypeEFIAction                  = 0x80000007 // EV_EFI_ACTION
	EventTypeEFIPlatformFirmwareBlob    = 0x80000008 // EV_EFI_PLATFORM_FIRMWARE_BLOB
	EventTypeEFIHandoffTables           = 0x80000009 // EF_EFI_HANDOFF_TABLES
	EventTypeEFIHCRTMEvent              = 0x80000010 // EF_EFI_HCRTM_EVENT
	EventTypeEFIVariableAuthority       = 0x800000e0 // EV_EFI_VARIABLE_AUTHORITY
)

const (
	AlgorithmSha1   AlgorithmId = 0x0004 // TPM_ALG_SHA1
	AlgorithmSha256             = 0x000b // TPM_ALG_SHA256
	AlgorithmSha384             = 0x000c // TPM_ALG_SHA384
	AlgorithmSha512             = 0x000d // TPM_ALG_SHA512
)

const (
	// SpecUnknown indicates that the specification to which the log conforms is unknown because it doesn't
	// start with a spec ID event.
	SpecUnknown Spec = iota

	// SpecPCClient indicates that the log conforms to "TCG PC Client Specific Implementation Specification
	// for Conventional BIOS".
	// See https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf
	SpecPCClient

	// SpecEFI_1_2 indicates that the log conforms to "TCG EFI Platform Specification For TPM Family 1.1 or
	// 1.2".
	// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf
	SpecEFI_1_2

	// SpecEFI_2 indicates that the log conforms to "TCG PC Client Platform Firmware Profile Specification"
	// See https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientSpecPlat_TPM_2p0_1p04_pub.pdf
	SpecEFI_2
)

const (
	separatorEventErrorValue uint32 = 1
)

var knownAlgorithms = map[AlgorithmId]uint16{
	AlgorithmSha1:   20,
	AlgorithmSha256: 32,
	AlgorithmSha384: 48,
	AlgorithmSha512: 64,
}
