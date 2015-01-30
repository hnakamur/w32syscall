package w32syscall

import "syscall"

// Registry

const (
	RRF_RT_ANY           = 0x0000ffff
	RRF_RT_DWORD         = 0x00000018
	RRF_RT_QWORD         = 0x00000048
	RRF_RT_REG_BINARY    = 0x00000008
	RRF_RT_REG_DWORD     = 0x00000010
	RRF_RT_REG_EXPAND_SZ = 0x00000004
	RRF_RT_REG_MULTI_SZ  = 0x00000020
	RRF_RT_REG_NONE      = 0x00000001
	RRF_RT_REG_QWORD     = 0x00000040
	RRF_RT_REG_SZ        = 0x00000002
	RRF_NOEXPAND         = 0x10000000
	RRF_ZEROONFAILURE    = 0x20000000
)

// AccessToken

const (
	ERROR_SUCCESS          = 0
	ERROR_INVALID_FUNCTION = 1
	ERROR_NOT_ALL_ASSIGNED = 1300
)

type Luid struct {
	LowPart  uint32
	HighPart int32
}

type LuidAndAttributes struct {
	Luid       Luid
	Attributes uint32
}

const ANYSIZE_ARRAY = 1

// https://msdn.microsoft.com/ja-jp/library/windows/desktop/aa379630(v=vs.85).aspx
type TokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [ANYSIZE_ARRAY]LuidAndAttributes
}

// TimeZone

type DynamicTimeZoneInformation struct {
	Bias                        int32
	StandardName                [32]uint16
	StandardDate                syscall.Systemtime
	StandardBias                int32
	DaylightName                [32]uint16
	DaylightDate                syscall.Systemtime
	DaylightBias                int32
	TimeZoneKeyName             [128]uint16
	DynamicDaylightTimeDisabled uint8 /* BOOLEAN */
}

const (
	TIME_ZONE_ID_INVALID  = 0xFFFFFFFF
	TIME_ZONE_ID_UNKNOWN  = 0
	TIME_ZONE_ID_STANDARD = 1
	TIME_ZONE_ID_DAYLIGHT = 2
)

const SE_TIME_ZONE_NAME = "SeTimeZonePrivilege"

const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

	SE_PRIVILEGE_VALID_ATTRIBUTES = SE_PRIVILEGE_ENABLED_BY_DEFAULT |
		SE_PRIVILEGE_ENABLED |
		SE_PRIVILEGE_REMOVED |
		SE_PRIVILEGE_USED_FOR_ACCESS
)
