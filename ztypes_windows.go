package w32syscall

import "syscall"

type ThreadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

type Rect struct {
	Left   uint32
	Top    uint32
	Right  uint32
	Bottom uint32
}

type GuiThreadInfo struct {
	Size      uint32
	Flags     uint32
	Active    syscall.Handle
	Focus     syscall.Handle
	Capture   syscall.Handle
	MenuOwner syscall.Handle
	MoveSize  syscall.Handle
	Caret     syscall.Handle
	CaretRect Rect
}

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

// NOTE: These constants are not []uint16 but Go string. You need to convert
// these constants using syscall.UTF16FromString()
const (
	SE_CREATE_TOKEN_NAME           = "SeCreateTokenPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME     = "SeAssignPrimaryTokenPrivilege"
	SE_LOCK_MEMORY_NAME            = "SeLockMemoryPrivilege"
	SE_INCREASE_QUOTA_NAME         = "SeIncreaseQuotaPrivilege"
	SE_UNSOLICITED_INPUT_NAME      = "SeUnsolicitedInputPrivilege"
	SE_MACHINE_ACCOUNT_NAME        = "SeMachineAccountPrivilege"
	SE_TCB_NAME                    = "SeTcbPrivilege"
	SE_SECURITY_NAME               = "SeSecurityPrivilege"
	SE_TAKE_OWNERSHIP_NAME         = "SeTakeOwnershipPrivilege"
	SE_LOAD_DRIVER_NAME            = "SeLoadDriverPrivilege"
	SE_SYSTEM_PROFILE_NAME         = "SeSystemProfilePrivilege"
	SE_SYSTEMTIME_NAME             = "SeSystemtimePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME    = "SeProfileSingleProcessPrivilege"
	SE_INC_BASE_PRIORITY_NAME      = "SeIncreaseBasePriorityPrivilege"
	SE_CREATE_PAGEFILE_NAME        = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME       = "SeCreatePermanentPrivilege"
	SE_BACKUP_NAME                 = "SeBackupPrivilege"
	SE_RESTORE_NAME                = "SeRestorePrivilege"
	SE_SHUTDOWN_NAME               = "SeShutdownPrivilege"
	SE_DEBUG_NAME                  = "SeDebugPrivilege"
	SE_AUDIT_NAME                  = "SeAuditPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME     = "SeSystemEnvironmentPrivilege"
	SE_CHANGE_NOTIFY_NAME          = "SeChangeNotifyPrivilege"
	SE_REMOTE_SHUTDOWN_NAME        = "SeRemoteShutdownPrivilege"
	SE_UNDOCK_NAME                 = "SeUndockPrivilege"
	SE_SYNC_AGENT_NAME             = "SeSyncAgentPrivilege"
	SE_ENABLE_DELEGATION_NAME      = "SeEnableDelegationPrivilege"
	SE_MANAGE_VOLUME_NAME          = "SeManageVolumePrivilege"
	SE_IMPERSONATE_NAME            = "SeImpersonatePrivilege"
	SE_CREATE_GLOBAL_NAME          = "SeCreateGlobalPrivilege"
	SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege"
	SE_RELABEL_NAME                = "SeRelabelPrivilege"
	SE_INC_WORKING_SET_NAME        = "SeIncreaseWorkingSetPrivilege"
	SE_TIME_ZONE_NAME              = "SeTimeZonePrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME   = "SeCreateSymbolicLinkPrivilege"
)

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

/*
 * ExitWindowsEx
 */

const (
	EWX_LOGOFF   = 0
	EWX_SHUTDOWN = 0x00000001
	EWX_REBOOT   = 0x00000002
	EWX_FORCE    = 0x00000004
	EWX_POWEROFF = 0x00000008
	// #if(_WIN32_WINNT >= 0x0500)
	EWX_FORCEIFHUNG = 0x00000010
	// #endif /* _WIN32_WINNT >= 0x0500 */
	EWX_QUICKRESOLVE = 0x00000020
	// #if(_WIN32_WINNT >= 0x0600)
	EWX_RESTARTAPPS = 0x00000040
	// #endif /* _WIN32_WINNT >= 0x0600 */
)

// Reason flags

// Flags used by the various UIs.
const (
	SHTDN_REASON_FLAG_COMMENT_REQUIRED          = 0x01000000
	SHTDN_REASON_FLAG_DIRTY_PROBLEM_ID_REQUIRED = 0x02000000
	SHTDN_REASON_FLAG_CLEAN_UI                  = 0x04000000
	SHTDN_REASON_FLAG_DIRTY_UI                  = 0x08000000
)

// Flags that end up in the event log code.
const (
	SHTDN_REASON_FLAG_USER_DEFINED = 0x40000000
	SHTDN_REASON_FLAG_PLANNED      = 0x80000000
)

// Microsoft major reasons.
const (
	SHTDN_REASON_MAJOR_OTHER           = 0x00000000
	SHTDN_REASON_MAJOR_NONE            = 0x00000000
	SHTDN_REASON_MAJOR_HARDWARE        = 0x00010000
	SHTDN_REASON_MAJOR_OPERATINGSYSTEM = 0x00020000
	SHTDN_REASON_MAJOR_SOFTWARE        = 0x00030000
	SHTDN_REASON_MAJOR_APPLICATION     = 0x00040000
	SHTDN_REASON_MAJOR_SYSTEM          = 0x00050000
	SHTDN_REASON_MAJOR_POWER           = 0x00060000
	SHTDN_REASON_MAJOR_LEGACY_API      = 0x00070000
)

// Microsoft minor reasons.
const (
	SHTDN_REASON_MINOR_OTHER                 = 0x00000000
	SHTDN_REASON_MINOR_NONE                  = 0x000000ff
	SHTDN_REASON_MINOR_MAINTENANCE           = 0x00000001
	SHTDN_REASON_MINOR_INSTALLATION          = 0x00000002
	SHTDN_REASON_MINOR_UPGRADE               = 0x00000003
	SHTDN_REASON_MINOR_RECONFIG              = 0x00000004
	SHTDN_REASON_MINOR_HUNG                  = 0x00000005
	SHTDN_REASON_MINOR_UNSTABLE              = 0x00000006
	SHTDN_REASON_MINOR_DISK                  = 0x00000007
	SHTDN_REASON_MINOR_PROCESSOR             = 0x00000008
	SHTDN_REASON_MINOR_NETWORKCARD           = 0x00000009
	SHTDN_REASON_MINOR_POWER_SUPPLY          = 0x0000000a
	SHTDN_REASON_MINOR_CORDUNPLUGGED         = 0x0000000b
	SHTDN_REASON_MINOR_ENVIRONMENT           = 0x0000000c
	SHTDN_REASON_MINOR_HARDWARE_DRIVER       = 0x0000000d
	SHTDN_REASON_MINOR_OTHERDRIVER           = 0x0000000e
	SHTDN_REASON_MINOR_BLUESCREEN            = 0x0000000F
	SHTDN_REASON_MINOR_SERVICEPACK           = 0x00000010
	SHTDN_REASON_MINOR_HOTFIX                = 0x00000011
	SHTDN_REASON_MINOR_SECURITYFIX           = 0x00000012
	SHTDN_REASON_MINOR_SECURITY              = 0x00000013
	SHTDN_REASON_MINOR_NETWORK_CONNECTIVITY  = 0x00000014
	SHTDN_REASON_MINOR_WMI                   = 0x00000015
	SHTDN_REASON_MINOR_SERVICEPACK_UNINSTALL = 0x00000016
	SHTDN_REASON_MINOR_HOTFIX_UNINSTALL      = 0x00000017
	SHTDN_REASON_MINOR_SECURITYFIX_UNINSTALL = 0x00000018
	SHTDN_REASON_MINOR_MMC                   = 0x00000019
	SHTDN_REASON_MINOR_SYSTEMRESTORE         = 0x0000001a
	SHTDN_REASON_MINOR_TERMSRV               = 0x00000020
	SHTDN_REASON_MINOR_DC_PROMOTION          = 0x00000021
	SHTDN_REASON_MINOR_DC_DEMOTION           = 0x00000022

	SHTDN_REASON_UNKNOWN    = SHTDN_REASON_MINOR_NONE
	SHTDN_REASON_LEGACY_API = (SHTDN_REASON_MAJOR_LEGACY_API | SHTDN_REASON_FLAG_PLANNED)
)

// This mask cuts out UI flags.
const SHTDN_REASON_VALID_BIT_MASK = 0xc0ffffff
