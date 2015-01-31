package w32syscall

import "syscall"

// Error codes

const (
	NO_ERROR                    = 0
	ERROR_SUCCESS               = 0
	ERROR_INVALID_FUNCTION      = 1
	ERROR_FILE_NOT_FOUND        = 2
	ERROR_INVALID_PARAMETER     = 87
	ERROR_INVALID_FLAGS         = 1004
	ERROR_CANCELLED             = 1223
	ERROR_NOT_ALL_ASSIGNED      = 1300
	ERROR_NO_SUCH_LOGON_SESSION = 1312
)

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

// User Credentials

type CreduiInfo struct {
	Size        uint32
	Parent      syscall.Handle
	MessageText *uint16
	CaptionText *uint16
	Banner      syscall.Handle
}

//
// Credential Attribute
//

const MAXUSHORT = 65535

// Maximum length of the various credential string fields (in characters)
const CRED_MAX_STRING_LENGTH = 256

// Maximum length of the UserName field.  The worst case is <User>@<DnsDomain>
const CRED_MAX_USERNAME_LENGTH = (256 + 1 + 256)

// Maximum length of the TargetName field for CRED_TYPE_GENERIC (in characters)
const CRED_MAX_GENERIC_TARGET_NAME_LENGTH = 32767

// Maximum length of the TargetName field for CRED_TYPE_DOMAIN_* (in characters)
//      Largest one is <DfsRoot>\<DfsShare>
const CRED_MAX_DOMAIN_TARGET_NAME_LENGTH = (256 + 1 + 80)

// Maximum length of a target namespace
const CRED_MAX_TARGETNAME_NAMESPACE_LENGTH = (256)

// Maximum length of a target attribute
const CRED_MAX_TARGETNAME_ATTRIBUTE_LENGTH = (256)

// Maximum size of the Credential Attribute Value field (in bytes)
const CRED_MAX_VALUE_SIZE = (256)

// Maximum number of attributes per credential
const CRED_MAX_ATTRIBUTES = 64

// String length limits:

const (
	CREDUI_MAX_MESSAGE_LENGTH        = 32767
	CREDUI_MAX_CAPTION_LENGTH        = 128
	CREDUI_MAX_GENERIC_TARGET_LENGTH = CRED_MAX_GENERIC_TARGET_NAME_LENGTH
	CREDUI_MAX_DOMAIN_TARGET_LENGTH  = CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
)

//
//  Username can be in <domain>\<user> or <user>@<domain>
//  Length in characters, not including NULL termination.
//

const (
	CREDUI_MAX_USERNAME_LENGTH = CRED_MAX_USERNAME_LENGTH
	CREDUI_MAX_PASSWORD_LENGTH = (512 / 2)
)

//
//  Packed credential returned by SspiEncodeAuthIdentityAsStrings().
//  Length in characters, not including NULL termination.
//

const CREDUI_MAX_PACKED_CREDENTIALS_LENGTH = ((MAXUSHORT / 2) - 2)

// maximum length in bytes for binary credential blobs

const CREDUI_MAX_CREDENTIALS_BLOB_SIZE = (MAXUSHORT)

//
// Flags for CredUIPromptForCredentials and/or CredUICmdLinePromptForCredentials
//

const (
	CREDUI_FLAGS_INCORRECT_PASSWORD          = 0x00001 // indicates the username is valid, but password is not
	CREDUI_FLAGS_DO_NOT_PERSIST              = 0x00002 // Do not show "Save" checkbox, and do not persist credentials
	CREDUI_FLAGS_REQUEST_ADMINISTRATOR       = 0x00004 // Populate list box with admin accounts
	CREDUI_FLAGS_EXCLUDE_CERTIFICATES        = 0x00008 // do not include certificates in the drop list
	CREDUI_FLAGS_REQUIRE_CERTIFICATE         = 0x00010
	CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX         = 0x00040
	CREDUI_FLAGS_ALWAYS_SHOW_UI              = 0x00080
	CREDUI_FLAGS_REQUIRE_SMARTCARD           = 0x00100
	CREDUI_FLAGS_PASSWORD_ONLY_OK            = 0x00200
	CREDUI_FLAGS_VALIDATE_USERNAME           = 0x00400
	CREDUI_FLAGS_COMPLETE_USERNAME           = 0x00800 //
	CREDUI_FLAGS_PERSIST                     = 0x01000 // Do not show "Save" checkbox, but persist credentials anyway
	CREDUI_FLAGS_SERVER_CREDENTIAL           = 0x04000
	CREDUI_FLAGS_EXPECT_CONFIRMATION         = 0x20000  // do not persist unless caller later confirms credential via CredUIConfirmCredential() api
	CREDUI_FLAGS_GENERIC_CREDENTIALS         = 0x40000  // Credential is a generic credential
	CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS = 0x80000  // Credential has a username as the target
	CREDUI_FLAGS_KEEP_USERNAME               = 0x100000 // don't allow the user to change the supplied username

	//
	// Mask of flags valid for CredUIPromptForCredentials
	//
	CREDUI_FLAGS_PROMPT_VALID = CREDUI_FLAGS_INCORRECT_PASSWORD |
		CREDUI_FLAGS_DO_NOT_PERSIST |
		CREDUI_FLAGS_REQUEST_ADMINISTRATOR |
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES |
		CREDUI_FLAGS_REQUIRE_CERTIFICATE |
		CREDUI_FLAGS_SHOW_SAVE_CHECK_BOX |
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_REQUIRE_SMARTCARD |
		CREDUI_FLAGS_PASSWORD_ONLY_OK |
		CREDUI_FLAGS_VALIDATE_USERNAME |
		CREDUI_FLAGS_COMPLETE_USERNAME |
		CREDUI_FLAGS_PERSIST |
		CREDUI_FLAGS_SERVER_CREDENTIAL |
		CREDUI_FLAGS_EXPECT_CONFIRMATION |
		CREDUI_FLAGS_GENERIC_CREDENTIALS |
		CREDUI_FLAGS_USERNAME_TARGET_CREDENTIALS |
		CREDUI_FLAGS_KEEP_USERNAME
)

//
// Flags for CredUIPromptForWindowsCredentials and CPUS_CREDUI Usage Scenarios
//

const (
	CREDUIWIN_GENERIC                = 0x00000001 // Plain text username/password is being requested
	CREDUIWIN_CHECKBOX               = 0x00000002 // Show the Save Credential checkbox
	CREDUIWIN_AUTHPACKAGE_ONLY       = 0x00000010 // Only Cred Providers that support the input auth package should enumerate
	CREDUIWIN_IN_CRED_ONLY           = 0x00000020 // Only the incoming cred for the specific auth package should be enumerated
	CREDUIWIN_ENUMERATE_ADMINS       = 0x00000100 // Cred Providers should enumerate administrators only
	CREDUIWIN_ENUMERATE_CURRENT_USER = 0x00000200 // Only the incoming cred for the specific auth package should be enumerated
	CREDUIWIN_SECURE_PROMPT          = 0x00001000 // The Credui prompt should be displayed on the secure desktop
	CREDUIWIN_PACK_32_WOW            = 0x10000000 // Tell the credential provider it should be packing its Auth Blob 32 bit even though it is running 64 native

	CREDUIWIN_VALID_FLAGS = CREDUIWIN_GENERIC |
		CREDUIWIN_CHECKBOX |
		CREDUIWIN_AUTHPACKAGE_ONLY |
		CREDUIWIN_IN_CRED_ONLY |
		CREDUIWIN_ENUMERATE_ADMINS |
		CREDUIWIN_ENUMERATE_CURRENT_USER |
		CREDUIWIN_SECURE_PROMPT |
		CREDUIWIN_PACK_32_WOW
)
