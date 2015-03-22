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

// Types for SendInput

type KeybdInput struct {
	Vk        uint16
	Scan      uint16
	Flags     uint32
	Time      uint32
	ExtraInfo *uint32
}

// Constants for KeybdInput.Vk
const (
	/*
	 * Virtual Keys, Standard Set
	 */
	VK_LBUTTON = 0x01
	VK_RBUTTON = 0x02
	VK_CANCEL  = 0x03
	VK_MBUTTON = 0x04 /* NOT contiguous with L & RBUTTON */

	VK_XBUTTON1 = 0x05 /* NOT contiguous with L & RBUTTON */
	VK_XBUTTON2 = 0x06 /* NOT contiguous with L & RBUTTON */

	/*
	 * 0x07 : unassigned
	 */

	VK_BACK = 0x08
	VK_TAB  = 0x09

	/*
	 * 0x0A - 0x0B : reserved
	 */

	VK_CLEAR  = 0x0C
	VK_RETURN = 0x0D

	VK_SHIFT   = 0x10
	VK_CONTROL = 0x11
	VK_MENU    = 0x12
	VK_PAUSE   = 0x13
	VK_CAPITAL = 0x14

	VK_KANA   = 0x15
	VK_HANGUL = 0x15
	VK_JUNJA  = 0x17
	VK_FINAL  = 0x18
	VK_HANJA  = 0x19
	VK_KANJI  = 0x19

	VK_ESCAPE = 0x1B

	VK_CONVERT    = 0x1C
	VK_NONCONVERT = 0x1D
	VK_ACCEPT     = 0x1E
	VK_MODECHANGE = 0x1F

	VK_SPACE    = 0x20
	VK_PRIOR    = 0x21
	VK_NEXT     = 0x22
	VK_END      = 0x23
	VK_HOME     = 0x24
	VK_LEFT     = 0x25
	VK_UP       = 0x26
	VK_RIGHT    = 0x27
	VK_DOWN     = 0x28
	VK_SELECT   = 0x29
	VK_PRINT    = 0x2A
	VK_EXECUTE  = 0x2B
	VK_SNAPSHOT = 0x2C
	VK_INSERT   = 0x2D
	VK_DELETE   = 0x2E
	VK_HELP     = 0x2F

	/*
	 * VK_0 - VK_9 are the same as ASCII '0' - '9' (0x30 - 0x39)
	 * 0x40 : unassigned
	 * VK_A - VK_Z are the same as ASCII 'A' - 'Z' (0x41 - 0x5A)
	 */

	VK_LWIN = 0x5B
	VK_RWIN = 0x5C
	VK_APPS = 0x5D

	/*
	 * 0x5E : reserved
	 */

	VK_SLEEP = 0x5F

	VK_NUMPAD0   = 0x60
	VK_NUMPAD1   = 0x61
	VK_NUMPAD2   = 0x62
	VK_NUMPAD3   = 0x63
	VK_NUMPAD4   = 0x64
	VK_NUMPAD5   = 0x65
	VK_NUMPAD6   = 0x66
	VK_NUMPAD7   = 0x67
	VK_NUMPAD8   = 0x68
	VK_NUMPAD9   = 0x69
	VK_MULTIPLY  = 0x6A
	VK_ADD       = 0x6B
	VK_SEPARATOR = 0x6C
	VK_SUBTRACT  = 0x6D
	VK_DECIMAL   = 0x6E
	VK_DIVIDE    = 0x6F
	VK_F1        = 0x70
	VK_F2        = 0x71
	VK_F3        = 0x72
	VK_F4        = 0x73
	VK_F5        = 0x74
	VK_F6        = 0x75
	VK_F7        = 0x76
	VK_F8        = 0x77
	VK_F9        = 0x78
	VK_F10       = 0x79
	VK_F11       = 0x7A
	VK_F12       = 0x7B
	VK_F13       = 0x7C
	VK_F14       = 0x7D
	VK_F15       = 0x7E
	VK_F16       = 0x7F
	VK_F17       = 0x80
	VK_F18       = 0x81
	VK_F19       = 0x82
	VK_F20       = 0x83
	VK_F21       = 0x84
	VK_F22       = 0x85
	VK_F23       = 0x86
	VK_F24       = 0x87

	/*
	 * 0x88 - 0x8F : unassigned
	 */

	VK_NUMLOCK = 0x90
	VK_SCROLL  = 0x91

	/*
	 * NEC PC-9800 kbd definitions
	 */
	VK_OEM_NEC_EQUAL = 0x92 // '=' key on numpad

	/*
	 * Fujitsu/OASYS kbd definitions
	 */
	VK_OEM_FJ_JISHO   = 0x92 // 'Dictionary' key
	VK_OEM_FJ_MASSHOU = 0x93 // 'Unregister word' key
	VK_OEM_FJ_TOUROKU = 0x94 // 'Register word' key
	VK_OEM_FJ_LOYA    = 0x95 // 'Left OYAYUBI' key
	VK_OEM_FJ_ROYA    = 0x96 // 'Right OYAYUBI' key

	/*
	 * 0x97 - 0x9F : unassigned
	 */

	/*
	 * VK_L* & VK_R* - left and right Alt, Ctrl and Shift virtual keys.
	 * Used only as parameters to GetAsyncKeyState() and GetKeyState().
	 * No other API or message will distinguish left and right keys in this way.
	 */
	VK_LSHIFT   = 0xA0
	VK_RSHIFT   = 0xA1
	VK_LCONTROL = 0xA2
	VK_RCONTROL = 0xA3
	VK_LMENU    = 0xA4
	VK_RMENU    = 0xA5

	VK_BROWSER_BACK      = 0xA6
	VK_BROWSER_FORWARD   = 0xA7
	VK_BROWSER_REFRESH   = 0xA8
	VK_BROWSER_STOP      = 0xA9
	VK_BROWSER_SEARCH    = 0xAA
	VK_BROWSER_FAVORITES = 0xAB
	VK_BROWSER_HOME      = 0xAC

	VK_VOLUME_MUTE         = 0xAD
	VK_VOLUME_DOWN         = 0xAE
	VK_VOLUME_UP           = 0xAF
	VK_MEDIA_NEXT_TRACK    = 0xB0
	VK_MEDIA_PREV_TRACK    = 0xB1
	VK_MEDIA_STOP          = 0xB2
	VK_MEDIA_PLAY_PAUSE    = 0xB3
	VK_LAUNCH_MAIL         = 0xB4
	VK_LAUNCH_MEDIA_SELECT = 0xB5
	VK_LAUNCH_APP1         = 0xB6
	VK_LAUNCH_APP2         = 0xB7

	/*
	 * 0xB8 - 0xB9 : reserved
	 */

	VK_OEM_1      = 0xBA // ';:' for US
	VK_OEM_PLUS   = 0xBB // '+' any country
	VK_OEM_COMMA  = 0xBC // ',' any country
	VK_OEM_MINUS  = 0xBD // '-' any country
	VK_OEM_PERIOD = 0xBE // '.' any country
	VK_OEM_2      = 0xBF // '/?' for US
	VK_OEM_3      = 0xC0 // '`~' for US

	/*
	 * 0xC1 - 0xD7 : reserved
	 */

	/*
	 * 0xD8 - 0xDA : unassigned
	 */

	VK_OEM_4 = 0xDB //  '[{' for US
	VK_OEM_5 = 0xDC //  '\|' for US
	VK_OEM_6 = 0xDD //  ']}' for US
	VK_OEM_7 = 0xDE //  ''"' for US
	VK_OEM_8 = 0xDF

	/*
	 * 0xE0 : reserved
	 */

	/*
	 * Various extended or enhanced keyboards
	 */
	VK_OEM_AX   = 0xE1 //  'AX' key on Japanese AX kbd
	VK_OEM_102  = 0xE2 //  "<>" or "\|" on RT 102-key kbd.
	VK_ICO_HELP = 0xE3 //  Help key on ICO
	VK_ICO_00   = 0xE4 //  00 key on ICO

	VK_PROCESSKEY = 0xE5

	VK_ICO_CLEAR = 0xE6

	VK_PACKET = 0xE7

	/*
	 * 0xE8 : unassigned
	 */

	/*
	 * Nokia/Ericsson definitions
	 */
	VK_OEM_RESET   = 0xE9
	VK_OEM_JUMP    = 0xEA
	VK_OEM_PA1     = 0xEB
	VK_OEM_PA2     = 0xEC
	VK_OEM_PA3     = 0xED
	VK_OEM_WSCTRL  = 0xEE
	VK_OEM_CUSEL   = 0xEF
	VK_OEM_ATTN    = 0xF0
	VK_OEM_FINISH  = 0xF1
	VK_OEM_COPY    = 0xF2
	VK_OEM_AUTO    = 0xF3
	VK_OEM_ENLW    = 0xF4
	VK_OEM_BACKTAB = 0xF5

	VK_ATTN      = 0xF6
	VK_CRSEL     = 0xF7
	VK_EXSEL     = 0xF8
	VK_EREOF     = 0xF9
	VK_PLAY      = 0xFA
	VK_ZOOM      = 0xFB
	VK_NONAME    = 0xFC
	VK_PA1       = 0xFD
	VK_OEM_CLEAR = 0xFE

	/*
	 * 0xFF : reserved
	 */
)

// Constants for KeybdInput.Flags
const (
	KEYEVENTF_EXTENDEDKEY = 0x0001
	KEYEVENTF_KEYUP       = 0x0002
	KEYEVENTF_SCANCODE    = 0x0008
	KEYEVENTF_UNICODE     = 0x0004
)

type MouseInput struct {
	X         int32
	Y         int32
	MouseData uint32
	Flags     uint32
	Time      uint32
	ExtraInfo *uint32
}

// Constants for MouseInput.MouseData
const (
	XBUTTON1 = 0x0001
	XBUTTON2 = 0x0002
)

// Constants for MouseInput.Flags
const (
	MOUSEEVENTF_ABSOLUTE        = 0x8000
	MOUSEEVENTF_HWHEEL          = 0x01000
	MOUSEEVENTF_MOVE            = 0x0001
	MOUSEEVENTF_MOVE_NOCOALESCE = 0x2000
	MOUSEEVENTF_LEFTDOWN        = 0x0002
	MOUSEEVENTF_LEFTUP          = 0x0004
	MOUSEEVENTF_RIGHTDOWN       = 0x0008
	MOUSEEVENTF_RIGHTUP         = 0x0010
	MOUSEEVENTF_MIDDLEDOWN      = 0x0020
	MOUSEEVENTF_MIDDLEUP        = 0x0040
	MOUSEEVENTF_VIRTUALDESK     = 0x4000
	MOUSEEVENTF_WHEEL           = 0x0800
	MOUSEEVENTF_XDOWN           = 0x0080
	MOUSEEVENTF_XUP             = 0x0100
)

type HardwareInput struct {
	Msg    uint32
	ParamL int16
	ParamW int16
}

const (
	INPUT_MOUSE    = 0
	INPUT_KEYBOARD = 1
	INPUT_HARDWARE = 2
)

func (hi HardwareInput) ToInput() Input {
	input := Input{Type: INPUT_HARDWARE}
	input.Bytes[0] = byte(hi.Msg)
	input.Bytes[1] = byte(hi.Msg >> 8)
	input.Bytes[2] = byte(hi.Msg >> 16)
	input.Bytes[3] = byte(hi.Msg >> 24)
	input.Bytes[4] = byte(hi.ParamL)
	input.Bytes[5] = byte(hi.ParamL >> 8)
	input.Bytes[6] = byte(hi.ParamW)
	input.Bytes[7] = byte(hi.ParamW >> 8)
	return input
}

/*
 * Window Messages
 */

const (
	WM_NULL                           = 0x0000
	WM_CREATE                         = 0x0001
	WM_DESTROY                        = 0x0002
	WM_MOVE                           = 0x0003
	WM_SIZE                           = 0x0005
	WM_ACTIVATE                       = 0x0006
	WM_SETFOCUS                       = 0x0007
	WM_KILLFOCUS                      = 0x0008
	WM_ENABLE                         = 0x000A
	WM_SETREDRAW                      = 0x000B
	WM_SETTEXT                        = 0x000C
	WM_GETTEXT                        = 0x000D
	WM_GETTEXTLENGTH                  = 0x000E
	WM_PAINT                          = 0x000F
	WM_CLOSE                          = 0x0010
	WM_QUERYENDSESSION                = 0x0011
	WM_QUERYOPEN                      = 0x0013
	WM_ENDSESSION                     = 0x0016
	WM_QUIT                           = 0x0012
	WM_ERASEBKGND                     = 0x0014
	WM_SYSCOLORCHANGE                 = 0x0015
	WM_SHOWWINDOW                     = 0x0018
	WM_WININICHANGE                   = 0x001A
	WM_SETTINGCHANGE                  = WM_WININICHANGE
	WM_DEVMODECHANGE                  = 0x001B
	WM_ACTIVATEAPP                    = 0x001C
	WM_FONTCHANGE                     = 0x001D
	WM_TIMECHANGE                     = 0x001E
	WM_CANCELMODE                     = 0x001F
	WM_SETCURSOR                      = 0x0020
	WM_MOUSEACTIVATE                  = 0x0021
	WM_CHILDACTIVATE                  = 0x0022
	WM_QUEUESYNC                      = 0x0023
	WM_GETMINMAXINFO                  = 0x0024
	WM_PAINTICON                      = 0x0026
	WM_ICONERASEBKGND                 = 0x0027
	WM_NEXTDLGCTL                     = 0x0028
	WM_SPOOLERSTATUS                  = 0x002A
	WM_DRAWITEM                       = 0x002B
	WM_MEASUREITEM                    = 0x002C
	WM_DELETEITEM                     = 0x002D
	WM_VKEYTOITEM                     = 0x002E
	WM_CHARTOITEM                     = 0x002F
	WM_SETFONT                        = 0x0030
	WM_GETFONT                        = 0x0031
	WM_SETHOTKEY                      = 0x0032
	WM_GETHOTKEY                      = 0x0033
	WM_QUERYDRAGICON                  = 0x0037
	WM_COMPAREITEM                    = 0x0039
	WM_GETOBJECT                      = 0x003D
	WM_COMPACTING                     = 0x0041
	WM_WINDOWPOSCHANGING              = 0x0046
	WM_WINDOWPOSCHANGED               = 0x0047
	WM_POWER                          = 0x0048
	WM_COPYDATA                       = 0x004A
	WM_CANCELJOURNAL                  = 0x004B
	WM_NOTIFY                         = 0x004E
	WM_INPUTLANGCHANGEREQUEST         = 0x0050
	WM_INPUTLANGCHANGE                = 0x0051
	WM_TCARD                          = 0x0052
	WM_HELP                           = 0x0053
	WM_USERCHANGED                    = 0x0054
	WM_NOTIFYFORMAT                   = 0x0055
	WM_CONTEXTMENU                    = 0x007B
	WM_STYLECHANGING                  = 0x007C
	WM_STYLECHANGED                   = 0x007D
	WM_DISPLAYCHANGE                  = 0x007E
	WM_GETICON                        = 0x007F
	WM_SETICON                        = 0x0080
	WM_NCCREATE                       = 0x0081
	WM_NCDESTROY                      = 0x0082
	WM_NCCALCSIZE                     = 0x0083
	WM_NCHITTEST                      = 0x0084
	WM_NCPAINT                        = 0x0085
	WM_NCACTIVATE                     = 0x0086
	WM_GETDLGCODE                     = 0x0087
	WM_SYNCPAINT                      = 0x0088
	WM_NCMOUSEMOVE                    = 0x00A0
	WM_NCLBUTTONDOWN                  = 0x00A1
	WM_NCLBUTTONUP                    = 0x00A2
	WM_NCLBUTTONDBLCLK                = 0x00A3
	WM_NCRBUTTONDOWN                  = 0x00A4
	WM_NCRBUTTONUP                    = 0x00A5
	WM_NCRBUTTONDBLCLK                = 0x00A6
	WM_NCMBUTTONDOWN                  = 0x00A7
	WM_NCMBUTTONUP                    = 0x00A8
	WM_NCMBUTTONDBLCLK                = 0x00A9
	WM_NCXBUTTONDOWN                  = 0x00AB
	WM_NCXBUTTONUP                    = 0x00AC
	WM_NCXBUTTONDBLCLK                = 0x00AD
	WM_INPUT_DEVICE_CHANGE            = 0x00FE
	WM_INPUT                          = 0x00FF
	WM_KEYFIRST                       = 0x0100
	WM_KEYDOWN                        = 0x0100
	WM_KEYUP                          = 0x0101
	WM_CHAR                           = 0x0102
	WM_DEADCHAR                       = 0x0103
	WM_SYSKEYDOWN                     = 0x0104
	WM_SYSKEYUP                       = 0x0105
	WM_SYSCHAR                        = 0x0106
	WM_SYSDEADCHAR                    = 0x0107
	WM_UNICHAR                        = 0x0109
	WM_KEYLAST                        = 0x0109
	WM_IME_STARTCOMPOSITION           = 0x010D
	WM_IME_ENDCOMPOSITION             = 0x010E
	WM_IME_COMPOSITION                = 0x010F
	WM_IME_KEYLAST                    = 0x010F
	WM_INITDIALOG                     = 0x0110
	WM_COMMAND                        = 0x0111
	WM_SYSCOMMAND                     = 0x0112
	WM_TIMER                          = 0x0113
	WM_HSCROLL                        = 0x0114
	WM_VSCROLL                        = 0x0115
	WM_INITMENU                       = 0x0116
	WM_INITMENUPOPUP                  = 0x0117
	WM_GESTURE                        = 0x0119
	WM_GESTURENOTIFY                  = 0x011A
	WM_MENUSELECT                     = 0x011F
	WM_MENUCHAR                       = 0x0120
	WM_ENTERIDLE                      = 0x0121
	WM_MENURBUTTONUP                  = 0x0122
	WM_MENUDRAG                       = 0x0123
	WM_MENUGETOBJECT                  = 0x0124
	WM_UNINITMENUPOPUP                = 0x0125
	WM_MENUCOMMAND                    = 0x0126
	WM_CHANGEUISTATE                  = 0x0127
	WM_UPDATEUISTATE                  = 0x0128
	WM_QUERYUISTATE                   = 0x0129
	WM_CTLCOLORMSGBOX                 = 0x0132
	WM_CTLCOLOREDIT                   = 0x0133
	WM_CTLCOLORLISTBOX                = 0x0134
	WM_CTLCOLORBTN                    = 0x0135
	WM_CTLCOLORDLG                    = 0x0136
	WM_CTLCOLORSCROLLBAR              = 0x0137
	WM_CTLCOLORSTATIC                 = 0x0138
	MN_GETHMENU                       = 0x01E1
	WM_MOUSEFIRST                     = 0x0200
	WM_MOUSEMOVE                      = 0x0200
	WM_LBUTTONDOWN                    = 0x0201
	WM_LBUTTONUP                      = 0x0202
	WM_LBUTTONDBLCLK                  = 0x0203
	WM_RBUTTONDOWN                    = 0x0204
	WM_RBUTTONUP                      = 0x0205
	WM_RBUTTONDBLCLK                  = 0x0206
	WM_MBUTTONDOWN                    = 0x0207
	WM_MBUTTONUP                      = 0x0208
	WM_MBUTTONDBLCLK                  = 0x0209
	WM_MOUSEWHEEL                     = 0x020A
	WM_XBUTTONDOWN                    = 0x020B
	WM_XBUTTONUP                      = 0x020C
	WM_XBUTTONDBLCLK                  = 0x020D
	WM_MOUSEHWHEEL                    = 0x020E
	WM_MOUSELAST                      = 0x020E
	WM_PARENTNOTIFY                   = 0x0210
	WM_ENTERMENULOOP                  = 0x0211
	WM_EXITMENULOOP                   = 0x0212
	WM_NEXTMENU                       = 0x0213
	WM_SIZING                         = 0x0214
	WM_CAPTURECHANGED                 = 0x0215
	WM_MOVING                         = 0x0216
	WM_POWERBROADCAST                 = 0x0218
	WM_DEVICECHANGE                   = 0x0219
	WM_MDICREATE                      = 0x0220
	WM_MDIDESTROY                     = 0x0221
	WM_MDIACTIVATE                    = 0x0222
	WM_MDIRESTORE                     = 0x0223
	WM_MDINEXT                        = 0x0224
	WM_MDIMAXIMIZE                    = 0x0225
	WM_MDITILE                        = 0x0226
	WM_MDICASCADE                     = 0x0227
	WM_MDIICONARRANGE                 = 0x0228
	WM_MDIGETACTIVE                   = 0x0229
	WM_MDISETMENU                     = 0x0230
	WM_ENTERSIZEMOVE                  = 0x0231
	WM_EXITSIZEMOVE                   = 0x0232
	WM_DROPFILES                      = 0x0233
	WM_MDIREFRESHMENU                 = 0x0234
	WM_TOUCH                          = 0x0240
	WM_IME_SETCONTEXT                 = 0x0281
	WM_IME_NOTIFY                     = 0x0282
	WM_IME_CONTROL                    = 0x0283
	WM_IME_COMPOSITIONFULL            = 0x0284
	WM_IME_SELECT                     = 0x0285
	WM_IME_CHAR                       = 0x0286
	WM_IME_REQUEST                    = 0x0288
	WM_IME_KEYDOWN                    = 0x0290
	WM_IME_KEYUP                      = 0x0291
	WM_MOUSEHOVER                     = 0x02A1
	WM_MOUSELEAVE                     = 0x02A3
	WM_NCMOUSEHOVER                   = 0x02A0
	WM_NCMOUSELEAVE                   = 0x02A2
	WM_WTSSESSION_CHANGE              = 0x02B1
	WM_TABLET_FIRST                   = 0x02c0
	WM_TABLET_LAST                    = 0x02df
	WM_CUT                            = 0x0300
	WM_COPY                           = 0x0301
	WM_PASTE                          = 0x0302
	WM_CLEAR                          = 0x0303
	WM_UNDO                           = 0x0304
	WM_RENDERFORMAT                   = 0x0305
	WM_RENDERALLFORMATS               = 0x0306
	WM_DESTROYCLIPBOARD               = 0x0307
	WM_DRAWCLIPBOARD                  = 0x0308
	WM_PAINTCLIPBOARD                 = 0x0309
	WM_VSCROLLCLIPBOARD               = 0x030A
	WM_SIZECLIPBOARD                  = 0x030B
	WM_ASKCBFORMATNAME                = 0x030C
	WM_CHANGECBCHAIN                  = 0x030D
	WM_HSCROLLCLIPBOARD               = 0x030E
	WM_QUERYNEWPALETTE                = 0x030F
	WM_PALETTEISCHANGING              = 0x0310
	WM_PALETTECHANGED                 = 0x0311
	WM_HOTKEY                         = 0x0312
	WM_PRINT                          = 0x0317
	WM_PRINTCLIENT                    = 0x0318
	WM_APPCOMMAND                     = 0x0319
	WM_THEMECHANGED                   = 0x031A
	WM_CLIPBOARDUPDATE                = 0x031D
	WM_DWMCOMPOSITIONCHANGED          = 0x031E
	WM_DWMNCRENDERINGCHANGED          = 0x031F
	WM_DWMCOLORIZATIONCOLORCHANGED    = 0x0320
	WM_DWMWINDOWMAXIMIZEDCHANGE       = 0x0321
	WM_DWMSENDICONICTHUMBNAIL         = 0x0323
	WM_DWMSENDICONICLIVEPREVIEWBITMAP = 0x0326
	WM_GETTITLEBARINFOEX              = 0x033F
	WM_HANDHELDFIRST                  = 0x0358
	WM_HANDHELDLAST                   = 0x035F
	WM_AFXFIRST                       = 0x0360
	WM_AFXLAST                        = 0x037F
	WM_PENWINFIRST                    = 0x0380
	WM_PENWINLAST                     = 0x038F
	WM_APP                            = 0x8000
	WM_USER                           = 0x0400
)

/*
 * Class field offsets for GetClassLong()
 */
const (
	GCL_MENUNAME      = (-8)
	GCL_HBRBACKGROUND = (-10)
	GCL_HCURSOR       = (-12)
	GCL_HICON         = (-14)
	GCL_HMODULE       = (-16)
	GCL_CBWNDEXTRA    = (-18)
	GCL_CBCLSEXTRA    = (-20)
	GCL_WNDPROC       = (-24)
	GCL_STYLE         = (-26)
	GCW_ATOM          = (-32)
)
