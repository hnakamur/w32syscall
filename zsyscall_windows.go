package w32syscall

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modcredui   = syscall.NewLazyDLL("credui.dll")

	procGetDynamicTimeZoneInformation = modkernel32.NewProc("GetDynamicTimeZoneInformation")
	procSetDynamicTimeZoneInformation = modkernel32.NewProc("SetDynamicTimeZoneInformation")

	procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
	procLookupPrivilegeValue  = modadvapi32.NewProc("LookupPrivilegeValueW")
	procRegCreateKeyExW       = modadvapi32.NewProc("RegCreateKeyExW")
	procRegDeleteKeyValueW    = modadvapi32.NewProc("RegDeleteKeyValueW")
	procRegDeleteTreeW        = modadvapi32.NewProc("RegDeleteTreeW")
	procRegGetValueW          = modadvapi32.NewProc("RegGetValueW")
	procRegSetKeyValueW       = modadvapi32.NewProc("RegSetKeyValueW")

	procCredUIPromptForCredentialsW        = modcredui.NewProc("CredUIPromptForCredentialsW")
	procCredUICmdLinePromptForCredentialsW = modcredui.NewProc("CredUICmdLinePromptForCredentialsW")
)

func GetDynamicTimeZoneInformation(timeZoneInformation *DynamicTimeZoneInformation) (err error) {
	r0, _, e1 := syscall.Syscall(procGetDynamicTimeZoneInformation.Addr(), 1,
		uintptr(unsafe.Pointer(timeZoneInformation)),
		0,
		0)
	if r0 == TIME_ZONE_ID_INVALID {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func SetDynamicTimeZoneInformation(timeZoneInformation *DynamicTimeZoneInformation) (err error) {
	r0, _, e1 := syscall.Syscall(procSetDynamicTimeZoneInformation.Addr(), 1,
		uintptr(unsafe.Pointer(timeZoneInformation)),
		0,
		0)
	if r0 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func AdjustTokenPrivileges(tokenHandle syscall.Token, disableAllPrivileges bool, newState *TokenPrivileges, bufferLength uint32, previousState *TokenPrivileges, returnLength *uint32) (err error) {
	var _p0 uint32
	if disableAllPrivileges {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r1, _, e1 := syscall.Syscall6(procAdjustTokenPrivileges.Addr(), 6,
		uintptr(tokenHandle),
		uintptr(_p0),
		uintptr(unsafe.Pointer(newState)),
		uintptr(bufferLength),
		uintptr(unsafe.Pointer(previousState)),
		uintptr(unsafe.Pointer(returnLength)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func LookupPrivilegeValue(systemName, name *uint16, luid *Luid) (err error) {
	r1, _, e1 := syscall.Syscall(procLookupPrivilegeValue.Addr(), 3,
		uintptr(unsafe.Pointer(systemName)),
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(luid)))
	if r1 == 0 {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func RegCreateKeyEx(key syscall.Handle, subkey *uint16, reserved uint32, class *uint16, options uint32, desiredAccess uint32, securityAttributes *syscall.SecurityAttributes, result *syscall.Handle, disposition *uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall9(procRegCreateKeyExW.Addr(), 9, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(reserved), uintptr(unsafe.Pointer(class)), uintptr(options), uintptr(desiredAccess), uintptr(unsafe.Pointer(securityAttributes)), uintptr(unsafe.Pointer(result)), uintptr(unsafe.Pointer(disposition)))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegDeleteKeyValue(key syscall.Handle, subkey *uint16, valname *uint16) (regerrno error) {
	r0, _, _ := syscall.Syscall(procRegDeleteKeyValueW.Addr(), 3, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(unsafe.Pointer(valname)))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegDeleteTree(key syscall.Handle, subkey *uint16) (regerrno error) {
	r0, _, _ := syscall.Syscall(procRegDeleteTreeW.Addr(), 2, uintptr(key), uintptr(unsafe.Pointer(subkey)), 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegGetValue(key syscall.Handle, subkey *uint16, valname *uint16, flags uint32, valtype *uint32, buf *byte, buflen *uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall9(procRegGetValueW.Addr(), 7, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(unsafe.Pointer(valname)), uintptr(flags), uintptr(unsafe.Pointer(valtype)), uintptr(unsafe.Pointer(buf)), uintptr(unsafe.Pointer(buflen)), 0, 0)
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func RegSetKeyValue(key syscall.Handle, subkey *uint16, valname *uint16, valtype uint32, buf *byte, buflen uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall6(procRegSetKeyValueW.Addr(), 6, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(unsafe.Pointer(valname)), uintptr(valtype), uintptr(unsafe.Pointer(buf)), uintptr(buflen))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}

func CredUIPromptForCredentials(
	uiInfo *CreduiInfo,
	targetName *uint16,
	reserved syscall.Handle,
	authError uint32,
	userName *uint16,
	userNameMaxChars uint32,
	password *uint16,
	passwordMaxChars uint32,
	save *uint32,
	flags uint32) (err error) {
	r0, _, _ := syscall.Syscall12(procCredUIPromptForCredentialsW.Addr(), 10,
		uintptr(unsafe.Pointer(uiInfo)),
		uintptr(unsafe.Pointer(targetName)),
		uintptr(unsafe.Pointer(reserved)),
		uintptr(authError),
		uintptr(unsafe.Pointer(userName)),
		uintptr(userNameMaxChars),
		uintptr(unsafe.Pointer(password)),
		uintptr(passwordMaxChars),
		uintptr(unsafe.Pointer(save)),
		uintptr(flags),
		0,
		0)
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}

func CredUICmdLinePromptForCredentials(
	targetName *uint16,
	reserved syscall.Handle,
	authError uint32,
	userName *uint16,
	userNameMaxChars uint32,
	password *uint16,
	passwordMaxChars uint32,
	save *uint32,
	flags uint32) (err error) {
	r0, _, _ := syscall.Syscall9(procCredUICmdLinePromptForCredentialsW.Addr(), 9,
		uintptr(unsafe.Pointer(targetName)),
		uintptr(unsafe.Pointer(reserved)),
		uintptr(authError),
		uintptr(unsafe.Pointer(userName)),
		uintptr(userNameMaxChars),
		uintptr(unsafe.Pointer(password)),
		uintptr(passwordMaxChars),
		uintptr(unsafe.Pointer(save)),
		uintptr(flags))
	if r0 != 0 {
		err = syscall.Errno(r0)
	}
	return
}
