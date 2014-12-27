package w32syscall

import (
	"syscall"
	"unsafe"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procRegCreateKeyExW    = modadvapi32.NewProc("RegCreateKeyExW")
	procRegDeleteKeyValueW = modadvapi32.NewProc("RegDeleteKeyValueW")
	procRegDeleteTreeW     = modadvapi32.NewProc("RegDeleteTreeW")
	procRegGetValueW       = modadvapi32.NewProc("RegGetValueW")
	procRegSetKeyValueW    = modadvapi32.NewProc("RegSetKeyValueW")
)

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
