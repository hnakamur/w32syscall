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
	procRegSetKeyValueW    = modadvapi32.NewProc("RegSetKeyValueW")
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

func RegSetKeyValue(key syscall.Handle, subkey *uint16, valname *uint16, valtype uint32, buf *byte, buflen uint32) (regerrno error) {
	r0, _, _ := syscall.Syscall6(procRegSetKeyValueW.Addr(), 6, uintptr(key), uintptr(unsafe.Pointer(subkey)), uintptr(unsafe.Pointer(valname)), uintptr(valtype), uintptr(unsafe.Pointer(buf)), uintptr(buflen))
	if r0 != 0 {
		regerrno = syscall.Errno(r0)
	}
	return
}
