// +build amd64
// +build windows

package w32syscall

import "syscall"

var (
	procGetClassLongPtrW = moduser32.NewProc("GetClassLongPtrW")
)

func GetClassLongPtr(hwnd syscall.Handle, index int) (result uintptr, err error) {
	result, _, e1 := syscall.Syscall(procGetClassLongPtrW.Addr(), 2, uintptr(hwnd), uintptr(index), 0)
	if result == 0 {
		err = error(e1)
	}
	return
}
