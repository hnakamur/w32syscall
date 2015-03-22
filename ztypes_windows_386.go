// +build 386
// +build windows

package w32syscall

import "unsafe"

// Types for SendInput

type Input struct {
	Type  uint32
	Bytes [24]byte
}

func (mi MouseInput) ToInput() Input {
	input := Input{Type: INPUT_MOUSE}
	input.Bytes[0] = byte(mi.X)
	input.Bytes[1] = byte(mi.X >> 8)
	input.Bytes[2] = byte(mi.X >> 16)
	input.Bytes[3] = byte(mi.X >> 24)
	input.Bytes[4] = byte(mi.Y)
	input.Bytes[5] = byte(mi.Y >> 8)
	input.Bytes[6] = byte(mi.Y >> 16)
	input.Bytes[7] = byte(mi.Y >> 24)
	input.Bytes[8] = byte(mi.MouseData)
	input.Bytes[9] = byte(mi.MouseData >> 8)
	input.Bytes[10] = byte(mi.MouseData >> 16)
	input.Bytes[11] = byte(mi.MouseData >> 24)
	input.Bytes[12] = byte(mi.Flags)
	input.Bytes[13] = byte(mi.Flags >> 8)
	input.Bytes[14] = byte(mi.Flags >> 16)
	input.Bytes[15] = byte(mi.Flags >> 24)
	input.Bytes[16] = byte(mi.Time)
	input.Bytes[17] = byte(mi.Time >> 8)
	input.Bytes[18] = byte(mi.Time >> 16)
	input.Bytes[19] = byte(mi.Time >> 24)
	extraInfo := uintptr(unsafe.Pointer(mi.ExtraInfo))
	input.Bytes[20] = byte(extraInfo)
	input.Bytes[21] = byte(extraInfo >> 8)
	input.Bytes[22] = byte(extraInfo >> 16)
	input.Bytes[23] = byte(extraInfo >> 24)
	return input
}

func (ki KeybdInput) ToInput() Input {
	input := Input{Type: INPUT_KEYBOARD}
	input.Bytes[0] = byte(ki.Vk)
	input.Bytes[1] = byte(ki.Vk >> 8)
	input.Bytes[2] = byte(ki.Scan)
	input.Bytes[3] = byte(ki.Scan >> 8)
	input.Bytes[4] = byte(ki.Flags)
	input.Bytes[5] = byte(ki.Flags >> 8)
	input.Bytes[6] = byte(ki.Flags >> 16)
	input.Bytes[7] = byte(ki.Flags >> 24)
	input.Bytes[8] = byte(ki.Time)
	input.Bytes[9] = byte(ki.Time >> 8)
	input.Bytes[10] = byte(ki.Time >> 16)
	input.Bytes[11] = byte(ki.Time >> 24)
	extraInfo := uintptr(unsafe.Pointer(ki.ExtraInfo))
	input.Bytes[12] = byte(extraInfo)
	input.Bytes[13] = byte(extraInfo >> 8)
	input.Bytes[14] = byte(extraInfo >> 16)
	input.Bytes[15] = byte(extraInfo >> 24)
	return input
}
