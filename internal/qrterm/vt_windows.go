//go:build windows

package qrterm

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT turns on ANSI escape sequence processing in the Windows console.
func enableVT() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) == nil {
		_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
	_ = windows.SetConsoleOutputCP(65001) // UTF-8 for the block characters
}
