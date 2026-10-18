// Package qrterm prints QR codes to a terminal.
package qrterm

import (
	"fmt"
	"io"
	"strings"

	"rsc.io/qr"
)

const quiet = 2 // quiet zone in modules; scanners cope with less than 4

// Print writes text as a QR code using half-block characters. Colors are
// set explicitly (black on white) so the code scans on dark and light
// terminal themes alike.
func Print(w io.Writer, text string) error {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return err
	}
	enableVT()
	const (
		start = "\x1b[30;107m" // black foreground, bright white background
		reset = "\x1b[0m"
	)
	n := code.Size + 2*quiet
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		b.WriteString(start)
		for x := 0; x < n; x++ {
			top := code.Black(x-quiet, y-quiet)
			bottom := y+1 < n && code.Black(x-quiet, y+1-quiet)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(reset)
		b.WriteString("\n")
	}
	_, err = fmt.Fprint(w, b.String())
	return err
}
