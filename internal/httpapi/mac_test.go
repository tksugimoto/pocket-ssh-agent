package httpapi

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// The same vector is checked by web/test/lib.test.mjs, so both sides of the
// protocol compute identical MACs.
const goVector = "ljXD7DjIya-YjNXhB3G8TzsJMPyEinQ0gncq67WZB4E"

func TestMacVector(t *testing.T) {
	got := base64.RawURLEncoding.EncodeToString(Mac(bytes.Repeat([]byte{1}, 32), labelReq, "a", "b", "", "0", "c"))
	if got != goVector {
		t.Fatalf("Mac = %s, want %s", got, goVector)
	}
}
