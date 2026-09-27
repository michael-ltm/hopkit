//go:build darwin && cgo

package keychainfixture

/*
#include <stdlib.h>
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include "fixture.h"
*/
import "C"

import "unsafe"

// Native fixture support is deliberately excluded from production binaries.
// It reads only access metadata for the exact synthetic item supplied by a test.
func Operation(operation, ref string) int {
	mode, account := C.CString(operation), C.CString(ref)
	defer C.free(unsafe.Pointer(mode))
	defer C.free(unsafe.Pointer(account))
	return int(C.sshmKeychainFixture(mode, account))
}
