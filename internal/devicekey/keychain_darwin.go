//go:build darwin && cgo

package devicekey

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// File-based user keychain supports command-line binaries without application
// entitlements. All access is noninteractive, including locked-keychain errors.
static OSStatus sshmKeychain(const char *account, unsigned char *key, int create) {
    Boolean previous = true;
    OSStatus status = SecKeychainGetUserInteractionAllowed(&previous);
    if (status != errSecSuccess) return status;
    status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    CFStringRef name = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR("sshm.device"));
    CFDictionarySetValue(query, kSecAttrAccount, name);
    CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
    if (create) {
        CFDataRef data = CFDataCreate(NULL, key, 32);
        CFDictionarySetValue(query, kSecValueData, data);
        status = SecItemAdd(query, NULL);
        CFRelease(data);
    } else {
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
        CFTypeRef result = NULL;
        status = SecItemCopyMatching(query, &result);
        if (status == errSecSuccess) {
            if (!result || CFGetTypeID(result) != CFDataGetTypeID() || CFDataGetLength((CFDataRef)result) != 32) status = errSecDecode;
            else memcpy(key, CFDataGetBytePtr((CFDataRef)result), 32);
        }
        if (result) CFRelease(result);
    }
    CFRelease(query);
    CFRelease(name);
    SecKeychainSetUserInteractionAllowed(previous);
    return status;
}
*/
import "C"

import (
	"sync"
	"unsafe"
)

var keychainMu sync.Mutex

func keychainOperation(id string, key []byte, create bool) error {
	if len(key) != 32 {
		return ErrUnavailable
	}
	name := C.CString(id)
	defer C.free(unsafe.Pointer(name))
	mode := C.int(0)
	if create {
		mode = 1
	}
	keychainMu.Lock()
	status := C.sshmKeychain(name, (*C.uchar)(unsafe.Pointer(&key[0])), mode)
	keychainMu.Unlock()
	if status != C.errSecSuccess {
		return ErrUnavailable
	}
	return nil
}
func readKeychainKey(id string) ([]byte, error) {
	key := make([]byte, 32)
	if err := keychainOperation(id, key, false); err != nil {
		clear(key)
		return nil, err
	}
	return key, nil
}
func addKeychainKey(id string, key []byte) error { return keychainOperation(id, key, true) }
