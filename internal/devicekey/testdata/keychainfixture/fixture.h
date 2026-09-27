#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <string.h>

// Test-only fixture: inspect exactly the random sshm.device item created by
// the native test. Never enumerate items, change ACLs, or return secret data.
static OSStatus sshmKeychainFixture(const char *operation, const char *ref) {
    if (strlen(ref) != 32 || strspn(ref, "0123456789abcdef") != 32) return errSecParam;
    Boolean previous = true;
    OSStatus status = SecKeychainGetUserInteractionAllowed(&previous);
    if (status != errSecSuccess) return status;
    status = SecKeychainSetUserInteractionAllowed(false);
    if (status != errSecSuccess) return status;
    CFStringRef account = CFStringCreateWithCString(NULL, ref, kCFStringEncodingUTF8);
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query, kSecAttrService, CFSTR("sshm.device"));
    CFDictionarySetValue(query, kSecAttrAccount, account);
    status = errSecParam;
    if (!strcmp(operation, "policy")) {
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);
        CFTypeRef item = NULL;
        status = SecItemCopyMatching(query, &item);
        SecAccessRef access = NULL;
        if (status == errSecSuccess) status = SecKeychainItemCopyAccess((SecKeychainItemRef)item, &access);
        if (status == errSecSuccess) {
            CFArrayRef owners = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationChangeACL);
            CFArrayRef decrypts = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
            CFArrayRef partitions = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationPartitionID);
            printf("partition_rules=%ld\n", partitions ? CFArrayGetCount(partitions) : 0L);
            if (partitions) CFRelease(partitions);
            int ownerPreserved = 0, decryptOnly = 0;
            if (owners && CFArrayGetCount(owners) == 1) {
                CFArrayRef apps = NULL;
                CFStringRef description = NULL;
                SecKeychainPromptSelector prompt = 0;
                if (SecACLCopyContents((SecACLRef)CFArrayGetValueAtIndex(owners, 0), &apps, &description, &prompt) == errSecSuccess)
                    ownerPreserved = apps && CFArrayGetCount(apps) == 0;
                if (apps) CFRelease(apps);
                if (description) CFRelease(description);
            }
            if (decrypts) for (CFIndex i = 0; i < CFArrayGetCount(decrypts); i++) {
                SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(decrypts, i);
                CFArrayRef apps = NULL;
                CFStringRef description = NULL;
                SecKeychainPromptSelector prompt = 0;
                CFArrayRef authorizations = SecACLCopyAuthorizations(acl);
                if (SecACLCopyContents(acl, &apps, &description, &prompt) == errSecSuccess && !apps && prompt == 0 && authorizations && CFArrayGetCount(authorizations) == 1 && CFEqual(CFArrayGetValueAtIndex(authorizations, 0), kSecACLAuthorizationDecrypt))
                    decryptOnly = 1;
                if (apps) CFRelease(apps);
                if (description) CFRelease(description);
                if (authorizations) CFRelease(authorizations);
            }
            printf("owner_preserved=%d broad_decrypt_rule=%d\n", ownerPreserved, decryptOnly);
            if (!ownerPreserved || decryptOnly) status = errSecAuthFailed;
            if (owners) CFRelease(owners);
            if (decrypts) CFRelease(decrypts);
        }
        if (access) CFRelease(access);
        if (item) CFRelease(item);
    }
    CFRelease(query);
    CFRelease(account);
    printf("status=%d\n", (int)status);
    fflush(stdout);
    SecKeychainSetUserInteractionAllowed(previous);
    return status;
}
