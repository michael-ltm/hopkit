ObjC.import('Foundation');
ObjC.import('Security');
function run() {
    const raw = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
    const request = JSON.parse(ObjC.unwrap($.NSString.alloc.initWithDataEncoding(raw, $.NSUTF8StringEncoding)));
    if (!/^[0-9a-f]{32}$/.test(request.ref)) throw new Error('invalid reference');
    if ($.SecKeychainSetUserInteractionAllowed(false) !== 0) throw new Error('unavailable');
    const cast = ObjC.castRefToObject;
    const query = $.NSMutableDictionary.dictionary;
    query.setObjectForKey(cast($.kSecClassGenericPassword), cast($.kSecClass));
    query.setObjectForKey($('sshm.device'), cast($.kSecAttrService));
    query.setObjectForKey($(request.ref), cast($.kSecAttrAccount));
    query.setObjectForKey(cast($.kSecUseAuthenticationUIFail), cast($.kSecUseAuthenticationUI));
    return String($.SecItemDelete(query));
}
