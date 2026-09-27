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
    if (request.operation === 'create') {
        const data = $.NSData.alloc.initWithBase64EncodedStringOptions($(request.key), 0);
        if (!data || Number(data.length) !== 32) throw new Error('invalid key');
        query.setObjectForKey(data, cast($.kSecValueData));
        return JSON.stringify({status: $.SecItemAdd(query, Ref())});
    }
    if (request.operation === 'read') {
        query.setObjectForKey(cast($.kCFBooleanTrue), cast($.kSecReturnData));
        query.setObjectForKey(cast($.kSecMatchLimitOne), cast($.kSecMatchLimit));
        const result = Ref();
        const status = $.SecItemCopyMatching(query, result);
        if (status !== 0) return JSON.stringify({status: status});
        const data = cast(result[0]);
        return JSON.stringify({status: status, key: ObjC.unwrap(data.base64EncodedStringWithOptions(0))});
    }
    throw new Error('invalid operation');
}
