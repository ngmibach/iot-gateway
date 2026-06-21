// ============================================================
// Replacement code for the "Decrypt Parameters" function node
// (consider renaming the node to "Decrypt Message")
//
// This version decrypts the ENTIRE original JSON message
// (new encryption method).
// ============================================================

function fernetDecrypt(tokenB64url, keyB64url) {
    const keyBuf = Buffer.from(keyB64url, 'base64');
    if (keyBuf.length !== 32) {
        throw new Error('Invalid key length: ' + keyBuf.length + ' (expected 32)');
    }
    const signingKey = keyBuf.slice(0, 16);
    const encryptionKey = keyBuf.slice(16, 32);

    const tokenBuf = Buffer.from(tokenB64url, 'base64');
    if (tokenBuf.length < 57) {
        throw new Error('Token too short: ' + tokenBuf.length);
    }

    const version = tokenBuf[0];
    if (version !== 0x80) {
        throw new Error('Unsupported Fernet version: 0x' + version.toString(16));
    }

    // Verify HMAC-SHA256
    const hmacData = tokenBuf.slice(0, tokenBuf.length - 32);
    const hmacGiven = tokenBuf.slice(tokenBuf.length - 32);
    const hmacCalc = crypto.createHmac('sha256', signingKey).update(hmacData).digest();
    if (!crypto.timingSafeEqual(hmacGiven, hmacCalc)) {
        throw new Error('HMAC verification failed — wrong key or corrupted data');
    }

    // Decrypt AES-128-CBC
    const iv = tokenBuf.slice(9, 25);
    const ciphertext = tokenBuf.slice(25, tokenBuf.length - 32);
    const decipher = crypto.createDecipheriv('aes-128-cbc', encryptionKey, iv);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

    return JSON.parse(decrypted.toString('utf8'));
}

try {
    let wrapper = (typeof msg.payload === 'string')
        ? JSON.parse(msg.payload)
        : msg.payload;

    const key = wrapper.key;
    const encrypted = wrapper.encrypted;

    if (!key || !encrypted) {
        node.warn('Missing "key" or "encrypted" — forwarding as-is');
        msg.payload = JSON.stringify(wrapper);
        return msg;
    }

    // Decrypt the entire original message
    const decrypted = fernetDecrypt(encrypted, key);

    // decrypted is the full original JSON (with clear parameters, etc.)
    msg.payload = JSON.stringify(decrypted);
    return msg;

} catch (e) {
    node.warn('Decryption failed: ' + e.message);
    return null;   // or return msg; to forward the wrapper
}