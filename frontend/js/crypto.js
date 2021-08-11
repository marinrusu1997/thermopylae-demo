function assertPemFormat(value) {
    if (!value.startsWith('-----BEGIN RSA PRIVATE KEY-----\n')) {
        throw new Error('Private key is not in PEM format. It needs to begin with \'-----BEGIN RSA PRIVATE KEY-----\', followed by a new line.');
    }

    if (!value.endsWith('\n-----END RSA PRIVATE KEY-----')) {
        throw new Error('Private key is not in PEM format. It needs to end with \'-----END RSA PRIVATE KEY-----\' on last line.');
    }
}

const CRYPTO = {
    /**
     * @param {string}  privateKey
     * @param {string}  ciphertext
     * @returns {string}
     */
   privateDecrypt(privateKey, ciphertext) {
       assertPemFormat(privateKey);

       const forgePrivateKey = forge.pki.privateKeyFromPem(privateKey);
       return forgePrivateKey.decrypt(forge.util.decode64(ciphertext), 'RSA-OAEP', {
           md: forge.md.sha256.create()
       });
    }
}
Object.freeze(CRYPTO);

export { CRYPTO };
