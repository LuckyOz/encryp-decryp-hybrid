import crypto from 'crypto';

/**
 * Encryption result object
 * @typedef {Object} EncryptRequest
 * @property {string} data - AES encrypted data (Base64)
 * @property {string} aes - RSA encrypted AES key (Base64)
 * @property {string} iv - Initialization vector (Base64)
 */

/**
 * Generates a random AES-256 key
 * @returns {Buffer} 32-byte AES key
 */
function generateAesKey() {
    return crypto.randomBytes(32); // 256 bits
}

/**
 * Generates a random IV for AES-CBC
 * @returns {Buffer} 16-byte IV
 */
function generateIV() {
    return crypto.randomBytes(16); // 128 bits
}

/**
 * Encrypts plaintext using AES-256-CBC
 * @param {string} plaintext - The text to encrypt
 * @param {Buffer} key - AES key
 * @param {Buffer} iv - Initialization vector
 * @returns {string} Base64 encoded ciphertext
 */
function encryptData(plaintext, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

/**
 * Decrypts ciphertext using AES-256-CBC
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {Buffer} key - AES key
 * @param {Buffer} iv - Initialization vector
 * @returns {string} Decrypted plaintext
 */
function decryptData(ciphertext, key, iv) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

/**
 * Encrypts AES key using RSA public key with OAEP-SHA256 padding
 * @param {Buffer} aesKey - AES key to encrypt
 * @param {string} publicKeyBase64 - Base64 encoded PEM public key
 * @returns {string} Base64 encoded encrypted AES key
 */
function encryptAesKey(aesKey, publicKeyBase64) {
    // Decode Base64 to get the PEM key
    const publicKeyPem = Buffer.from(publicKeyBase64, 'base64').toString('utf8');
    
    const encryptedAesKey = crypto.publicEncrypt(
        {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        aesKey
    );
    
    return encryptedAesKey.toString('base64');
}

/**
 * Decrypts AES key using RSA private key with OAEP-SHA256 padding
 * @param {string} encryptedAesKeyBase64 - Base64 encoded encrypted AES key
 * @param {string} privateKeyBase64 - Base64 encoded PEM private key
 * @returns {Buffer} Decrypted AES key
 */
function decryptAesKey(encryptedAesKeyBase64, privateKeyBase64) {
    // Decode Base64 to get the PEM key
    const privateKeyPem = Buffer.from(privateKeyBase64, 'base64').toString('utf8');
    const encryptedAesKey = Buffer.from(encryptedAesKeyBase64, 'base64');
    
    return crypto.privateDecrypt(
        {
            key: privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        encryptedAesKey
    );
}

/**
 * Encrypts data using hybrid encryption (AES-256-CBC + RSA-2048)
 * @param {string} data - Plaintext to encrypt
 * @param {string} publicKey - Base64 encoded RSA public key (PEM format)
 * @returns {EncryptRequest} Encryption result with encrypted data, AES key, and IV
 */
export function encrypt(data, publicKey) {
    // Generate AES & IV keys
    const aesKey = generateAesKey();
    const ivKey = generateIV();
    
    // Encrypt data with AES
    const encryptedData = encryptData(data, aesKey, ivKey);
    
    // Encrypt AES key with RSA
    const encryptedAesKey = encryptAesKey(aesKey, publicKey);
    
    // Return response
    return {
        data: encryptedData,
        aes: encryptedAesKey,
        iv: ivKey.toString('base64')
    };
}

/**
 * Decrypts data using hybrid encryption (AES-256-CBC + RSA-2048)
 * @param {EncryptRequest} request - Encryption result object
 * @param {string} privateKey - Base64 encoded RSA private key (PEM format)
 * @returns {string} Decrypted plaintext
 */
export function decrypt(request, privateKey) {
    // Decrypt AES key using RSA
    const aesKey = decryptAesKey(request.aes, privateKey);
    
    // Decrypt data using AES
    const iv = Buffer.from(request.iv, 'base64');
    return decryptData(request.data, aesKey, iv);
}

export default { encrypt, decrypt };
