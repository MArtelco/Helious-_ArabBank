const crypto = require('crypto');

// **Match your Java constants**:
const SALT_SIZE     = 16;     // 16 bytes
const IV_SIZE       = 12;     // 12 bytes
const TAG_SIZE      = 16;     // 16 bytes (128-bit tag)
const KEY_LENGTH    = 16;     // 16 bytes = 128 bits
const ITERATIONS    = 100_000;
const DIGEST        = 'sha256';

function encryptPin(pin, passphrase) {
  const salt = crypto.randomBytes(SALT_SIZE);
  const iv   = crypto.randomBytes(IV_SIZE);

  // Derive key exactly as Java: PBKDF2WithHmacSHA256, 100k iterations, 256-bit
  const key = crypto.pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LENGTH, DIGEST);

  const cipher = crypto.createCipheriv('aes-128-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(pin, 'utf8'),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();

  // [salt || iv || ciphertext || authTag]
  const output = Buffer.concat([salt, iv, ciphertext, authTag]);
  return output.toString('base64');
}

function decryptPin(encryptedBase64, passphrase) {
  const data = Buffer.from(encryptedBase64, 'base64');

  // Slice out salt, iv, tag, and ciphertext
  const salt       = data.slice(0, SALT_SIZE);
  const iv         = data.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
  const authTag    = data.slice(data.length - TAG_SIZE);
  const ciphertext = data.slice(SALT_SIZE + IV_SIZE, data.length - TAG_SIZE);

  // Re-derive key
  const key = crypto.pbkdf2Sync(passphrase, salt, ITERATIONS, KEY_LENGTH, DIGEST);

  const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

module.exports = { encryptPin, decryptPin };
