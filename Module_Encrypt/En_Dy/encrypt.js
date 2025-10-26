const crypto = require('crypto');

async function encryptPin(pin, passphrase) {
  const saltSize = 32; // Matches Java
  const ivSize = 12; // Matches Java
  const tagSize = 16; // Auth Tag Size (GCM)
  const keyLength = 32; // 256-bit AES key
  const iterations = 200000; // Increased iterations

  const salt = crypto.randomBytes(saltSize);
  const iv = crypto.randomBytes(ivSize);

  // Derive Key (PBKDF2 with HmacSHA256)
  const key = crypto.pbkdf2Sync(passphrase, salt, iterations, keyLength, 'sha256');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(pin, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // ✅ Order: [SALT (32)] [IV (12)] [CIPHERTEXT] [AUTH_TAG (16)]
  const output = Buffer.concat([salt, iv, encrypted, tag]).toString('base64');

  return output;
}

if (process.argv.length !== 4) {
  console.log('Usage: node encrypt.js <pin> <passphrase>');
  process.exit(1);
}

const pin = process.argv[2];
const passphrase = process.argv[3];

encryptPin(pin, passphrase).then(encryptedPin => {
  console.log('Encrypted PIN:', encryptedPin);
}).catch(err => {
  console.error('Error:', err);
});
