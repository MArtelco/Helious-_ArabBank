const crypto = require('crypto');

function decryptPin(base64Data, passphrase) {
  try {
    const saltSize = 32; // Matches Java
    const ivSize = 12; // Matches Java
    const tagSize = 16; // Auth Tag Size (GCM)
    const keyLength = 32; // 256-bit AES key
    const iterations = 200000; // Increased iterations

    const allBytes = Buffer.from(base64Data, 'base64');

    const salt = allBytes.slice(0, saltSize);
    const iv = allBytes.slice(saltSize, saltSize + ivSize);
    const ciphertext = allBytes.slice(saltSize + ivSize, allBytes.length - tagSize);
    const authTag = allBytes.slice(-tagSize);

    // Derive Key (PBKDF2 with HmacSHA256)
    const key = crypto.pbkdf2Sync(passphrase, salt, iterations, keyLength, 'sha256');

    // Initialize AES-GCM Decryption
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    // Perform decryption
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');

    return decrypted;
  } catch (err) {
    console.error('Error during decryption:', err.message);
    process.exit(1);
  }
}

if (process.argv.length !== 4) {
  console.log('Usage: node decrypt.js <base64_encrypted_data> <passphrase>');
  process.exit(1);
}

const encryptedData = process.argv[2];
const passphrase = process.argv[3];

// Perform decryption
const decryptedPin = decryptPin(encryptedData, passphrase);
console.log('Decrypted PIN:', decryptedPin);
