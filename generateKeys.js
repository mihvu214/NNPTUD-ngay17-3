const crypto = require('crypto');
const fs = require('fs');

// Tạo RSA key pair (2048 bytes)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

// Export private key
const privateKeyPem = privateKey.export({
  type: 'pkcs8',
  format: 'pem'
});

// Export public key
const publicKeyPem = publicKey.export({
  type: 'spki',
  format: 'pem'
});

// Lưu vào file
fs.writeFileSync('./keys/private.pem', privateKeyPem);
fs.writeFileSync('./keys/public.pem', publicKeyPem);

console.log('✅ Generated RSA keys:');
console.log('- Private key: ./keys/private.pem');
console.log('- Public key: ./keys/public.pem');
