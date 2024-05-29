import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  removePEMHeadersFromString,
} from "./utils.ts";

const crypto = window.crypto.subtle;

export async function genRSAKeyPair() {
  return await crypto.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096, // 4096-bit modulus
      publicExponent: new Uint8Array([1, 0, 1]), // Public exponent 65537 (recommended)
      hash: "SHA-256",
    },
    true, // extractable - true (makes it possible to export key)
    ["encrypt", "decrypt"],
  );
}

function base64ToPEM(str: string, type: "PUBLIC" | "PRIVATE") {
  let finalString = `-----BEGIN ${type} KEY-----\n`;

  while (str.length > 0) {
    finalString += str.substring(0, 64) + "\n";
    str = str.substring(64);
  }

  finalString = finalString + `-----END ${type} KEY-----`;

  return finalString;
}

export async function exportRSAPublicKeyAsPEM(publicKey: CryptoKey) {
  const keyData = await crypto.exportKey("spki", publicKey);
  const keyDataBase64 = arrayBufferToBase64(keyData);
  const keyDataPEM = base64ToPEM(keyDataBase64, "PUBLIC");
  return keyDataPEM;
}

export async function exportRSAPrivateKeyAsPEM(privateKey: CryptoKey) {
  const keyData = await crypto.exportKey("pkcs8", privateKey);
  const keyDataBase64 = arrayBufferToBase64(keyData);
  const keyDataPEM = base64ToPEM(keyDataBase64, "PRIVATE");
  return keyDataPEM;
}

export async function importRSAPrivateKeyPEM(privateKeyPEM: string) {
  const keyDataBase64 = removePEMHeadersFromString(privateKeyPEM);
  const keyDataArrayBuffer = base64ToArrayBuffer(keyDataBase64);
  const key = await crypto.importKey(
    "pkcs8",
    keyDataArrayBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"],
  );
  return key;
}

export async function importRSAPublicKeyPEM(publicKeyPEM: string) {
  const keyDataBase64 = removePEMHeadersFromString(publicKeyPEM);
  const keyDataArrayBuffer = base64ToArrayBuffer(keyDataBase64);
  const key = await crypto.importKey(
    "spki",
    keyDataArrayBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["encrypt"],
  );
  return key;
}

export async function RSAEncrypt(publicKey: CryptoKey, cleartext: string) {
  const encoder = new TextEncoder();
  const cleartextEncoded = encoder.encode(cleartext);

  const ciphertext = await crypto.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    cleartextEncoded,
  );

  return arrayBufferToBase64(ciphertext);
}

export async function RSADecrypt(
  privateKey: CryptoKey,
  ciphertextBase64: string,
) {
  const ciphertextArrayBuffer = base64ToArrayBuffer(ciphertextBase64);

  const cleartext = await crypto.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    ciphertextArrayBuffer,
  );

  const decoder = new TextDecoder();
  return decoder.decode(cleartext);
}
