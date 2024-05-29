import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils.ts";

const crypto = window.crypto.subtle;

export async function genAESKey() {
  return await crypto.generateKey(
    {
      name: "AES-GCM",
      length: 256, // 256-bit key length (highest security available)
    },
    true, // extractable - true, makes it possible to export key
    ["encrypt", "decrypt"],
  );
}

export async function exportAESKey(key: CryptoKey) {
  const keyData = await crypto.exportKey("raw", key);
  const keyDataBase64 = arrayBufferToBase64(keyData);
  return keyDataBase64;
}

export async function importAESKeyBase64(keyBase64: string) {
  const keyDataArrayBuffer = base64ToArrayBuffer(keyBase64);
  return await crypto.importKey(
    "raw",
    keyDataArrayBuffer,
    "AES-GCM",
    true,
    ["encrypt", "decrypt"],
  );
}

// Encrypts cleartext string with AES key
// Outputs a base64-encoded JSON string containing iv and ciphertext (both base64 encoded themselves)
// This string can be directly passed back into the AESDecrypt function later
export async function AESEncrypt(key: CryptoKey, cleartext: string) {
  const encoder = new TextEncoder();
  const cleartextEncoded = encoder.encode(cleartext);

  // iv must never be re-used
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    cleartextEncoded,
  );

  const encryptedData = {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer),
  };

  return btoa(JSON.stringify(encryptedData));
}

// Decrypts encryptedData (a base64-encoded JSON string containing iv and ciphertext, outputted by AESEncrypt)
export async function AESDecrypt(key: CryptoKey, encryptedData: string) {
  const encrytedDataObj = JSON.parse(atob(encryptedData));
  const iv = encrytedDataObj["iv"] as string;
  const ciphertext = encrytedDataObj["ciphertext"] as string;

  const ciphertextArrayBuffer = base64ToArrayBuffer(ciphertext);
  const ivUint8Array = new Uint8Array(base64ToArrayBuffer(iv));

  const cleartext = await crypto.decrypt(
    {
      name: "AES-GCM",
      iv: ivUint8Array,
    },
    key,
    ciphertextArrayBuffer,
  );

  const decoder = new TextDecoder();
  return decoder.decode(cleartext); 
}
