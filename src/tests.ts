import { assertNotEquals } from "https://deno.land/std@0.224.0/assert/assert_not_equals.ts";
import {
  AESDecrypt,
  AESEncrypt,
  exportAESKey,
  genAESKey,
  importAESKeyBase64,
} from "./aes.ts";
import { hybridDecrypt } from "./main.ts";
import { decryptVaultData } from "./main.ts";
import { createVault } from "./main.ts";
import { hybridEncrypt } from "./main.ts";

import {
  exportRSAPrivateKeyAsPEM,
  exportRSAPublicKeyAsPEM,
  genRSAKeyPair,
  importRSAPrivateKeyPEM,
  importRSAPublicKeyPEM,
  RSADecrypt,
  RSAEncrypt,
} from "./rsa.ts";

import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

Deno.test("AES encrypt and decrypt", async () => {
  // Create new AES key
  const AESKey = await genAESKey();

  // Export key
  const AESKeyExported = await exportAESKey(AESKey);

  // Import key
  const AESKeyImported = await importAESKeyBase64(AESKeyExported);

  // Encrypt data
  const cleartext = "Hello world, this is an AES encryption test!";
  const ciphertext = await AESEncrypt(AESKeyImported, cleartext);

  // Decrypt data
  const decrypted = await AESDecrypt(AESKeyImported, ciphertext);

  // Check data
  assertEquals(decrypted, cleartext);
});

Deno.test("RSA encrypt and decrypt", async () => {
  // Create new RSA keypair
  const RSAKeyPair = await genRSAKeyPair();

  // Export, then import public key
  const RSAPublicKeyExported = await exportRSAPublicKeyAsPEM(
    RSAKeyPair.publicKey,
  );
  const RSAPublicKeyImported = await importRSAPublicKeyPEM(
    RSAPublicKeyExported,
  );

  // Export, then import private key
  const RSAPrivateKeyExported = await exportRSAPrivateKeyAsPEM(
    RSAKeyPair.privateKey,
  );
  const RSAPrivateKeyImported = await importRSAPrivateKeyPEM(
    RSAPrivateKeyExported,
  );

  // Encrypt data
  const cleartext = "Hello world, this is an RSA encryption test!";
  const ciphertext = await RSAEncrypt(RSAPublicKeyImported, cleartext);

  // Decrypt data
  const decrypted = await RSADecrypt(RSAPrivateKeyImported, ciphertext);

  // Check data
  assertEquals(decrypted, cleartext);
});

Deno.test("Hybrid AES/RSA encrypt and decrypt", async () => {
  // Create new RSA keypair
  const RSAKeyPair = await genRSAKeyPair();

  // Export RSA public key
  const RSAPublicKeyExported = await exportRSAPublicKeyAsPEM(
    RSAKeyPair.publicKey,
  );

  // Export RSA private key
  const RSAPrivateKeyExported = await exportRSAPrivateKeyAsPEM(
    RSAKeyPair.privateKey,
  );

  // Encrypt data
  const cleartext = "Hello world, this is a hybrid AES/RSA encryption test!";
  const encrypted = await hybridEncrypt(RSAPublicKeyExported, cleartext);

  // Decrypt data
  const decrypted = await hybridDecrypt(RSAPrivateKeyExported, encrypted);

  // Check data
  assertEquals(cleartext, decrypted);
});

Deno.test("End-to-end vault creation, encrypt and decrypt", async () => {
  // Create new vault, numOfShares=5, threshold=3
  const vault = await createVault(5, 3);

  // Encrypt new data
  const cleartext = "Hello world, this is a vault test!";
  const vaultEncryptedData = await hybridEncrypt(
    vault.RSAPublicKeyPEM,
    cleartext,
  );

  // Decrypt data with 3 shares
  const privateKeyShares = vault.RSAPrivateKeyShares.slice(0, 3);
  const decrypted = await decryptVaultData(
    privateKeyShares,
    vaultEncryptedData,
  );

  // Check data
  assertEquals(cleartext, decrypted);
});

Deno.test("Decrypt vault with insufficient number of shares throws error", async () => {
  // Create new vault, numOfShares=5, threshold=3
  const vault = await createVault(5, 3);

  // Encrypt new data
  const cleartext = "Hello world, this is a vault test!";
  const vaultEncryptedData = await hybridEncrypt(
    vault.RSAPublicKeyPEM,
    cleartext,
  );

  // Try and decrypt with 2 shares
  const privateKeyShares = vault.RSAPrivateKeyShares.slice(0, 2);
  let error = null;

  try {
    await decryptVaultData(
      privateKeyShares,
      vaultEncryptedData,
    );
  } catch (e) {
    error = e;
  }

  assertNotEquals(error, null);
});
