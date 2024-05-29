import { AESEncrypt, exportAESKey, genAESKey } from "./aes.ts";
import {
  exportRSAPublicKeyAsPEM,
  genRSAKeyPair,
  importRSAPublicKeyPEM,
  RSAEncrypt,
} from "./rsa.ts";
import { importRSAPrivateKeyPEM } from "./rsa.ts";
import { RSADecrypt } from "./rsa.ts";
import { importAESKeyBase64 } from "./aes.ts";
import { AESDecrypt } from "./aes.ts";
import { exportRSAPrivateKeyAsPEM } from "./rsa.ts";
import { shamirSplitSecret } from "./shamir.ts";
import { shamirCombineShares } from "./shamir.ts";
import { removePEMHeadersFromString } from "./utils.ts";

// Encrypt data using hybrid RSA and AES
// 1. A new 256-bit AES key is generated
// 2. The data is encrypted with this AES key
// 3. A copy of the AES key is encrypted with the provided RSA public key
// 4. Both the encrypted data and encrypted key is returned in a base64-encoded JSON string
export async function hybridEncrypt(
  rsaPublicKeyPEM: string,
  cleartext: string,
) {
  // Decode RSA public key PEM
  const RSAPublicKey = await importRSAPublicKeyPEM(rsaPublicKeyPEM);

  // Generate a new random AES key to encrypt the data
  const AESKey = await genAESKey();

  // Encrypt the cleartext data with the AES key
  const encryptedData = await AESEncrypt(AESKey, cleartext);

  // Encrypt the AES key with the RSA public key
  const AESKeyExported = await exportAESKey(AESKey);
  const encryptedKey = await RSAEncrypt(RSAPublicKey, AESKeyExported);

  return btoa(JSON.stringify({
    encryptedData,
    encryptedKey,
  }));
}

// Decrypts the encryptedDataBundle returned from hybridEncrypt function, using RSA private key
export async function hybridDecrypt(
  rsaPrivateKeyPEM: string,
  encryptedDataBundle: string,
) {
  // Decode RSA private key PEM
  const RSAPrivateKey = await importRSAPrivateKeyPEM(rsaPrivateKeyPEM);

  // Extract data from encryptedDataBundle
  const encryptedDataBundleObj = JSON.parse(atob(encryptedDataBundle));
  const encryptedData = encryptedDataBundleObj["encryptedData"] as string;
  const encryptedKey = encryptedDataBundleObj["encryptedKey"] as string;

  // Decrypt encryptedKey to extract AES key
  const AESKeyBase64 = await RSADecrypt(RSAPrivateKey, encryptedKey);
  const AESKey = await importAESKeyBase64(AESKeyBase64);

  // Decrypt the encryptedData using AES key
  const cleartext = await AESDecrypt(AESKey, encryptedData);

  return cleartext;
}

// Create a new vault
// Returns an RSA private key split into shares (Shamir's Secret Sharing), and the corresponding RSA public key in PEM format
export async function createVault(numOfShares: number, threshold: number) {
  // Create RSA keypair for the vault
  const RSAKeyPair = await genRSAKeyPair();

  // Split RSA private key into shares
  const RSAPrivateKeyPEM = await exportRSAPrivateKeyAsPEM(
    RSAKeyPair.privateKey,
  );
  const RSAPrivateKeyShares = await shamirSplitSecret(
    RSAPrivateKeyPEM,
    numOfShares,
    threshold,
  );

  // Export RSA public key to PEM
  const RSAPublicKeyPEM = await exportRSAPublicKeyAsPEM(RSAKeyPair.publicKey);

  return {
    RSAPrivateKeyShares,
    RSAPublicKeyPEM,
  };
}

// Decrypts data from the vault, using shares of the vault private RSA key
export async function decryptVaultData(
  shares: string[],
  encryptedData: string,
) {
  // Decode shares
  const sharesDecoded = shares.map((share) =>
    removePEMHeadersFromString(share)
  );

  // Decode encrypted data
  const encryptedDataDecoded = removePEMHeadersFromString(encryptedData);

  // Recombine shares with Shamir's Secret Sharing algorithm to retrieve RSA Private Key PEM
  const RSAPrivateKeyPEM = await shamirCombineShares(sharesDecoded);

  // Decrypt the data
  const cleartext = await hybridDecrypt(RSAPrivateKeyPEM, encryptedDataDecoded);

  return cleartext;
}
