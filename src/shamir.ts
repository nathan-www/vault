import * as ShamirSecretSharing from "npm:shamir-secret-sharing";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils.ts";

export async function shamirSplitSecret(
  secret: string,
  numOfShares: number,
  threshold: number,
) {
  const encoder = new TextEncoder();
  const secretEncoded = encoder.encode(secret.normalize("NFKC"));

  const shares = await ShamirSecretSharing.split(
    secretEncoded,
    numOfShares,
    threshold,
  );

  return shares.map((share) => arrayBufferToBase64(share.buffer));
}

export async function shamirCombineShares(shares: string[]) {
  const sharesUint8Arrays = shares.map((share) =>
    new Uint8Array(base64ToArrayBuffer(share))
  );
  const secret = await ShamirSecretSharing.combine(sharesUint8Arrays);

  const decoder = new TextDecoder();
  return decoder.decode(secret);
}
