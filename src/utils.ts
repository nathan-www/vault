export function arrayBufferToBase64(buffer: ArrayBuffer) {
  let byteStr = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    byteStr += String.fromCharCode(bytes[i]);
  }
  return btoa(byteStr);
}

export function base64ToArrayBuffer(stringBase64: string) {
  const byteStr = atob(stringBase64);
  const bytes = new Uint8Array(byteStr.length);
  for (let i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i);
  }
  return bytes.buffer;
}

export function removePEMHeadersFromString(pem: string) {
  const lines = pem.split("\n");
  let base64 = "";
  for (let i = 0; i < lines.length; i++) {
    if (
      lines[i].trim().length > 0 &&
      !lines[i].includes("-")
    ) {
      base64 += lines[i].trim();
    }
  }
  return base64;
}
