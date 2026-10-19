const IV_LENGTH = 12;
const TAG_LENGTH_BYTES = 16;
const NAME_LENGTH_PREFIX_BYTES = 4;

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Share link has an invalid decryption key.');
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function encryptSecureShare(file: Blob, filename: string): Promise<{ ciphertext: Blob; keyFragment: string; readerToken: string }> {
  if (!globalThis.crypto?.subtle) throw new Error('Secure sharing requires HTTPS or localhost with Web Crypto support.');
  const safeName = filename.split(/[\\/]/).pop()?.replace(/[\u0000-\u001f<>:"|?*]/g, '_') || 'ase-corrected.zip';
  const name = new TextEncoder().encode(safeName);
  if (name.length > 2048) throw new Error('File name is too long for secure sharing.');
  const data = new Uint8Array(await file.arrayBuffer());
  const packed = new Uint8Array(NAME_LENGTH_PREFIX_BYTES + name.length + data.length);
  new DataView(packed.buffer).setUint32(0, name.length, false);
  packed.set(name, NAME_LENGTH_PREFIX_BYTES);
  packed.set(data, NAME_LENGTH_PREFIX_BYTES + name.length);

  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, packed));
  const envelope = new Uint8Array(IV_LENGTH + encrypted.length);
  envelope.set(iv);
  envelope.set(encrypted, IV_LENGTH);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  const domain = new TextEncoder().encode('ASE secure share reader token v1\0');
  const tokenInput = new Uint8Array(domain.length + rawKey.length);
  tokenInput.set(domain);
  tokenInput.set(rawKey, domain.length);
  const readerToken = encodeBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', tokenInput)));
  return { ciphertext: new Blob([envelope], { type: 'application/octet-stream' }), keyFragment: encodeBase64Url(rawKey), readerToken };
}

export async function deriveSecureShareReaderToken(keyFragment: string): Promise<string> {
  const rawKey = decodeBase64Url(keyFragment);
  if (rawKey.length !== 32) throw new Error('Share link has an invalid decryption key.');
  const domain = new TextEncoder().encode('ASE secure share reader token v1\0');
  const tokenInput = new Uint8Array(domain.length + rawKey.length);
  tokenInput.set(domain);
  tokenInput.set(rawKey, domain.length);
  return encodeBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', tokenInput)));
}

export async function decryptSecureShare(envelope: ArrayBuffer, keyFragment: string): Promise<{ blob: Blob; filename: string }> {
  if (!globalThis.crypto?.subtle) throw new Error('This browser does not support Web Crypto. Open the link over HTTPS or localhost.');
  const bytes = new Uint8Array(envelope);
  if (bytes.length < IV_LENGTH + TAG_LENGTH_BYTES + NAME_LENGTH_PREFIX_BYTES) throw new Error('The encrypted file is incomplete.');
  const rawKey = decodeBase64Url(keyFragment);
  if (rawKey.length !== 32) throw new Error('Share link has an invalid decryption key.');
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const iv = bytes.slice(0, IV_LENGTH);
  let packed: ArrayBuffer;
  try {
    packed = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, bytes.slice(IV_LENGTH));
  } catch {
    throw new Error('Decryption failed. The link may be incomplete or the encrypted file may have been changed.');
  }
  const plaintext = new Uint8Array(packed);
  if (plaintext.length < NAME_LENGTH_PREFIX_BYTES) throw new Error('Decrypted file metadata is invalid.');
  const nameLength = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength).getUint32(0, false);
  if (nameLength < 1 || nameLength > 2048 || NAME_LENGTH_PREFIX_BYTES + nameLength > plaintext.length) {
    throw new Error('Decrypted file name is invalid.');
  }
  const decodedName = new TextDecoder('utf-8', { fatal: true }).decode(plaintext.slice(NAME_LENGTH_PREFIX_BYTES, NAME_LENGTH_PREFIX_BYTES + nameLength));
  const filename = decodedName.split(/[\\/]/).pop()?.replace(/[\u0000-\u001f<>:"|?*]/g, '_') || 'ase-corrected.zip';
  const data = plaintext.slice(NAME_LENGTH_PREFIX_BYTES + nameLength);
  return { blob: new Blob([data], { type: 'application/zip' }), filename };
}
