import { useEffect, useState } from 'react';
import { API } from '../api';
import { decryptSecureShare, deriveSecureShareReaderToken } from '../secureShareCrypto';

function shareDetails() {
  const match = window.location.pathname.match(/^\/secure-share\/([0-9a-f-]{36})\/?$/i);
  return { id: match?.[1] ?? '', key: window.location.hash.slice(1) };
}

export default function SecureShareDownload() {
  const [details] = useState(shareDetails);
  const [status, setStatus] = useState<'ready'|'downloading'|'done'|'error'>('ready');
  const [message, setMessage] = useState('');

  useEffect(() => {
    // The key has already been captured in component memory; remove it from the visible URL.
    if (window.location.hash) window.history.replaceState(null, document.title, window.location.pathname);
  }, []);

  async function download() {
    if (!details.id || !details.key) {
      setStatus('error');
      setMessage('This share link is incomplete. Ask the sender for the full link.');
      return;
    }
    setStatus('downloading');
    setMessage('Downloading and decrypting in this browser…');
    try {
      const readerToken = await deriveSecureShareReaderToken(details.key);
      const ciphertext = await API.downloadSecureShareCiphertext(details.id, readerToken);
      const file = await decryptSecureShare(ciphertext, details.key);
      const objectUrl = URL.createObjectURL(file.blob);
      const anchor = document.createElement('a');
      anchor.href = objectUrl;
      anchor.download = file.filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
      window.history.replaceState(null, document.title, window.location.pathname);
      setStatus('done');
      setMessage('The decrypted file was downloaded to this device.');
    } catch (error) {
      const detail = error as { response?: { status?: number }; message?: string };
      setStatus('error');
      setMessage(detail.response?.status === 404
        ? 'This share link has expired, was revoked, or reached its download limit.'
        : detail.message ?? 'The file could not be downloaded or decrypted.');
    }
  }

  return <main className="min-h-screen bg-slate-950 text-slate-100 grid place-items-center p-6">
    <section className="w-full max-w-lg rounded-xl border border-slate-700 bg-slate-900 p-6 space-y-4">
      <h1 className="text-xl font-semibold">ASE secure file share</h1>
      <p className="text-sm text-slate-300">The encrypted file is decrypted in this browser. The share key is not sent to ASE.</p>
      {message&&<p role="status" className={status==='error'?'text-rose-300':'text-slate-300'}>{message}</p>}
      {status!=='done'&&<button className="rounded bg-indigo-600 px-4 py-2 text-sm disabled:opacity-50" disabled={status==='downloading'} onClick={download}>
        {status==='downloading'?'Please wait…':'Decrypt and download file'}
      </button>}
    </section>
  </main>;
}
