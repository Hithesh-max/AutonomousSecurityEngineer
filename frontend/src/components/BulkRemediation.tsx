import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { API, type Finding } from '../api';
import DiffViewer from './DiffViewer';
import { encryptSecureShare } from '../secureShareCrypto';

function message(error:unknown):string {
  const e=error as {response?:{data?:{detail?:string|{message?:string}}};message?:string};
  const detail=e?.response?.data?.detail;
  return typeof detail==='string' ? detail : detail?.message ?? e?.message ?? 'Request failed';
}
function save(blob:Blob,name:string) {
  const url=URL.createObjectURL(blob);const a=document.createElement('a');
  a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
const button='rounded bg-indigo-600 px-3 py-2 text-sm disabled:opacity-40';
export default function BulkRemediation({findings,onReview,projectId,onRepositoryChange}:{findings:Finding[];onReview:(id:string)=>void;projectId:string;onRepositoryChange:(id:string)=>void}) {
  const repositoryList=useQuery({queryKey:['remediation-repositories',projectId],queryFn:()=>API.getRepositories(projectId)});
  const repos=[...new Set([...(repositoryList.data??[]).map(r=>r.id),...findings.map(f=>f.repository_id).filter((id):id is string=>!!id)])];
  const [repo,setRepo]=useState('');const [consent,setConsent]=useState(false);
  const [reviewed,setReviewed]=useState(false);const [reviewedHashes,setReviewedHashes]=useState<Record<string,string>>({});const [selected,setSelected]=useState<string[]>([]);
  const [diff,setDiff]=useState<{path:string;diff:string}[]>([]);
  const [share,setShare]=useState<{id:string;url:string;expiresAt:string;maxDownloads:number;copied:boolean}|null>(null);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  const client=useQueryClient();
  const inventory=useQuery({queryKey:['remediation-inventory',repo],queryFn:()=>API.getRemediationInventory(repo),enabled:!!repo,refetchInterval:4000});
  const batches=useQuery({queryKey:['remediation-batches',repo],queryFn:()=>API.getRemediationBatches(repo),enabled:!!repo,refetchInterval:3000});
  const batch=batches.data?.[0];const active=!!batch && ['QUEUED','RUNNING','PAUSING'].includes(batch.status);
  const items=inventory.data?.items??[];const proposals=items.filter(i=>i.patch_status==='PATCH_PROPOSED');
  const approved=items.filter(i=>['APPROVED','INCONCLUSIVE','VERIFIED'].includes(i.patch_status??''));
  async function act(fn:()=>Promise<unknown>) {
    setBusy(true);setError('');try{await fn();await client.invalidateQueries({queryKey:['remediation-inventory',repo]});await client.invalidateQueries({queryKey:['remediation-batches',repo]});}
    catch(e){setError(message(e));}finally{setBusy(false);}
  }
  async function approve(all:boolean) {
    const failures:string[]=[];
    for(const i of proposals.filter(i=>all||selected.includes(i.finding_id))) {
      try{if(reviewedHashes[i.patch_id!]!==i.patch_sha256)throw new Error('Proposal changed since review. Review it again.');await API.approvePatch(i.patch_id!,reviewedHashes[i.patch_id!]);}catch(e){failures.push(`${i.title}: ${message(e)}`);}
    }
    setReviewed(false);setSelected([]);
    if(failures.length)throw new Error(failures.join('\n'));
  }
  async function createSecureShare() {
    const filename=`ase-corrected-${repo}.zip`;
    const correctedZip=await API.downloadCorrectedRepository(repo,[]);
    const {ciphertext,keyFragment,readerToken}=await encryptSecureShare(correctedZip,filename);
    const created=await API.createSecureShare(ciphertext,readerToken);
    const url=new URL(`/secure-share/${created.id}`,window.location.origin);
    url.hash=keyFragment;
    let copied=false;
    try { await navigator.clipboard.writeText(url.toString()); copied=true; } catch { /* Link remains available for manual copying. */ }
    setShare({id:created.id,url:url.toString(),expiresAt:created.expires_at,maxDownloads:created.max_downloads,copied});
  }
  if(!repos.length)return null;
  return <section className="rounded-xl border border-indigo-600/40 bg-slate-900 p-5 space-y-4" aria-label="Whole-project remediation">
    <h3 className="text-lg font-bold">Whole-project remediation</h3>
    <p className="text-sm text-slate-300">Analyze findings, review validated proposals, approve changes, and download a corrected project. Original uploads remain unchanged.</p>
    <label>Uploaded repository <select className="ml-2 bg-slate-800 rounded p-2" value={repo} disabled={busy} onChange={e=>{setRepo(e.target.value);onRepositoryChange(e.target.value);setReviewedHashes({});setConsent(false);setDiff([]);setSelected([]);setReviewed(false);setShare(null);setError('');}}>
      <option value="">Select repository</option>{repos.map(id=><option key={id} value={id}>{repositoryList.data?.find(r=>r.id===id)?.name??id}</option>)}
    </select></label>
    {repositoryList.isError&&<p role="alert">{message(repositoryList.error)}</p>}
    {(inventory.isError||batches.isError)&&<p role="alert">{message(inventory.error||batches.error)}</p>}
    {inventory.isLoading&&<p>Loading findings…</p>}
    {inventory.data&&<div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
      {[['All findings',inventory.data.total],['Eligible',inventory.data.eligible],['Manual review',inventory.data.unsupported],['Approved',approved.length]].map(([name,value])=><div key={name} className="rounded bg-slate-800 p-3">{name}: <strong>{value}</strong></div>)}
    </div>}
    {repo&&<label className="flex gap-2 text-sm"><input type="checkbox" checked={consent} onChange={e=>setConsent(e.target.checked)}/>I authorize sending redacted findings and verified source context to the configured external AI provider. Costs and rate limits may apply.</label>}
    <div className="flex flex-wrap gap-2">
      <button className={button} disabled={!repo||!consent||busy||active||!items.length} onClick={()=>act(()=>API.startRemediationBatch(repo,'ANALYZE',consent))}>Analyze all findings</button>
      <button className={button} disabled={!repo||!consent||busy||active||!inventory.data?.eligible} onClick={()=>act(()=>API.startRemediationBatch(repo,'PROPOSE',consent))}>Generate all eligible fixes</button>
      <button className={button} disabled={!active||busy} onClick={()=>act(()=>API.controlRemediationBatch(batch!.id,'pause'))}>Pause</button>
      {batch&&<button className={button} disabled={busy||batch.status==='COMPLETED'} title="Running jobs can resume only after 15 minutes without a checkpoint" onClick={()=>act(()=>API.controlRemediationBatch(batch.id,'resume'))}>Resume saved job</button>}
      <button className={button} disabled={!approved.length||busy} onClick={()=>act(async()=>setDiff((await API.getProjectDiff(repo)).files))}>Review combined approved diff</button>
      <button className={button} disabled={!approved.length||busy||active} onClick={()=>act(async()=>save(await API.downloadCorrectedRepository(repo,[]),`ase-corrected-${repo}.zip`))}>Download corrected project ZIP</button>
      <button className={button} disabled={!approved.length||busy||active} onClick={()=>act(createSecureShare)}>Create encrypted share link</button>
      <button className={button} disabled={!repo||busy} onClick={()=>act(async()=>save(new Blob([JSON.stringify(await API.getRemediationReport(repo),null,2)],{type:'application/json'}),`ase-remediation-${repo}.json`))}>Download audit report</button>
    </div>
    {share&&<div className="rounded border border-slate-700 bg-slate-800/60 p-3 space-y-2 text-sm">
      <p>{share.copied?'Encrypted share link copied.':'Encrypted share link created; copy it below.'} Expires {new Date(share.expiresAt).toLocaleString()} or after {share.maxDownloads} downloads.</p>
      <input className="w-full rounded bg-slate-950 p-2 text-xs" aria-label="Encrypted share link" readOnly value={share.url} onFocus={e=>e.currentTarget.select()}/>
      <button className={button} onClick={async()=>{try{await navigator.clipboard.writeText(share.url);setShare({...share,copied:true});}catch{setError('Clipboard access is unavailable. Select and copy the link above.');}}}>Copy link</button>
      <button className="rounded border border-rose-700 px-3 py-2 text-sm text-rose-300 disabled:opacity-40" disabled={busy} onClick={()=>act(async()=>{await API.revokeSecureShare(share.id);setShare(null);})}>Revoke link</button>
      <p className="text-xs text-amber-300">The decryption key is inside the link. Share the complete link only with its intended recipient.</p>
    </div>}
    {batch&&<div role="status" className="rounded bg-slate-800 p-3 text-sm">
      <p>{batch.mode} · {batch.status} · {batch.processed}/{batch.total} processed</p>
      <progress className="w-full" value={batch.processed} max={Math.max(batch.total,1)}/><p>{batch.message}</p>
      <p className="text-xs text-slate-400">Progress is saved on the server. You may close or refresh this page. Pause takes effect after the current provider request.</p>
      <details><summary>Job results</summary>{batch.items.map(i=><p key={i.finding_id}>{i.title}: {i.status} {i.detail}</p>)}</details>
    </div>}
    {!!diff.length&&<details open><summary>Combined approved changes</summary>{diff.map(f=><article key={f.path}><h4>{f.path}</h4><DiffViewer diff={f.diff}/></article>)}</details>}
    {error&&<p role="alert" className="text-amber-300 whitespace-pre-wrap">{error}</p>}
    {!!proposals.length&&<div className="space-y-2"><label className="flex gap-2 text-sm"><input type="checkbox" checked={reviewed} onChange={e=>{setReviewed(e.target.checked);setReviewedHashes(Object.fromEntries(proposals.map(p=>[p.patch_id!,p.patch_sha256!])));}}/>I have reviewed the exact diffs and approve the selected changes for export. They are not verified security fixes.</label>
      <button className={button} disabled={!reviewed||!selected.length||busy} onClick={()=>act(()=>approve(false))}>Approve selected ({selected.length})</button>{' '}
      <button className={button} disabled={!reviewed||busy} onClick={()=>act(()=>approve(true))}>Approve all validated ({proposals.length})</button>
    </div>}
    {!!items.length&&<div className="max-h-96 overflow-auto space-y-2">{items.map(i=><div key={i.finding_id} className="rounded border border-slate-700 p-3 text-sm">
      {i.patch_status==='PATCH_PROPOSED'&&<input aria-label={`Select ${i.title}`} type="checkbox" className="mr-2" checked={selected.includes(i.finding_id)} onChange={e=>setSelected(s=>e.target.checked?[...s,i.finding_id]:s.filter(id=>id!==i.finding_id))}/>}
      <strong>{i.severity} · {i.title}</strong><p className="text-xs text-slate-400">{i.source_path} · {i.eligible?(i.patch_status??'Eligible'):i.reason} · {i.verification_status}</p>
      <button className="text-indigo-300 underline" onClick={()=>onReview(i.finding_id)}>Review source, diff and approval</button>
    </div>)}</div>}
    <p className="text-xs text-amber-300">Only approved, compatible changes are exported. Unsupported languages and complex fixes require manual review. Syntax checks and ZIP export do not establish that a vulnerability is fixed.</p>
  </section>;
}
