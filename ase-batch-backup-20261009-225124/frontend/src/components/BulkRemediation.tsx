import { useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { API, type Finding } from '../api';

type Result = {id:string; title:string; status:'PROPOSED'|'SKIPPED'|'FAILED'|'APPROVED'; detail:string};

function safeMessage(error: unknown): string {
  if (error && typeof error === 'object' && 'response' in error) {
    const response = (error as {response?:{status?:number;data?:{detail?:string|{code?:string;message?:string}}}}).response;
    const detail = response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail === 'object') return `${detail.code ?? 'ERROR'}: ${detail.message ?? 'Request failed'}`;
    return `HTTP ${response?.status ?? 'error'}`;
  }
  return error instanceof Error ? error.message : 'Request failed';
}

export default function BulkRemediation({findings, onReview}: {findings:Finding[]; onReview:(id:string)=>void}) {
  const repositories = [...new Set(findings.map(f=>f.repository_id).filter((v):v is string=>Boolean(v)))];
  const [repo,setRepo] = useState('');
  const [consent,setConsent] = useState(false);
  const [approvalConsent,setApprovalConsent] = useState(false);
  const [running,setRunning] = useState(false);
  const [operation,setOperation] = useState('');
  const [progress,setProgress] = useState(0);
  const [total,setTotal] = useState(0);
  const [results,setResults] = useState<Result[]>([]);
  const [error,setError] = useState('');
  const [exporting,setExporting] = useState(false);
  const cancelRef = useRef(false);
  const client = useQueryClient();
  const inventory = useQuery({queryKey:['remediation-inventory',repo],queryFn:()=>API.getRemediationInventory(repo),enabled:!!repo,staleTime:0});
  const items = inventory.data?.items ?? [];
  const eligible = items.filter(i=>i.eligible);
  const proposals = items.filter(i=>i.patch_status === 'PATCH_PROPOSED' && i.patch_id && i.patch_sha256);
  const approved = items.filter(i=>['APPROVED','INCONCLUSIVE','VERIFIED'].includes(i.patch_status ?? ''));

  const run = async () => {
    if (!repo || !consent || running || inventory.isPending) return;
    cancelRef.current=false;setRunning(true);setOperation('Generating proposals');setError('');setResults([]);
    setProgress(0);setTotal(eligible.length);
    const outcomes:Result[]=[];
    for (const item of eligible) {
      if (cancelRef.current) {setError('Paused by user. Click again to resume from saved proposals.');break;}
      try {
        const summary=await API.getRemediation(item.finding_id);
        const current=summary.patches.find(p=>['PATCH_PROPOSED','APPROVED','INCONCLUSIVE','VERIFIED'].includes(p.status));
        if (current) {
          outcomes.push({id:item.finding_id,title:item.title,status:'SKIPPED',detail:'Existing proposal preserved; review or approve it.'});
        } else {
          const analysis=summary.analyses.find(a=>a.status==='COMPLETED') ?? await API.analyzeFinding(item.finding_id,true);
          await API.generatePatch(item.finding_id,analysis.id,true);
          outcomes.push({id:item.finding_id,title:item.title,status:'PROPOSED',detail:'Patch generated and validated. Not applied or security-verified.'});
        }
      } catch(e) {
        const detail=safeMessage(e);
        outcomes.push({id:item.finding_id,title:item.title,status:'FAILED',detail});
        if (/RATE_LIMIT|429|quota/i.test(detail)) {
          setError('Provider quota/rate limit reached. Stopped to avoid repeated requests; resume when quota is available.');
          setResults([...outcomes]);setProgress(outcomes.length);break;
        }
      }
      setResults([...outcomes]);setProgress(outcomes.length);
    }
    await client.invalidateQueries({queryKey:['remediation-inventory',repo]});
    setRunning(false);setOperation('');
  };

  const approveAll = async () => {
    if (!repo || !approvalConsent || running || !proposals.length) return;
    cancelRef.current=false;setRunning(true);setOperation('Approving reviewed proposals');setError('');setResults([]);
    setProgress(0);setTotal(proposals.length);
    const outcomes:Result[]=[];
    for (const item of proposals) {
      if(cancelRef.current) {setError('Approval paused. Existing approvals are preserved.');break;}
      try {
        await API.approvePatch(item.patch_id!,item.patch_sha256!);
        outcomes.push({id:item.finding_id,title:item.title,status:'APPROVED',detail:'Approved for corrected-project export; not security-verified.'});
      } catch(e) {
        outcomes.push({id:item.finding_id,title:item.title,status:'FAILED',detail:safeMessage(e)});
      }
      setResults([...outcomes]);setProgress(outcomes.length);
    }
    await client.invalidateQueries({queryKey:['remediation-inventory',repo]});
    setApprovalConsent(false);setRunning(false);setOperation('');
  };

  const download = async () => {
    if(!repo || exporting || running) return;
    setExporting(true);setError('');
    try {
      const blob=await API.downloadCorrectedRepository(repo,[]);
      const url=URL.createObjectURL(blob);
      const anchor=document.createElement('a');anchor.href=url;anchor.download=`ase-corrected-${repo}.zip`;
      document.body.appendChild(anchor);anchor.click();anchor.remove();
      setTimeout(()=>URL.revokeObjectURL(url),1000);
    } catch(e) {setError(safeMessage(e));}
    finally {setExporting(false);}
  };

  const downloadReport = () => {
    if(!inventory.data) return;
    const report={generated_at:new Date().toISOString(),repository_id:repo,scan_id:inventory.data.scan_id,
      note:'AI proposals are not proof of remediation. Unapproved and unsupported findings remain unresolved.',
      summary:{total:inventory.data.total,eligible:inventory.data.eligible,unsupported:inventory.data.unsupported,approved:inventory.data.approved},
      findings:items,latest_attempt:results};
    const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));
    const anchor=document.createElement('a');anchor.href=url;anchor.download=`ase-remediation-report-${repo}.json`;
    document.body.appendChild(anchor);anchor.click();anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  };

  if(!repositories.length) return null;
  return <section className="rounded-xl border border-indigo-600/40 bg-slate-900 p-5 space-y-4" aria-label="Project-wide remediation">
    <h3 className="text-lg font-bold">Whole-project AI remediation</h3>
    <p className="text-sm text-slate-300">Inventory every finding from the latest repository scan, propose fixes for all safely mapped source findings, review/approve proposals, then export one corrected project ZIP. Unsupported findings are explicitly reported; no original files are modified.</p>
    <label className="block text-sm">Uploaded repository <select className="ml-2 rounded bg-slate-800 border border-slate-600 p-2" value={repo} disabled={running} onChange={e=>{setRepo(e.target.value);setResults([]);setError('');setApprovalConsent(false);}}>
      <option value="">Select repository</option>{repositories.map(id=><option key={id} value={id}>{id}</option>)}
    </select></label>
    {inventory.isLoading && <p>Loading complete finding inventory…</p>}
    {inventory.isError && <p role="alert" className="text-amber-300">Inventory unavailable: {safeMessage(inventory.error)}</p>}
    {inventory.data && <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
      <div className="bg-slate-800 p-3 rounded">All findings: <strong>{inventory.data.total}</strong></div>
      <div className="bg-slate-800 p-3 rounded">Source-eligible: <strong>{inventory.data.eligible}</strong></div>
      <div className="bg-slate-800 p-3 rounded">Needs manual work: <strong>{inventory.data.unsupported}</strong></div>
      <div className="bg-slate-800 p-3 rounded">Approved: <strong>{inventory.data.approved}</strong></div>
    </div>}
    {repo && <label className="flex gap-2 text-sm"><input type="checkbox" checked={consent} disabled={running} onChange={e=>setConsent(e.target.checked)}/>I authorize sending redacted finding details and verified source snippets to the configured external AI provider. Requests may incur costs and rate limits.</label>}
    <div className="flex flex-wrap gap-2">
      <button onClick={run} disabled={!repo || !consent || running || eligible.length === 0}>Generate proposals for all eligible findings</button>
      <button onClick={() => { cancelRef.current = true; }} disabled={!running}>Pause</button>
      <button onClick={download} disabled={approved.length === 0 || running || exporting}>Export corrected project ZIP</button>
      <button onClick={downloadReport} disabled={!inventory.data || running}>Download findings report</button>
    </div>
    {proposals.length > 0 && (
      <div className="rounded p-3">
        <label><input type="checkbox" checked={approvalConsent} disabled={running} onChange={e => setApprovalConsent(e.target.checked)} />I reviewed these proposals and approve them for export; they are not security-verified.</label>
        <button onClick={approveAll} disabled={!approvalConsent || running}>Approve {proposals.length} proposals</button>
      </div>
    )}
    {running && <p role="status">{operation}: {progress}/{total} completed. This can take time; don't refresh during the current request.</p>}
    {error && <p role="alert" className="text-amber-300">{error}</p>}
    {results.length>0 && <details open><summary>Latest run ({results.length})</summary><div className="max-h-56 overflow-auto space-y-1 mt-2">{results.map(r=><div key={r.id} className="border border-slate-700 rounded p-2 text-xs"><strong>{r.status}</strong> — {r.title}: {r.detail} <button className="text-indigo-300 underline ml-2" onClick={()=>onReview(r.id)}>Review</button></div>)}</div></details>}
    {items.length>0 && <details><summary>All findings and eligibility ({items.length})</summary><div className="max-h-72 overflow-auto mt-2 space-y-1">{items.map(i=><div key={i.finding_id} className="border border-slate-700 rounded p-2 text-xs"><strong>{i.severity} · {i.title}</strong> — {i.eligible ? (i.patch_status || 'Eligible, not proposed') : `Manual review: ${i.reason}`} <button className="text-indigo-300 underline ml-2" onClick={()=>onReview(i.finding_id)}>Open</button></div>)}</div></details>}
    <p className="text-xs text-amber-300">Only approved, nonconflicting proposals are exported. Source eligibility is currently limited to verified Python files. A proposal or successful ZIP export does not mean the vulnerability has been fixed or tested.</p>
  </section>;
}
