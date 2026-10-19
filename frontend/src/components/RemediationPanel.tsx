import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isAxiosError } from 'axios';
import { API } from '../api';
import DiffViewer from './DiffViewer';

function errorText(error: unknown) {
  if (isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (typeof detail?.message === 'string') return `${detail.message}${detail.code ? ` (${detail.code})` : ''}`;
    if (error.response?.status === 401) return 'Your session expired. Sign in again.';
  }
  return 'Request failed. Check backend connectivity.';
}
const btn = 'bg-indigo-600 rounded px-3 py-1.5 text-sm disabled:opacity-40';
const checkColor = (s: string) => s === 'PASS' ? 'text-green-300' : s === 'NOT_RUN' ? 'text-amber-300' : 'text-red-300';

export default function RemediationPanel({ findingId, defaultOpen = false }: { findingId: string; defaultOpen?: boolean }) {
  const [opened, setOpened] = useState(defaultOpen);
  if (!opened) return <button className={btn + ' mt-3'} onClick={() => setOpened(true)}>Open AI remediation</button>;
  return <RemediationBody findingId={findingId} />;
}

function RemediationBody({ findingId }: { findingId: string }) {
  const queryClient = useQueryClient();
  const [consent, setConsent] = useState(false);
  const key = ['remediation', findingId];
  const summary = useQuery({ queryKey: key, queryFn: () => API.getRemediation(findingId), retry: false });
  const refresh = async () => { await queryClient.invalidateQueries({ queryKey: key }); await queryClient.invalidateQueries({queryKey:['remediation-inventory']}); };
  const analyze = useMutation({ mutationFn: () => API.analyzeFinding(findingId, consent), onSettled: refresh });
  const latestOk = summary.data?.analyses.find(a => a.status === 'COMPLETED');
  const patch = useMutation({ mutationFn: () => API.generatePatch(findingId, latestOk!.id, consent), onSettled: refresh });
  const data = summary.data;
  const proposal = data?.patches.find(p => p.status === 'PATCH_PROPOSED') ?? data?.patches[0];
  const approve = useMutation({ mutationFn: () => API.approvePatch(proposal!.id, proposal!.patch_sha256), onSettled: refresh });
  const reject = useMutation({ mutationFn: () => API.rejectPatch(proposal!.id, proposal!.patch_sha256), onSettled: refresh });
  const verify = useMutation({ mutationFn: () => API.verifyPatch(proposal!.id), onSettled: refresh });
  const revoke = useMutation({mutationFn:()=>API.revokePatch(proposal!.id,proposal!.patch_sha256),onSettled:refresh});
  const [showFile,setShowFile]=useState(false);
  const fullFile=useQuery({queryKey:['corrected-source',proposal?.id],queryFn:()=>API.getCorrectedSource(proposal!.id),enabled:!!proposal&&showFile});
  const busy = revoke.isPending || analyze.isPending || patch.isPending || approve.isPending || reject.isPending || verify.isPending;
  const ai = data?.ai;
  const analysis = latestOk?.result;

  return <section className="mt-4 space-y-3 border-t border-slate-700 pt-3" aria-label="AI remediation">
    <h4 className="font-semibold">AI remediation <span className="text-xs font-normal text-slate-400">(proposals only · nothing is applied to your project)</span></h4>
    {summary.isPending && <p className="text-slate-400">Loading remediation state…</p>}
    {summary.isError && <p role="alert" className="text-red-400">{errorText(summary.error)}</p>}
    {data && <>
      {!ai?.configured && <p role="alert" className="text-amber-300">AI provider not configured: {ai?.reason} Analysis and patch generation are unavailable until this is set.</p>}
      {ai?.configured && ai.is_external && <label className="flex gap-2 text-sm">
        <input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} />
        I allow redacted finding details and the relevant source snippet to be sent to the external AI provider ({ai.provider}, {ai.model}).
      </label>}
      <div className="flex flex-wrap gap-2">
        <button className={btn} disabled={busy || !ai?.configured || (ai.is_external && !consent)} onClick={() => analyze.mutate()}>
          {analyze.isPending ? 'Analyzing…' : 'Analyze Vulnerability'}</button>
        <button className={btn} disabled={busy || !ai?.configured || (ai.is_external && !consent) || !latestOk || !data.source.available}
          title={!data.source.available ? 'No verified source is available for this finding' : !latestOk ? 'Run the analysis first' : ''}
          onClick={() => patch.mutate()}>{patch.isPending ? 'Generating patch…' : 'Generate Secure Patch'}</button>
      </div>
      {!data.source.available && <p className="text-xs text-amber-300">Patch generation unavailable: {data.source.message}</p>}
      {analyze.isError && <p role="alert" className="text-red-400">{errorText(analyze.error)}</p>}
      {patch.isError && <p role="alert" className="text-red-400">{errorText(patch.error)}</p>}

      {latestOk && analysis && <article className="rounded border border-slate-700 p-3 space-y-1 text-sm">
        <p className="text-xs text-amber-300">{latestOk.label} · {latestOk.provider}/{latestOk.model} · analysis confidence {analysis.confidence}</p>
        {latestOk.is_mock && <p role="alert" className="text-red-400 font-semibold">MOCK RESULT — not produced by a real AI model.</p>}
        <p><strong>{analysis.vulnerability_type}</strong> {analysis.cwe ?? analysis.scanner_cwe ?? ''}</p>
        <p><strong>Root cause:</strong> {analysis.root_cause}</p>
        <p><strong>Impact:</strong> {analysis.security_impact}</p>
        <p><strong>Evidence:</strong> {analysis.evidence_summary}</p>
        <p><strong>Recommended fix:</strong> {analysis.recommended_fix}</p>
        {analysis.affected_location && <p className="text-xs text-slate-400">Location (ASE-verified): {analysis.affected_location.path}:{analysis.affected_location.highlight_line}</p>}
        {!!analysis.limitations.length && <p className="text-xs text-slate-400">Limitations: {analysis.limitations.join(' · ')}</p>}
      </article>}
      {data.analyses[0]?.status === 'FAILED' && <p className="text-xs text-red-300">Latest analysis failed: {data.analyses[0].error_code}. {data.analyses[0].error_message}</p>}

      {proposal && <article className="rounded border border-slate-700 p-3 space-y-2 text-sm">
        <p className="text-xs text-amber-300">{proposal.label} · status <strong>{proposal.status}</strong> · verification <strong>{proposal.verification_status}</strong></p>
        {proposal.is_mock && <p role="alert" className="text-red-400 font-semibold">MOCK RESULT — not produced by a real AI model.</p>}
        <p>{proposal.explanation}</p>
        <DiffViewer diff={proposal.unified_diff} />
        <button className={btn} onClick={()=>setShowFile(v=>!v)}>{showFile?'Hide full files':'View original and entire corrected file'}</button>
        {showFile&&fullFile.isPending&&<p>Loading full source…</p>}
        {showFile&&fullFile.isError&&<p role="alert">{errorText(fullFile.error)}</p>}
        {showFile&&fullFile.data&&<div className="grid md:grid-cols-2 gap-2">{[['Original',fullFile.data.original_content],['Proposed',fullFile.data.content]].map(([label,content])=><div key={label}><h5>{label} · {fullFile.data.path}</h5><pre className="overflow-auto max-h-96 text-xs bg-slate-950 p-2">{content.split('\n').map((line,index)=>`${index+1} | ${line}`).join('\n')}</pre></div>)}</div>}
        {['APPROVED','INCONCLUSIVE','VERIFIED'].includes(proposal.status)&&<button className={btn} disabled={busy} onClick={()=>revoke.mutate()}>Revoke approval for future exports</button>}
        {revoke.isError&&<p role="alert">{errorText(revoke.error)}</p>}
        <details><summary>Checks measured by ASE on this proposal</summary>
          <p className="text-xs text-slate-400">These checks are not verification. Functional tests and security rescans have not run. Approval permits isolated syntax checking and export.</p>
          {Object.entries(proposal.static_checks).filter(([, v]) => typeof v === 'object').map(([name, v]) => {
            const c = v as { status: string; detail?: string };
            return <p key={name} className="text-xs"><span className={checkColor(c.status)}>{c.status}</span> · {name.replace(/_/g, ' ')}{c.detail ? ` — ${c.detail}` : ''}</p>;
          })}
        </details>
        <p className="text-xs text-slate-500 break-all">Patch hash {proposal.patch_sha256} · built against source {proposal.source_sha256.slice(0, 12)}…</p>
        {!!proposal.limitations?.length && <p className="text-xs text-slate-400">Limitations: {proposal.limitations.join(' · ')}</p>}
        {proposal.status === 'PATCH_PROPOSED' && <div className="flex flex-wrap gap-2">
          <button className={btn} disabled={busy} onClick={() => { if (window.confirm('Approve this exact patch for isolated checking and export? Original source will not change.')) approve.mutate(); }}>Approve patch</button>
          <button className="border border-red-500 rounded px-3 py-1.5 text-sm" disabled={busy} onClick={() => reject.mutate()}>Reject patch</button>
        </div>}
        {proposal.status === 'APPROVED' && <button className={btn} disabled={busy} onClick={() => verify.mutate()}>Apply to isolated copy &amp; check syntax</button>}
        {(approve.isError || reject.isError || verify.isError) && <p role="alert" className="text-red-400">{errorText(approve.error || reject.error || verify.error)}</p>}
        {verify.data && <div role="status" className="border border-amber-600 rounded p-3 space-y-2">
          <p className="font-semibold">{verify.data.status}: {verify.data.message}</p>
          {Object.entries(verify.data.checks).map(([name, c]) => <p key={name} className="text-xs">{name}: {c.status} — {c.detail}</p>)}
        </div>}
        {proposal.status === 'INCONCLUSIVE' && <p className="text-amber-300 text-sm">Isolated syntax check completed. Functional testing and ZAP rescan are NOT performed; security remediation remains unverified. Review the audit trail for details.</p>}
        {proposal.status === 'REJECTED' && <p className="text-sm text-slate-400">Proposal rejected. No files were modified.</p>}
      </article>}
      {!!data.events.length && <details><summary className="text-xs text-slate-400">Audit trail ({data.events.length})</summary>
        {data.events.map((e, i) => <p key={i} className="text-xs text-slate-500">{e.created_at} · {e.event_type}{e.to_state ? ` → ${e.to_state}` : ''}</p>)}
      </details>}
    </>}
  </section>;
}
