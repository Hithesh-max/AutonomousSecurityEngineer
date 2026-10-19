import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isAxiosError } from 'axios';
import { API } from '../api';
import RemediationPanel from '../components/RemediationPanel';

const busy = (status: string) => ['QUEUED','RUNNING'].includes(status);
function message(error: unknown) {
  if (isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (typeof detail?.message === 'string') return detail.message;
    if (error.response?.status === 422) return 'Check the scan profile and authorization confirmation.';
  }
  return 'Request failed. Check backend connectivity and sign in again if your session expired.';
}
const field = 'bg-slate-900 border border-slate-700 rounded p-2';
const button = 'bg-indigo-600 rounded px-4 py-2 disabled:opacity-40';

type LabSource = {path:string; start_line:number; end_line:number; highlight_line:number; content:string; sha256:string; mapping_status:string; mapping_note:string};
function LabSourceSnippet({jobId, finding}: {jobId:string; finding: {id:string; title:string; tool_rule_id?:string|null}}) {
  const code = useQuery<LabSource>({
    queryKey: ['lab-source', jobId, finding.id],
    queryFn: () => API.getLabFindingSource(jobId, finding.id),
    retry: false,
  });
  return <div className="mt-3 space-y-2">
    <h4 className="font-semibold">Bundled lab source snippet</h4>
    {code.isPending && <p className="text-slate-400">Loading source…</p>}
    {code.isError && <p className="text-amber-300">Source mapping unavailable: {message(code.error)}</p>}
    {code.data && <>
      <p className="text-xs text-slate-300">{code.data.path} · line {code.data.highlight_line} · {code.data.mapping_status}</p>
      <div className="overflow-x-auto rounded border border-slate-700 bg-slate-950 font-mono text-xs" aria-label="Vulnerable source code">
        {code.data.content.split('\n').map((line, i) => {
          const number = code.data!.start_line + i;
          return <div key={number} className={'flex gap-3 px-3 py-1 whitespace-pre ' + (number === code.data!.highlight_line ? 'bg-red-950/70 border-l-2 border-red-400' : '')}>
            <span className="select-none text-slate-500">{number}</span><code>{line || ' '}</code>
          </div>;
        })}
      </div>
      <p className="text-xs text-slate-400">{code.data.mapping_note}</p>
    </>}
  </div>;
}

export default function WebLab() {
  const queryClient = useQueryClient();
  const [project, setProject] = useState('');
  const [profile, setProfile] = useState<'SAFE' | 'STANDARD'>('SAFE');
  const [approved, setApproved] = useState(false);
  const [active, setActive] = useState(false);
  const [selected, setSelected] = useState('');
  const [currentTargetId, setCurrentTargetId] = useState('');
  const [showDeployedForm, setShowDeployedForm] = useState(false);
  const [depName, setDepName] = useState('');
  const [depUrl, setDepUrl] = useState('');
  const [depScope, setDepScope] = useState('');
  const [depConsent, setDepConsent] = useState(false);
  const [deployedMsg, setDeployedMsg] = useState('');
  const [deployedErr, setDeployedErr] = useState('');

  const config = useQuery({queryKey:['web-config'],queryFn:API.getWebScanConfig});
  const projects = useQuery({queryKey:['projects'],queryFn:API.getProjects});
  const targets = useQuery({queryKey:['targets',project],queryFn:()=>API.getTargets(project),enabled:!!project});
  const labTarget = targets.data?.find(t=>t.url === config.data?.lab_url || t.url === config.data?.lab_url+'/');
  const target = targets.data?.find(t => t.id === currentTargetId) || labTarget || targets.data?.[0];
  const activeTarget = target;

  const scans = useQuery({queryKey:['web-scans',project],queryFn:()=>API.getWebScans(project),enabled:!!project,
    refetchInterval:query=>query.state.data?.some(j=>busy(j.status)) ? 2000 : false});
  const selectedJob = scans.data?.find(j=>j.id===selected) ?? scans.data?.[0];
  const findings = useQuery({queryKey:['web-findings',selectedJob?.id,selectedJob?.status],
    queryFn:()=>API.getWebFindings(selectedJob!.id),enabled:!!selectedJob && !busy(selectedJob.status)});
  const register = useMutation({mutationFn:()=>API.registerLabTarget(project),onSuccess:()=>queryClient.invalidateQueries({queryKey:['targets']})});
  const registerDeployed = useMutation({
    mutationFn: () => API.registerDeployedTarget(project, { name: depName, url: depUrl, explicit_scope: depScope, ownership_declaration: 'AUTHORIZED_BY_OPERATOR' }),
    onSuccess: (data) => {
      setDeployedMsg(`Registered successfully: ${data.name} (${data.explicit_scope})`);
      setDeployedErr('');
      setDepName(''); setDepUrl(''); setDepScope(''); setDepConsent(false);
      queryClient.invalidateQueries({queryKey: ['targets']});
      setCurrentTargetId(data.target_id);
    },
    onError: (err: any) => {
      setDeployedErr(message(err));
      setDeployedMsg('');
    }
  });
  const approve = useMutation({mutationFn:(scopeToApprove?: string)=>API.approveTarget(target!.id, scopeToApprove || activeTarget?.explicit_scope || 'ase-lab'),onSuccess:()=>queryClient.invalidateQueries({queryKey:['targets']})});
  const revoke = useMutation({mutationFn:()=>API.revokeTarget(target!.id),onSuccess:()=>queryClient.invalidateQueries({queryKey:['targets']})});
  const start = useMutation({mutationFn:()=>API.startWebScan(target!.id,profile,active),onSuccess:data=>{
    setSelected(data.job_id);queryClient.invalidateQueries({queryKey:['web-scans']});queryClient.invalidateQueries({queryKey:['jobs']});
  },onError:()=>queryClient.invalidateQueries({queryKey:['web-scans']})});
  const canScan = config.data?.enabled && target?.authorization_status === 'APPROVED' && target.is_active && !scans.data?.some(j=>j.target_id===target.id && busy(j.status));
  const errors = [config,projects,targets,scans,register,approve,revoke,start].filter(item=>item.isError);
  return <div className="max-w-6xl mx-auto space-y-6 pb-12">
    <h2 className="text-3xl font-bold">Web Lab</h2>
    <p className="text-slate-400">Assess the bundled, isolated training application using real Nmap and OWASP ZAP. This scan path accepts only {config.data?.lab_url ?? 'the configured ASE lab'}.</p>
    {config.data && !config.data.enabled && <p role="alert" className="text-amber-300">Lab scanning is disabled. Follow WEB_LAB_UPDATE.md to start the lab services.</p>}
    <section className="bg-[#0F1523] border border-slate-800 p-6 rounded-xl space-y-4">
      <div className="flex flex-wrap gap-4 items-center justify-between">
        <label className="block">Project <select className={field+' ml-2'} value={project} onChange={e=>{setProject(e.target.value);setSelected('');setApproved(false);setActive(false);}}>
          <option value="">Select project</option>{projects.data?.map(p=><option value={p.id} key={p.id}>{p.name}</option>)}
        </select></label>

        {project && (
          <div className="flex gap-2">
            {!target && <button className={button} disabled={register.isPending} onClick={()=>register.mutate()}>Register bundled lab target</button>}
            <button className="bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded text-sm text-slate-200 border border-slate-700" onClick={() => setShowDeployedForm(!showDeployedForm)}>
              {showDeployedForm ? 'Hide Deployed Target Form' : '+ Register Deployed Target (SSRF Protected)'}
            </button>
          </div>
        )}
      </div>

      {showDeployedForm && project && (
        <div className="bg-slate-900/90 border border-indigo-500/30 p-4 rounded-lg space-y-3">
          <h4 className="font-semibold text-indigo-400">Register Authorized Deployed Web Target</h4>
          <p className="text-xs text-slate-400">All targets undergo pre-flight SSRF resolution and address verification. Private IP ranges, loopbacks, link-local metadata (169.254.169.254), and out-of-scope destinations are strictly blocked.</p>
          <div className="grid md:grid-cols-3 gap-3">
            <input className={field} placeholder="Target Name (e.g. Staging Portal)" value={depName} onChange={e => setDepName(e.target.value)} />
            <input className={field} placeholder="Target URL (e.g. https://staging.example.com)" value={depUrl} onChange={e => setDepUrl(e.target.value)} />
            <input className={field} placeholder="Explicit Scope (e.g. staging.example.com)" value={depScope} onChange={e => setDepScope(e.target.value)} />
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input type="checkbox" checked={depConsent} onChange={e => setDepConsent(e.target.checked)} />
            I declare and confirm written ownership or authorization to perform security testing against this endpoint.
          </label>
          <button
            className={button}
            disabled={!depName || !depUrl || !depScope || !depConsent || registerDeployed.isPending}
            onClick={() => registerDeployed.mutate()}
          >
            {registerDeployed.isPending ? 'Verifying SSRF & Scope…' : 'Register Deployed Target'}
          </button>
          {deployedMsg && <p className="text-xs text-emerald-400">{deployedMsg}</p>}
          {deployedErr && <p className="text-xs text-red-400" role="alert">{deployedErr}</p>}
        </div>
      )}

      {targets.data && targets.data.length > 0 && (
        <label className="block">Active Web Target: 
          <select
            className={field + ' ml-2'}
            value={currentTargetId || target?.id || ''}
            onChange={e => setCurrentTargetId(e.target.value)}
          >
            {targets.data.map(t => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.url}) — {t.authorization_status}
              </option>
            ))}
          </select>
        </label>
      )}

      {activeTarget && <>
        <p>{activeTarget.name} · {activeTarget.url} · <strong>{activeTarget.authorization_status}</strong> {activeTarget.explicit_scope ? `[Scope: ${activeTarget.explicit_scope}]` : ''}</p>
        {activeTarget.authorization_status !== 'APPROVED' || !activeTarget.is_active ? <>
          <label className="flex gap-2"><input type="checkbox" checked={approved} onChange={e=>setApproved(e.target.checked)}/> I authorize testing of {activeTarget.name}, with scope {activeTarget.explicit_scope || 'ase-lab'}.</label>
          <button className={button} disabled={!approved || approve.isPending} onClick={()=>approve.mutate(activeTarget.explicit_scope || 'ase-lab')}>Confirm authorization</button>
        </> : <button className="text-red-300 underline" disabled={revoke.isPending} onClick={()=>revoke.mutate()}>Revoke authorization</button>}
        <label className="block">Reconnaissance profile <select className={field+' ml-2'} value={profile} onChange={e=>setProfile(e.target.value as 'SAFE'|'STANDARD')}>
          <option value="SAFE">SAFE — TCP port 8080</option><option value="STANDARD">STANDARD — port 8080 and service version probes</option>
        </select></label>
        <p className="text-sm text-slate-400">ZAP crawls the target and passively analyzes responses by default. Active injection tests require explicit consent.</p>
        <label className="flex gap-2"><input type="checkbox" checked={active} onChange={e=>setActive(e.target.checked)}/> I explicitly authorize active XSS and SQL injection testing against this target.</label>
        <button className={button} disabled={!canScan || start.isPending} onClick={()=>start.mutate()}>{start.isPending?'Submitting…':active?'Start authorized active web scan':'Start crawl and passive web scan'}</button>
      </>}
      {errors.map((item,i)=><p key={i} role="alert" className="text-red-400">{message(item.error)}</p>)}
    </section>
    {!!scans.data?.length && <label className="block">Scan history <select className={field+' ml-2'} value={selectedJob?.id ?? ''} onChange={e=>setSelected(e.target.value)}>
      {scans.data.map(j=><option value={j.id} key={j.id}>{j.status} · {j.id.slice(0,8)} · {j.result.configuration?.active_testing?'Active':'Passive'}</option>)}
    </select></label>}
    {selectedJob && <section className="bg-[#0F1523] border border-slate-800 p-6 rounded-xl space-y-4">
      <p role="status"><strong>{selectedJob.status}</strong> · {selectedJob.current_stage} · {selectedJob.message}</p>
      {selectedJob.failure_message && <p className="text-red-400">{selectedJob.failure_code}: {selectedJob.failure_message}</p>}
      <p className="text-sm text-slate-400">{selectedJob.result.coverage_note}</p>
      <p className="text-xs break-all">Scan ID: {selectedJob.id} · Target: {selectedJob.result.target_url} · IP: {selectedJob.result.resolved_ip ?? 'Not resolved'}</p>
      {selectedJob.result.tools?.map(tool=><article className="border border-slate-700 rounded p-3 space-y-2" key={tool.tool}>
        <p><strong>{tool.tool}: {tool.status}</strong> · Version {tool.version ?? 'Unavailable'} · {tool.duration_seconds ?? '—'} seconds · {tool.finding_count} findings</p>
        {tool.failure_message && <p className="text-red-400">{tool.failure_code}: {tool.failure_message}</p>}
        {tool.ports?.map(p=><p key={p.port}>{p.port}/{p.protocol}: {p.state} · {p.service} {p.product} {p.version}</p>)}
        {tool.endpoints && <details><summary>Discovered endpoints ({tool.endpoints.length})</summary>{tool.endpoints.map(url=><p key={url}>{url}</p>)}</details>}
      </article>)}
      {!busy(selectedJob.status) && <>
        <h3 className="font-bold">Stored findings ({findings.data?.length ?? 'Loading'})</h3>
        {findings.isError && <p role="alert">{message(findings.error)}</p>}
        {findings.data?.length===0 && <p>No stored findings. Check tool coverage and failure messages; this does not prove the application is secure.</p>}
        {findings.data?.map(f=><details className="border border-slate-700 rounded p-3" key={f.id}><summary>{f.severity} · {f.title}</summary>
          <p>{f.description}</p><p>{f.endpoint?.method} {f.endpoint?.path} · Parameter: {f.parameter || 'None'} · {f.cwe}</p>
          <p>Scanner confidence: {f.confidence} · Status: {f.status} · Rule: {f.tool_rule_id}</p>
          <pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(f.evidence,null,2)}</pre>
        {selectedJob && ['40012', '40018', '10038', '10020', '10021', '10010', '10054', '10036'].includes(String(f.tool_rule_id)) && (
        <LabSourceSnippet jobId={selectedJob.id} finding={f} />
        )}
        {selectedJob && f.source === 'DAST' && (
          <RemediationPanel findingId={f.id} />
        )}
        </details>)}
      </>}
      <details><summary>Recorded job stages</summary>{selectedJob.result.events?.map((event,i)=><p key={i}>{event.at} · {event.stage} {event.percent===undefined?'':`${event.percent}%`}</p>)}</details>
    </section>}
  </div>;
}
