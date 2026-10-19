import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { API, type OpenApiImportResponse, type ApiAuthTestResponse, type BenchmarkEvaluationResponse, type CrossToolCorrelationResponse, type NodeTransferPackage, type NodeReceiveResponse } from '../api';

const field = 'bg-slate-900 border border-slate-700 rounded p-2 text-sm w-full';
const button = 'bg-indigo-600 px-4 py-2 rounded text-sm disabled:opacity-40';
const card = 'bg-slate-900 border border-slate-700 rounded-xl p-5 space-y-3';
function explain(e: any): string { const d=e.response?.data?.detail; return typeof d==='string' ? d : Array.isArray(d) ? d.map(x=>x.msg).join('; ') : d?.message || e.message || 'Request failed'; }
function encoded(bytes: Uint8Array) { let s=''; for (let i=0;i<bytes.length;i+=8192) s+=String.fromCharCode(...bytes.subarray(i,i+8192)); return btoa(s); }
function downloadPayload(result: NodeReceiveResponse) {
  const bytes=Uint8Array.from(atob(result.payload_b64), c=>c.charCodeAt(0));
  const url=URL.createObjectURL(new Blob([bytes])); const a=document.createElement('a'); a.href=url;a.download=`ase-verified-${result.media_type.toLowerCase()}.bin`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export default function SecuritySuite() {
  const [tab,setTab]=useState('api');
  const [project,setProject]=useState(''); const [target,setTarget]=useState('');
  const projects=useQuery({queryKey:['projects'],queryFn:API.getProjects});
  const targets=useQuery({queryKey:['targets',project],queryFn:()=>API.getTargets(project),enabled:!!project});
  const [specText,setSpecText]=useState(''); const [spec,setSpec]=useState<OpenApiImportResponse|null>(null);
  const [tokens,setTokens]=useState({a:'',b:'',admin:''}); const [resource,setResource]=useState('');
  const [auth,setAuth]=useState<ApiAuthTestResponse|null>(null);
  const [benchmark,setBenchmark]=useState<BenchmarkEvaluationResponse|null>(null);
  const [correlation,setCorrelation]=useState<CrossToolCorrelationResponse|null>(null);
  const [error,setError]=useState(''); const [file,setFile]=useState<File|null>(null);
  const [media,setMedia]=useState('TEXT'); const [text,setText]=useState('Security demonstration message');
  const [secret,setSecret]=useState(''); const [payloadFile,setPayloadFile]=useState<File|null>(null);
  const [packet,setPacket]=useState<NodeTransferPackage|null>(null);const [received,setReceived]=useState<NodeReceiveResponse|null>(null);
  const imported=useMutation({mutationFn:async()=>{if(!file)throw new Error('Choose an OpenAPI file.'); const content=await file.text(); const report=await API.importOpenApi(project,target,file);return {content,report};},onSuccess:({content,report})=>{setSpecText(content);setSpec(report);setAuth(null);setError('');},onError:e=>setError(explain(e))});
  const authRun=useMutation({mutationFn:()=>API.runApiAuthTest(project,target,specText,tokens.a,tokens.b,tokens.admin,resource),onSuccess:r=>{setAuth(r);setError('');},onError:e=>setError(explain(e))});
  const evalRun=useMutation({mutationFn:()=>API.runBenchmarkEvaluation(false),onSuccess:r=>{setBenchmark(r);setError('');},onError:e=>setError(explain(e))});
  const correlate=useMutation({mutationFn:()=>API.getCrossToolCorrelation(project),onSuccess:r=>{setCorrelation(r);setError('');},onError:e=>setError(explain(e))});
  const encrypt=useMutation({mutationFn:async()=>{
    const bytes=media==='TEXT'?new TextEncoder().encode(text):new Uint8Array(await payloadFile!.arrayBuffer());
    if(bytes.length>5*1024*1024)throw new Error('Maximum payload is 5 MiB.');
    return API.sendNodeTransfer({sender_node:'NODE_A',receiver_node:'NODE_B',media_type:media,payload_b64:encoded(bytes),shared_key_seed:secret});
  },onSuccess:r=>{setPacket(r);setReceived(null);setError('');},onError:e=>setError(explain(e))});
  const decrypt=useMutation({mutationFn:()=>API.receiveNodeTransfer({packet:packet!,shared_key_seed:secret}),onSuccess:r=>{setReceived(r);setError('');},onError:e=>setError(explain(e))});
  const security=useQuery({queryKey:['security-evaluation'],queryFn:API.getSecurityEvaluation,enabled:tab==='transfer',retry:false});
  const busy=imported.isPending||authRun.isPending||evalRun.isPending||correlate.isPending||encrypt.isPending||decrypt.isPending;
  function clearContext() {setSpec(null);setSpecText('');setAuth(null);setCorrelation(null);setTokens({a:'',b:'',admin:''});setResource('');setError('');}
  return <div className="max-w-6xl mx-auto space-y-5 pb-12">
    <h2 className="text-3xl font-bold">Security Suite</h2>
    <p className="text-sm text-slate-400">API access checks, finding comparison and local encryption demonstrations. Each result states what was actually tested.</p>
    <div className="flex flex-wrap gap-3">{[['api','API Authorization'],['benchmark','Benchmark & Findings'],['transfer','Encryption Demonstration']].map(([id,label])=><button className={button} key={id} disabled={busy} onClick={()=>{setTab(id);setError('');}}>{label}</button>)}</div>
    {tab!=='transfer'&&<section className={card}>
      <label>Project<select aria-label="Security project" className={field} value={project} disabled={busy} onChange={e=>{setProject(e.target.value);setTarget('');clearContext();}}><option value="">Select project</option>{projects.data?.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
      {tab==='api'&&<label>Approved target<select className={field} value={target} disabled={busy||!project} onChange={e=>{setTarget(e.target.value);clearContext();}}><option value="">Select target</option>{targets.data?.filter(t=>t.authorization_status==='APPROVED'&&t.is_active).map(t=><option key={t.id} value={t.id}>{t.name} · {t.url}</option>)}</select></label>}
      {(projects.isError||targets.isError)&&<p role="alert">{explain(projects.error||targets.error)}</p>}
    </section>}
    {error&&<p role="alert" className="text-red-300 whitespace-pre-wrap">{error}</p>}
    {tab==='api'&&<>
      <section className={card}><h3 className="font-bold">1. Import your target's OpenAPI specification</h3>
        <p className="text-sm">Use a JSON/YAML API specification, not your project ZIP. The existing ASE Lab has search/echo pages; it does not provide synthetic user/admin API resources for this test.</p>
        <input type="file" accept=".json,.yaml,.yml" disabled={busy} onChange={e=>{setFile(e.target.files?.[0]||null);setSpec(null);setSpecText('');setAuth(null);}}/>
        <button className={button} disabled={!project||!target||!file||busy} onClick={()=>imported.mutate()}>{imported.isPending?'Importing…':'Import specification'}</button>
        {spec&&<p>{spec.title} · API {spec.api_version} · {spec.total_endpoints} endpoints · {spec.bola_candidates} object-access candidates · {spec.bfla_candidates} privileged candidates</p>}
      </section>
      <section className={card}><h3 className="font-bold">2. Configure synthetic test accounts</h3>
        <p className="text-sm">Use two distinct test users and an administrator on the approved target. Enter User A's existing resource ID. Only GET/HEAD requests are permitted; failed control requests are inconclusive.</p>
        {([['a','User A bearer token'],['b','User B bearer token'],['admin','Administrator bearer token']] as const).map(([id,label])=><label className="block" key={id}>{label}<input type="password" autoComplete="off" className={field} value={tokens[id]} disabled={busy} onChange={e=>setTokens({...tokens,[id]:e.target.value})}/></label>)}
        <label className="block">User A resource ID<input className={field} value={resource} disabled={busy} onChange={e=>setResource(e.target.value)}/></label>
        <button className={button} disabled={!spec||!target||!tokens.a||!tokens.b||!tokens.admin||!resource||busy} onClick={()=>authRun.mutate()}>{authRun.isPending?'Testing…':'Run authorization checks'}</button>
        {auth&&<div className="space-y-2"><p>{auth.tested_endpoints_count} cases · {auth.vulnerable_count} access-control alerts · {auth.secure_count} denied accesses · {auth.inconclusive_count} inconclusive</p>{auth.results.map((r,i)=><p key={i}>{r.test_type} · {r.method} {r.endpoint} · <strong>{r.status}</strong><br/>{r.evidence}</p>)}{auth.limitations.map(l=><p className="text-xs text-amber-300" key={l}>{l}</p>)}</div>}
      </section>
    </>}
    {tab==='benchmark'&&<>
      <section className={card}><h3 className="font-bold">Synthetic heuristic benchmark</h3><p>This checks simple string-based detection against 10 labeled snippets. It does not run Semgrep, Gitleaks or ZAP and is not their measured accuracy.</p>
        <button className={button} disabled={busy} onClick={()=>evalRun.mutate()}>{evalRun.isPending?'Evaluating…':'Run heuristic demonstration'}</button>
        {benchmark&&<><p>Mode: {benchmark.evaluation_mode} · Samples: {benchmark.confusion_matrix.total_samples}</p><p>Precision {benchmark.metrics.precision} · Recall {benchmark.metrics.recall} · F1 {benchmark.metrics.f1_score} · Accuracy {benchmark.metrics.accuracy}</p>{benchmark.sample_limitations.map(l=><p className="text-xs text-amber-300" key={l}>{l}</p>)}<details><summary>Case results</summary>{benchmark.evaluation_details.map(r=><p key={r.sample_id}>{r.title}: expected {r.ground_truth}, detected {String(r.detected)}, {r.correct?'correct':'incorrect'}</p>)}</details></>}
      </section>
      <section className={card}><h3 className="font-bold">Compare finding locations</h3><p>Groups stored findings by location. Shared locations are not proof that tools detected the same vulnerability. This is not a Jaccard or accuracy measurement.</p>
        <button className={button} disabled={!project||busy} onClick={()=>correlate.mutate()}>Compare findings</button>
        {correlation&&<><p>{correlation.total_findings} findings · {correlation.total_locations} locations</p>{correlation.correlated_items.map((r,i)=><p key={i}>{r.location}: {r.finding_count} finding(s) · {r.tools_involved.join(', ')||'Tool provenance unavailable'} · {r.severities.join(', ')}</p>)}<p className="text-xs">{correlation.provenance_policy}</p></>}
      </section>
    </>}
    {tab==='transfer'&&<>
      <section className={card}><h3 className="font-bold">Local AES-GCM round trip</h3><p>Encrypt and decrypt text or a real media file through this backend. NODE_A and NODE_B are labels here: this does not demonstrate delivery between two devices or containers.</p>
        <label>Payload type<select className={field} value={media} disabled={busy} onChange={e=>{setMedia(e.target.value);setPacket(null);setReceived(null);setPayloadFile(null);}}>{['TEXT','IMAGE','AUDIO','VIDEO'].map(t=><option key={t}>{t}</option>)}</select></label>
        {media==='TEXT'?<textarea className={field} value={text} disabled={busy} onChange={e=>setText(e.target.value)}/>:<input type="file" accept={media==='IMAGE'?'image/*':media==='AUDIO'?'audio/*':'video/*'} disabled={busy} onChange={e=>setPayloadFile(e.target.files?.[0]||null)}/>}
        <label className="block">Demonstration shared secret (at least 32 characters)<input type="password" autoComplete="off" className={field} value={secret} disabled={busy} onChange={e=>setSecret(e.target.value)}/></label>
        <div className="flex gap-3"><button className={button} disabled={busy||secret.length<32||(media==='TEXT'?!text:!payloadFile)} onClick={()=>encrypt.mutate()}>Encrypt payload</button><button className={button} disabled={busy||!packet||secret.length<32} onClick={()=>decrypt.mutate()}>Decrypt and verify</button></div>
        {packet&&<p>Encrypted {packet.original_size_bytes} bytes · {packet.performance.encryption_latency_ms} ms · SHA-256 {packet.original_sha256}</p>}
        {received&&<><p>Integrity verified: {String(received.integrity_verified)} · Decryption {received.decryption_latency_ms} ms</p>{received.media_type==='TEXT'?<pre className="whitespace-pre-wrap">{new TextDecoder().decode(Uint8Array.from(atob(received.payload_b64),c=>c.charCodeAt(0)))}</pre>:<button className={button} onClick={()=>downloadPayload(received)}>Download verified payload</button>}</>}
      </section>
      <section className={card}><h3 className="font-bold">Local security experiments</h3>
        {security.isPending&&<p>Measuring…</p>}{security.isError&&<p role="alert">{explain(security.error)}</p>}
        {security.data&&<><p>Redaction/encryption: {security.data.confidentiality.status} · Ciphertext tampering: {security.data.integrity.status}</p><p>Authentication: {security.data.authentication_and_accountability.authentication_status} · Accountability: {security.data.authentication_and_accountability.accountability_status}</p><p>Process CPU: {security.data.performance.cpu_usage_percent??'unavailable'}% · Memory: {security.data.performance.ram_resident_set_mb??'unavailable'} MiB · Local encryption: {security.data.performance.encryption_throughput_mb_per_sec} MiB/s</p>{security.data.limitations.map(l=><p className="text-xs text-amber-300" key={l}>{l}</p>)}</>}
      </section>
    </>}
  </div>;
}
