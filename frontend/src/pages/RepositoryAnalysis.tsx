import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isAxiosError } from 'axios';
import { API, type Repository, type SourceContext } from '../api';

function explain(error: unknown): string {
  if (isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (typeof detail?.message === 'string') return detail.message;
  }
  return 'Request failed. Check the API and worker.';
}
const active = (status: string) => ['QUEUED', 'RUNNING'].includes(status);

export default function RepositoryAnalysis({ repository }: {repository: Repository}) {
  const client = useQueryClient();
  const [selectedScan, setSelectedScan] = useState('');
  const [search, setSearch] = useState('');
  const [source, setSource] = useState<SourceContext | null>(null);
  const analyses = useQuery({queryKey: ['analyses', repository.id], queryFn: () => API.getAnalyses(repository.id),
    refetchInterval: query => active(repository.analysis_status) || query.state.data?.some(j => active(j.status)) ? 2000 : false});
  const scanId = selectedScan || repository.latest_analysis_job_id || '';
  const analysis = analyses.data?.find(j => j.id === scanId);
  const finished = !!analysis && !active(analysis.status);
  const findings = useQuery({queryKey: ['repository-findings', repository.id, scanId, analysis?.status],
    queryFn: () => API.getRepositoryFindings(repository.id, scanId), enabled: finished});
  const files = useQuery({queryKey: ['repository-files', repository.id, scanId, search, analysis?.status],
    queryFn: () => API.getRepositoryFiles(repository.id, scanId, search), enabled: finished});
  const start = useMutation({mutationFn: () => API.analyzeRepository(repository.id),
    onSuccess: data => {setSelectedScan(data.job_id); setSource(null); client.invalidateQueries({queryKey: ['analyses', repository.id]}); client.invalidateQueries({queryKey: ['repositories']});},
    onError: () => {client.invalidateQueries({queryKey: ['analyses', repository.id]}); client.invalidateQueries({queryKey: ['repositories']});}});
  const view = useMutation({mutationFn: ({path, line}: {path: string; line: number}) => API.getSource(repository.id, scanId, path, line),
    onSuccess: result => setSource(result), onError: () => setSource(null)});
  // Repository metadata reflects its latest run; older runs retain their own file index.
  const intelligence = scanId === repository.latest_analysis_job_id ? repository.intelligence : null;
  return <section className="border-t border-slate-700 pt-4 space-y-4">
    <button className="bg-indigo-600 px-4 py-2 rounded disabled:opacity-40" disabled={start.isPending || active(repository.analysis_status)} onClick={() => start.mutate()}>
      {start.isPending ? 'Submitting…' : active(repository.analysis_status) ? 'Analysis in progress…' : 'Analyze repository'}
    </button>
    <p className="text-sm text-slate-400">Runs trusted local Semgrep rules and Gitleaks. Application code is never executed. No findings does not prove the application is secure.</p>
    {start.isError && <p role="alert" className="text-red-400">{explain(start.error)}</p>}
    {analyses.isError && <p role="alert">{explain(analyses.error)}</p>}
    {!!analyses.data?.length && <label className="block">Analysis history <select className="bg-slate-900 p-2 ml-2" value={scanId} onChange={e => {setSelectedScan(e.target.value); setSource(null);}}>
      {analyses.data.map(j => <option value={j.id} key={j.id}>{j.status} · {new Date(j.created_at.endsWith('Z') || /[+-]\d\d:\d\d$/.test(j.created_at) ? j.created_at : j.created_at + 'Z').toLocaleString()} · {j.id.slice(0, 8)}</option>)}
    </select></label>}
    {analysis && <>
      <p role="status"><strong>{analysis.status}</strong> · {analysis.current_stage} · {analysis.message}</p>
      {analysis.failure_message && <p className="text-red-400">{analysis.failure_code}: {analysis.failure_message}</p>}
      <div className="overflow-auto"><table className="w-full text-left"><thead><tr><th>Tool</th><th>Status</th><th>Version</th><th>Findings</th><th>Coverage / errors</th></tr></thead><tbody>
        {analysis.result.tools?.map(tool => <tr key={tool.tool}><td className="p-2">{tool.tool}</td><td>{tool.status}</td><td>{tool.version ?? 'Unavailable'}</td><td>{tool.finding_count}</td><td>{tool.failure_message || (tool.scanned_files !== undefined ? `${tool.scanned_files} scanned files; ${tool.error_count ?? 0} errors` : 'Snapshot secret detection')}</td></tr>)}
      </tbody></table></div>
      <p className="text-xs text-slate-400 break-all">Scan ID: {analysis.id} · Archive: {analysis.result.archive_sha256 ?? repository.archive_sha256}</p>
    </>}
    {intelligence && <div className="space-y-4 bg-slate-900/60 p-4 rounded-lg border border-slate-800">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <h4 className="font-semibold text-indigo-300">Software Bill of Materials (SBOM) & Supply Chain</h4>
        <div className="flex gap-2">
          <button
            className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded border border-slate-700 flex items-center gap-1.5"
            onClick={async () => {
              try {
                const sbom = await API.getSbom(repository.id, 'cyclonedx');
                const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `sbom-cyclonedx-${repository.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}.json`;
                a.click();
                URL.revokeObjectURL(url);
              } catch (e: any) {
                alert(`Failed to export CycloneDX SBOM: ${explain(e)}`);
              }
            }}
          >
            Export CycloneDX v1.5 JSON
          </button>
          <button
            className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded border border-slate-700 flex items-center gap-1.5"
            onClick={async () => {
              try {
                const sbom = await API.getSbom(repository.id, 'spdx');
                const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `sbom-spdx-${repository.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}.json`;
                a.click();
                URL.revokeObjectURL(url);
              } catch (e: any) {
                alert(`Failed to export SPDX SBOM: ${explain(e)}`);
              }
            }}
          >
            Export SPDX 2.3 JSON
          </button>
        </div>
      </div>

      <div className="text-sm space-y-1 text-slate-300">
        <p><strong>Languages:</strong> {intelligence.languages.map(l => `${l.language} ${l.percentage}% (${l.files} files)`).join(', ') || 'None detected'}</p>
        <p><strong>Frameworks:</strong> {intelligence.frameworks.map(f => `${f.framework} (${f.confidence} confidence)`).join(', ') || 'None detected'}</p>
        <p><strong>Manifests:</strong> {intelligence.manifests.map(m => `${m.path}: ${m.status}`).join(', ') || 'None detected'}</p>
        {intelligence.warnings.map(w => <p key={w} className="text-amber-300">Inspection warning: {w}</p>)}
      </div>

      <details className="mt-2">
        <summary className="cursor-pointer text-sm font-medium text-slate-300 hover:text-white">
          Dependencies & Advisories ({intelligence.dependencies.length})
        </summary>
        <div className="mt-2 max-h-72 overflow-auto rounded border border-slate-800">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950 text-slate-400">
              <tr>
                <th className="p-2">Package</th>
                <th className="p-2">Version / Constraint</th>
                <th className="p-2">Ecosystem</th>
                <th className="p-2">Manifest</th>
                <th className="p-2">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {intelligence.dependencies.map((d, i) => (
                <tr key={i} className="hover:bg-slate-800/40">
                  <td className="p-2 font-mono">{d.name}</td>
                  <td className="p-2">{d.version ?? d.constraint ?? 'Unspecified'}{d.locked ? ' [locked]' : ''}</td>
                  <td className="p-2">{d.ecosystem}</td>
                  <td className="p-2 font-mono text-[11px] text-slate-400">{d.manifest}</td>
                  <td className="p-2">
                    <button
                      className="text-[11px] text-indigo-400 hover:underline"
                      onClick={async () => {
                        const targetVer = prompt(`Propose upgrade version for ${d.name}:`, '');
                        if (targetVer) {
                          try {
                            const res = await API.proposeDependencyUpgrade(repository.id, d.manifest, d.name, targetVer);
                            alert(`Upgrade preview only; not saved or approved. Manifest: ${res.manifest_path}\nStatus: ${res.status}`);
                          } catch (e: any) {
                            alert(`Upgrade proposal failed: ${explain(e)}`);
                          }
                        }
                      }}
                    >
                      Preview Upgrade
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </div>}

    {finished && (
      <div className="space-y-4 bg-slate-900/60 p-4 rounded-lg border border-slate-800">
        <h4 className="font-semibold text-indigo-300">Approved Patch Checks & Conflicts</h4>
        <div className="flex flex-wrap gap-3">
          <button
            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-2 rounded text-slate-200 border border-slate-700"
            onClick={async () => {
              try {
                const conf = await API.getRemediationConflicts(repository.id);
                if (conf.conflict_count === 0) {
                  alert(`No conflicts detected among ${conf.approved_count} patch proposals.`);
                } else {
                  alert(`Warning: ${conf.conflict_count} conflict(s) detected!\n` + conf.conflicts.map(c => `[${c.type}] ${c.file_path}: ${c.description}`).join('\n'));
                }
              } catch (e: any) {
                alert(`Conflict check failed: ${explain(e)}`);
              }
            }}
          >
            Check Patch Conflicts
          </button>

          <button
            className="bg-indigo-600/80 hover:bg-indigo-600 text-xs px-3 py-2 rounded text-white font-medium"
            onClick={async () => {
              try {
                const v = await API.runRepositoryVerification(repository.id);
                alert(`Static checks complete: ${v.overall_status}\n` + v.finding_evaluations.map(r => `${r.status}: ${r.evidence}`).join('\n') + '\nBuild, functional and dynamic tests were not run.');
              } catch (e: any) {
                alert(`Verification failed: ${explain(e)}`);
              }
            }}
          >
            Validate Approved Changes (Static)
          </button>

          <button
            className="bg-slate-800 hover:bg-slate-700 text-xs px-3 py-2 rounded text-slate-200 border border-slate-700"
            onClick={async () => {
              try {
                const html = await API.getRemediationReport(repository.id);
                const w = window.open('', '_blank');
                if (w) {
                  w.document.write(typeof html === 'string' ? html : JSON.stringify(html));
                  w.document.close();
                }
              } catch (e: any) {
                alert(`Failed to load remediation report: ${explain(e)}`);
              }
            }}
          >
            View Printable Remediation Report
          </button>
        </div>
      </div>
    )}

    {finished && <>
      <h4 className="font-bold">Stored findings for this analysis ({findings.data?.length ?? 'Loading'})</h4>
      {findings.isError && <p role="alert">{explain(findings.error)}</p>}
      {findings.data?.length === 0 && <p>No stored findings. Review tool status and coverage above.</p>}
      {findings.data?.map(f => <details className="border border-slate-700 p-3 rounded" key={f.id}><summary>{f.severity} · {f.title}</summary>
        <p>{f.description}</p><p>{f.source} · {f.tool_rule_id} · {f.cwe} · {f.confidence} confidence · {f.status}</p>
        <p>{f.source_location?.file}:{f.source_location?.start_line} {f.source_location?.function && `(${f.source_location.function})`}</p>
        <pre className="text-xs whitespace-pre-wrap break-all overflow-auto">{JSON.stringify(f.evidence, null, 2)}</pre>
        {f.source_location?.file && <button className="underline text-indigo-300" disabled={view.isPending} onClick={() => view.mutate({path: f.source_location!.file!, line: f.source_location?.start_line ?? 1})}>View source context</button>}
      </details>)}
      <details><summary>Source index ({files.data?.length ?? 'Loading'})</summary>
        <input aria-label="Search indexed paths" className="bg-slate-900 p-2 my-2" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search file paths" />
        {files.isError && <p role="alert">{explain(files.error)}</p>}
        <div className="max-h-64 overflow-auto">{files.data?.map(file => <p key={file.path}><button className="underline text-indigo-300" disabled={view.isPending || !file.is_text} onClick={() => view.mutate({path: file.path, line: 1})}>{file.path}</button> · {file.language ?? 'Unclassified'} · {file.functions.length} functions · {file.classes.length} classes · {file.routes.length} route candidates</p>)}</div>
      </details>
    </>}
    {view.isError && <p role="alert" className="text-amber-300">{explain(view.error)}</p>}
    {source && <div><p>{source.path} · source window, redaction enabled</p><pre className="max-h-96 overflow-auto text-sm bg-slate-950 p-3 rounded">{source.content.split('\n').map((text, i) => <div key={i} className={i + source.start_line === source.highlight_line ? 'bg-amber-900/50' : ''}><span className="text-slate-500 select-none mr-4">{i + source.start_line}</span>{text}</div>)}</pre></div>}
  </section>;
}
