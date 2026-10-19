import { useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isAxiosError } from 'axios';
import { API, type RepositoryJob } from '../api';
import RepositoryAnalysis from './RepositoryAnalysis';

function errorMessage(error: unknown): string {
  if (isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === 'string') return detail;
    if (detail && typeof detail.message === 'string') return detail.message;
    if (error.response?.status === 422) return 'Check the project, target, repository name, and authorization confirmation.';
  }
  return 'Request failed. Check backend connectivity and try again.';
}

const inputClass = 'w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-200';

export default function Repositories() {
  const queryClient = useQueryClient();
  const [projectId, setProjectId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [name, setName] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [authorized, setAuthorized] = useState(false);
  const [notice, setNotice] = useState('');
  const [formError, setFormError] = useState('');
  const projects = useQuery({ queryKey: ['projects'], queryFn: API.getProjects });
  const targets = useQuery({ queryKey: ['targets', projectId], queryFn: () => API.getTargets(projectId), enabled: !!projectId });
  const repositories = useQuery({
    queryKey: ['repositories', projectId],
    queryFn: () => API.getRepositories(projectId), enabled: !!projectId,
    refetchInterval: query => query.state.data?.some(r => ['QUEUED', 'RUNNING'].includes(r.ingestion_status) || ['QUEUED', 'RUNNING'].includes(r.analysis_status)) ? 2000 : false,
  });
  const jobs = useQuery({
    queryKey: ['repository-jobs'], queryFn: API.getRepositoryJobs, enabled: !!projectId,
    refetchInterval: query => query.state.data?.some(j => ['QUEUED', 'INITIALIZING', 'RUNNING'].includes(j.status)) ? 2000 : false,
  });
  const selectedTarget = targets.data?.find(t => t.id === targetId);
  const canUpload = selectedTarget?.authorization_status === 'APPROVED' && selectedTarget.is_active;
  const upload = useMutation({
    mutationFn: (selectedFile: File) => API.uploadRepository(targetId, name.trim(), selectedFile),
    onSuccess: data => {
      setNotice(`ZIP accepted. Ingestion job ${data.job_id} is queued. Track its status below.`);
      setFormError('');
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      queryClient.invalidateQueries({ queryKey: ['repository-jobs'] });
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
    onError: error => {
      setFormError(errorMessage(error));
      // A broker failure still has a persisted FAILED or claimed job.
      queryClient.invalidateQueries({ queryKey: ['repositories'] });
      queryClient.invalidateQueries({ queryKey: ['repository-jobs'] });
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setNotice('');
    setFormError('');
    if (!file || !authorized || !canUpload) return;
    if (file.size > 20 * 1024 * 1024) {
      setFormError('Select a ZIP under 20 MiB. Exclude dependencies, virtual environments, and build folders.');
      return;
    }
    upload.mutate(file);
  };
  const repositoryJob = (id: string): RepositoryJob | undefined => jobs.data?.find(j => j.repository_id === id && j.job_type === 'REPOSITORY_INGESTION');

  return (
    <div className="max-w-6xl mx-auto space-y-6 pb-12">
      <h2 className="text-3xl font-bold">Repositories</h2>
      <p className="text-slate-400">Upload authorized source code into a private workspace. After ingestion, run technology detection and real static/secret analysis. Git ingestion remains a future module. Use Web Lab for authorized lab network testing.</p>
      <form onSubmit={submit} className="bg-[#0F1523] border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="grid md:grid-cols-2 gap-4">
          <label>Project
            <select className={inputClass} value={projectId} required disabled={upload.isPending} onChange={e => { setProjectId(e.target.value); setTargetId(''); setNotice(''); setFormError(''); }}>
              <option value="">Select a project</option>
              {projects.data?.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </label>
          <label>Approved target
            <select className={inputClass} value={targetId} required disabled={!projectId || upload.isPending} onChange={e => setTargetId(e.target.value)}>
              <option value="">Select a target</option>
              {targets.data?.map(t => <option key={t.id} value={t.id} disabled={t.authorization_status !== 'APPROVED' || !t.is_active}>{t.name} ({t.authorization_status})</option>)}
            </select>
          </label>
        </div>
        <label className="block">Repository name
          <input className={inputClass} value={name} onChange={e => setName(e.target.value)} required maxLength={120} disabled={upload.isPending} placeholder="Lab application source" />
        </label>
        <label className="block">Source ZIP (maximum 20 MiB)
          <input className={inputClass} type="file" accept=".zip,application/zip" required disabled={upload.isPending} onChange={e => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <p className="text-sm text-slate-400">Exclude node_modules, virtual environments, build output, and real credentials. Files in the ZIP will not be executed.</p>
        <label className="flex items-start gap-3">
          <input type="checkbox" checked={authorized} onChange={e => setAuthorized(e.target.checked)} required disabled={upload.isPending} />
          <span>I am authorized to upload and analyze this application's source code.</span>
        </label>
        <button type="submit" disabled={!canUpload || !file || !authorized || !name.trim() || upload.isPending} className="bg-indigo-600 rounded-lg px-5 py-2 disabled:opacity-40">{upload.isPending ? 'Uploading ZIP…' : 'Upload and ingest ZIP'}</button>
        {projects.isError && <p role="alert" className="text-red-400">{errorMessage(projects.error)}</p>}
        {targets.isError && <p role="alert" className="text-red-400">{errorMessage(targets.error)}</p>}
        {!!projectId && targets.data?.length === 0 && <p>Create and approve a target in Scan Center first.</p>}
        {formError && <p role="alert" className="text-red-400">{formError}</p>}
        {notice && <p role="status" className="text-blue-300">{notice}</p>}
      </form>
      {repositories.isError && <p role="alert" className="text-red-400">{errorMessage(repositories.error)}</p>}
      {jobs.isError && <p role="alert" className="text-red-400">Unable to load ingestion job progress: {errorMessage(jobs.error)}</p>}
      {repositories.isLoading && <p>Loading repositories…</p>}
      {projectId && repositories.data?.length === 0 && <p>No repositories uploaded for this project.</p>}
      {repositories.data?.map(repository => {
        const job = repositoryJob(repository.id);
        return (
          <article key={repository.id} className="bg-[#0F1523] border border-slate-800 rounded-xl p-6 space-y-2">
            <h3 className="text-xl font-bold">{repository.name}</h3>
            <p>Ingestion: <strong>{repository.ingestion_status}</strong> · Analysis: <strong>{repository.analysis_status}</strong></p>
            <p className="text-slate-400">{job ? job.status === 'COMPLETED' ? 'ZIP ingestion completed.' : `${job.current_stage}: ${job.message ?? ''}` : 'Loading job details…'}</p>
            {repository.failure_message && <p role="alert" className="text-red-400">{repository.failure_code}: {repository.failure_message}</p>}
            <p>Uploaded: {(repository.upload_bytes / 1024).toFixed(1)} KiB · Files: {repository.file_count ?? 'Not available'} · Extracted: {repository.extracted_bytes == null ? 'Not available' : `${(repository.extracted_bytes / 1024).toFixed(1)} KiB`}</p>
            <p className="text-xs text-slate-400 break-all">Archive SHA-256: {repository.archive_sha256}</p>
            <p className="text-xs text-slate-400">Repository ID: {repository.id}</p>
            {repository.ingested_at && <p className="text-sm">Ingested: {new Date(repository.ingested_at).toLocaleString()}</p>}
            {repository.ingestion_status === 'READY' && <RepositoryAnalysis repository={repository} />}
          </article>
        );
      })}
    </div>
  );
}
