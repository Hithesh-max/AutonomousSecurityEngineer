import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export interface Project {
  id: string;
  name: string;
  description?: string;
  created_at: string;
}

export interface Target {
  id: string;
  name: string;
  url: string;
  project_id: string;
  authorization_status: string;
  explicit_scope?: string;
  is_active?: boolean;
}

export interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  confidence?: string;
  scan_id?: string | null;
  repository_id?: string | null;
  description?: string | null;
  source?: string | null;
  tool_rule_id?: string | null;
  cwe?: string | null;
  source_location?: { file?: string; start_line?: number; end_line?: number; function?: string; sha256?: string } | null;
  evidence?: Record<string, unknown> | null;
  endpoint?: {method?: string; path?: string} | null;
  parameter?: string | null;
}

export interface Repository {
  id: string;
  project_id: string;
  target_id: string;
  name: string;
  source_type: string;
  ingestion_status: 'QUEUED' | 'RUNNING' | 'READY' | 'FAILED';
  analysis_status: string;
  latest_analysis_job_id?: string | null;
  intelligence?: Intelligence | null;
  archive_sha256: string;
  upload_bytes: number;
  extracted_bytes?: number | null;
  file_count?: number | null;
  ingested_at?: string | null;
  failure_code?: string | null;
  failure_message?: string | null;
}

export interface RepositoryJob {
  id: string;
  repository_id?: string | null;
  job_type: string;
  status: string;
  current_stage: string;
  message?: string | null;
}

export interface SourceFile {
  path: string; language: string | null; language_confidence: string | null; size: number; sha256: string; is_text: boolean;
  functions: {name: string; line: number; end_line?: number}[];
  classes: {name: string; line: number}[];
  imports: string[];
  routes: {path: string; method: string; confidence: string; prefix_resolved: boolean}[];
}
export interface Intelligence {
  languages: {language: string; percentage: number; files: number}[];
  frameworks: {framework: string; confidence: string; evidence: {file: string; kind: string}[]}[];
  dependencies: {name: string; version: string | null; constraint: string | null; ecosystem: string; manifest: string; group: string; locked: boolean}[];
  manifests: {path: string; status: string; dependency_count: number}[];
  warnings: string[];
}
export interface ToolResult {
  tool: string; status: string; version?: string; rule_pack?: string; finding_count: number;
  scanned_files?: number; error_count?: number; failure_code?: string; failure_message?: string; duration_seconds?: number;
}
export interface Analysis {
  id: string; status: string; current_stage: string; message: string | null;
  created_at: string; started_at: string | null; finished_at: string | null;
  failure_code: string | null; failure_message: string | null;
  result: {tools?: ToolResult[]; finding_count?: number; archive_sha256?: string; coverage_note?: string};
}
export interface SourceContext { path: string; start_line: number; end_line: number; highlight_line: number; content: string; redacted: boolean; sha256: string }

export interface WebScan extends Omit<Analysis, 'result'> {
  target_id: string;
  result: {
    configuration?: {profile: string; active_testing: boolean};
    tools?: (ToolResult & {ports?: {port: number; protocol: string; state: string; service: string; product: string; version: string}[]; endpoints?: string[]})[];
    finding_count?: number; target_url?: string; resolved_ip?: string; coverage_note?: string;
    events?: {stage: string; at: string; percent?: number}[];
  };
}


export interface AIStatus { configured: boolean; provider: string | null; model: string; is_mock: boolean; is_external: boolean; reason: string | null }
export interface AIAnalysisRecord {
  id: string; finding_id: string; status: 'COMPLETED' | 'FAILED'; provider: string; model: string; is_mock: boolean; label: string;
  result: null | {
    vulnerability_type: string; cwe: string | null; scanner_cwe: string | null; root_cause: string; security_impact: string;
    evidence_summary: string; recommended_fix: string; preconditions: string[]; confidence: string; limitations: string[];
    affected_location: null | { path: string; start_line: number; end_line: number; highlight_line: number };
  };
  error_code: string | null; error_message: string | null; created_at: string;
}
export interface PatchCheck { status: string; detail?: string; value?: number }
export interface PatchProposalRecord {
  id: string; finding_id: string; analysis_id: string; status: string; is_mock: boolean; label: string; provider: string; model: string;
  source_path: string; source_sha256: string; patch_sha256: string; unified_diff: string; explanation: string; behavior_notes: string | null;
  limitations: string[]; verification_status: string; created_at: string;
  static_checks: Record<string, PatchCheck | string | number>;
}
export interface RemediationSummary {
  finding_id: string; ai: AIStatus;
  source: { available: boolean; path?: string; start_line?: number; end_line?: number; highlight_line?: number; sha256?: string; message?: string };
  analyses: AIAnalysisRecord[]; patches: PatchProposalRecord[];
  events: { event_type: string; from_state: string | null; to_state: string | null; created_at: string }[];
}

export const API = {
  login: async (formData: FormData) => {
    const res = await apiClient.post('/api/auth/token', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return res.data;
  },
  getProjects: () => apiClient.get<Project[]>('/api/projects').then(res => res.data),
  createProject: (data: {name: string, description: string}) => apiClient.post<Project>('/api/projects', data).then(res => res.data),
  getTargets: (projectId?: string) => apiClient.get<Target[]>('/api/targets', { params: { project_id: projectId } }).then(res => res.data),
  createTarget: (data: any) => apiClient.post<Target>('/api/targets', data).then(res => res.data),
  approveTarget: (targetId: string, scope: string) => apiClient.post(`/api/targets/${targetId}/approve?scope=${encodeURIComponent(scope)}`).then(res => res.data),
  revokeTarget: (targetId: string) => apiClient.post(`/api/targets/${targetId}/revoke`).then(res => res.data),
  getFindings: (projectId?: string) => apiClient.get<Finding[]>('/api/findings', { params: { project_id: projectId } }).then(res => res.data),
  triggerScan: (targetId: string, jobType: string = "SECURITY_SCAN") => apiClient.post(`/api/targets/${targetId}/jobs?job_type=${jobType}`).then(res => res.data),
  getJobs: () => apiClient.get('/api/jobs').then(res => res.data),
  triggerAIRemediation: (findingId: string) => apiClient.post(`/api/findings/${findingId}/remediate`).then(res => res.data),
  getRepositories: (projectId: string) => apiClient.get<Repository[]>('/api/repositories', { params: { project_id: projectId } }).then(res => res.data),
  getRepositoryJobs: () => apiClient.get<RepositoryJob[]>('/api/jobs').then(res => res.data),
  uploadRepository: (targetId: string, name: string, file: File) => apiClient.post<{ repository_id: string; job_id: string; message: string }>(
    `/api/targets/${targetId}/repositories/upload`, file,
    { params: { name, source_authorized: true }, headers: { 'Content-Type': 'application/zip' }, timeout: 120000 },
  ).then(res => res.data),
  analyzeRepository: (id: string) => apiClient.post<{job_id: string; message: string}>(`/api/repositories/${id}/analyze`).then(res => res.data),
  getAnalyses: (id: string) => apiClient.get<Analysis[]>(`/api/repositories/${id}/analyses`).then(res => res.data),
  getRepositoryFindings: (id: string, scanId?: string) => apiClient.get<Finding[]>(`/api/repositories/${id}/findings`, {params: {scan_id: scanId}}).then(res => res.data),
  getRepositoryFiles: (id: string, scanId?: string, search?: string) => apiClient.get<SourceFile[]>(`/api/repositories/${id}/files`, {params: {scan_id: scanId, search}}).then(res => res.data),
  getSource: (id: string, scanId: string, path: string, line: number) => apiClient.get<SourceContext>(`/api/repositories/${id}/source`, {params: {scan_id: scanId, path, line}}).then(res => res.data),
  getWebScanConfig: () => apiClient.get<{enabled: boolean; lab_url: string; scope: string}>('/api/web-scans/config').then(res => res.data),
  registerLabTarget: (projectId: string) => apiClient.post<{target_id: string; message: string}>(`/api/projects/${projectId}/lab-target`).then(res => res.data),
  startWebScan: (targetId: string, profile: 'SAFE' | 'STANDARD', active: boolean) => apiClient.post<{job_id: string; message: string}>(`/api/targets/${targetId}/web-scans`, {profile, active_testing: active, active_consent: active}).then(res => res.data),
  getWebScans: (projectId: string) => apiClient.get<WebScan[]>('/api/web-scans', {params: {project_id: projectId}}).then(res => res.data),
  getLabFindingSource: (jobId: string, findingId: string) => apiClient.get<{path:string;start_line:number;end_line:number;highlight_line:number;content:string;sha256:string;mapping_status:string;mapping_note:string}>(`/api/web-scans/${jobId}/findings/${findingId}/lab-source`).then(res => res.data),
  getWebFindings: (jobId: string) => apiClient.get<Finding[]>(`/api/web-scans/${jobId}/findings`).then(res => res.data),
  getRemediationInventory: (repositoryId: string) => apiClient.get<{repository_id:string;scan_id:string|null;total:number;eligible:number;unsupported:number;approved:number;items:{finding_id:string;title:string;severity:string;source:string|null;source_path:string|null;eligible:boolean;reason:string|null;patch_id:string|null;patch_status:string|null;patch_sha256:string|null;analysis_status:string|null;verification_status:string}[]}>(`/api/repositories/${repositoryId}/remediation-inventory`).then(res => res.data),
  getRemediation: (findingId: string) => apiClient.get<RemediationSummary>(`/api/findings/${findingId}/remediation`).then(res => res.data),
  analyzeFinding: (findingId: string, acknowledge: boolean) => apiClient.post<AIAnalysisRecord>(`/api/findings/${findingId}/analysis`, { acknowledge_external_transmission: acknowledge }).then(res => res.data),
  generatePatch: (findingId: string, analysisId: string, acknowledge: boolean) => apiClient.post<PatchProposalRecord>(`/api/findings/${findingId}/patches`, { analysis_id: analysisId, acknowledge_external_transmission: acknowledge }).then(res => res.data),
  approvePatch: (patchId: string, hash: string) => apiClient.post<PatchProposalRecord>(`/api/patches/${patchId}/approve`, {patch_sha256: hash}).then(res => res.data),
  rejectPatch: (patchId: string, hash: string) => apiClient.post<PatchProposalRecord>(`/api/patches/${patchId}/reject`, {patch_sha256: hash}).then(res => res.data),
  verifyPatch: (patchId: string) => apiClient.post<{status:string;message:string;checks:Record<string,{status:string;detail:string}>}>(`/api/patches/${patchId}/verify`).then(res => res.data),
  getCorrectedSource: (patchId: string) => apiClient.get<{path: string; content: string; patched_sha256: string; status: string}>(`/api/patches/${patchId}/corrected-source`).then(res => res.data),
  downloadCorrectedRepository: async (repositoryId: string, patchIds: string[]) => {
    const res = await apiClient.get(`/api/repositories/${repositoryId}/corrected-zip`, {
      params: patchIds.length ? { patch_ids: patchIds.join(',') } : { all_approved: true }, responseType: 'blob', timeout: 120000,
    });
    return res.data as Blob;
  },
  getMetrics: () => apiClient.get('/api/metrics').then(res => res.data),
};
