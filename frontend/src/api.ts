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

export type RemediationBatch = {id:string; repository_id:string; scan_id:string; status:string; mode:string; processed:number; total:number; message:string|null; items:{finding_id:string;title:string;status:string;detail?:string}[]};
export interface DependencyAdvisory {
  id: string;
  cve?: string;
  summary?: string;
  severity?: string;
  fixed_in?: string;
  source?: string;
}

export interface DependencyItem {
  name: string;
  version: string | null;
  constraint: string | null;
  ecosystem: string;
  manifest: string;
  group: string;
  locked: boolean;
  advisories?: DependencyAdvisory[];
}

export interface DependencyListResponse {
  repository_id: string;
  advisory_status: string;
  advisory_source: string;
  timestamp: string;
  total_dependencies: number;
  vulnerable_count: number;
  dependencies: DependencyItem[];
}

export interface DependencyUpgradeResponse {
  dependency_name: string;
  current_version: string | null;
  target_version: string;
  manifest_path: string;
  status: string;
  unified_diff: string;
  patch_proposal_id?: string | null;
}

export interface RemediationConflict {
  type: string; file_path: string; description: string; patch_ids: string[];
}
export interface RemediationConflictsResponse {
  repository_id: string; approved_count: number; conflict_count: number;
  conflicts: RemediationConflict[];
}

export interface VerificationResultItem {
  patch_id: string;
  file_path: string;
  syntax_valid: boolean;
  syntax_message?: string;
  build_outcome: string;
  test_outcome: string;
  security_outcome: string;
  overall_classification: 'VERIFIED_FIXED' | 'STILL_VULNERABLE' | 'REGRESSION' | 'FAILED' | 'UNSUPPORTED' | 'INCONCLUSIVE';
  summary: string;
}

export interface RepositoryVerificationResponse {
  overall_status: string;
  finding_evaluations: {finding_id: string; status: string; evidence: string}[];
  build_result: {status: string; reason: string};
  test_result: {status: string; reason: string};
  coverage_limitations: string[];
}
export interface OpenApiImportResponse {
  title: string; spec_version: string; api_version: string; total_endpoints: number;
  bola_candidates: number; bfla_candidates: number;
  endpoints: {method: string; path: string; security_required: boolean; bola_candidate: boolean; bfla_candidate: boolean}[];
}
export interface ApiAuthTestResponse {
  target_base_url: string; tested_endpoints_count: number; vulnerable_count: number;
  secure_count: number; inconclusive_count: number; limitations: string[];
  results: {test_type: string; endpoint: string; method: string; status: string; evidence: string}[];
}
export interface BenchmarkEvaluationResponse {
  evaluation_mode: string;
  metrics: {precision: number; recall: number; f1_score: number; accuracy: number};
  confusion_matrix: {true_positives: number; false_positives: number; true_negatives: number; false_negatives: number; total_samples: number};
  evaluation_details: {sample_id: string; title: string; ground_truth: string; detected: boolean; correct: boolean}[];
  sample_limitations: string[];
}
export interface CrossToolCorrelationResponse {
  project_id: string; total_findings: number; total_locations: number; locations_with_divergence: number;
  correlated_items: {location: string; tools_involved: string[]; finding_count: number; severities: string[]; divergence_detected: boolean}[];
  provenance_policy: string;
}
export interface NodeTransferPackage {
  transfer_id: string; media_type: string; sender_node: string; receiver_node: string;
  nonce_b64: string; ciphertext_b64: string; associated_data: string; original_sha256: string;
  original_size_bytes: number; performance: {encryption_latency_ms: number; throughput_mb_per_sec: number};
}
export interface NodeReceiveResponse {
  transfer_id: string; media_type: string; payload_b64: string; integrity_verified: boolean;
  verified_sha256: string; decryption_latency_ms: number;
}
export interface SecurityEvaluationResponse {
  confidentiality: {status: string; redaction_effective: boolean};
  integrity: {status: string; tampering_detected_and_rejected: boolean};
  authentication_and_accountability: {authentication_status: string; accountability_status: string};
  performance: {cpu_usage_percent: number | null; ram_resident_set_mb: number | null; encryption_throughput_mb_per_sec: number; '1mb_encryption_latency_ms': number; '1mb_decryption_latency_ms': number};
  limitations: string[];
}

export const API = {
  getProjectDiff: (id:string) => apiClient.get<{files:{path:string;diff:string}[]}>(`/api/repositories/${id}/remediation-diff`).then(r=>r.data),
  getRemediationBatches: (id:string) => apiClient.get<RemediationBatch[]>(`/api/repositories/${id}/remediation-batches`).then(r=>r.data),
  startRemediationBatch: (id:string, mode:'ANALYZE'|'PROPOSE', consent:boolean) => apiClient.post<RemediationBatch>(`/api/repositories/${id}/remediation-batches`, {mode,acknowledge_external_transmission:consent}).then(r=>r.data),
  controlRemediationBatch: (id:string, action:'pause'|'resume') => apiClient.post<RemediationBatch>(`/api/remediation-batches/${id}/${action}`).then(r=>r.data),
  revokePatch: (id:string, hash:string) => apiClient.post(`/api/patches/${id}/revoke`, {patch_sha256:hash}).then(r=>r.data),
  getRemediationReport: (id:string) => apiClient.get(`/api/repositories/${id}/remediation-report`).then(r=>r.data),
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
  getFindings: (projectId?: string, repositoryId?: string) => apiClient.get<Finding[]>('/api/findings', { params: { project_id: projectId, repository_id: repositoryId || undefined } }).then(res => res.data),
  triggerScan: (targetId: string, jobType: string = "SECURITY_SCAN") => apiClient.post(`/api/targets/${targetId}/jobs?job_type=${jobType}`).then(res => res.data),
  getJobs: () => apiClient.get('/api/jobs').then(res => res.data),
  triggerAIRemediation: (findingId: string) => apiClient.post(`/api/findings/${findingId}/remediate`).then(res => res.data),
  getRepositories: (projectId?: string) => apiClient.get<Repository[]>('/api/repositories', { params: { project_id: projectId } }).then(res => res.data),
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
  registerDeployedTarget: (projectId: string, data: { name: string; url: string; explicit_scope: string; ownership_declaration: string }) => apiClient.post<{ target_id: string; name: string; url: string; explicit_scope: string; authorization_status: string; message: string }>(`/api/projects/${projectId}/deployed-target`, data).then(res => res.data),
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
  getCorrectedSource: (patchId: string) => apiClient.get<{path: string; content: string; original_content:string; patched_sha256: string; status: string}>(`/api/patches/${patchId}/corrected-source`).then(res => res.data),
  downloadCorrectedRepository: async (repositoryId: string, patchIds: string[]) => {
    const res = await apiClient.get(`/api/repositories/${repositoryId}/corrected-zip`, {
      params: patchIds.length ? { patch_ids: patchIds.join(',') } : { all_approved: true }, responseType: 'blob', timeout: 120000,
    });
    return res.data as Blob;
  },
  createSecureShare: (ciphertext: Blob, readerToken: string) => apiClient.post<{id:string;expires_at:string;max_downloads:number;encryption:string}>(
    '/api/secure-shares', ciphertext,
    {headers: {'Content-Type': 'application/octet-stream', 'X-Share-Token': readerToken}, timeout: 120000},
  ).then(res => res.data),
  downloadSecureShareCiphertext: (shareId: string, readerToken: string) => apiClient.get<ArrayBuffer>(
    `/api/secure-shares/${shareId}/ciphertext`, {headers: {'X-Share-Token': readerToken}, responseType: 'arraybuffer', timeout: 120000},
  ).then(res => res.data),
  revokeSecureShare: (shareId: string) => apiClient.delete<void>(`/api/secure-shares/${shareId}`).then(res => res.data),
  getMetrics: () => apiClient.get('/api/metrics').then(res => res.data),
  // Supply Chain & SBOM
  getSbom: (repoId: string, format: 'cyclonedx' | 'spdx' = 'cyclonedx') => apiClient.get<Record<string, unknown>>(`/api/repositories/${repoId}/sbom`, { params: { format } }).then(res => res.data),
  getDependencies: (repoId: string, refreshAdvisories: boolean = false) => apiClient.get<DependencyListResponse>(`/api/repositories/${repoId}/dependencies`, { params: { refresh_advisories: refreshAdvisories } }).then(res => res.data),
  proposeDependencyUpgrade: (repoId: string, manifestPath: string, depName: string, targetVersion: string) => apiClient.post<DependencyUpgradeResponse>(`/api/repositories/${repoId}/dependency-upgrade`, { manifest_path: manifestPath, package_name: depName, target_version: targetVersion }).then(res => res.data),
  // Remediation Conflicts & Sandbox Verification
  getRemediationConflicts: (repoId: string) => apiClient.get<RemediationConflictsResponse>(`/api/repositories/${repoId}/remediation-conflicts`).then(res => res.data),
  runRepositoryVerification: (repoId: string, patchIds?: string[], testCommand?: string) => apiClient.post<RepositoryVerificationResponse>(`/api/repositories/${repoId}/verify`, { patch_ids: patchIds, test_command: testCommand }, {timeout: 120000}).then(res => res.data),
  // API Security & OpenAPI
  importOpenApi: (projectId: string, targetId: string, file: File) => {
    const fd = new FormData();
    fd.append('file', file);
    return apiClient.post<OpenApiImportResponse>(`/api/projects/${projectId}/openapi-import`, fd, { params: { target_id: targetId }, headers: { 'Content-Type': 'multipart/form-data' } }).then(res => res.data);
  },
  runApiAuthTest: (projectId: string, targetId: string, specContent: string, userAToken: string, userBToken: string, adminToken: string, resourceId: string) => apiClient.post<ApiAuthTestResponse>(`/api/projects/${projectId}/api-auth-test`, {spec_content: specContent, user_a_token: userAToken, user_b_token: userBToken, admin_token: adminToken, resource_id: resourceId}, { params: { target_id: targetId }, timeout: 120000 }).then(res => res.data),
  // Evaluation & Benchmark
  getBenchmarkCases: () => apiClient.get<{ total_samples: number; vulnerable_count: number; benign_count: number; samples: Record<string, unknown>[] }>('/api/evaluation/benchmark').then(res => res.data),
  runBenchmarkEvaluation: (runMockScanners: boolean = false) => apiClient.post<BenchmarkEvaluationResponse>('/api/evaluation/evaluate', null, { params: { run_mock_scanners: runMockScanners } }).then(res => res.data),
  getCrossToolCorrelation: (projectId: string) => apiClient.get<CrossToolCorrelationResponse>(`/api/projects/${projectId}/cross-tool-correlation`).then(res => res.data),
  // Collaboration, Node Transfer & CIA+AA Evaluation
  sendNodeTransfer: (data: {sender_node: string; receiver_node: string; media_type: string; payload_b64: string; shared_key_seed: string}) => apiClient.post<NodeTransferPackage>('/api/collaboration/node-transfer', data).then(res => res.data),
  receiveNodeTransfer: (data: { packet: NodeTransferPackage; shared_key_seed: string }) => apiClient.post<NodeReceiveResponse>('/api/collaboration/node-receive', data).then(res => res.data),
  getAuditLog: () => apiClient.get<any[]>('/api/collaboration/audit-log').then(res => res.data),
  getSecurityEvaluation: () => apiClient.get<SecurityEvaluationResponse>('/api/collaboration/security-evaluation').then(res => res.data),
};
