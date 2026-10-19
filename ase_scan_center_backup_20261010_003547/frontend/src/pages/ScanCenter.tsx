import React, { useState } from 'react';
import { Crosshair, ShieldCheck, Play, Server, Lock, XCircle, Activity, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { API } from '../api';

export default function ScanCenter() {
  const [projectId, setProjectId] = useState('');
  const [targetName, setTargetName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const queryClient = useQueryClient();

  const { data: projects = [] } = useQuery({ queryKey: ['projects'], queryFn: API.getProjects });
  const { data: targets = [], isLoading } = useQuery({ queryKey: ['targets'], queryFn: () => API.getTargets() });
  
  // Define Job type inline for safety
  interface Job {
      id: string;
      status: string;
      job_type: string;
      current_stage: string;
      message: string;
      failure_code?: string;
      failure_message?: string;
      created_at: string;
      started_at?: string;
      finished_at?: string;
  }

  // Job polling
  const { data: jobs = [], isLoading: jobsLoading } = useQuery({ 
    queryKey: ['jobs'], 
    queryFn: () => API.getJobs(),
    refetchInterval: (query: any) => {
        if (typeof window === 'undefined') return false; // Browser runtime check
        const data = query.state.data as Job[] | undefined;
        // Stop polling if ALL jobs are in a terminal state (COMPLETED, FAILED, CANCELLED)
        const hasActiveJobs = data?.some((job: Job) => ['QUEUED', 'INITIALIZING', 'RUNNING'].includes(job.status));
        return hasActiveJobs ? 2000 : false;
    }
  });

  const createTargetMutation = useMutation({
    mutationFn: (data: any) => API.createTarget(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      setTargetName('');
      setTargetUrl('');
    }
  });

  const approveMutation = useMutation({
    mutationFn: (data: {id: string, scope: string}) => API.approveTarget(data.id, data.scope),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['targets'] }),
    onError: (e: any) => alert(`Approval failed: ${e.response?.data?.detail || e.message}`)
  });

  const revokeMutation = useMutation({
    mutationFn: API.revokeTarget,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['targets'] })
  });

  const scanMutation = useMutation({
    mutationFn: (data: {id: string, job_type: string}) => API.triggerScan(data.id, data.job_type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['jobs'] });
    },
    onError: (error: any) => {
      alert(`Failed to submit job: ${error.response?.data?.detail || error.message}`);
    }
  });

  const handleRegister = (e: React.FormEvent) => {
    e.preventDefault();
    if (projectId && targetName && targetUrl) {
      createTargetMutation.mutate({ project_id: projectId, name: targetName, url: targetUrl });
    }
  };

  const handleApprove = (targetId: string) => {
    const scope = prompt("Enter explicit scope (e.g., api.example.com):");
    if (scope && scope.trim() !== "" && scope.trim() !== "*") {
      approveMutation.mutate({ id: targetId, scope });
    } else {
      alert("Invalid scope. Cannot be empty or '*'");
    }
  };

  const startLiveScan = (target: any, type: string = "SECURITY_SCAN") => {
    scanMutation.mutate({ id: target.id, job_type: type });
  };
  
  const formatDate = (dateString: string | null | undefined) => {
      if (!dateString) return '-';
      return new Date(dateString).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-12">
      <div className="flex items-center gap-3 mb-8">
        <Crosshair className="text-red-400" size={32} />
        <h2 className="text-3xl font-bold text-slate-100">Scan Center</h2>
      </div>
      
      <div className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-5"><Server size={120} /></div>
        <h3 className="text-lg font-bold mb-4 text-slate-200">Register New Target</h3>
        <form onSubmit={handleRegister} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end relative z-10">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Project</label>
            <select value={projectId} onChange={e => setProjectId(e.target.value)} className="w-full p-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 focus:ring-2 focus:ring-indigo-500 outline-none" required>
              <option value="">Select Project...</option>
              {(projects as any[]).map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Target Name</label>
            <input type="text" value={targetName} onChange={e => setTargetName(e.target.value)} className="w-full p-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="E.g., Payment API" required />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Target URL</label>
            <input type="url" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} className="w-full p-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="https://api.example.com" required />
          </div>
          <button type="submit" disabled={createTargetMutation.isPending} className="bg-indigo-600 text-white px-4 py-2.5 rounded-lg hover:bg-indigo-700 transition shadow-[0_0_15px_rgba(79,70,229,0.4)] font-medium flex justify-center items-center gap-2">
            <Crosshair size={18} />
            {createTargetMutation.isPending ? 'Registering...' : 'Lock Target'}
          </button>
        </form>
      </div>

      <div className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg">
        <h3 className="text-lg font-bold mb-6 text-slate-200 flex items-center gap-2"><Lock size={18} className="text-indigo-400"/> Locked Targets</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900 text-slate-400 text-xs uppercase tracking-wider">
                <th className="p-4 rounded-tl-lg">Name</th>
                <th className="p-4">URL</th>
                <th className="p-4">Auth Status</th>
                <th className="p-4">Scope</th>
                <th className="p-4 rounded-tr-lg text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={5} className="p-8 text-center text-slate-500">Scanning databanks...</td></tr>
              ) : (targets as any[]).length === 0 ? (
                <tr><td colSpan={5} className="p-12 text-center text-slate-500">No targets registered yet.</td></tr>
              ) : (
                (targets as any[]).map((t: any) => {
                  const isApproved = t.authorization_status === 'APPROVED' && t.is_active;
                  return (
                    <tr key={t.id} className="hover:bg-slate-800/50 text-sm border-b border-slate-800/50 transition-colors">
                      <td className="p-4 font-medium text-slate-200">{t.name}</td>
                      <td className="p-4 text-slate-400 font-mono text-xs">{t.url}</td>
                      <td className="p-4">
                        <span className={`px-2.5 py-1 text-[10px] uppercase tracking-wider font-bold rounded-full ${
                          t.authorization_status === 'APPROVED' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 
                          t.authorization_status === 'REJECTED' ? 'bg-red-500/10 text-red-500 border-red-500/20' : 
                          'bg-yellow-500/10 text-yellow-500 border border-yellow-500/20'
                        }`}>
                          {t.authorization_status}
                        </span>
                      </td>
                      <td className="p-4 text-slate-400 font-mono text-xs">{t.explicit_scope || 'N/A'}</td>
                      <td className="p-4 flex gap-2 justify-end">
                        {t.authorization_status !== 'APPROVED' ? (
                          <button onClick={() => handleApprove(t.id)} className="p-2 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500 hover:text-white rounded transition" title="Approve">
                            <ShieldCheck size={16} />
                          </button>
                        ) : (
                          <button onClick={() => revokeMutation.mutate(t.id)} className="p-2 bg-slate-700/50 text-slate-400 hover:bg-red-500 hover:text-white rounded transition" title="Revoke">
                            <XCircle size={16} />
                          </button>
                        )}
                        
                        <button 
                          onClick={() => startLiveScan(t, "DIAGNOSTIC")}
                          disabled={!isApproved || scanMutation.isPending}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
                            isApproved 
                              ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30 hover:bg-blue-500 hover:text-white shadow-[0_0_10px_rgba(59,130,246,0.2)]' 
                              : 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed opacity-50'
                          }`}>
                          <Activity size={12} />
                          DIAGNOSTIC
                        </button>

                        <button 
                          onClick={() => startLiveScan(t, "SECURITY_SCAN")}
                          disabled={!isApproved || scanMutation.isPending}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
                            isApproved 
                              ? 'bg-red-500/10 text-red-400 border border-red-500/30 hover:bg-red-500 hover:text-white shadow-[0_0_10px_rgba(239,68,68,0.2)]' 
                              : 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed opacity-50'
                          }`}>
                          <Play size={12} fill={isApproved ? "currentColor" : "none"} />
                          SCAN
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
      
      {/* Background Jobs Tracking */}
      <div className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg">
        <h3 className="text-lg font-bold mb-6 text-slate-200 flex items-center gap-2"><Activity size={18} className="text-indigo-400"/> Background Jobs</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-slate-900 text-slate-400 text-xs uppercase tracking-wider">
                <th className="p-4 rounded-tl-lg">Job ID</th>
                <th className="p-4">Type</th>
                <th className="p-4">Status / Stage</th>
                <th className="p-4">Message</th>
                <th className="p-4">Created</th>
                <th className="p-4">Started</th>
                <th className="p-4 rounded-tr-lg">Finished</th>
              </tr>
            </thead>
            <tbody>
              {jobsLoading ? (
                <tr><td colSpan={7} className="p-8 text-center text-slate-500">Loading jobs...</td></tr>
              ) : (jobs as Job[]).length === 0 ? (
                <tr><td colSpan={7} className="p-12 text-center text-slate-500">No background jobs executed yet.</td></tr>
              ) : (
                (jobs as Job[]).map((job: Job) => (
                  <tr key={job.id} className="hover:bg-slate-800/50 text-sm border-b border-slate-800/50 transition-colors">
                    <td className="p-4 text-slate-400 font-mono text-[10px] uppercase truncate max-w-[80px]" title={job.id}>{job.id.split('-')[0]}...</td>
                    <td className="p-4 text-slate-300 font-bold text-xs">{job.job_type}</td>
                    <td className="p-4">
                      <div className="flex items-center gap-2">
                         {job.status === 'COMPLETED' && <CheckCircle size={14} className="text-emerald-500" />}
                         {job.status === 'FAILED' && <AlertCircle size={14} className="text-red-500" />}
                         {job.status === 'QUEUED' && <Clock size={14} className="text-yellow-500" />}
                         {job.status === 'RUNNING' && <Activity size={14} className="text-blue-500 animate-pulse" />}
                         <div>
                           <div className={`text-xs font-bold ${
                              job.status === 'COMPLETED' ? 'text-emerald-500' :
                              job.status === 'FAILED' ? 'text-red-500' :
                              job.status === 'RUNNING' ? 'text-blue-500' : 'text-yellow-500'
                           }`}>{job.status}</div>
                           <div className="text-[10px] text-slate-400 font-mono uppercase">{job.current_stage}</div>
                         </div>
                      </div>
                    </td>
                    <td className="p-4 text-slate-300 text-xs">
                        {job.message}
                        {job.failure_message && (
                            <div className="mt-1 text-red-400 font-mono text-[10px] break-words">
                                ERROR: {job.failure_code} - {job.failure_message}
                            </div>
                        )}
                    </td>
                    <td className="p-4 text-slate-400 font-mono text-xs">{formatDate(job.created_at)}</td>
                    <td className="p-4 text-slate-400 font-mono text-xs">{formatDate(job.started_at)}</td>
                    <td className="p-4 text-slate-400 font-mono text-xs">{formatDate(job.finished_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
