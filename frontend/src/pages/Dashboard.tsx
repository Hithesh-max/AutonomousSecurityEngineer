import { useQuery } from '@tanstack/react-query';
import { API } from '../api';
import { Activity, ShieldCheck, Target, AlertOctagon } from 'lucide-react';
import { motion } from 'framer-motion';

export default function Dashboard() {
  const { data: metrics, isLoading } = useQuery({ 
    queryKey: ['metrics'], 
    queryFn: () => API.getMetrics() 
  });

  if (isLoading) return <div className="p-8 text-center text-slate-400">Initializing telemetry...</div>;
  if (!metrics) return <div className="p-8 text-center text-red-500">Failed to establish connection.</div>;

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div className="flex items-center gap-3 mb-8">
        <Activity className="text-indigo-400" size={32} />
        <h2 className="text-3xl font-bold text-slate-100">Executive Dashboard</h2>
      </div>
      
      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }} className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10"><Target size={64} /></div>
          <p className="text-sm font-semibold text-slate-400 uppercase tracking-widest">Active Projects</p>
          <p className="text-4xl font-bold text-slate-100 mt-2">{metrics.overview.projects}</p>
        </motion.div>
        
        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }} className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10"><Activity size={64} /></div>
          <p className="text-sm font-semibold text-slate-400 uppercase tracking-widest">Monitored Targets</p>
          <p className="text-4xl font-bold text-slate-100 mt-2">{metrics.overview.targets}</p>
        </motion.div>

        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.3 }} className="bg-[#0F1523] p-6 rounded-xl border border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.1)] relative overflow-hidden">
          <div className="absolute top-0 right-0 p-4 opacity-10"><AlertOctagon size={64} /></div>
          <p className="text-sm font-semibold text-slate-400 uppercase tracking-widest">Open Findings</p>
          <p className="text-4xl font-bold text-red-400 mt-2">{metrics.overview.findings}</p>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Severity Breakdown */}
        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.4 }} className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg">
          <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
            <AlertOctagon size={18} className="text-indigo-400" />
            Vulnerability Severity
          </h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center group">
              <span className="flex items-center gap-3 text-slate-300"><div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"></div> Critical</span>
              <span className="font-mono text-lg text-slate-300">{metrics.severity.CRITICAL}</span>
            </div>
            <div className="flex justify-between items-center group">
              <span className="flex items-center gap-3 text-slate-300"><div className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]"></div> High</span>
              <span className="font-mono text-lg text-slate-300">{metrics.severity.HIGH}</span>
            </div>
            <div className="flex justify-between items-center group">
              <span className="flex items-center gap-3 text-slate-300"><div className="w-2 h-2 rounded-full bg-yellow-400 shadow-[0_0_8px_rgba(250,204,21,0.8)]"></div> Medium</span>
              <span className="font-mono text-lg text-slate-300">{metrics.severity.MEDIUM}</span>
            </div>
            <div className="flex justify-between items-center group">
              <span className="flex items-center gap-3 text-slate-300"><div className="w-2 h-2 rounded-full bg-blue-400 shadow-[0_0_8px_rgba(96,165,250,0.8)]"></div> Low</span>
              <span className="font-mono text-lg text-slate-300">{metrics.severity.LOW}</span>
            </div>
          </div>
        </motion.div>

        {/* Remediation Status */}
        <motion.div initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.5 }} className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg flex flex-col justify-between">
          <div>
            <h3 className="text-lg font-bold text-slate-200 mb-6 flex items-center gap-2">
              <ShieldCheck size={18} className="text-emerald-400" />
              Remediation Progress
            </h3>
            <div className="space-y-4">
              <div className="flex justify-between items-center p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                <span className="font-semibold text-red-400">Open / Unresolved</span>
                <span className="font-mono text-2xl text-red-400">{metrics.status.OPEN}</span>
              </div>
              <div className="flex justify-between items-center p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg">
                <span className="font-semibold text-emerald-400">Fixed / Verified</span>
                <span className="font-mono text-2xl text-emerald-400">{metrics.status.FIXED}</span>
              </div>
            </div>
          </div>
          <div className="mt-6 text-xs text-slate-500 flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-slate-500"></div>
            AI Remediation Pipeline Status Unverified
          </div>
        </motion.div>
      </div>
    </div>
  );
}
