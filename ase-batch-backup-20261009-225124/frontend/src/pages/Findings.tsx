import React, { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { API } from '../api';
import { AlertTriangle, Download, RefreshCw, Cpu } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import RemediationPanel from '../components/RemediationPanel';
import BulkRemediation from '../components/BulkRemediation';

export default function Findings() {
  const queryClient = useQueryClient();
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: findings = [], isLoading } = useQuery({ 
    queryKey: ['findings'], 
    queryFn: () => API.getFindings() 
  });

  const getSeverityColor = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10 text-red-400 border-red-500/20';
      case 'HIGH': return 'bg-orange-500/10 text-orange-400 border-orange-500/20';
      case 'MEDIUM': return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      default: return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
    }
  };

  const exportToJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(findings, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", "ase_security_report.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-12">
      <div className="flex justify-between items-center mb-8">
        <div className="flex items-center gap-3">
          <AlertTriangle className="text-yellow-500" size={32} />
          <h2 className="text-3xl font-bold text-slate-100">Vulnerability Findings</h2>
        </div>
        <div className="space-x-3 flex">
          <button onClick={exportToJson} className="px-4 py-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg shadow hover:bg-emerald-500 hover:text-white transition-all font-medium text-sm flex items-center gap-2">
            <Download size={16} /> Export JSON
          </button>
          <button onClick={() => queryClient.invalidateQueries({ queryKey: ['findings'] })} className="px-4 py-2 bg-slate-800 text-slate-300 border border-slate-700 rounded-lg shadow hover:bg-slate-700 transition-all font-medium text-sm flex items-center gap-2">
            <RefreshCw size={16} /> Refresh
          </button>
        </div>
      </div>
      
      <BulkRemediation findings={findings} onReview={id => setExpandedId(id)} />
      <div className="bg-[#0F1523] rounded-xl border border-slate-800 shadow-lg overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 text-xs uppercase tracking-wider">
              <th className="p-4">Vulnerability</th>
              <th className="p-4">Severity</th>
              <th className="p-4">Status</th>
              <th className="p-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={4} className="p-12 text-center text-slate-500">Querying database...</td></tr>
            ) : findings.length === 0 ? (
              <tr>
                <td colSpan={4} className="p-16 text-center text-slate-500">
                  <p className="text-lg font-medium">No vulnerabilities found!</p>
                  <p className="text-sm mt-2">Run a scan in the Scan Center to identify issues.</p>
                </td>
              </tr>
            ) : (
              findings.map((f: any) => (
                <React.Fragment key={f.id}>
                  <tr className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 font-medium text-slate-200">{f.title}</td>
                    <td className="p-4">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold border ${getSeverityColor(f.severity)}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className="text-sm text-slate-400 font-bold">{f.status}</span>
                    </td>
                    <td className="p-4 flex gap-3 justify-end">
                      <button 
                        onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                        className="text-indigo-400 hover:text-indigo-300 text-sm font-medium px-3 py-1.5 rounded-lg border border-indigo-500/20 bg-indigo-500/5 hover:bg-indigo-500/10 transition-colors"
                      >
                        {expandedId === f.id ? 'Hide' : 'Details'}
                      </button>
                      <button
                        onClick={() => setExpandedId(f.id)}
                        className="bg-indigo-600/20 text-indigo-300 border border-indigo-500/50 text-sm font-medium px-4 py-1.5 rounded-lg"
                      >Analyze &amp; Suggest Fix</button>
                    </td>
                  </tr>
                  <AnimatePresence>
                    {expandedId === f.id && (
                      <motion.tr 
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="bg-[#0B0F19] border-b border-slate-800"
                      >
                        <td colSpan={4} className="p-6">
                          <div className="mb-6">
                            <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Vulnerability Context (JSON)</h4>
                            <pre className="bg-slate-900 border border-slate-800 text-emerald-400 p-4 rounded-lg text-xs overflow-x-auto font-mono shadow-inner">
                              {JSON.stringify(f.source_location || f.evidence || "No context available.", null, 2)}
                            </pre>
                          </div>
                          <RemediationPanel findingId={f.id} defaultOpen />
                          {f.remediation_plan && (
                            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
                              <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                                <Cpu size={14} />
                                AI Remediation Plan
                              </h4>
                              <div className="bg-indigo-900/10 border border-indigo-500/20 p-5 rounded-lg text-slate-300 whitespace-pre-wrap font-mono text-sm shadow-inner leading-relaxed">
                                {f.remediation_plan}
                              </div>
                            </motion.div>
                          )}
                        </td>
                      </motion.tr>
                    )}
                  </AnimatePresence>
                </React.Fragment>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
