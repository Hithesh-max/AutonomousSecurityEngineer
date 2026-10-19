import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { API } from '../api';
import { Folder, Plus, LayoutGrid } from 'lucide-react';

export default function Projects() {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  const { data: projects = [], isLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: API.getProjects
  });

  const createMutation = useMutation({
    mutationFn: API.createProject,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['projects'] });
      setName('');
      setDescription('');
    }
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (name) createMutation.mutate({ name, description });
  };

  return (
    <div className="max-w-6xl mx-auto space-y-8 pb-12">
      <div className="flex items-center gap-3 mb-8">
        <LayoutGrid className="text-blue-400" size={32} />
        <h2 className="text-3xl font-bold text-slate-100">Projects Workspace</h2>
      </div>
      
      <div className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 shadow-lg relative overflow-hidden">
        <h3 className="text-lg font-bold mb-4 text-slate-200">Create New Project</h3>
        <form onSubmit={handleSubmit} className="flex gap-4 items-end relative z-10">
          <div className="flex-1">
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Project Name</label>
            <input type="text" value={name} onChange={e => setName(e.target.value)} className="w-full p-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="E.g., Production E-Commerce" required />
          </div>
          <div className="flex-1">
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Description</label>
            <input type="text" value={description} onChange={e => setDescription(e.target.value)} className="w-full p-2.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-600 focus:ring-2 focus:ring-indigo-500 outline-none" placeholder="Internal microservices..." />
          </div>
          <button type="submit" disabled={createMutation.isPending} className="bg-indigo-600 text-white px-6 py-2.5 rounded-lg hover:bg-indigo-700 transition shadow-[0_0_15px_rgba(79,70,229,0.4)] font-medium flex items-center gap-2">
            <Plus size={18} />
            {createMutation.isPending ? 'Creating...' : 'Create Project'}
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {isLoading ? (
          <p className="text-slate-500 p-4">Loading projects...</p>
        ) : projects.length === 0 ? (
          <p className="text-slate-500 col-span-3 text-center py-12 border border-dashed border-slate-700 rounded-xl">No projects found. Create one above!</p>
        ) : (
          projects.map((p: any) => (
            <div key={p.id} className="bg-[#0F1523] p-6 rounded-xl border border-slate-800 hover:border-indigo-500/50 shadow-lg hover:shadow-[0_0_20px_rgba(79,70,229,0.15)] transition-all group">
              <div className="flex items-start justify-between mb-4">
                <div className="p-3 bg-blue-500/10 rounded-lg text-blue-400 group-hover:bg-indigo-500/20 group-hover:text-indigo-400 transition-colors">
                  <Folder size={24} />
                </div>
                <div className="text-[10px] text-slate-600 font-mono">ID: {p.id.split('-')[0]}</div>
              </div>
              <h4 className="text-xl font-bold text-slate-200 mb-2">{p.name}</h4>
              <p className="text-slate-400 text-sm mb-4">{p.description || "No description provided."}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
