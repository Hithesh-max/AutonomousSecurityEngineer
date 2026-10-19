import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { Shield, LayoutDashboard, Target, AlertTriangle, Activity, LogOut, Cpu } from 'lucide-react';
import Dashboard from './pages/Dashboard';
import Projects from './pages/Projects';
import ScanCenter from './pages/ScanCenter';
import Findings from './pages/Findings';
import Login from './pages/Login';
import Repositories from './pages/Repositories';
import WebLab from './pages/WebLab';
import SecuritySuite from './pages/SecuritySuite';
import SecureShareDownload from './pages/SecureShareDownload';
import { useAuth } from './AuthContext';

function NavLink({ to, icon: Icon, children }: { to: string, icon: any, children: React.ReactNode }) {
  const location = useLocation();
  const isActive = location.pathname === to;
  return (
    <Link to={to} className={`flex items-center gap-3 p-3 rounded-lg transition-all duration-200 font-medium ${isActive ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 shadow-[0_0_15px_rgba(79,70,229,0.15)]' : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'}`}>
      <Icon size={18} />
      {children}
    </Link>
  );
}

function App() {
  const { token, logout } = useAuth();

  // Share recipients do not need an ASE account; the fragment key stays in their browser.
  if (window.location.pathname.startsWith('/secure-share/')) return <SecureShareDownload />;
  
  if (!token) {
    return <Login />;
  }

  return (
    <Router>
      <div className="min-h-screen bg-[#0B0F19] text-slate-200 flex font-sans selection:bg-indigo-500/30">
        {/* Sidebar */}
        <div className="w-64 bg-[#0F1523] border-r border-slate-800/50 flex flex-col z-10">
          <div className="p-6 flex items-center gap-3 border-b border-slate-800/50">
            <div className="p-2 bg-indigo-500/10 rounded-lg border border-indigo-500/20">
              <Shield className="text-indigo-400" size={24} />
            </div>
            <div>
              <div className="font-bold tracking-wider text-slate-100">ASE <span className="text-indigo-400">PRO</span></div>
              <div className="text-[10px] text-slate-500 uppercase tracking-widest font-semibold">Autonomous Security</div>
            </div>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <NavLink to="/" icon={LayoutDashboard}>Dashboard</NavLink>
            <NavLink to="/projects" icon={Target}>Projects</NavLink>
            <NavLink to="/scans" icon={Activity}>Scan Center</NavLink>
            <NavLink to="/web-lab" icon={Activity}>Web Lab</NavLink>
            <NavLink to="/repositories" icon={Target}>Repositories</NavLink>
            <NavLink to="/findings" icon={AlertTriangle}>Findings</NavLink>
            <NavLink to="/security-suite" icon={Cpu}>Security Suite</NavLink>
          </nav>
        </div>

        {/* Main Content */}
        <div className="flex-1 flex flex-col h-screen overflow-hidden">
          <header className="bg-[#0F1523]/80 backdrop-blur-md border-b border-slate-800/50 p-4 flex justify-between items-center z-0 sticky top-0">
            <h1 className="text-lg font-medium text-slate-300">Command Center</h1>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-3 bg-slate-900/50 px-3 py-1.5 rounded-full border border-slate-800">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                </span>
                <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Interface online</span>
              </div>
              <button onClick={logout} className="p-2 text-slate-400 hover:text-red-400 hover:bg-slate-800/50 rounded-lg transition-colors" title="Logout">
                <LogOut size={18} />
              </button>
            </div>
          </header>
          
          <main className="flex-1 overflow-auto p-8 relative">
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-indigo-900/10 via-[#0B0F19] to-[#0B0F19] pointer-events-none"></div>
            <div className="relative z-10">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/projects" element={<Projects />} />
                <Route path="/scans" element={<ScanCenter />} />
                <Route path="/web-lab" element={<WebLab />} />
                <Route path="/repositories" element={<Repositories />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/security-suite" element={<SecuritySuite />} />
              </Routes>
            </div>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
