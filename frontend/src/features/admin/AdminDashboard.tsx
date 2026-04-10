import React, { useEffect, useState, useCallback } from 'react';
import { Users, DollarSign, TrendingUp, ShieldAlert, Activity, ChevronLeft, ChevronRight } from 'lucide-react';
import api from '../../api/client';

interface PlatformStats {
  mrr: number;
  total_revenue: number;
  user_count: number;
  conversion_rate: number;
}

interface Customer {
  id: string;
  email: string;
  role: string;
  plan: string;
  created_at: string;
}

interface CustomerListResponse {
  items: Customer[];
  page: number;
  per_page: number;
  total: number;
}

const AdminStat = ({ label, value, icon: Icon, color }: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  color: string;
}) => (
  <div className="bg-black border border-white/10 p-6 rounded-2xl">
    <div className="flex justify-between items-start mb-4">
      <div className={`p-2 rounded-lg ${color} bg-opacity-10`}>
        <Icon className={color.replace('bg-', 'text-')} size={24} />
      </div>
    </div>
    <div className="text-gray-500 text-xs font-mono uppercase mb-1">{label}</div>
    <div className="text-3xl font-black text-white">{value}</div>
  </div>
);

const PER_PAGE = 20;

const AdminDashboard = () => {
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [customers, setCustomers] = useState<Customer[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));

  const fetchCustomers = useCallback(async (p: number) => {
    const res = await api.get<CustomerListResponse>(`/api/admin/customers?page=${p}&per_page=${PER_PAGE}`);
    setCustomers(res.data.items);
    setTotal(res.data.total);
  }, []);

  useEffect(() => {
    const fetchStats = async () => {
      const res = await api.get<PlatformStats>('/api/admin/stats');
      setStats(res.data);
    };
    fetchStats();
  }, []);

  useEffect(() => {
    fetchCustomers(page);
  }, [page, fetchCustomers]);

  const handleExportCsv = useCallback(() => {
    const token = localStorage.getItem('olympus_token') ?? '';
    const baseUrl = import.meta.env.VITE_API_BASE_URL ?? '';
    const link = document.createElement('a');
    link.href = `${baseUrl}/api/admin/customers/export`;
    // For API-key-gated downloads we open in a new tab; the browser will
    // handle the Content-Disposition attachment header.  If the endpoint
    // requires an API key header the operator should use curl/wget instead.
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.click();
  }, []);

  if (!stats) return <div className="p-20 font-mono text-cyan-500 animate-pulse">INIT_ADMIN_SESSION...</div>;

  return (
    <div className="min-h-screen bg-[#050505] text-white p-8">
      <header className="mb-12 flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-black tracking-tighter">HQ_COMMAND_CENTER</h1>
          <p className="text-gray-500 font-mono text-sm">Real-time revenue &amp; node oversight</p>
        </div>
        <div className="bg-red-500/10 border border-red-500/50 text-red-500 px-4 py-2 rounded font-bold text-xs flex items-center gap-2">
          <ShieldAlert size={16} /> ADMIN_MODE_ACTIVE
        </div>
      </header>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-12">
        <AdminStat label="Total MRR" value={`$${stats.mrr}`} icon={DollarSign} color="bg-green-500" />
        <AdminStat label="Total Users" value={stats.user_count} icon={Users} color="bg-cyan-500" />
        <AdminStat label="Total Sales" value={`$${stats.total_revenue}`} icon={TrendingUp} color="bg-purple-500" />
        <AdminStat label="Conversion" value={`${stats.conversion_rate.toFixed(1)}%`} icon={Activity} color="bg-orange-500" />
      </div>

      {/* Customer Table */}
      <div className="bg-black border border-white/10 rounded-2xl overflow-hidden">
        <div className="p-6 border-b border-white/10 flex justify-between items-center">
          <h2 className="font-bold font-mono">CUSTOMER_REGISTRY</h2>
          <button onClick={handleExportCsv} className="text-xs text-cyan-400 hover:underline">
            EXPORT_CSV
          </button>
        </div>
        <table className="w-full text-left font-mono text-sm">
          <thead>
            <tr className="bg-white/5 text-gray-500 uppercase text-[10px]">
              <th className="p-4">ID</th>
              <th className="p-4">Identity</th>
              <th className="p-4">Plan_Tier</th>
              <th className="p-4">Join_Date</th>
              <th className="p-4">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {customers.map((user) => (
              <tr key={user.id} className="hover:bg-white/[0.02] transition-colors">
                <td className="p-4 text-gray-500">#{user.id}</td>
                <td className="p-4 font-bold">{user.email}</td>
                <td className="p-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] ${user.plan !== 'free' ? 'bg-cyan-500 text-black' : 'border border-gray-700 text-gray-500'}`}>
                    {user.plan.toUpperCase()}
                  </span>
                </td>
                <td className="p-4 text-gray-400 text-xs">{new Date(user.created_at).toLocaleDateString()}</td>
                <td className="p-4">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                    <span className="text-[10px] text-green-500">ACTIVE</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination Controls */}
        <div className="p-4 border-t border-white/10 flex justify-between items-center text-xs font-mono text-gray-500">
          <span>{total} total customer{total !== 1 ? 's' : ''}</span>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="p-1 rounded hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronLeft size={16} />
            </button>
            <span>
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="p-1 rounded hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
