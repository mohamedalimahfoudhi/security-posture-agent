import React, { useState, useEffect, useCallback } from 'react';
import { Database, ShieldAlert, Server, Globe, Search, Building2, Lock } from 'lucide-react';
import { getAssets } from '../api/client';
import Panel from './ui/Panel';
import MetricBlock from './ui/MetricBlock';
import DataTable from './ui/DataTable';
import FilterBar from './ui/FilterBar';
import EmptyState from './ui/EmptyState';
import RiskIndicator from './ui/RiskIndicator';
import SeverityBadge from './ui/SeverityBadge';

export default function TechnologyInventory({ customerId }) {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState({
    owner: { value: 'ALL', options: [
      { value: 'ALL', label: 'All Owners' },
      { value: 'CUSTOMER', label: 'Customer-Owned' },
      { value: 'THIRD_PARTY', label: 'Third-Party' }
    ]},
    status: { value: 'ALL', options: [
      { value: 'ALL', label: 'All Statuses' },
      { value: 'EXPOSED', label: 'Exposed' },
      { value: 'CLEAN', label: 'Clean' }
    ]}
  });

  const loadAssets = useCallback(async () => {
    if (!customerId) {
      setAssets([]);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const data = await getAssets(customerId);
      
      let items = [];
      if (Array.isArray(data)) {
        items = data;
      } else if (data && typeof data === 'object') {
        items = data.assets || data.data || [];
      }
      
      setAssets(items);
      setError(null);
    } catch (err) {
      setError('Failed to load technology inventory: ' + err.message);
      setAssets([]);
    } finally {
      setLoading(false);
    }
  }, [customerId]);

  useEffect(() => {
    loadAssets();
  }, [customerId, loadAssets]);

  const totalAssets = assets.length;
  const customerAssets = assets.filter(a => a.vendor_id === null).length;
  const thirdPartyAssets = assets.filter(a => a.vendor_id !== null).length;
  const exposedAssets = assets.filter(a => a.internet_exposed === true).length;

  const filteredAssets = assets.filter(a => {
    const term = search.toLowerCase();
    const matchesSearch = 
      (a.technology || '').toLowerCase().includes(term) || 
      (a.vendor || '').toLowerCase().includes(term) ||
      (a.category || '').toLowerCase().includes(term);
      
    const isCustomer = a.vendor_id === null;
    const matchesOwner = filters.owner.value === 'ALL' || 
                         (filters.owner.value === 'CUSTOMER' && isCustomer) || 
                         (filters.owner.value === 'THIRD_PARTY' && !isCustomer);
                         
    const isExposed = a.internet_exposed === true;
    const matchesStatus = filters.status.value === 'ALL' ||
                          (filters.status.value === 'EXPOSED' && isExposed) ||
                          (filters.status.value === 'CLEAN' && !isExposed);
    
    return matchesSearch && matchesOwner && matchesStatus;
  });

  const handleFilterChange = (key, val) => {
    setFilters(prev => ({ ...prev, [key]: { ...prev[key], value: val } }));
  };

  return (
    <div className="flex flex-col h-full space-y-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-display font-semibold text-ink uppercase tracking-wide">TECHNOLOGY INVENTORY</h1>
        <p className="text-sm text-mist font-body mt-1">Ecosystem architecture, third-party dependencies, and customer infrastructure.</p>
      </div>


      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 flex-none">
        <MetricBlock label="TOTAL TECHNOLOGIES" value={totalAssets} highlight />
        <MetricBlock label="THIRD-PARTY DEPENDENCIES" value={thirdPartyAssets} highlight={thirdPartyAssets > 0} />
        <MetricBlock label="CUSTOMER INFRASTRUCTURE" value={customerAssets} highlight={customerAssets > 0} />
        <MetricBlock label="EXPOSED ASSETS" value={exposedAssets} highlight={exposedAssets > 0} />
      </div>

      <Panel className="flex-1 flex flex-col min-h-0">
        <FilterBar 
          search={search} 
          onSearchChange={setSearch} 
          filters={filters} 
          onFilterChange={handleFilterChange} 
          placeholder="Search technologies, vendors, categories..."
        />
        
        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="animate-pulse text-mist">Loading architecture intelligence...</div>
          </div>
        ) : error ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-sev-critical font-bold">Error: {error}</div>
          </div>
        ) : (
          <div className="flex-1 overflow-auto mt-4 custom-scrollbar">
            <DataTable 
              headers={['TECHNOLOGY', 'VERSION', 'OWNER', 'VENDOR', 'CATEGORY', 'CRITICALITY', 'RISK', 'EXPOSED', 'SENSITIVE', 'ALERTS', 'CONFIDENCE']}
              emptyMessage={assets.length === 0 ? "No technologies found." : "No technologies match the selected filters."}
            >
              {filteredAssets.map(a => {
                const isCustomer = a.vendor_id === null;
                
                return (
                  <tr key={a.id} className="hover:bg-void cursor-pointer transition-colors group">
                    <td className="px-3 py-2 font-medium text-ink flex items-center gap-2 group-hover:text-viz-blue">
                      <Server className="w-3.5 h-3.5 text-viz-blue" />
                      {a.technology}
                    </td>
                    <td className="px-3 py-2 text-xs text-mist font-mono">
                      {a.version || '—'}
                    </td>
                    <td className="px-3 py-2">
                      <span className="flex items-center gap-1.5 text-[10px] font-bold text-mist tracking-widest uppercase">
                        {isCustomer ? <Globe className="w-3 h-3 text-viz-teal" /> : <Building2 className="w-3 h-3 text-viz-blue" />}
                        {isCustomer ? 'CUSTOMER' : 'THIRD-PARTY'}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-xs text-mist font-medium truncate max-w-[150px]" title={isCustomer ? 'Internal' : (a.vendor || 'Unknown')}>
                      {isCustomer ? 'Internal' : (a.vendor || 'Unknown')}
                    </td>
                    <td className="px-3 py-2 text-[10px] text-mist font-mono uppercase tracking-widest">
                      {a.category || '—'}
                    </td>
                    <td className="px-3 py-2">
                      <SeverityBadge severity={a.criticality} />
                    </td>
                    <td className="px-3 py-2">
                      <RiskIndicator score={a.risk_score != null ? a.risk_score : (a.criticality === 'CRITICAL' ? 90 : a.criticality === 'HIGH' ? 70 : a.criticality === 'MEDIUM' ? 50 : 30)} />
                    </td>
                    <td className="px-3 py-2">
                      {a.internet_exposed ? (
                        <span className="text-[9px] text-sev-critical bg-sev-critical/10 border border-sev-critical/30 px-2 py-0.5 rounded font-bold tracking-widest uppercase flex items-center gap-1">
                          <Globe className="w-2.5 h-2.5" /> YES
                        </span>
                      ) : (
                        <span className="text-[9px] text-sev-low bg-sev-low/10 border border-sev-low/30 px-2 py-0.5 rounded font-bold tracking-widest uppercase flex items-center gap-1">
                          <Lock className="w-2.5 h-2.5" /> NO
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {a.sensitive_data ? (
                        <span className="text-[9px] text-ember-bright bg-ember-bright/10 border border-ember-bright/30 px-2 py-0.5 rounded font-bold tracking-widest uppercase flex items-center gap-1">
                          <ShieldAlert className="w-2.5 h-2.5" /> YES
                        </span>
                      ) : (
                        <span className="text-[9px] text-mist bg-void border border-hairline px-2 py-0.5 rounded font-bold tracking-widest uppercase">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {a.alerts_count > 0 ? (
                        <span className="text-ember-bright font-bold text-xs">{a.alerts_count}</span>
                      ) : (
                        <span className="text-mist text-xs font-mono">0</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-mist font-mono">
                      {a.confidence ? `${a.confidence}%` : '—'}
                    </td>
                  </tr>
                );
              })}
            </DataTable>
          </div>
        )}
      </Panel>
    </div>
  );
}
