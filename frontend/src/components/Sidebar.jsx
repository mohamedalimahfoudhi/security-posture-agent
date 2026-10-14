import { useState, useEffect } from 'react';
import { 
  LayoutDashboard, 
  AlertTriangle, 
  Search, 
  Users, 
  Building2, 
  Bot, 
  FileText, 
  Settings,
  Upload,
  Database,
  ChevronDown,
  Building,
  Shield,
  ShieldAlert
} from 'lucide-react';
import logo from '../assets/shield-logo.svg';
import { getAllCustomers } from '../api/client';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
  { id: '3rd-party', label: 'Third Parties', icon: Building2 },
  { id: 'data-breaches', label: 'Data Breaches', icon: ShieldAlert },
  { id: 'threat-feed', label: 'Threat Feed', icon: Search },
  { id: 'technology-inventory', label: 'Technologies', icon: Database },
  { id: 'customers', label: 'Customers', icon: Users, adminOnly: true },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'weekly-digest', label: 'Weekly Digest', icon: FileText },
  { id: 'ai-assist', label: 'AI Assist', icon: Bot },
  { id: 'settings', label: 'Settings', icon: Settings, adminOnly: true },
];

export default function Sidebar({ activeNav = 'dashboard', onNavChange, role, selectedCustomerId, onCustomerChange }) {
  const [customers, setCustomers] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [selectedCustomer, setSelectedCustomer] = useState(null);

  useEffect(() => {
    if (role === 'Admin') {
      getAllCustomers()
        .then(data => {
          setCustomers(data);
          if (selectedCustomerId) {
            const found = data.find(c => c.id === selectedCustomerId);
            if (found) setSelectedCustomer(found);
          }
        })
        .catch(() => {/* ignore errors loading customer list */});
    }
  }, [role]);

  useEffect(() => {
    if (customers.length > 0 && selectedCustomerId) {
      const found = customers.find(c => c.id === selectedCustomerId);
      if (found) setSelectedCustomer(found);
    }
  }, [selectedCustomerId, customers]);

  const handleSelectCustomer = (customer) => {
    setSelectedCustomer(customer);
    setDropdownOpen(false);
    setSearchQuery('');
    onCustomerChange?.(customer.id);
  };

  const filteredCustomers = customers.filter(c => 
    c.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <aside className="w-60 bg-bg-base border-r border-border-base flex flex-col">
      {/* Logo */}
      <div className="p-4 border-b border-border-base shrink-0">
        <img 
          src={logo} 
          alt="Security Posture Agent" 
          className="h-8 w-auto"
        />
      </div>

      {/* Admin-only customer switcher */}
      {role === 'Admin' && (
        <div className="p-3 border-b border-border-base shrink-0">
          <div className="relative">
            <button
              onClick={() => setDropdownOpen(v => !v)}
              className="w-full flex items-center justify-between gap-2 px-3 py-2 bg-panel/50 border border-border-base rounded text-sm text-text-primary hover:border-accent-primary/50 hover:bg-panel transition-all duration-200"
            >
              <div className="flex items-center gap-2 min-w-0">
                <Building className="w-4 h-4 text-accent-primary shrink-0" />
                <span className="truncate font-body font-medium">
                  {selectedCustomer?.name || 'Select customer…'}
                </span>
              </div>
              <ChevronDown className={`w-4 h-4 text-text-secondary shrink-0 transition-transform duration-200 ${dropdownOpen ? 'rotate-180 text-accent-primary' : ''}`} />
            </button>

            {dropdownOpen && (
              <div className="absolute left-0 right-0 top-full mt-2 z-50 bg-panel border border-border-base rounded-lg shadow-xl overflow-hidden flex flex-col">
                <div className="p-2 border-b border-border-base bg-panel/90 backdrop-blur">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
                    <input
                      type="text"
                      placeholder="Search customers..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-9 pr-3 py-1.5 bg-bg-base border border-border-base rounded-md text-sm text-text-primary placeholder-text-muted/70 focus:outline-none focus:border-accent-primary/50 transition-colors"
                      autoFocus
                    />
                  </div>
                </div>
                
                <div className="overflow-y-auto max-h-[240px] p-1 custom-scrollbar">
                  {filteredCustomers.length === 0 ? (
                    <div className="px-3 py-4 text-center text-xs text-text-secondary font-medium">No customers found</div>
                  ) : (
                    filteredCustomers.map(c => (
                      <button
                        key={c.id}
                        onClick={() => handleSelectCustomer(c)}
                        className={`w-full flex items-center justify-between px-3 py-2 text-sm font-body transition-colors rounded-md group
                          ${c.id === selectedCustomerId ? 'bg-accent-primary/10 text-accent-primary font-medium' : 'text-text-secondary hover:text-text-primary hover:bg-bg-surface'}`}
                      >
                        <span className="truncate">{c.name}</span>
                        {c.id === selectedCustomerId && (
                          <div className="w-1.5 h-1.5 rounded-full bg-accent-primary shrink-0 shadow-[0_0_8px_rgba(255,87,34,0.6)]" />
                        )}
                      </button>
                    ))
                  )}
                </div>

                <div className="p-2 border-t border-border-base bg-panel/90">
                  <button
                    onClick={() => {
                      setDropdownOpen(false);
                      onNavChange?.('customers');
                    }}
                    className="w-full flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-accent-primary transition-colors rounded-md hover:bg-bg-surface"
                  >
                    <Settings className="w-3.5 h-3.5" />
                    Manage Customers
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto custom-scrollbar">
        {navItems.filter((item) => !item.adminOnly || role === 'Admin').map((item) => {
          const Icon = item.icon;
          const isActive = activeNav === item.id;
          
          return (
            <button
              key={item.id}
              onClick={() => onNavChange?.(item.id)}
              className={`
                w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium
                transition-colors duration-150
                ${isActive 
                  ? 'text-accent-primary bg-panel border-l-2 border-accent-primary' 
                  : 'text-text-secondary hover:text-text-primary hover:bg-panel'
                }
              `}
            >
              <Icon className="w-5 h-5" />
              <span className="font-body">{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 border-t border-border-base">
        <p className="text-xs text-text-muted font-body">
          Security Posture Agent v1.0
        </p>
      </div>
    </aside>
  );
}
