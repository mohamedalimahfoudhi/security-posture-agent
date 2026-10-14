import { useState, useEffect } from 'react';
import { Users, Plus, Edit2, Trash2, Search, Building2, AlertTriangle, X } from 'lucide-react';
import { getAllCustomers, createCustomer, updateCustomer, deleteCustomer } from '../api/client';

export default function CustomersPage({ role }) {
  const [customers, setCustomers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Modal states
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  
  const [selectedCustomer, setSelectedCustomer] = useState(null);
  const [formData, setFormData] = useState({ name: '', industry: '' });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [modalError, setModalError] = useState(null);

  useEffect(() => {
    if (role === 'Admin') {
      loadCustomers();
    }
  }, [role]);

  const loadCustomers = async () => {
    try {
      setLoading(true);
      const data = await getAllCustomers();
      setCustomers(data);
      setError(null);
    } catch (err) {
      setError('Failed to load customers');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setModalError(null);
    setIsSubmitting(true);
    try {
      await createCustomer(formData);
      setIsCreateModalOpen(false);
      setFormData({ name: '', industry: '' });
      await loadCustomers();
      // Notify other components that customers changed
      window.dispatchEvent(new Event("data:refresh"));
    } catch (err) {
      setModalError(err.message || 'Failed to create customer');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEditSubmit = async (e) => {
    e.preventDefault();
    setModalError(null);
    setIsSubmitting(true);
    try {
      await updateCustomer(selectedCustomer.id, formData);
      setIsEditModalOpen(false);
      setSelectedCustomer(null);
      await loadCustomers();
      window.dispatchEvent(new Event("data:refresh"));
    } catch (err) {
      setModalError(err.message || 'Failed to update customer');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteSubmit = async () => {
    setModalError(null);
    setIsSubmitting(true);
    try {
      await deleteCustomer(selectedCustomer.id);
      setIsDeleteModalOpen(false);
      setSelectedCustomer(null);
      await loadCustomers();
      window.dispatchEvent(new Event("data:refresh"));
    } catch (err) {
      setModalError(err.message || 'Failed to delete customer');
    } finally {
      setIsSubmitting(false);
    }
  };

  const openEditModal = (customer) => {
    setSelectedCustomer(customer);
    setFormData({ name: customer.name, industry: customer.industry || '' });
    setIsEditModalOpen(true);
  };

  const openDeleteModal = (customer) => {
    setSelectedCustomer(customer);
    setIsDeleteModalOpen(true);
  };

  if (role !== 'Admin') {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-sm text-mist font-body">You do not have permission to view this page.</p>
      </div>
    );
  }

  const filteredCustomers = customers.filter(c => 
    c.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
    (c.industry && c.industry.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="h-full overflow-y-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold font-display text-ink flex items-center gap-2">
            <Users className="w-6 h-6 text-ember-bright" />
            Customer Management
          </h1>
          <p className="text-sm text-mist font-body mt-1">
            Manage tenant workspaces and global customer catalog
          </p>
        </div>
        <button
          onClick={() => {
            setFormData({ name: '', industry: '' });
            setIsCreateModalOpen(true);
          }}
          className="flex items-center gap-2 px-4 py-2 bg-ember-bright text-white rounded-md hover:bg-ember-bright/90 transition-colors font-medium text-sm shadow-[0_0_15px_rgba(255,87,34,0.3)]"
        >
          <Plus className="w-4 h-4" />
          Add Customer
        </button>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-4 bg-panel border border-hairline p-4 rounded-lg">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-mist" />
          <input
            type="text"
            placeholder="Search customers..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-void border border-hairline rounded-md text-sm text-ink placeholder-mist/70 focus:outline-none focus:border-ember-bright/50 transition-colors"
          />
        </div>
      </div>

      {/* Grid */}
      <div className="bg-panel border border-hairline rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-void border-b border-hairline text-xs uppercase tracking-wider text-mist">
                <th className="px-6 py-4 text-left font-semibold">ID</th>
                <th className="px-6 py-4 text-left font-semibold">Name</th>
                <th className="px-6 py-4 text-left font-semibold">Industry</th>
                <th className="px-6 py-4 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-hairline">
              {loading ? (
                <tr>
                  <td colSpan="4" className="px-6 py-8 text-center text-mist">Loading...</td>
                </tr>
              ) : error ? (
                <tr>
                  <td colSpan="4" className="px-6 py-8 text-center text-error">{error}</td>
                </tr>
              ) : filteredCustomers.length === 0 ? (
                <tr>
                  <td colSpan="4" className="px-6 py-8 text-center text-mist">No customers found.</td>
                </tr>
              ) : (
                filteredCustomers.map((customer) => (
                  <tr key={customer.id} className="hover:bg-void/50 transition-colors group">
                    <td className="px-6 py-4 text-mist font-mono text-xs">{customer.id}</td>
                    <td className="px-6 py-4 text-ink font-medium">
                      <div className="flex items-center gap-2">
                        <Building2 className="w-4 h-4 text-mist group-hover:text-ember-bright transition-colors" />
                        {customer.name}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-mist">{customer.industry || '—'}</td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={() => openEditModal(customer)}
                          className="p-1.5 text-mist hover:text-ink hover:bg-void rounded transition-colors"
                          title="Edit Customer"
                        >
                          <Edit2 className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => openDeleteModal(customer)}
                          className="p-1.5 text-mist hover:text-error hover:bg-error/10 rounded transition-colors"
                          title="Delete Customer"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modals */}
      {(isCreateModalOpen || isEditModalOpen) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-panel border border-hairline rounded-lg w-full max-w-md shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-hairline">
              <h2 className="text-lg font-semibold text-ink font-display">
                {isCreateModalOpen ? 'Create New Customer' : 'Edit Customer'}
              </h2>
              <button 
                onClick={() => {
                  setIsCreateModalOpen(false);
                  setIsEditModalOpen(false);
                }}
                className="text-mist hover:text-ink transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <form onSubmit={isCreateModalOpen ? handleCreateSubmit : handleEditSubmit} className="p-4 space-y-4">
              {modalError && (
                <div className="p-3 bg-error/10 border border-error/30 rounded text-error text-sm">
                  {modalError}
                </div>
              )}
              
              <div>
                <label className="block text-xs font-medium text-mist mb-1">Customer Name *</label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-3 py-2 bg-void border border-hairline rounded text-sm text-ink focus:outline-none focus:border-ember-bright/50 transition-colors"
                  placeholder="e.g. Acme Corp"
                />
              </div>
              
              <div>
                <label className="block text-xs font-medium text-mist mb-1">Industry</label>
                <input
                  type="text"
                  value={formData.industry}
                  onChange={e => setFormData({ ...formData, industry: e.target.value })}
                  className="w-full px-3 py-2 bg-void border border-hairline rounded text-sm text-ink focus:outline-none focus:border-ember-bright/50 transition-colors"
                  placeholder="e.g. Healthcare"
                />
              </div>
              
              <div className="pt-4 flex items-center justify-end gap-3 border-t border-hairline">
                <button
                  type="button"
                  onClick={() => {
                    setIsCreateModalOpen(false);
                    setIsEditModalOpen(false);
                  }}
                  className="px-4 py-2 text-sm font-medium text-mist hover:text-ink transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-ember-bright text-white rounded text-sm font-medium hover:bg-ember-bright/90 transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? 'Saving...' : 'Save Customer'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {isDeleteModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-panel border border-error/30 rounded-lg w-full max-w-md shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-hairline bg-error/5">
              <h2 className="text-lg font-semibold text-error font-display flex items-center gap-2">
                <AlertTriangle className="w-5 h-5" />
                Delete Customer
              </h2>
              <button 
                onClick={() => setIsDeleteModalOpen(false)}
                className="text-mist hover:text-ink transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            
            <div className="p-4 space-y-4">
              <p className="text-sm text-ink">
                Are you absolutely sure you want to delete <strong className="text-ember-bright">{selectedCustomer?.name}</strong>?
              </p>
              
              <div className="p-3 bg-void border border-error/30 rounded text-xs text-mist space-y-2">
                <p className="font-semibold text-error uppercase">⚠️ Permanent Data Loss Warning</p>
                <p>Deleting this customer will instantly and permanently erase all associated tenant data, including:</p>
                <ul className="list-disc pl-4 space-y-1">
                  <li>Users and API keys</li>
                  <li>Customer third-party maps</li>
                  <li>All generated alerts and exposures</li>
                  <li>Architecture intelligence reports</li>
                  <li>Tenant-owned assets and documents</li>
                </ul>
              </div>

              {modalError && (
                <div className="p-3 bg-error/10 border border-error/30 rounded text-error text-sm">
                  {modalError}
                </div>
              )}
              
              <div className="pt-4 flex items-center justify-end gap-3 border-t border-hairline">
                <button
                  onClick={() => setIsDeleteModalOpen(false)}
                  className="px-4 py-2 text-sm font-medium text-mist hover:text-ink transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeleteSubmit}
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-error text-white rounded text-sm font-medium hover:bg-error/90 transition-colors shadow-[0_0_15px_rgba(226,72,60,0.3)] disabled:opacity-50 flex items-center gap-2"
                >
                  {isSubmitting ? 'Deleting...' : 'Yes, Delete Customer'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
