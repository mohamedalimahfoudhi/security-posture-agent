import { useState, useEffect } from 'react';
import { useAuth } from '../auth/AuthContext';
import { changePassword, getUsers, updateUser, getNotificationRecipients, createNotificationRecipient, deleteNotificationRecipient, getNotificationDrafts } from '../api/client';

export default function SettingsPage() {
  const { user } = useAuth();
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [usersError, setUsersError] = useState(null);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [statusMessage, setStatusMessage] = useState(null);
  const [statusType, setStatusType] = useState('');
  const [updatingUserId, setUpdatingUserId] = useState(null);
  
  // Notification recipients state
  const [recipients, setRecipients] = useState([]);
  const [loadingRecipients, setLoadingRecipients] = useState(true);
  const [newRecipientName, setNewRecipientName] = useState('');
  const [newRecipientEmail, setNewRecipientEmail] = useState('');
  
  // Notification history state
  const [notificationHistory, setNotificationHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(true);

  useEffect(() => {
    async function loadUsers() {
      try {
        setLoadingUsers(true);
        const data = await getUsers();
        setUsers(data);
        setUsersError(null);
      } catch (err) {
        console.error('Failed to load users:', err);
        setUsersError('Failed to load users');
      } finally {
        setLoadingUsers(false);
      }
    }

    async function loadRecipients() {
      try {
        setLoadingRecipients(true);
        const data = await getNotificationRecipients();
        setRecipients(data);
      } catch (err) {
        console.error('Failed to load notification recipients:', err);
      } finally {
        setLoadingRecipients(false);
      }
    }

    async function loadNotificationHistory() {
      try {
        setLoadingHistory(true);
        const data = await getNotificationDrafts();
        setNotificationHistory(data);
      } catch (err) {
        console.error('Failed to load notification history:', err);
      } finally {
        setLoadingHistory(false);
      }
    }

    loadUsers();
    loadRecipients();
    loadNotificationHistory();
  }, []);

  if (!user) {
    return (
      <div className="h-full flex items-center justify-center">
        <p className="text-sm text-mist font-body">Loading profile...</p>
      </div>
    );
  }

  const handleChangePassword = async (event) => {
    event.preventDefault();
    setStatusMessage(null);
    setStatusType('');

    if (newPassword !== confirmPassword) {
      setStatusMessage('New password and confirmation do not match.');
      setStatusType('error');
      return;
    }

    try {
      await changePassword(currentPassword, newPassword);
      setStatusMessage('Password changed successfully.');
      setStatusType('success');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      console.error('Password change failed:', err);
      setStatusMessage(err.message || 'Failed to change password.');
      setStatusType('error');
    }
  };

  const toggleUserActive = async (userId, currentlyActive) => {
    setUpdatingUserId(userId);
    try {
      const updatedUser = await updateUser(userId, { is_active: !currentlyActive });
      setUsers((prev) => prev.map((u) => (u.id === userId ? updatedUser : u)));
    } catch (err) {
      console.error('Failed to update user status:', err);
      setStatusMessage('Failed to update user status.');
      setStatusType('error');
    } finally {
      setUpdatingUserId(null);
    }
  };

  const addRecipient = async (event) => {
    event.preventDefault();
    if (!newRecipientName || !newRecipientEmail) {
      setStatusMessage('Please provide both name and email.');
      setStatusType('error');
      return;
    }

    try {
      const newRecipient = await createNotificationRecipient({
        customer_id: user.customer_id,
        name: newRecipientName,
        email: newRecipientEmail,
      });
      setRecipients([...recipients, newRecipient]);
      setNewRecipientName('');
      setNewRecipientEmail('');
      setStatusMessage('Notification recipient added successfully.');
      setStatusType('success');
    } catch (err) {
      console.error('Failed to add notification recipient:', err);
      setStatusMessage(err.message || 'Failed to add notification recipient.');
      setStatusType('error');
    }
  };

  const removeRecipient = async (recipientId) => {
    try {
      await deleteNotificationRecipient(recipientId);
      setRecipients(recipients.filter(r => r.id !== recipientId));
      setStatusMessage('Notification recipient removed successfully.');
      setStatusType('success');
    } catch (err) {
      console.error('Failed to remove notification recipient:', err);
      setStatusMessage(err.message || 'Failed to remove notification recipient.');
      setStatusType('error');
    }
  };

  return (
    <div className="h-full bg-panel border border-hairline rounded-lg p-6 overflow-auto">
      <div className="mb-6">
        <h2 className="text-lg font-semibold text-ink font-display">Settings</h2>
        <p className="text-sm text-mist font-body mt-1">Account profile information and admin management.</p>
      </div>

      <div className="grid gap-4 max-w-2xl">
        <div className="bg-void border border-hairline rounded-lg p-4 hover:shadow-md hover:border-hairline/80 transition-all duration-200">
          <p className="text-xs text-mist font-body uppercase tracking-wide">Username</p>
          <p className="text-sm text-ink font-medium mt-2">{user.username || 'Unknown'}</p>
        </div>
        <div className="bg-void border border-hairline rounded-lg p-4 hover:shadow-md hover:border-hairline/80 transition-all duration-200">
          <p className="text-xs text-mist font-body uppercase tracking-wide">Email</p>
          <p className="text-sm text-ink font-medium mt-2">{user.email || 'Unknown'}</p>
        </div>
        <div className="bg-void border border-hairline rounded-lg p-4 hover:shadow-md hover:border-hairline/80 transition-all duration-200">
          <p className="text-xs text-mist font-body uppercase tracking-wide">Role</p>
          <p className="text-sm text-ink font-medium mt-2">{user.role || 'Unknown'}</p>
        </div>
      </div>

      <div className="mt-10">
        <div className="mb-4">
          <h3 className="text-base font-semibold text-ink font-display">Change Password</h3>
          <p className="text-sm text-mist font-body mt-1">Update your admin password securely.</p>
        </div>

        <form onSubmit={handleChangePassword} className="grid gap-4 max-w-2xl">
          <label className="block">
            <span className="text-xs text-mist uppercase tracking-wide">Current Password</span>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="mt-2 w-full rounded-md border border-hairline bg-void px-3 py-2 text-sm text-ink"
              required
            />
          </label>
          <label className="block">
            <span className="text-xs text-mist uppercase tracking-wide">New Password</span>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="mt-2 w-full rounded-md border border-hairline bg-void px-3 py-2 text-sm text-ink"
              required
            />
          </label>
          <label className="block">
            <span className="text-xs text-mist uppercase tracking-wide">Confirm New Password</span>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="mt-2 w-full rounded-md border border-hairline bg-void px-3 py-2 text-sm text-ink"
              required
            />
          </label>

          {statusMessage && (
            <div className={`rounded-md p-3 ${statusType === 'success' ? 'bg-emerald-100 text-emerald-900' : 'bg-rose-100 text-rose-900'}`}>
              {statusMessage}
            </div>
          )}

          <button
            type="submit"
            className="inline-flex items-center justify-center rounded-md bg-ember-bright px-4 py-2 text-sm font-semibold text-white hover:bg-ember-dark"
          >
            Update Password
          </button>
        </form>
      </div>

      <div className="mt-10">
        <div className="mb-4">
          <h3 className="text-base font-semibold text-ink font-display">User Management</h3>
          <p className="text-sm text-mist font-body mt-1">View all users for your customer. Toggle active/inactive status if available.</p>
        </div>

        {loadingUsers ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, idx) => (
              <div key={idx} className="bg-void border border-hairline rounded-lg p-4 animate-pulse">
                <div className="flex gap-4">
                  <div className="h-4 bg-panel/50 rounded w-1/4"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/3"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/6"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/6"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/5"></div>
                </div>
              </div>
            ))}
          </div>
        ) : usersError ? (
          <p className="text-sm text-rose-500">{usersError}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-hairline bg-void">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-hairline bg-panel">
                <tr>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Username</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Email</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Role</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Active</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Action</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-b border-hairline last:border-none hover:bg-panel/50 transition-colors">
                    <td className="px-4 py-3 text-ink">{u.username}</td>
                    <td className="px-4 py-3 text-ink">{u.email}</td>
                    <td className="px-4 py-3 text-ink">{u.role}</td>
                    <td className="px-4 py-3 text-ink">{u.is_active ? 'Active' : 'Inactive'}</td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => toggleUserActive(u.id, u.is_active)}
                        disabled={updatingUserId === u.id}
                        className="rounded-md border border-hairline bg-panel px-3 py-1 text-sm text-ink hover:bg-void hover:border-ember-bright hover:text-ember-bright transition-all disabled:opacity-50"
                      >
                        {u.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-10">
        <div className="mb-4">
          <h3 className="text-base font-semibold text-ink font-display">Notification Recipients</h3>
          <p className="text-sm text-mist font-body mt-1">Manage external contacts who receive CRITICAL/HIGH alert notifications.</p>
        </div>

        <form onSubmit={addRecipient} className="grid gap-4 max-w-2xl mb-4">
          <div className="grid grid-cols-2 gap-4">
            <label className="block">
              <span className="text-xs text-mist uppercase tracking-wide">Name</span>
              <input
                type="text"
                value={newRecipientName}
                onChange={(e) => setNewRecipientName(e.target.value)}
                className="mt-2 w-full rounded-md border border-hairline bg-void px-3 py-2 text-sm text-ink"
                placeholder="Contact name"
              />
            </label>
            <label className="block">
              <span className="text-xs text-mist uppercase tracking-wide">Email</span>
              <input
                type="email"
                value={newRecipientEmail}
                onChange={(e) => setNewRecipientEmail(e.target.value)}
                className="mt-2 w-full rounded-md border border-hairline bg-void px-3 py-2 text-sm text-ink"
                placeholder="contact@example.com"
              />
            </label>
          </div>
          <button
            type="submit"
            className="inline-flex items-center justify-center rounded-md bg-ember-bright px-4 py-2 text-sm font-semibold text-white hover:bg-ember-dark"
          >
            Add Recipient
          </button>
        </form>

        {loadingRecipients ? (
          <div className="space-y-2">
            {[...Array(2)].map((_, idx) => (
              <div key={idx} className="bg-void border border-hairline rounded-lg p-4 animate-pulse">
                <div className="flex gap-4">
                  <div className="h-4 bg-panel/50 rounded w-1/4"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/2"></div>
                </div>
              </div>
            ))}
          </div>
        ) : recipients.length === 0 ? (
          <p className="text-sm text-mist">No notification recipients configured.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-hairline bg-void">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-hairline bg-panel">
                <tr>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Name</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Email</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Action</th>
                </tr>
              </thead>
              <tbody>
                {recipients.map((r) => (
                  <tr key={r.id} className="border-b border-hairline last:border-none hover:bg-panel/50 transition-colors">
                    <td className="px-4 py-3 text-ink">{r.name}</td>
                    <td className="px-4 py-3 text-ink">{r.email}</td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        onClick={() => removeRecipient(r.id)}
                        className="rounded-md border border-hairline bg-panel px-3 py-1 text-sm text-ink hover:bg-void hover:border-sev-critical hover:text-sev-critical transition-all"
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-10">
        <div className="mb-4">
          <h3 className="text-base font-semibold text-ink font-display">Notification History</h3>
          <p className="text-sm text-mist font-body mt-1">Audit trail of sent notifications for CRITICAL/HIGH alerts.</p>
        </div>

        {loadingHistory ? (
          <div className="space-y-2">
            {[...Array(3)].map((_, idx) => (
              <div key={idx} className="bg-void border border-hairline rounded-lg p-4 animate-pulse">
                <div className="flex gap-4">
                  <div className="h-4 bg-panel/50 rounded w-1/4"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/3"></div>
                  <div className="h-4 bg-panel/50 rounded w-1/6"></div>
                </div>
              </div>
            ))}
          </div>
        ) : notificationHistory.length === 0 ? (
          <p className="text-sm text-mist">No notification history available.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-hairline bg-void">
            <table className="min-w-full text-left text-sm">
              <thead className="border-b border-hairline bg-panel">
                <tr>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Alert</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Risk Level</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Status</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Created</th>
                  <th className="px-4 py-3 text-mist uppercase tracking-wide">Sent</th>
                </tr>
              </thead>
              <tbody>
                {notificationHistory.map((h) => (
                  <tr key={h.id} className="border-b border-hairline last:border-none hover:bg-panel/50 transition-colors">
                    <td className="px-4 py-3 text-ink">{h.alert_title || `Alert #${h.alert_id}`}</td>
                    <td className="px-4 py-3 text-ink">{h.alert_risk_level || 'N/A'}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-semibold px-2 py-1 rounded ${
                        h.status === 'sent' ? 'bg-sev-low text-void' :
                        h.status === 'failed' ? 'bg-sev-critical text-void' :
                        h.status === 'skipped-no-recipients' ? 'bg-sev-elevated text-void' :
                        'bg-mist text-ink'
                      }`}>
                        {h.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-ink text-xs">
                      {h.created_at ? new Date(h.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td className="px-4 py-3 text-ink text-xs">
                      {h.sent_at ? new Date(h.sent_at).toLocaleString() : 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
