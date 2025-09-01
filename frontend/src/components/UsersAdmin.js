import React, { useEffect, useState } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';
import { TrashIcon, ShieldIcon, UploadIcon } from './Icons';
import { useAuth } from '../contexts/AuthContext';

const UsersAdmin = () => {
  const { user } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchUsers = async () => {
    try {
      const res = await axios.get('/api/users');
      console.log('Users API response:', res.data);
      setUsers(res.data);
    } catch (e) {
      toast.error(e.response?.data?.error || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const onUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await axios.post('/api/upload/excel', form, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      toast.success(`Uploaded: users ${res.data?.inserted?.users || 0}, roles ${res.data?.inserted?.roles || 0}, plans ${res.data?.inserted?.plans || 0}`);
    } catch (e) {
      toast.error(e.response?.data?.error || 'Upload failed');
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const onDelete = async (id) => {
    if (!window.confirm('Delete this user?')) return;
    try {
      await axios.delete(`/api/users/${id}`);
      toast.success('User deleted');
      fetchUsers();
    } catch (e) {
      toast.error(e.response?.data?.error || 'Failed to delete user');
    }
  };

  if (!user || user.role !== 'admin') {
    return <div className="card">Only admins can view this page.</div>;
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
          <ShieldIcon className="h-6 w-6 text-primary-600" /> Users (Admin)
        </h1>
        <label className="btn-primary cursor-pointer inline-flex items-center gap-2">
          <UploadIcon className="h-4 w-4" /> Import Excel
          <input type="file" accept=".xlsx,.xls" className="hidden" onChange={onUpload} />
        </label>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {users.map(u => (
                <tr key={u.id}>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{u.email}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{u.name || 'N/A'}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{u.role}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{u.department}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(u.created_at).toLocaleString()}</td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm">
                    <button className="text-red-600 hover:text-red-800" onClick={() => onDelete(u.id)} disabled={u.role === 'admin'}>
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UsersAdmin;




