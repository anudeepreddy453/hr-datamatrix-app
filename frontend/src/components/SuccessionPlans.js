import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { PlusIcon, EditIcon, TrashIcon, SearchIcon, CalendarIcon, UserIcon, TargetIcon, ShieldIcon } from './Icons';
import axios from 'axios';
import toast from 'react-hot-toast';
import { formatIndianTime } from '../utils/timeUtils';

const SuccessionPlans = () => {
  const location = useLocation();
  const { user } = useAuth();
  const [plans, setPlans] = useState([]);
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingPlan, setEditingPlan] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterReadiness, setFilterReadiness] = useState('');



  const [formData, setFormData] = useState({
    role_id: '',
    incumbent_name: '',
    incumbent_employee_id: '',
    incumbent_tenure: '',
    retirement_date: '',
    readiness_level: '1-2 years'
  });

  // Check if user has HR access
  const hasHrAccess = user?.role === 'admin' || user?.role === 'hr_manager';

  useEffect(() => {
    if (hasHrAccess) {
      fetchData();
      if (location.state?.openCreate) {
        setShowModal(true);
      }
      if (location.state?.presetSearch) {
        setSearchTerm(location.state.presetSearch);
      }
    }
  }, [location.state, hasHrAccess]);

  const fetchData = async () => {
    try {
      const [plansRes, rolesRes] = await Promise.all([
        axios.get('/api/succession-plans'),
        axios.get('/api/roles')
      ]);
      setPlans(plansRes.data);
      setRoles(rolesRes.data);
      setLoading(false);
    } catch (error) {
      toast.error('Failed to fetch data');
      setLoading(false);
    }
  };

  // If user doesn't have HR access, show access denied message
  if (!hasHrAccess) {
    return (
      <div className="space-y-6">
        <div className="text-center py-12">
          <ShieldIcon className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900">Access Denied</h3>
          <p className="mt-1 text-sm text-gray-500">
            You need HR access to view succession plans. Please contact your administrator.
          </p>
        </div>
      </div>
    );
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      if (editingPlan) {
        await axios.put(`/api/succession-plans/${editingPlan.id}`, formData);
        toast.success('Succession plan updated successfully');
      } else {
        await axios.post('/api/succession-plans', formData);
        toast.success('Succession plan created successfully');
      }
      
      setShowModal(false);
      setEditingPlan(null);
      resetForm();
      fetchData();
    } catch (error) {
      toast.error('Failed to save succession plan');
    }
  };

  const handleEdit = (plan) => {
    setEditingPlan(plan);
    setFormData({
      role_id: plan.role_id,
      incumbent_name: plan.incumbent_name,
      incumbent_employee_id: plan.incumbent_employee_id,
      incumbent_tenure: plan.incumbent_tenure,
      retirement_date: plan.retirement_date || '',
      readiness_level: plan.readiness_level
    });
    setShowModal(true);
  };

  const handleDelete = async (planId) => {
    if (window.confirm('Are you sure you want to delete this succession plan?')) {
      try {
        await axios.delete(`/api/succession-plans/${planId}`);
        toast.success('Succession plan deleted successfully');
        fetchData();
      } catch (error) {
        toast.error('Failed to delete succession plan');
      }
    }
  };

  const resetForm = () => {
    setFormData({
      role_id: '',
      incumbent_name: '',
      incumbent_employee_id: '',
      incumbent_tenure: '',
      retirement_date: '',
      readiness_level: '1-2 years'
    });
  };

  const getRoleTitle = (roleId) => {
    const role = roles.find(r => r.id === roleId);
    return role ? role.title : 'Unknown Role';
  };

  const getReadinessColor = (readiness) => {
    switch (readiness) {
      case 'Ready Now': return 'text-green-600 bg-green-100';
      case '1-2 years': return 'text-yellow-600 bg-yellow-100';
      case '3-5 years': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const filteredPlans = plans.filter(plan => {
    const matchesSearch = plan.incumbent_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         getRoleTitle(plan.role_id).toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = !filterReadiness || plan.readiness_level === filterReadiness;
    return matchesSearch && matchesFilter;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Succession Plans</h1>
          <p className="mt-2 text-sm text-gray-600">
            Manage succession planning for critical organizational roles
          </p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          className="btn-primary flex items-center"
        >
          <PlusIcon className="h-4 w-4 mr-2" />
          Add Succession Plan
        </button>
      </div>

      {/* Filters and Search */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search plans..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input-field pl-10"
          />
        </div>
        <select
          value={filterReadiness}
          onChange={(e) => setFilterReadiness(e.target.value)}
          className="input-field max-w-xs"
        >
          <option value="">All Readiness Levels</option>
          <option value="Ready Now">Ready Now</option>
          <option value="1-2 years">1-2 years</option>
          <option value="3-5 years">3-5 years</option>
        </select>
      </div>

      {/* Succession Plans Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Role
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Name
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Employee ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Tenure (Months)
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Retirement Date
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Readiness
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredPlans.map((plan) => (
                <tr key={plan.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">{getRoleTitle(plan.role_id)}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{plan.incumbent_name}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{plan.incumbent_employee_id}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{plan.incumbent_tenure}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      {plan.retirement_date ? new Date(plan.retirement_date).toLocaleDateString() : 'N/A'}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getReadinessColor(plan.readiness_level)}`}>
                      {plan.readiness_level}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                    <div className="flex space-x-2">
                      <button
                        onClick={() => handleEdit(plan)}
                        className="text-primary-600 hover:text-primary-900"
                      >
                        <EditIcon className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(plan.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add/Edit Succession Plan Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {editingPlan ? 'Edit Succession Plan' : 'Add New Succession Plan'}
              </h3>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Role
                  </label>
                  <select
                    required
                    value={formData.role_id}
                    onChange={(e) => setFormData({...formData, role_id: e.target.value})}
                    className="input-field"
                  >
                    <option value="">Select Role</option>
                    {roles.map(role => (
                      <option key={role.id} value={role.id}>
                        {role.title} - {role.department}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Name
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.incumbent_name}
                    onChange={(e) => setFormData({...formData, incumbent_name: e.target.value})}
                    className="input-field"
                    placeholder="Enter name"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Employee ID
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.incumbent_employee_id}
                    onChange={(e) => setFormData({...formData, incumbent_employee_id: e.target.value})}
                    className="input-field"
                    placeholder="Enter employee ID"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tenure (Months)
                  </label>
                  <input
                    type="number"
                    required
                    value={formData.incumbent_tenure}
                    onChange={(e) => setFormData({...formData, incumbent_tenure: e.target.value})}
                    className="input-field"
                    placeholder="Enter tenure in months"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Retirement Date
                  </label>
                  <input
                    type="date"
                    value={formData.retirement_date}
                    onChange={(e) => setFormData({...formData, retirement_date: e.target.value})}
                    className="input-field"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Readiness Level
                  </label>
                  <select
                    required
                    value={formData.readiness_level}
                    onChange={(e) => setFormData({...formData, readiness_level: e.target.value})}
                    className="input-field"
                  >
                    <option value="Ready Now">Ready Now</option>
                    <option value="1-2 years">1-2 years</option>
                    <option value="3-5 years">3-5 years</option>
                  </select>
                </div>

                <div className="flex space-x-3 pt-4">
                  <button
                    type="submit"
                    className="btn-primary flex-1"
                  >
                    {editingPlan ? 'Update' : 'Create'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowModal(false);
                      setEditingPlan(null);
                      resetForm();
                    }}
                    className="btn-secondary flex-1"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SuccessionPlans;
