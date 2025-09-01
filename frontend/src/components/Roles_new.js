import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { PlusIcon, EditIcon, TrashIcon, SearchIcon, FilterIcon, ShieldIcon } from './Icons';
import axios from 'axios';
import toast from 'react-hot-toast';

const Roles = () => {
  const location = useLocation();
  const { user } = useAuth();
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingRole, setEditingRole] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterDepartment, setFilterDepartment] = useState('');

  // Check if user has HR access
  const hasHrAccess = user?.role === 'admin' || user?.role === 'hr_manager';

  const [formData, setFormData] = useState({
    title: '',
    department: '',
    business_line: '',
    criticality: 'Medium'
  });

  useEffect(() => {
    fetchRoles();
    if (location.state?.openCreate) {
      setShowModal(true);
    }
    if (location.state?.presetSearch) {
      setSearchTerm(location.state.presetSearch);
    }
  }, [location.state]);

  const fetchRoles = async () => {
    try {
      const response = await axios.get('/api/roles');
      setRoles(response.data);
      setLoading(false);
    } catch (error) {
      toast.error('Failed to fetch roles');
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!hasHrAccess) {
      toast.error('You need HR access to manage roles');
      return;
    }
    
    // Check if all required fields are filled
    if (!formData.title || !formData.department || !formData.business_line || !formData.criticality) {
      toast.error('Please fill in all required fields');
      return;
    }
    
    try {
      if (editingRole) {
        await axios.put(`/api/roles/${editingRole.id}`, formData);
        toast.success('Role updated successfully');
      } else {
        const response = await axios.post('/api/roles', formData);
        toast.success('Role created successfully');
      }
      
      setShowModal(false);
      setEditingRole(null);
      resetForm();
      fetchRoles();
    } catch (error) {
      console.error('Role submission error:', error);
      toast.error(`Failed to save role: ${error.response?.data?.error || error.message}`);
    }
  };

  const handleEdit = (role) => {
    if (!hasHrAccess) {
      toast.error('You need HR access to edit roles');
      return;
    }
    
    setEditingRole(role);
    setFormData({
      title: role.title,
      department: role.department,
      business_line: role.business_line,
      criticality: role.criticality
    });
    setShowModal(true);
  };

  const handleDelete = async (roleId) => {
    if (!hasHrAccess) {
      toast.error('You need HR access to delete roles');
      return;
    }
    
    if (window.confirm('Are you sure you want to delete this role?')) {
      try {
        await axios.delete(`/api/roles/${roleId}`);
        toast.success('Role deleted successfully');
        fetchRoles();
      } catch (error) {
        toast.error('Failed to delete role');
      }
    }
  };

  const resetForm = () => {
    setFormData({
      title: '',
      department: '',
      business_line: '',
      criticality: 'Medium'
    });
    setEditingRole(null);
  };

  const filteredRoles = roles.filter(role => {
    const matchesSearch = role.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         role.department.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFilter = !filterDepartment || role.department === filterDepartment;
    return matchesSearch && matchesFilter;
  });

  const getCriticalityColor = (criticality) => {
    switch (criticality) {
      case 'High': return 'text-red-600 bg-red-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

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
          <h1 className="text-2xl font-bold text-gray-900 flex items-center">
            <ShieldIcon className="mr-3 h-8 w-8 text-primary-600" />
            Role Management
          </h1>
          <p className="mt-1 text-sm text-gray-500">
            {hasHrAccess ? 'Manage organizational roles and their criticality levels' : 'View organizational roles and their criticality levels (Read-only access)'}
          </p>
        </div>
        {hasHrAccess && (
          <button
            onClick={() => setShowModal(true)}
            className="btn-primary flex items-center"
          >
            <PlusIcon className="mr-2 h-4 w-4" />
            Add Role
          </button>
        )}
      </div>

      {/* Search and Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:space-x-4 space-y-4 sm:space-y-0">
        <div className="relative flex-1">
          <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
          <input
            type="text"
            placeholder="Search roles..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input-field pl-10"
          />
        </div>
        <div className="relative">
          <FilterIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
          <select
            value={filterDepartment}
            onChange={(e) => setFilterDepartment(e.target.value)}
            className="input-field pl-10 pr-8"
          >
            <option value="">All Departments</option>
            <option value="CCR">CCR</option>
            <option value="i2r">i2r</option>
            <option value="Bacardi">Bacardi</option>
            <option value="Riskweb">Riskweb</option>
            <option value="Xone">Xone</option>
            <option value="MKD">MKD</option>
            <option value="CIS">CIS</option>
            <option value="CQIS">CQIS</option>
            <option value="OSD">OSD</option>
            <option value="DAT">DAT</option>
            <option value="DIR">DIR</option>
            <option value="DLF">DLF</option>
          </select>
        </div>
      </div>

      {/* Roles Table */}
      <div className="bg-white shadow-sm rounded-lg border border-gray-200">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Role Title
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Department
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Business Line
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Criticality
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Created
                </th>
                {hasHrAccess && (
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                )}
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredRoles.map((role) => (
                <tr key={role.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900">{role.title}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{role.department}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">{role.business_line}</div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${getCriticalityColor(role.criticality)}`}>
                      {role.criticality}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900">
                      {new Date(role.created_at).toLocaleDateString()}
                    </div>
                  </td>
                  {hasHrAccess && (
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <button
                        onClick={() => handleEdit(role)}
                        className="text-primary-600 hover:text-primary-900 mr-3"
                      >
                        <EditIcon className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(role.id)}
                        className="text-red-600 hover:text-red-900"
                      >
                        <TrashIcon className="h-4 w-4" />
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add/Edit Role Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {editingRole ? 'Edit Role' : 'Add New Role'}
              </h3>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Role Title
                  </label>
                  <select
                    required
                    value={formData.title}
                    onChange={(e) => setFormData({...formData, title: e.target.value})}
                    className="input-field"
                  >
                    <option value="">Select Role Title</option>
                    <optgroup label="Software Development">
                      <option value="Software Engineer">Software Engineer</option>
                      <option value="Frontend Developer (React/Angular/Vue)">Frontend Developer (React/Angular/Vue)</option>
                      <option value="Backend Developer (Java/Python/.NET/Node.js)">Backend Developer (Java/Python/.NET/Node.js)</option>
                      <option value="Full Stack Developer">Full Stack Developer</option>
                      <option value="Mobile App Developer (iOS/Android/Flutter)">Mobile App Developer (iOS/Android/Flutter)</option>
                      <option value="Cloud Developer (AWS/Azure/GCP)">Cloud Developer (AWS/Azure/GCP)</option>
                    </optgroup>
                    <optgroup label="Data & AI">
                      <option value="Data Engineer">Data Engineer</option>
                      <option value="Data Scientist">Data Scientist</option>
                      <option value="Machine Learning Engineer">Machine Learning Engineer</option>
                      <option value="AI Engineer">AI Engineer</option>
                      <option value="Business Intelligence (BI) Developer">Business Intelligence (BI) Developer</option>
                      <option value="Big Data Engineer">Big Data Engineer</option>
                    </optgroup>
                    <optgroup label="IT Infrastructure & Cloud">
                      <option value="System Administrator">System Administrator</option>
                      <option value="Cloud Engineer">Cloud Engineer</option>
                      <option value="DevOps Engineer">DevOps Engineer</option>
                      <option value="Site Reliability Engineer (SRE)">Site Reliability Engineer (SRE)</option>
                      <option value="Network Engineer">Network Engineer</option>
                      <option value="Infrastructure Engineer">Infrastructure Engineer</option>
                    </optgroup>
                    <optgroup label="Cybersecurity">
                      <option value="Security Analyst">Security Analyst</option>
                      <option value="Security Engineer">Security Engineer</option>
                      <option value="SOC Analyst">SOC Analyst</option>
                      <option value="Penetration Tester">Penetration Tester</option>
                      <option value="Cybersecurity Consultant">Cybersecurity Consultant</option>
                      <option value="Information Security Manager">Information Security Manager</option>
                    </optgroup>
                    <optgroup label="Project & Product Management">
                      <option value="Project Manager">Project Manager</option>
                      <option value="Product Manager">Product Manager</option>
                      <option value="Scrum Master">Scrum Master</option>
                      <option value="Program Manager">Program Manager</option>
                      <option value="Business Analyst">Business Analyst</option>
                    </optgroup>
                    <optgroup label="Quality Assurance & Testing">
                      <option value="QA Engineer">QA Engineer</option>
                      <option value="Test Automation Engineer">Test Automation Engineer</option>
                      <option value="Performance Tester">Performance Tester</option>
                      <option value="Manual Tester">Manual Tester</option>
                      <option value="QA Lead">QA Lead</option>
                    </optgroup>
                    <optgroup label="HR">
                      <option value="HR Manager">HR Manager</option>
                      <option value="HR Business Partner">HR Business Partner</option>
                      <option value="Recruitment Specialist">Recruitment Specialist</option>
                      <option value="Talent Acquisition Manager">Talent Acquisition Manager</option>
                      <option value="Learning & Development Specialist">Learning & Development Specialist</option>
                      <option value="Compensation & Benefits Analyst">Compensation & Benefits Analyst</option>
                      <option value="Employee Relations Specialist">Employee Relations Specialist</option>
                      <option value="HR Operations Specialist">HR Operations Specialist</option>
                    </optgroup>
                    <optgroup label="Emerging Technologies">
                      <option value="Blockchain Developer">Blockchain Developer</option>
                      <option value="IoT Engineer">IoT Engineer</option>
                      <option value="AR/VR Developer">AR/VR Developer</option>
                    </optgroup>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Department
                  </label>
                  <select
                    required
                    value={formData.department}
                    onChange={(e) => setFormData({...formData, department: e.target.value})}
                    className="input-field"
                  >
                    <option value="">Select Department</option>
                    <option value="CCR">CCR</option>
                    <option value="i2r">i2r</option>
                    <option value="Bacardi">Bacardi</option>
                    <option value="Riskweb">Riskweb</option>
                    <option value="Xone">Xone</option>
                    <option value="MKD">MKD</option>
                    <option value="CIS">CIS</option>
                    <option value="CQIS">CQIS</option>
                    <option value="OSD">OSD</option>
                    <option value="DAT">DAT</option>
                    <option value="DIR">DIR</option>
                    <option value="DLF">DLF</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Business Line
                  </label>
                  <select
                    required
                    value={formData.business_line}
                    onChange={(e) => setFormData({...formData, business_line: e.target.value})}
                    className="input-field"
                  >
                    <option value="">Select Business Line</option>
                    <option value="KYU">KYU</option>
                    <option value="GBIS">GBIS</option>
                    <option value="DFIN">DFIN</option>
                    <option value="RISQ">RISQ</option>
                    <option value="CPLE">CPLE</option>
                    <option value="HRCO">HRCO</option>
                    <option value="COO">COO</option>
                    <option value="HR">HR</option>
                    <option value="RPBI">RPBI</option>
                    <option value="MIBS">MIBS</option>
                    <option value="CFT">CFT</option>
                    <option value="DDS">DDS</option>
                    <option value="DAI">DAI</option>
                    <option value="CTC">CTC</option>
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Criticality
                  </label>
                  <select
                    required
                    value={formData.criticality}
                    onChange={(e) => setFormData({...formData, criticality: e.target.value})}
                    className="input-field"
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                  </select>
                </div>

                <div className="flex space-x-3 pt-4">
                  <button
                    type="submit"
                    className="btn-primary flex-1"
                  >
                    {editingRole ? 'Update' : 'Create'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowModal(false);
                      setEditingRole(null);
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

export default Roles;
