import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line } from 'recharts';
import { TrendingUpIcon, UsersIcon, AlertTriangleIcon, CheckCircleIcon, FilterIcon } from './Icons';
import { useAuth } from '../contexts/AuthContext';
import axios from 'axios';
import toast from 'react-hot-toast';

const Analytics = () => {
  const { user } = useAuth();
  const [demographics, setDemographics] = useState({});
  const [trends, setTrends] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDepartment, setSelectedDepartment] = useState('all');

  // Check if user has HR access
  const hasHrAccess = user?.role === 'admin' || user?.role === 'hr_manager';

  const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884D8'];

  useEffect(() => {
    fetchAnalyticsData();
  }, []);

  const fetchAnalyticsData = async () => {
    try {
      const [demographicsRes, trendsRes] = await Promise.all([
        axios.get('/api/analytics/demographics'),
        axios.get('/api/analytics/trends')
      ]);
      
      setDemographics(demographicsRes.data);
      setTrends(trendsRes.data);
      setLoading(false);
    } catch (error) {
      toast.error('Failed to fetch analytics data');
      setLoading(false);
    }
  };

  const getCriticalityColor = (criticality) => {
    switch (criticality) {
      case 'High': return '#EF4444';
      case 'Medium': return '#F59E0B';
      case 'Low': return '#10B981';
      default: return '#6B7280';
    }
  };

  const getReadinessColor = (readiness) => {
    switch (readiness) {
      case 'Ready Now': return '#10B981';
      case '1-2 years': return '#F59E0B';
      case '3-5 years': return '#3B82F6';
      default: return '#6B7280';
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
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Analytics & Insights</h1>
        <p className="mt-2 text-sm text-gray-600">
          Comprehensive analysis of your HR succession planning data
        </p>
      </div>

      {/* Department Filter */}
      <div className="flex items-center space-x-4">
        <FilterIcon className="h-5 w-5 text-gray-500" />
        <select
          value={selectedDepartment}
          onChange={(e) => setSelectedDepartment(e.target.value)}
          className="input-field max-w-xs"
        >
          <option value="all">All Departments</option>
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

      {/* Key Metrics */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <UsersIcon className="h-8 w-8 text-primary-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Total Roles</dt>
                <dd className="text-lg font-medium text-gray-900">
                  {demographics.department_distribution?.reduce((sum, dept) => sum + dept.count, 0) || 0}
                </dd>
              </dl>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <AlertTriangleIcon className="h-8 w-8 text-red-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Critical Roles</dt>
                <dd className="text-lg font-medium text-gray-900">
                  {demographics.criticality_distribution?.find(c => c.criticality === 'High')?.count || 0}
                </dd>
              </dl>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircleIcon className="h-8 w-8 text-green-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Ready Successors</dt>
                <dd className="text-lg font-medium text-gray-900">
                  {demographics.readiness_distribution?.find(r => r.readiness === 'Ready Now')?.count || 0}
                </dd>
              </dl>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <TrendingUpIcon className="h-8 w-8 text-blue-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Succession Plans</dt>
                <dd className="text-lg font-medium text-gray-900">
                  {demographics.readiness_distribution?.reduce((sum, r) => sum + r.count, 0) || 0}
                </dd>
              </dl>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Department Distribution */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Department Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={demographics.department_distribution || []}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="department" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#3B82F6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Criticality Distribution */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Role Criticality Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={demographics.criticality_distribution || []}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ criticality, count }) => `${criticality}: ${count}`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="count"
              >
                {(demographics.criticality_distribution || []).map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={getCriticalityColor(entry.criticality)} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Readiness Level Distribution - Only for HR users */}
        {hasHrAccess && (
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Successor Readiness Levels</h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={demographics.readiness_distribution || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="readiness" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" fill="#10B981" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Historical Trends - Only for HR users */}
        {hasHrAccess && (
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Succession Activity Trends</h3>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={trends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#3B82F6" strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Detailed Analysis */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Department Analysis */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Department Analysis</h3>
          <div className="space-y-3">
            {(demographics.department_distribution || []).map((dept, index) => (
              <div key={dept.department} className="flex items-center justify-between">
                <span className="text-sm text-gray-600">{dept.department}</span>
                <div className="flex items-center space-x-2">
                  <div className="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      className="bg-primary-600 h-2 rounded-full" 
                      style={{ width: `${(dept.count / Math.max(...(demographics.department_distribution || []).map(d => d.count))) * 100}%` }}
                    ></div>
                  </div>
                  <span className="text-sm font-medium text-gray-900">{dept.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Criticality Analysis */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Criticality Analysis</h3>
          <div className="space-y-3">
            {(demographics.criticality_distribution || []).map((crit, index) => (
              <div key={crit.criticality} className="flex items-center justify-between">
                <span className="text-sm text-gray-600">{crit.criticality}</span>
                <div className="flex items-center space-x-2">
                  <div className="w-20 bg-gray-200 rounded-full h-2">
                    <div 
                      className="h-2 rounded-full" 
                      style={{ 
                        width: `${(crit.count / Math.max(...(demographics.criticality_distribution || []).map(c => c.count))) * 100}%`,
                        backgroundColor: getCriticalityColor(crit.criticality)
                      }}
                    ></div>
                  </div>
                  <span className="text-sm font-medium text-gray-900">{crit.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Readiness Analysis - Only for HR users */}
        {hasHrAccess && (
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Readiness Analysis</h3>
            <div className="space-y-3">
              {(demographics.readiness_distribution || []).map((readiness, index) => (
                <div key={readiness.readiness} className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">{readiness.readiness}</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 bg-gray-200 rounded-full h-2">
                      <div 
                        className="h-2 rounded-full" 
                        style={{ 
                          width: `${(readiness.count / Math.max(...(demographics.readiness_distribution || []).map(r => r.count))) * 100}%`,
                          backgroundColor: getReadinessColor(readiness.readiness)
                        }}
                      ></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">{readiness.count}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Insights */}
      <div className="card">
        <h3 className="text-lg font-medium text-gray-900 mb-4">Key Insights</h3>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="p-4 bg-blue-50 rounded-lg">
            <h4 className="font-medium text-blue-900 mb-2">Succession Coverage</h4>
            <p className="text-sm text-blue-700">
              {demographics.readiness_distribution?.find(r => r.readiness === 'Ready Now')?.count || 0} out of {
                demographics.readiness_distribution?.reduce((sum, r) => sum + r.count, 0) || 0
              } roles have immediate successors ready.
            </p>
          </div>
          
          <div className="p-4 bg-yellow-50 rounded-lg">
            <h4 className="font-medium text-yellow-900 mb-2">Risk Assessment</h4>
            <p className="text-sm text-yellow-700">
              {demographics.criticality_distribution?.find(c => c.criticality === 'High')?.count || 0} high-criticality roles require immediate attention.
            </p>
          </div>
          
          <div className="p-4 bg-green-50 rounded-lg">
            <h4 className="font-medium text-green-900 mb-2">Development Pipeline</h4>
            <p className="text-sm text-green-700">
              {demographics.readiness_distribution?.find(r => r.readiness === '3-5 years')?.count || 0} roles have successors in long-term development.
            </p>
          </div>
          
          <div className="p-4 bg-purple-50 rounded-lg">
            <h4 className="font-medium text-purple-900 mb-2">Trend Analysis</h4>
            <p className="text-sm text-purple-700">
              Succession planning activity shows {trends.length > 0 ? 'consistent' : 'developing'} patterns over time.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Analytics;
