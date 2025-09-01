import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { 
  UsersIcon, 
  TrendingUpIcon, 
  AlertTriangleIcon, 
  CheckCircleIcon,
  BuildingIcon,
  UserCheckIcon,
  TargetIcon,
  BarChartIcon
} from './Icons';
import axios from 'axios';
import toast from 'react-hot-toast';

const Dashboard = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [stats, setStats] = useState({
    totalRoles: 0,
    totalPlans: 0,
    criticalRoles: 0,
    readySuccessors: 0
  });
  const [recentPlans, setRecentPlans] = useState([]);
  const [loading, setLoading] = useState(true);

  // Check if user has HR access
  const hasHrAccess = user?.role === 'admin' || user?.role === 'hr_manager';

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const rolesRes = await axios.get('/api/roles');
      const roles = rolesRes.data;

      let plans = [];
      if (hasHrAccess) {
        try {
          const plansRes = await axios.get('/api/succession-plans');
          plans = plansRes.data;
        } catch (error) {
          // If user doesn't have access to succession plans, just continue with empty plans
          plans = [];
        }
      }

      setStats({
        totalRoles: roles.length,
        totalPlans: hasHrAccess ? plans.length : 0,
        criticalRoles: roles.filter(role => role.criticality === 'High').length,
        readySuccessors: hasHrAccess ? plans.filter(plan => plan.readiness_level === 'Ready Now').length : 0
      });

      setRecentPlans(hasHrAccess ? plans.slice(0, 5) : []);
      setLoading(false);
    } catch (error) {
      toast.error('Failed to fetch dashboard data');
      setLoading(false);
    }
  };

  const getCriticalityColor = (criticality) => {
    switch (criticality) {
      case 'High': return 'text-red-600 bg-red-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'Low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getReadinessColor = (readiness) => {
    switch (readiness) {
      case 'Ready Now': return 'text-green-600 bg-green-100';
      case '1-2 years': return 'text-yellow-600 bg-yellow-100';
      case '3-5 years': return 'text-blue-600 bg-blue-100';
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
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-2 text-sm text-gray-600">
          Overview of your HR succession planning system
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <UsersIcon className="h-8 w-8 text-primary-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Total Roles</dt>
                <dd className="text-lg font-medium text-gray-900">{stats.totalRoles}</dd>
              </dl>
            </div>
          </div>
        </div>

        {hasHrAccess && (
          <div className="card">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <TrendingUpIcon className="h-8 w-8 text-green-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Succession Plans</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.totalPlans}</dd>
                </dl>
              </div>
            </div>
          </div>
        )}

        <div className="card">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <AlertTriangleIcon className="h-8 w-8 text-red-600" />
            </div>
            <div className="ml-5 w-0 flex-1">
              <dl>
                <dt className="text-sm font-medium text-gray-500 truncate">Critical Roles</dt>
                <dd className="text-lg font-medium text-gray-900">{stats.criticalRoles}</dd>
              </dl>
            </div>
          </div>
        </div>

        {hasHrAccess && (
          <div className="card">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <CheckCircleIcon className="h-8 w-8 text-green-600" />
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">Ready Successors</dt>
                  <dd className="text-lg font-medium text-gray-900">{stats.readySuccessors}</dd>
                </dl>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Recent Activity and Quick Actions */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Recent Succession Plans - Only for HR users */}
        {hasHrAccess && (
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 mb-4">Recent Succession Plans</h3>
            <div className="space-y-3">
              {recentPlans.length > 0 ? (
                recentPlans.map((plan) => (
                  <div key={plan.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div>
                      <p className="text-sm font-medium text-gray-900">{plan.role_title}</p>
                      <p className="text-xs text-gray-500">{plan.incumbent_name}</p>
                    </div>
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${getReadinessColor(plan.readiness_level)}`}>
                      {plan.readiness_level}
                    </span>
                  </div>
                ))
              ) : (
                <p className="text-sm text-gray-500 text-center py-4">No succession plans found</p>
              )}
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="card">
          <h3 className="text-lg font-medium text-gray-900 mb-4">Quick Actions</h3>
          <div className="space-y-3">
            <button
              onClick={() => navigate('/roles', { state: { openCreate: true } })}
              className="w-full flex items-center justify-between p-3 text-left bg-primary-50 hover:bg-primary-100 rounded-lg transition-colors"
            >
              <div className="flex items-center">
                <UsersIcon className="h-5 w-5 text-primary-600 mr-3" />
                <span className="text-sm font-medium text-primary-900">Add New Role</span>
              </div>
              <span className="text-xs text-primary-600">→</span>
            </button>

            {hasHrAccess && (
              <button
                onClick={() => navigate('/succession-plans', { state: { openCreate: true } })}
                className="w-full flex items-center justify-between p-3 text-left bg-green-50 hover:bg-green-100 rounded-lg transition-colors"
              >
                <div className="flex items-center">
                  <TrendingUpIcon className="h-5 w-5 text-green-600 mr-3" />
                  <span className="text-sm font-medium text-green-900">Create Succession Plan</span>
                </div>
                <span className="text-xs text-green-600">→</span>
              </button>
            )}

            <button
              onClick={() => navigate('/analytics')}
              className="w-full flex items-center justify-between p-3 text-left bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors"
            >
              <div className="flex items-center">
                <BarChartIcon className="h-5 w-5 text-blue-600 mr-3" />
                <span className="text-sm font-medium text-blue-900">View Analytics</span>
              </div>
              <span className="text-xs text-blue-600">→</span>
            </button>

            {hasHrAccess && (
              <button
                onClick={() => navigate('/succession-plans')}
                className="w-full flex items-center justify-between p-3 text-left bg-purple-50 hover:bg-purple-100 rounded-lg transition-colors"
              >
                <div className="flex items-center">
                  <UserCheckIcon className="h-5 w-5 text-purple-600 mr-3" />
                  <span className="text-sm font-medium text-purple-900">Review Candidates</span>
                </div>
                <span className="text-xs text-purple-600">→</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* System Status */}
      <div className="card">
        <h3 className="text-lg font-medium text-gray-900 mb-4">System Status</h3>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircleIcon className="h-5 w-5 text-green-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-900">Database</p>
              <p className="text-xs text-gray-500">Connected</p>
            </div>
          </div>

          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircleIcon className="h-5 w-5 text-green-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-900">API</p>
              <p className="text-xs text-gray-500">Running</p>
            </div>
          </div>

          <div className="flex items-center">
            <div className="flex-shrink-0">
              <CheckCircleIcon className="h-5 w-5 text-green-600" />
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-gray-900">Security</p>
              <p className="text-xs text-gray-500">Active</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
