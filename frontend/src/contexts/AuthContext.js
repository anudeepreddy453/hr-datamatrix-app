import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import axios from 'axios';
import toast from 'react-hot-toast';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const logoutTimerRef = useRef(null);

  const clearLogoutTimer = () => {
    if (logoutTimerRef.current) {
      clearTimeout(logoutTimerRef.current);
      logoutTimerRef.current = null;
    }
  };

  const scheduleLogoutAt = (epochMs) => {
    clearLogoutTimer();
    const delay = Math.max(0, epochMs - Date.now());
    if (delay === 0) {
      // Already expired
      logout();
      return;
    }
    logoutTimerRef.current = setTimeout(() => {
      logout();
      toast.error('Session expired. Please sign in again.');
    }, delay);
  };

  const parseJwtExp = (token) => {
    try {
      const payloadBase64 = token.split('.')[1];
      if (!payloadBase64) return null;
      const base64 = payloadBase64.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join(''));
      const payload = JSON.parse(jsonPayload);
      return typeof payload.exp === 'number' ? payload.exp * 1000 : null; // ms
    } catch (_) {
      return null;
    }
  };

  useEffect(() => {
    // Check if user is already logged in (session-based)
    const token = sessionStorage.getItem('token');
    const userData = sessionStorage.getItem('user');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      const expMs = parseJwtExp(token);
      if (expMs) scheduleLogoutAt(expMs); else logout();
    }
    
    setLoading(false);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // Axios interceptor to auto-logout on 401s
    const interceptorId = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        const status = error?.response?.status;
        const code = error?.response?.data?.error;
        if (status === 401 || code === 'token_expired' || code === 'invalid_token' || code === 'authorization_required') {
          logout();
          toast.error('Your session has ended. Please sign in again.');
        }
        return Promise.reject(error);
      }
    );
    return () => {
      axios.interceptors.response.eject(interceptorId);
      clearLogoutTimer();
    };
  }, []);

  const login = async (email, password) => {
    try {
      const response = await axios.post('/api/auth/login', { email, password });
      const { access_token, user: userData } = response.data;
      
      sessionStorage.setItem('token', access_token);
      sessionStorage.setItem('user', JSON.stringify(userData));
      
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      setUser(userData);
      const expMs = parseJwtExp(access_token);
      if (expMs) scheduleLogoutAt(expMs);
      
      toast.success('Login successful!');
      return true;
    } catch (error) {
      const status = error.response?.status;
      const data = error.response?.data;
      
      if (status === 403) {
        if (data?.status === 'pending') {
          toast.error(`${data.error}: ${data.message}`);
        } else if (data?.status === 'rejected') {
          toast.error(`${data.error}: ${data.message}`);
        } else {
          toast.error(data?.error || 'Login failed');
        }
      } else {
        const message = data?.error || 'Login failed';
        toast.error(message);
      }
      return false;
    }
  };

  const logout = () => {
    clearLogoutTimer();
    sessionStorage.removeItem('token');
    sessionStorage.removeItem('user');
    delete axios.defaults.headers.common['Authorization'];
    setUser(null);
    toast.success('Logged out successfully');
  };

  const register = async (userData) => {
    try {
      const response = await axios.post('/api/auth/register', userData);
      const { message, status, department } = response.data;
      
      if (status === 'pending') {
        toast.success(`${message} Your request has been sent to ${department} HR for approval. You will be notified once approved.`);
      } else {
        toast.success(message || 'Registration successful! Please login.');
      }
      return true;
    } catch (error) {
      const message = error.response?.data?.error || 'Registration failed';
      toast.error(message);
      return false;
    }
  };

  const value = {
    user,
    loading,
    login,
    logout,
    register
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
