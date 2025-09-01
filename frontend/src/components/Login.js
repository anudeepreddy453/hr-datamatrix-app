import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { EyeIcon, EyeOffIcon, LockIcon, UserIcon, MailIcon, BriefcaseIcon, LogInIcon, UserPlusIcon, ArrowRightIcon } from './Icons';

const Login = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState({
    length: false,
    uppercase: false,
    lowercase: false,
    digit: false,
    special: false
  });
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    department: 'CCR'
  });
  
  const { login, register } = useAuth();
  const navigate = useNavigate();

  const validatePassword = (password) => {
    const strength = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      digit: /\d/.test(password),
      special: /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(password)
    };
    setPasswordStrength(strength);
    return Object.values(strength).every(Boolean);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (isLogin) {
      const success = await login(formData.email, formData.password);
      if (success) {
        navigate('/');
      }
    } else {
      // Validate password strength before registration
      if (!validatePassword(formData.password)) {
        return;
      }
      const success = await register(formData);
      if (success) {
        setIsLogin(true);
        setFormData({ name: '', email: '', password: '', department: 'CCR' });
        setPasswordStrength({
          length: false,
          uppercase: false,
          lowercase: false,
          digit: false,
          special: false
        });
      }
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    
    // Validate password strength in real-time
    if (name === 'password') {
      validatePassword(value);
    }
  };

  const switchToLogin = () => {
    setIsLogin(true);
    setFormData({ name: '', email: '', password: '', department: 'CCR' });
    setShowPassword(false);
  };

  const switchToRegister = () => {
    setIsLogin(false);
    setFormData({ name: '', email: '', password: '', department: 'CCR' });
    setShowPassword(false);
  };

  return (
    <div className="dual-form-container">
      {/* Animated Background */}
      <div className="animated-background">
        <div className="bg-shape bg-shape-1"></div>
        <div className="bg-shape bg-shape-2"></div>
        <div className="bg-shape bg-shape-3"></div>
        <div className="bg-shape bg-shape-4"></div>
      </div>

      {/* Main Form Container */}
      <div className="form-wrapper">
        <div className="dual-form-card">
          {/* Sliding Background */}
          <div className={`sliding-bg ${isLogin ? 'login-active' : 'register-active'}`}>
            {isLogin ? (
              <div className="sliding-content">
                <UserPlusIcon className="sliding-icon" />
                <h3>New Here?</h3>
                <p>Create an account to get started with HR Succession Planning</p>
                <button
                  type="button"
                  onClick={switchToRegister}
                  className="sliding-action-btn"
                >
                  Sign Up
                </button>
              </div>
            ) : (
              <div className="sliding-content">
                <LogInIcon className="sliding-icon" />
                <h3>Welcome Back!</h3>
                <p>Already have an account? Sign in to continue</p>
                <button
                  type="button"
                  onClick={switchToLogin}
                  className="sliding-action-btn"
                >
                  Sign In
                </button>
              </div>
            )}
          </div>

          {/* Toggle Header */}
          <div className="toggle-header">
            <button
              className={`toggle-btn ${isLogin ? 'active' : ''}`}
              onClick={switchToLogin}
            >
              <LogInIcon className="toggle-icon" />
              <span>Login</span>
            </button>
            <button
              className={`toggle-btn ${!isLogin ? 'active' : ''}`}
              onClick={switchToRegister}
            >
              <UserPlusIcon className="toggle-icon" />
              <span>Register</span>
            </button>
          </div>

          {/* Form Content Container */}
          <div className="form-content-wrapper">
            {/* Login Form */}
            <div className={`form-panel login-panel ${isLogin ? 'active' : ''}`}>
              <div className="panel-header">
                <h2 className="panel-title">Welcome Back!</h2>
                <p className="panel-subtitle">Sign in to continue to your dashboard</p>
              </div>

              <form onSubmit={handleSubmit} className="auth-form">
                <div className="form-group">
                  <label className="form-label">Email</label>
                  <div className="input-container">
                    <MailIcon className="input-icon" />
                    <input
                      type="email"
                      name="email"
                      value={isLogin ? formData.email : ''}
                      onChange={handleChange}
                      className="form-input"
                      placeholder="Enter your email"
                      required={isLogin}
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Password</label>
                  <div className="input-container">
                    <LockIcon className="input-icon" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      name="password"
                      value={isLogin ? formData.password : ''}
                      onChange={handleChange}
                      className="form-input with-toggle"
                      placeholder="Enter your password"
                      required={isLogin}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="toggle-password"
                    >
                      {showPassword ? <EyeOffIcon size={18} /> : <EyeIcon size={18} />}
                    </button>
                  </div>
                </div>

                <div className="form-extras">
                  <label className="checkbox-container">
                    <input type="checkbox" className="form-checkbox" />
                    <span>Remember me</span>
                  </label>
                  <Link to="/forgot-password" className="forgot-link">Forgot password?</Link>
                </div>

                <button type="submit" className="submit-button">
                  <span>Sign In</span>
                  <ArrowRightIcon className="button-icon" />
                </button>

                
              </form>
            </div>

            {/* Register Form */}
            <div className={`form-panel register-panel ${!isLogin ? 'active' : ''}`}>
              <div className="panel-header" style={{marginBottom: '8px', padding: '5px 0'}}>
                <h2 className="panel-title" style={{fontSize: '24px', marginBottom: '6px'}}>Create Account</h2>
                <p className="panel-subtitle" style={{fontSize: '14px'}}>Join us to manage your HR succession plans</p>
              </div>

              <form onSubmit={handleSubmit} className="auth-form">
                <div className="form-group" style={{marginBottom: '8px'}}>
                  <label className="form-label" style={{marginBottom: '4px', fontSize: '13px'}}>Full Name</label>
                  <div className="input-container">
                    <UserIcon className="input-icon" />
                    <input
                      type="text"
                      name="name"
                      value={!isLogin ? formData.name : ''}
                      onChange={handleChange}
                      className="form-input"
                      placeholder="Enter your full name"
                      required={!isLogin}
                      style={{padding: '8px 14px 8px 42px', fontSize: '14px'}}
                    />
                  </div>
                </div>

                <div className="form-group" style={{marginBottom: '8px'}}>
                  <label className="form-label" style={{marginBottom: '4px', fontSize: '13px'}}>Email</label>
                  <div className="input-container">
                    <MailIcon className="input-icon" />
                    <input
                      type="email"
                      name="email"
                      value={!isLogin ? formData.email : ''}
                      onChange={handleChange}
                      className="form-input"
                      placeholder="Enter your email"
                      required={!isLogin}
                      style={{padding: '8px 14px 8px 42px', fontSize: '14px'}}
                    />
                  </div>
                </div>

                <div className="form-group" style={{marginBottom: '8px'}}>
                  <label className="form-label" style={{marginBottom: '4px', fontSize: '13px'}}>Department</label>
                  <div className="input-container">
                    <BriefcaseIcon className="input-icon" />
                    <select
                      name="department"
                      value={formData.department}
                      onChange={handleChange}
                      className="form-input form-select"
                      required={!isLogin}
                      style={{padding: '8px 14px 8px 42px', fontSize: '14px'}}
                    >
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

                <div className="form-group" style={{marginBottom: '8px'}}>
                  <label className="form-label" style={{marginBottom: '4px', fontSize: '13px'}}>Password</label>
                  <div className="input-container">
                    <LockIcon className="input-icon" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      name="password"
                      value={!isLogin ? formData.password : ''}
                      onChange={handleChange}
                      className="form-input with-toggle"
                      placeholder="Create a password"
                      required={!isLogin}
                      style={{padding: '8px 14px 8px 42px', fontSize: '14px'}}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="toggle-password"
                    >
                      {showPassword ? <EyeOffIcon size={18} /> : <EyeIcon size={18} />}
                    </button>
                  </div>
                  
                  {/* Password Strength Indicator */}
                  {!isLogin && (
                    <div className="password-strength mt-1" style={{marginTop: '4px'}}>
                      <div className="text-xs text-gray-600 mb-1" style={{fontSize: '11px', marginBottom: '2px'}}>Password must contain:</div>
                      <div className="space-y-0.5" style={{gap: '2px'}}>
                        <div className={`flex items-center text-xs ${passwordStrength.length ? 'text-green-600' : 'text-gray-500'}`} style={{fontSize: '10px'}}>
                          <div className={`w-2 h-2 rounded-full mr-2 ${passwordStrength.length ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                          At least 8 characters
                        </div>
                        <div className={`flex items-center text-xs ${passwordStrength.uppercase ? 'text-green-600' : 'text-gray-500'}`} style={{fontSize: '10px'}}>
                          <div className={`w-2 h-2 rounded-full mr-2 ${passwordStrength.uppercase ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                          One uppercase letter (A-Z)
                        </div>
                        <div className={`flex items-center text-xs ${passwordStrength.lowercase ? 'text-green-600' : 'text-gray-500'}`} style={{fontSize: '10px'}}>
                          <div className={`w-2 h-2 rounded-full mr-2 ${passwordStrength.lowercase ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                          One lowercase letter (a-z)
                        </div>
                        <div className={`flex items-center text-xs ${passwordStrength.digit ? 'text-green-600' : 'text-gray-500'}`} style={{fontSize: '10px'}}>
                          <div className={`w-2 h-2 rounded-full mr-2 ${passwordStrength.digit ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                          One digit (0-9)
                        </div>
                        <div className={`flex items-center text-xs ${passwordStrength.special ? 'text-green-600' : 'text-gray-500'}`} style={{fontSize: '10px'}}>
                          <div className={`w-2 h-2 rounded-full mr-2 ${passwordStrength.special ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                          One special character (!@#$%^&*)
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <button type="submit" className="submit-button" style={{marginTop: '8px', marginBottom: '8px', padding: '8px 16px'}}>
                  <span>Create Account</span>
                  <ArrowRightIcon className="button-icon" />
                </button>

                
              </form>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;