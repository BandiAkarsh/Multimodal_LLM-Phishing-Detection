import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { Scan, Shield, History, Settings, AlertTriangle, CheckCircle } from 'lucide-react';
import './App.css';

// Components
import Scanner from './components/Scanner';
import Dashboard from './components/Dashboard';
import History from './components/History';
import Settings from './components/Settings';

function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [apiStatus, setApiStatus] = useState('checking');
  const [token, setToken] = useState('');

  useEffect(() => {
    checkApiStatus();
  }, []);

  const checkApiStatus = async () => {
    try {
      const health = await invoke('check_api_health');
      setApiStatus(health.status === 'healthy' ? 'online' : 'offline');
    } catch (error) {
      setApiStatus('offline');
    }
  };

  const handleAuth = async (username, password) => {
    try {
      const newToken = await invoke('authenticate', { username, password });
      setToken(newToken);
      return true;
    } catch (error) {
      console.error('Auth error:', error);
      return false;
    }
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="app-header">
        <div className="logo">
          <Shield className="logo-icon" />
          <h1>Phishing Guard</h1>
        </div>
        <div className={`status-indicator ${apiStatus}`}>
          <span className="status-dot"></span>
          <span className="status-text">
            {apiStatus === 'online' ? 'API Online' : 'API Offline'}
          </span>
        </div>
      </header>

      {/* Main Content */}
      <div className="app-container">
        {/* Sidebar */}
        <nav className="sidebar">
          <button
            className={`nav-button ${activeTab === 'scanner' ? 'active' : ''}`}
            onClick={() => setActiveTab('scanner')}
          >
            <Scan className="nav-icon" />
            <span>Scanner</span>
          </button>
          <button
            className={`nav-button ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Shield className="nav-icon" />
            <span>Dashboard</span>
          </button>
          <button
            className={`nav-button ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
          >
            <History className="nav-icon" />
            <span>History</span>
          </button>
          <button
            className={`nav-button ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => setActiveTab('settings')}
          >
            <Settings className="nav-icon" />
            <span>Settings</span>
          </button>
        </nav>

        {/* Content Area */}
        <main className="content">
          {!token && activeTab !== 'settings' ? (
            <div className="auth-required">
              <AlertTriangle className="auth-icon" />
              <h2>Authentication Required</h2>
              <p>Please configure API settings to continue</p>
              <button onClick={() => setActiveTab('settings')}>
                Go to Settings
              </button>
            </div>
          ) : (
            <>
              {activeTab === 'scanner' && <Scanner token={token} />}
              {activeTab === 'dashboard' && <Dashboard />}
              {activeTab === 'history' && <History />}
              {activeTab === 'settings' && (
                <Settings 
                  onAuth={handleAuth} 
                  isAuthenticated={!!token}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
