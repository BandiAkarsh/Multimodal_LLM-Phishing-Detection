import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Scan, Shield, AlertTriangle, CheckCircle, Info, FileText, Settings } from 'lucide-react';
import './App.css';

function App() {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [envStatus, setEnvStatus] = useState(null);
  const [batchMode, setBatchMode] = useState(false);
  const [batchUrls, setBatchUrls] = useState('');
  const [batchResults, setBatchResults] = useState([]);

  useEffect(() => {
    checkEnvironment();
  }, []);

  const checkEnvironment = async () => {
    try {
      const status = await invoke('check_environment');
      setEnvStatus(status);
    } catch (e) {
      setEnvStatus({ status: 'error', error: e.toString() });
    }
  };

  const handleScan = async () => {
    if (!url) return;
    
    setIsScanning(true);
    setError(null);
    setResult(null);
    
    try {
      const scanResult = await invoke('scan_url', { url });
      setResult(scanResult);
    } catch (e) {
      setError(e.toString());
    } finally {
      setIsScanning(false);
    }
  };

  const handleBatchScan = async () => {
    const urls = batchUrls.split('\n').filter(u => u.trim());
    if (urls.length === 0) return;
    
    setIsScanning(true);
    setBatchResults([]);
    
    try {
      const results = await invoke('scan_batch', { urls });
      setBatchResults(results);
    } catch (e) {
      setError(e.toString());
    } finally {
      setIsScanning(false);
    }
  };

  const getRiskColor = (score) => {
    if (score < 30) return '#22c55e';
    if (score < 70) return '#f97316';
    return '#ef4444';
  };

  const getClassificationIcon = (classification) => {
    switch(classification) {
      case 'legitimate':
        return <CheckCircle className="icon safe" />;
      case 'phishing':
      case 'phishing_kit':
        return <AlertTriangle className="icon danger" />;
      case 'ai_generated_phishing':
        return <AlertTriangle className="icon warning" />;
      default:
        return <Info className="icon" />;
    }
  };

  if (!envStatus) {
    return <div className="loading">Checking environment...</div>;
  }

  if (envStatus.status === 'error') {
    return (
      <div className="error-screen">
        <AlertTriangle className="error-icon" />
        <h2>Environment Error</h2>
        <p>Python 3 is required but not found.</p>
        <p>Please install Python 3.9 or higher.</p>
      </div>
    );
  }

  return (
    <div className="app">
      <header className="app-header">
        <Shield className="logo" />
        <h1>Phishing Guard</h1>
        <span className="version">v2.0</span>
      </header>

      <div className="mode-toggle">
        <button 
          className={!batchMode ? 'active' : ''}
          onClick={() => setBatchMode(false)}
        >
          <Scan size={16} /> Single URL
        </button>
        <button 
          className={batchMode ? 'active' : ''}
          onClick={() => setBatchMode(true)}
        >
          <FileText size={16} /> Batch Scan
        </button>
      </div>

      <main className="main-content">
        {!batchMode ? (
          <div className="scanner">
            <h2>Scan URL</h2>
            <div className="input-group">
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                onKeyPress={(e) => e.key === 'Enter' && handleScan()}
              />
              <button 
                onClick={handleScan} 
                disabled={isScanning || !url}
                className="scan-btn"
              >
                {isScanning ? 'Scanning...' : 'Scan'}
              </button>
            </div>

            {error && (
              <div className="error">
                <AlertTriangle size={20} />
                {error}
              </div>
            )}

            {result && (
              <div className={`result-card ${result.classification}`}>
                <div className="result-header">
                  {getClassificationIcon(result.classification)}
                  <div>
                    <h3>{result.classification.replace(/_/g, ' ').toUpperCase()}</h3>
                    <p className="url">{result.url}</p>
                  </div>
                </div>
                
                <div className="metrics">
                  <div className="metric">
                    <span className="label">Confidence</span>
                    <span className="value">{(result.confidence * 100).toFixed(1)}%</span>
                  </div>
                  <div className="metric">
                    <span className="label">Risk Score</span>
                    <span 
                      className="value"
                      style={{ color: getRiskColor(result.risk_score) }}
                    >
                      {result.risk_score}/100
                    </span>
                  </div>
                </div>

                <div className="explanation">
                  <h4>Analysis</h4>
                  <p>{result.explanation}</p>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="batch-scanner">
            <h2>Batch Scan</h2>
            <p>Paste multiple URLs (one per line):</p>
            <textarea
              value={batchUrls}
              onChange={(e) => setBatchUrls(e.target.value)}
              placeholder="https://example1.com&#10;https://example2.com&#10;https://example3.com"
              rows={6}
            />
            <button 
              onClick={handleBatchScan}
              disabled={isScanning || !batchUrls.trim()}
              className="scan-btn"
            >
              {isScanning ? 'Scanning...' : `Scan ${batchUrls.split('\n').filter(u => u.trim()).length} URLs`}
            </button>

            {batchResults.length > 0 && (
              <div className="batch-results">
                <h3>Results</h3>
                <table>
                  <thead>
                    <tr>
                      <th>URL</th>
                      <th>Classification</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {batchResults.map((r, i) => (
                      <tr key={i} className={r.classification}>
                        <td>{r.url.substring(0, 50)}...</td>
                        <td>{r.classification}</td>
                        <td style={{ color: getRiskColor(r.risk_score) }}>
                          {r.risk_score}/100
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </main>

      <footer className="app-footer">
        <p>Standalone Mode • Python {envStatus.python_version} • 93 ML Features</p>
      </footer>
    </div>
  );
}

export default App;
