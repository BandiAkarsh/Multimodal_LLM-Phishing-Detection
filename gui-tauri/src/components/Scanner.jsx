import React, { useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { Scan, AlertCircle, CheckCircle, AlertTriangle } from 'lucide-react';

function Scanner({ token }) {
  const [url, setUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!url) return;
    
    setIsScanning(true);
    setError('');
    setResult(null);
    
    try {
      const scanResult = await invoke('scan_url', { 
        url: url,
        token: token 
      });
      setResult(scanResult);
      
      // Show notification for high-risk results
      if (scanResult.risk_score > 70) {
        await invoke('show_notification', {
          title: `🚨 ${scanResult.classification.toUpperCase()} Detected!`,
          body: `Risk Score: ${scanResult.risk_score}/100`
        });
      }
    } catch (err) {
      setError(err.toString());
    } finally {
      setIsScanning(false);
    }
  };

  const getRiskColor = (score) => {
    if (score < 30) return '#22c55e';  // Green
    if (score < 70) return '#f97316';  // Orange
    return '#ef4444';  // Red
  };

  const getClassificationIcon = (classification) => {
    switch(classification) {
      case 'legitimate':
        return <CheckCircle className="result-icon safe" />;
      case 'phishing':
      case 'phishing_kit':
        return <AlertCircle className="result-icon danger" />;
      case 'ai_generated_phishing':
        return <AlertTriangle className="result-icon warning" />;
      default:
        return <AlertCircle className="result-icon" />;
    }
  };

  return (
    <div className="scanner">
      <h2>URL Scanner</h2>
      <p className="scanner-description">
        Enter a URL to analyze it for phishing indicators
      </p>
      
      <div className="input-group">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="url-input"
          onKeyPress={(e) => e.key === 'Enter' && handleScan()}
        />
        <button 
          onClick={handleScan} 
          disabled={isScanning || !url}
          className="scan-button"
        >
          {isScanning ? (
            <>
              <div className="spinner"></div>
              Scanning...
            </>
          ) : (
            <>
              <Scan className="button-icon" />
              Scan URL
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="error-message">
          <AlertCircle className="error-icon" />
          {error}
        </div>
      )}

      {result && (
        <div className={`result-card ${result.classification}`}>
          <div className="result-header">
            {getClassificationIcon(result.classification)}
            <div className="result-title">
              <h3>{result.classification.replace(/_/g, ' ').toUpperCase()}</h3>
              <span className="result-url">{result.url}</span>
            </div>
          </div>
          
          <div className="result-stats">
            <div className="stat">
              <span className="stat-label">Confidence</span>
              <span className="stat-value">{(result.confidence * 100).toFixed(1)}%</span>
            </div>
            <div className="stat">
              <span className="stat-label">Risk Score</span>
              <span 
                className="stat-value risk-score"
                style={{ color: getRiskColor(result.risk_score) }}
              >
                {result.risk_score}/100
              </span>
            </div>
          </div>
          
          <div className="result-explanation">
            <h4>Analysis</h4>
            <p>{result.explanation}</p>
          </div>
          
          <div className="result-recommendation">
            <h4>Recommendation</h4>
            <p className={`rec-${result.risk_score > 70 ? 'block' : result.risk_score > 30 ? 'warn' : 'safe'}`}>
              {result.risk_score > 70 
                ? '🔴 BLOCK: High risk of phishing. Do not visit this URL.'
                : result.risk_score > 30
                ? '🟡 WARNING: Suspicious elements detected. Proceed with caution.'
                : '🟢 SAFE: No significant threats detected.'
              }
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

export default Scanner;
