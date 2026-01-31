import React, { useState, useEffect, useCallback } from 'react';
// import { invoke } from '@tauri-apps/api/core';  // Enable when backend ready
import { open } from '@tauri-apps/plugin-shell';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Search, 
  FileText, 
  Info,
  Cpu,
  Globe,
  Lock,
  Activity,
  ChevronDown,
  ChevronUp,
  Loader2
} from 'lucide-react';
import './App.css';

// TypeScript Interfaces
interface DetectionResult {
  url: string;
  prediction: 'Legitimate' | 'Phishing' | 'AI-Generated Phishing' | 'Phishing Kit';
  confidence: number;
  probability: number;
  is_phishing: boolean;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  features?: Record<string, number | string | boolean>;
  threat_details?: string[];
}

interface ScanHistoryItem {
  url: string;
  result: DetectionResult;
  timestamp: string;
  scan_duration_ms: number;
}

interface FeatureInfo {
  name: string;
  description: string;
  importance: number;
}

// Components
const Header: React.FC = () => (
  <header className="app-header">
    <div className="logo">
      <Shield className="logo-icon" size={32} />
      <h1>Phishing Guard v2.0</h1>
    </div>
    <div className="subtitle">AI-Powered Phishing Detection</div>
  </header>
);

const URLInput: React.FC<{
  url: string;
  setUrl: (url: string) => void;
  onScan: () => void;
  isScanning: boolean;
}> = ({ url, setUrl, onScan, isScanning }) => (
  <div className="url-input-section">
    <div className="input-group">
      <input
        type="text"
        value={url}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setUrl(e.target.value)}
        placeholder="Enter URL to scan (e.g., https://example.com)"
        className="url-input"
        disabled={isScanning}
        onKeyPress={(e: React.KeyboardEvent<HTMLInputElement>) => {
          if (e.key === 'Enter' && !isScanning) onScan();
        }}
      />
      <button 
        onClick={onScan} 
        disabled={isScanning || !url.trim()}
        className="scan-button"
      >
        {isScanning ? (
          <><Loader2 className="spin" size={20} /> Scanning...</>
        ) : (
          <><Search size={20} /> Scan URL</>
        )}
      </button>
    </div>
  </div>
);

const ResultCard: React.FC<{ result: DetectionResult | null }> = ({ result }) => {
  if (!result) return null;

  const getRiskColor = (level: string): string => {
    switch (level) {
      case 'CRITICAL': return '#ff4444';
      case 'HIGH': return '#ff8800';
      case 'MEDIUM': return '#ffcc00';
      default: return '#00cc44';
    }
  };

  const getIcon = (prediction: string) => {
    if (prediction.includes('Phishing')) return <AlertTriangle size={48} color="#ff4444" />;
    if (prediction === 'Legitimate') return <CheckCircle size={48} color="#00cc44" />;
    return <Info size={48} color="#ffcc00" />;
  };

  return (
    <div className="result-card" style={{ borderColor: getRiskColor(result.risk_level) }}>
      <div className="result-header">
        {getIcon(result.prediction)}
        <div className="result-title">
          <h2>{result.prediction}</h2>
          <div className="confidence">
            Confidence: {(result.confidence * 100).toFixed(1)}%
          </div>
        </div>
      </div>
      
      <div className="risk-badge" style={{ backgroundColor: getRiskColor(result.risk_level) }}>
        {result.risk_level} RISK
      </div>

      {result.threat_details && result.threat_details.length > 0 && (
        <div className="threat-details">
          <h3>Detected Threats:</h3>
          <ul>
            {result.threat_details.map((threat: string, idx: number) => (
              <li key={idx}><AlertTriangle size={16} /> {threat}</li>
            ))}
          </ul>
        </div>
      )}

      {result.features && (
        <div className="features-section">
          <h3>Key Features Analyzed:</h3>
          <div className="features-grid">
            {Object.entries(result.features)
              .slice(0, 10)
              .map(([key, value]) => (
                <div key={key} className="feature-item">
                  <span className="feature-name">{key.replace(/_/g, ' ')}:</span>
                  <span className="feature-value">
                    {typeof value === 'number' ? value.toFixed(2) : String(value)}
                  </span>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};

const HistoryPanel: React.FC<{ history: ScanHistoryItem[] }> = ({ history }) => {
  const [expanded, setExpanded] = useState<boolean>(false);

  if (history.length === 0) return null;

  return (
    <div className="history-panel">
      <div className="history-header" onClick={() => setExpanded(!expanded)}>
        <h3><Activity size={20} /> Scan History ({history.length})</h3>
        {expanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
      </div>
      
      {expanded && (
        <div className="history-list">
          {history.map((item: ScanHistoryItem, idx: number) => (
            <div key={idx} className={`history-item ${item.result.is_phishing ? 'phishing' : 'safe'}`}>
              <div className="history-url" title={item.url}>
                {item.url.length > 50 ? item.url.substring(0, 50) + '...' : item.url}
              </div>
              <div className="history-result">
                {item.result.is_phishing ? (
                  <><XCircle size={16} color="#ff4444" /> Phishing</>
                ) : (
                  <><CheckCircle size={16} color="#00cc44" /> Safe</>
                )}
              </div>
              <div className="history-time">
                {new Date(item.timestamp).toLocaleTimeString()}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const StatsPanel: React.FC<{ history: ScanHistoryItem[] }> = ({ history }) => {
  const stats = {
    total: history.length,
    phishing: history.filter((h: ScanHistoryItem) => h.result.is_phishing).length,
    safe: history.filter((h: ScanHistoryItem) => !h.result.is_phishing).length,
    avgConfidence: history.length > 0 
      ? history.reduce((acc: number, h: ScanHistoryItem) => acc + h.result.confidence, 0) / history.length 
      : 0
  };

  return (
    <div className="stats-panel">
      <div className="stat-card">
        <Globe size={24} />
        <div className="stat-value">{stats.total}</div>
        <div className="stat-label">URLs Scanned</div>
      </div>
      <div className="stat-card safe">
        <CheckCircle size={24} />
        <div className="stat-value">{stats.safe}</div>
        <div className="stat-label">Safe</div>
      </div>
      <div className="stat-card danger">
        <AlertTriangle size={24} />
        <div className="stat-value">{stats.phishing}</div>
        <div className="stat-label">Phishing</div>
      </div>
      <div className="stat-card">
        <Cpu size={24} />
        <div className="stat-value">{(stats.avgConfidence * 100).toFixed(0)}%</div>
        <div className="stat-label">Avg Confidence</div>
      </div>
    </div>
  );
};

const FeatureShowcase: React.FC = () => {
  const features: FeatureInfo[] = [
    { name: 'IDN/Homograph Detection', description: 'Detects internationalized domain names and homograph attacks', importance: 9.5 },
    { name: 'TLS Analysis', description: 'Analyzes SSL/TLS certificates for security issues', importance: 8.8 },
    { name: 'URL Entropy', description: 'Measures randomness in domain names', importance: 7.5 },
    { name: 'Mixed Script Detection', description: 'Identifies mixed Unicode scripts (Cyrillic + Latin)', importance: 9.0 },
    { name: 'Brand Spoofing', description: 'Detects attempts to mimic legitimate brands', importance: 8.5 },
    { name: 'Security Validation', description: 'Checks for SSRF, open redirects, and other vulnerabilities', importance: 8.0 },
  ];

  return (
    <div className="feature-showcase">
      <h3><Shield size={20} /> 93 ML Features</h3>
      <div className="feature-list">
        {features.map((feature: FeatureInfo, idx: number) => (
          <div key={idx} className="feature-card">
            <div className="feature-header">
              <span className="feature-title">{feature.name}</span>
              <span className="importance-badge">{(feature.importance).toFixed(1)}/10</span>
            </div>
            <p className="feature-desc">{feature.description}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

// Main App Component
const App: React.FC = () => {
  const [url, setUrl] = useState<string>('');
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  // Model info loaded from backend - enable when API ready
  // const [modelInfo, setModelInfo] = useState<ModelInfo | null>(null);

  // Load history from localStorage on mount
  useEffect(() => {
    const savedHistory = localStorage.getItem('scanHistory');
    if (savedHistory) {
      try {
        const parsed = JSON.parse(savedHistory) as ScanHistoryItem[];
        setHistory(parsed);
      } catch (e) {
        console.error('Failed to parse history:', e);
      }
    }
  }, []);

  // Save history to localStorage when it changes
  useEffect(() => {
    if (history.length > 0) {
      localStorage.setItem('scanHistory', JSON.stringify(history.slice(0, 50)));
    }
  }, [history]);

  const handleScan = useCallback(async (): Promise<void> => {
    if (!url.trim()) return;

    setIsScanning(true);
    setError(null);
    setResult(null);
    
    const startTime = Date.now();

    try {
      // Simulate API call - in production, this would call the backend
      // const response = await invoke<DetectionResult>('scan_url', { url });
      
      // Simulated response for demo
      await new Promise((resolve) => setTimeout(resolve, 1500));
      
      const isPhishing = url.includes('phishing') || 
                        url.includes('fake') || 
                        url.includes('scam') ||
                        url.includes('login-');
      
      const mockResult: DetectionResult = {
        url: url,
        prediction: isPhishing ? 'Phishing' : 'Legitimate',
        confidence: isPhishing ? 0.92 : 0.98,
        probability: isPhishing ? 0.92 : 0.02,
        is_phishing: isPhishing,
        risk_level: isPhishing ? 'HIGH' : 'LOW',
        threat_details: isPhishing ? [
          'Suspicious domain pattern detected',
          'Known phishing keywords found',
          'High URL entropy score'
        ] : [],
        features: {
          url_length: url.length,
          num_dots: url.split('.').length - 1,
          has_https: url.startsWith('https') ? 1 : 0,
          domain_entropy: 3.5,
          suspicious_words: isPhishing ? 2 : 0,
          mixed_scripts: 0,
          brand_match: 0.1
        }
      };

      setResult(mockResult);
      
      const historyItem: ScanHistoryItem = {
        url: url,
        result: mockResult,
        timestamp: new Date().toISOString(),
        scan_duration_ms: Date.now() - startTime
      };
      
      setHistory(prev => [historyItem, ...prev].slice(0, 50));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan URL');
    } finally {
      setIsScanning(false);
    }
  }, [url]);

  const clearHistory = useCallback((): void => {
    setHistory([]);
    localStorage.removeItem('scanHistory');
  }, []);

  return (
    <div className="app">
      <Header />
      
      <main className="app-main">
        <URLInput 
          url={url} 
          setUrl={setUrl} 
          onScan={handleScan}
          isScanning={isScanning}
        />

        {error && (
          <div className="error-message">
            <AlertTriangle size={20} />
            {error}
          </div>
        )}

        <ResultCard result={result} />
        
        <StatsPanel history={history} />
        
        <HistoryPanel history={history} />

        <FeatureShowcase />

        <div className="actions-bar">
          {history.length > 0 && (
            <button onClick={clearHistory} className="secondary-button">
              <XCircle size={16} /> Clear History
            </button>
          )}
          <button 
            onClick={() => open('https://github.com/your-repo/phishing-guard')}
            className="secondary-button"
          >
            <FileText size={16} /> Documentation
          </button>
        </div>
      </main>

      <footer className="app-footer">
        <div className="footer-content">
          <div className="footer-section">
            <Lock size={16} />
            <span>Offline Capable</span>
          </div>
          <div className="footer-section">
            <Shield size={16} />
            <span>93 ML Features</span>
          </div>
          <div className="footer-section">
            <Cpu size={16} />
            <span>Random Forest v2.0</span>
          </div>
        </div>
        <div className="footer-copyright">
          © 2026 Phishing Guard - IEEE Final Year Project
        </div>
      </footer>
    </div>
  );
};

export default App;
