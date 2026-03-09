#!/usr/bin/env python3
"""
Additional component diagrams for documentation
"""
from PIL import Image, ImageDraw, ImageFont
import os

# Create output directory
os.makedirs('viva/pdf_images_v2', exist_ok=True)

COLORS = {
    'bg': (30, 60, 114),
    'light_bg': (70, 130, 180),
    'accent': (255, 200, 0),
    'white': (255, 255, 255),
    'green': (46, 204, 113),
    'red': (231, 76, 60),
    'orange': (243, 156, 18),
    'purple': (155, 89, 182),
    'cyan': (0, 188, 212),
    'gray': (150, 150, 150),
    'dark': (20, 40, 80)
}

def get_fonts():
    try:
        return {
            'title': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20),
            'subtitle': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14),
            'label': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11),
            'small': ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 9)
        }
    except:
        return {
            'title': ImageFont.load_default(),
            'subtitle': ImageFont.load_default(),
            'label': ImageFont.load_default(),
            'small': ImageFont.load_default()
        }

def create_api_architecture():
    """FastAPI REST API Architecture"""
    width, height = 1200, 700
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 220, 12), "REST API SERVICE ARCHITECTURE (FastAPI)", 
              fill=COLORS['white'], font=fonts['title'])
    
    # Server
    x, y = 500, 80
    draw.rounded_rectangle([x, y, x+200, y+60], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+40, y+20), "FastAPI Server", fill=COLORS['bg'], font=fonts['subtitle'])
    
    # Uvicorn
    x = 520
    draw.rounded_rectangle([x, y+70, x+160, y+100], radius=5, fill=COLORS['cyan'], outline=COLORS['white'])
    draw.text((x+30, y+80), "Uvicorn ASGI", fill=COLORS['bg'], font=fonts['small'])
    
    # Endpoints
    y = 200
    endpoints = [
        ("GET /", "API info (public)"),
        ("GET /health", "Health check (public)"),
        ("GET /connectivity", "Connection status"),
        ("POST /auth/login", "Get JWT token"),
        ("POST /auth/api-key", "Generate API key"),
        ("POST /api/v1/analyze", "Analyze single URL"),
        ("POST /api/v1/batch-analyze", "Batch analysis"),
        ("GET /api/v1/features", "Extract features"),
    ]
    
    x = 50
    draw.rounded_rectangle([x-10, y-20, x+350, y+220], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x, y-10), "API ENDPOINTS", fill=COLORS['white'], font=fonts['subtitle'])
    
    for i, (endpoint, desc) in enumerate(endpoints):
        draw.text((x, y+15 + i*25), endpoint, fill=COLORS['white'], font=fonts['label'])
        draw.text((x+180, y+15 + i*25), desc, fill=COLORS['gray'], font=fonts['small'])
    
    # Authentication
    x = 450
    draw.rounded_rectangle([x, y-20, x+300, y+220], radius=10, fill=COLORS['red'], outline=COLORS['white'], width=2)
    draw.text((x+10, y-10), "AUTHENTICATION & SECURITY", fill=COLORS['white'], font=fonts['subtitle'])
    
    auth_items = [
        ("JWT Tokens", "HS256, 24hr expiry"),
        ("API Keys", "SHA-256 hashed"),
        ("Rate Limiting", "100 req/min/IP"),
        ("CORS", "Cross-origin enabled"),
        ("HTTPS", "TLS 1.2+ required"),
    ]
    for i, (name, value) in enumerate(auth_items):
        draw.text((x+10, y+20 + i*35), f"• {name}", fill=COLORS['white'], font=fonts['label'])
        draw.text((x+20, y+35 + i*35), value, fill=COLORS['gray'], font=fonts['small'])
    
    # Request Flow
    x = 800
    draw.rounded_rectangle([x, y-20, x+350, y+220], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+10, y-10), "REQUEST PROCESSING FLOW", fill=COLORS['bg'], font=fonts['subtitle'])
    
    flow = [
        ("1. Request received",
         "  ↓"),
        ("2. Validate auth token",
         "  ↓"),
        ("3. Rate limit check",
         "  ↓"),
        ("4. Extract URL features",
         "  ↓"),
        ("5. Run ML prediction",
         "  ↓"),
        ("6. Optional: LLM analysis",
         "  ↓"),
        ("7. Return result JSON",
         "  ✓")
    ]
    for i, (step, arrow) in enumerate(flow):
        draw.text((x+10, y+15 + i*25), step, fill=COLORS['bg'], font=fonts['small'])
        draw.text((x+150, y+15 + i*25), arrow, fill=COLORS['dark'], font=fonts['small'])
    
    # Models/Schemas
    y = 480
    draw.rounded_rectangle([50, y, 400, y+180], radius=10, fill=COLORS['orange'], outline=COLORS['white'], width=2)
    draw.text((60, y+10), "Pydantic Schemas", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((60, y+35), "URLAnalysisRequest", fill=COLORS['bg'], font=fonts['label'])
    draw.text((60, y+55), "URLAnalysisResponse", fill=COLORS['bg'], font=fonts['label'])
    draw.text((60, y+75), "ClassificationResult", fill=COLORS['bg'], font=fonts['label'])
    draw.text((60, y+95), "BatchURLAnalysisRequest", fill=COLORS['bg'], font=fonts['label'])
    draw.text((60, y+115), "HealthResponse", fill=COLORS['bg'], font=fonts['label'])
    draw.text((60, y+135), "TokenResponse", fill=COLORS['bg'], font=fonts['label'])
    draw.text((60, y+155), "UserCreate", fill=COLORS['bg'], font=fonts['label'])
    
    # Response Format
    x = 500
    draw.rounded_rectangle([x, y, x+650, y+180], radius=10, fill=COLORS['accent'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "RESPONSE FORMAT (JSON)", fill=COLORS['dark'], font=fonts['subtitle'])
    draw.text((x+10, y+35), '{', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+50), '"url": "https://example.com",', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+65), '"classification": "LEGITIMATE",', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+80), '"confidence": 0.99,', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+95), '"risk_score": 0.01,', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+110), '"is_online": true,', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+125), '"features": {...},', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+140), '"ml_analysis": {...},', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+155), '"llm_analysis": {...}', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+10, y+170), '}', fill=COLORS['dark'], font=fonts['small'])
    
    img.save('viva/pdf_images_v2/api_architecture.png')
    print("✓ Created api_architecture.png")

def create_browser_extension():
    """Browser Extension Architecture"""
    width, height = 1200, 700
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 250, 12), "BROWSER EXTENSION ARCHITECTURE (Chrome Manifest V3)", 
              fill=COLORS['white'], font=fonts['title'])
    
    # Extension Components
    components = [
        ("manifest.json", "Extension config\nManifest V3\nPermissions", (50, 80), COLORS['cyan']),
        ("background.js", "Service Worker\nEvent handling\nMessage passing", (300, 80), COLORS['purple']),
        ("content.js", "DOM Observer\nLink scanning\nDOM injection", (550, 80), COLORS['green']),
        ("popup.html/js", "User Interface\nScan button\nResults display", (800, 80), COLORS['orange']),
    ]
    
    for name, desc, (x, y), color in components:
        draw.rounded_rectangle([x, y, x+200, y+120], radius=10, fill=color, outline=COLORS['white'], width=2)
        draw.text((x+10, y+10), name, fill=COLORS['white'], font=fonts['subtitle'])
        draw.text((x+10, y+40), desc, fill=COLORS['white'], font=fonts['small'])
    
    # Flow
    y = 250
    draw.rounded_rectangle([50, y, 1100, y+300], radius=10, fill=COLORS['dark'], outline=COLORS['white'], width=2)
    draw.text((60, y+10), "DETECTION FLOW", fill=COLORS['white'], font=fonts['subtitle'])
    
    steps = [
        ("1. User visits page", "content.js injects into page", 80),
        ("2. DOM Observer scans all links", "Extracts href attributes", 130),
        ("3. Send to API/ML model", "background.js handles", 180),
        ("4. Receive classification", "Safe/Suspicious/Malicious", 230),
        ("5. Update UI indicators", "Color-coded links", 280),
        ("6. Store in localStorage", "History tracking", 330),
    ]
    
    for title, desc, y_pos in steps:
        draw.text((80, y+y_pos), f"→ {title}", fill=COLORS['accent'], font=fonts['label'])
        draw.text((250, y+y_pos), desc, fill=COLORS['gray'], font=fonts['small'])
    
    # Features
    x = 50
    y = 580
    draw.rounded_rectangle([x, y, x+280, y+100], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "KEY FEATURES", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "• Real-time scanning", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+50), "• Color-coded indicators", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+65), "• One-click full scan", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+80), "• History & statistics", fill=COLORS['bg'], font=fonts['small'])
    
    x = 360
    draw.rounded_rectangle([x, y, x+280, y+100], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "PERMISSIONS", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "• activeTab", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+10, y+50), "• storage", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+10, y+65), "• notifications", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+10, y+80), "• scripting", fill=COLORS['white'], font=fonts['small'])
    
    x = 670
    draw.rounded_rectangle([x, y, x+280, y+100], radius=10, fill=COLORS['red'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "UI INDICATORS", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "🟢 Green - Safe", fill=COLORS['green'], font=fonts['small'])
    draw.text((x+10, y+50), "🟡 Yellow - Suspicious", fill=COLORS['orange'], font=fonts['small'])
    draw.text((x+10, y+65), "🔴 Red - Malicious", fill=COLORS['red'], font=fonts['small'])
    draw.text((x+10, y+80), "⚪ Gray - Unchecked", fill=COLORS['gray'], font=fonts['small'])
    
    x = 980
    draw.rounded_rectangle([x, y, x+180, y+100], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "INSTALL", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "1. Load unpacked", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+50), "2. Point to folder", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+65), "3. Enable in Chrome", fill=COLORS['bg'], font=fonts['small'])
    
    img.save('viva/pdf_images_v2/browser_extension.png')
    print("✓ Created browser_extension.png")

def create_tauri_gui():
    """Tauri Desktop App Architecture"""
    width, height = 1200, 600
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 220, 12), "DESKTOP APPLICATION ARCHITECTURE (Tauri + React)", 
              fill=COLORS['white'], font=fonts['title'])
    
    # Frontend
    x, y = 50, 80
    draw.rounded_rectangle([x, y, x+250, y+200], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "FRONTEND (React + TypeScript)", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+10, y+40), "Components:", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+20, y+60), "• URLInput", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+75), "• ResultDisplay", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+90), "• HistoryList", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+105), "• Statistics", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+120), "• Settings", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+135), "• ScanButton", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+150), "• StatusBar", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+165), "• ThemeToggle", fill=COLORS['dark'], font=fonts['small'])
    
    # Arrow
    draw.line([300, 180, 380, 180], fill=COLORS['white'], width=3)
    draw.polygon([380, 180, 365, 175, 365, 185], fill=COLORS['white'])
    
    # Tauri Core
    x = 380
    draw.rounded_rectangle([x, y, x+180, y+200], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "TAURI CORE", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+10, y+40), "Backend:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+60), "• Rust runtime", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+75), "• IPC commands", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+90), "• Window mgmt", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+105), "• System tray", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+120), "• Native dialogs", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+135), "• File system", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+150), "• Notifications", fill=COLORS['white'], font=fonts['small'])
    
    # Arrow
    draw.line([560, 180, 640, 180], fill=COLORS['white'], width=3)
    
    # Python Backend
    x = 640
    draw.rounded_rectangle([x, y, x+250, y+200], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "PYTHON BACKEND (API)", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+10, y+40), "Services:", fill=COLORS['bg'], font=fonts['label'])
    draw.text((x+20, y+60), "• PhishDetector", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+75), "• URLFeatureExtractor", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+90), "• TyposquattingDetector", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+105), "• TLSAnalyzer", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+120), "• WebScraper", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+135), "• ML models (RF, XGB)", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+150), "• LLM integration", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+165), "• JWT auth", fill=COLORS['dark'], font=fonts['small'])
    
    # Arrow
    draw.line([770, 180, 850, 180], fill=COLORS['white'], width=3)
    
    # ML Models
    x = 850
    draw.rounded_rectangle([x, y, x+180, y+200], radius=10, fill=COLORS['orange'], outline=COLORS['white'], width=2)
    draw.text((x+20, y+10), "ML MODELS", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+10, y+40), "Loaded:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+60), "• Random Forest", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+75), "• XGBoost", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+90), "• Soft Voting", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+115), "Performance:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+135), "• 99.64% accuracy", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+150), "• 99.70% F1", fill=COLORS['white'], font=fonts['small'])
    draw.text((x+20, y+165), "• 93 features", fill=COLORS['white'], font=fonts['small'])
    
    # Bottom - Features
    y = 350
    draw.rounded_rectangle([50, y, 600, y+220], radius=10, fill=COLORS['light_bg'], outline=COLORS['white'], width=2)
    draw.text((60, y+10), "DESKTOP APP FEATURES", fill=COLORS['white'], font=fonts['subtitle'])
    
    features = [
        ("Native desktop experience", "Cross-platform (Windows, Mac, Linux)"),
        ("Offline capability", "Works without internet (local ML model)"),
        ("System tray", "Background scanning, notifications"),
        ("Native notifications", "Alert on phishing detection"),
        ("File system access", "Export scan history"),
        ("Dark/Light theme", "User preference support"),
    ]
    for i, (name, desc) in enumerate(features):
        draw.text((70, y+40 + i*30), f"• {name}", fill=COLORS['white'], font=fonts['label'])
        draw.text((220, y+40 + i*30), desc, fill=COLORS['gray'], font=fonts['small'])
    
    # Build info
    x = 680
    draw.rounded_rectangle([x, y, x+350, y+220], radius=10, fill=COLORS['accent'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "BUILD & DEPLOYMENT", fill=COLORS['dark'], font=fonts['subtitle'])
    
    build_info = [
        ("Frontend Build:", "Vite + React + TypeScript"),
        ("Backend:", "Tauri 2.x + Python 3.9+"),
        ("Package Manager:", "npm + pip"),
        ("Output:", "Native executables (.exe, .app, .deb)"),
        ("Size:", "~5-10MB (compressed)"),
        ("Security:", "Sandboxed, no remote code"),
    ]
    for i, (label, value) in enumerate(build_info):
        draw.text((x+10, y+40 + i*30), label, fill=COLORS['dark'], font=fonts['label'])
        draw.text((x+140, y+40 + i*30), value, fill=COLORS['dark'], font=fonts['small'])
    
    img.save('viva/pdf_images_v2/tauri_gui.png')
    print("✓ Created tauri_gui.png")

def create_mllm_integration():
    """MLLM (Qwen2.5) Integration for AI-generated phishing detection"""
    width, height = 1200, 700
    img = Image.new('RGB', (width, height), color=COLORS['bg'])
    draw = ImageDraw.Draw(img)
    fonts = get_fonts()
    
    # Title
    draw.rectangle([0, 0, width, 50], fill=COLORS['light_bg'])
    draw.text((width//2 - 280, 12), "MLLM INTEGRATION (Qwen2.5-3B-Instruct for AI Phishing Detection)", 
              fill=COLORS['white'], font=fonts['title'])
    
    # Problem Statement
    y = 80
    draw.rounded_rectangle([50, y, 550, y+100], radius=10, fill=COLORS['red'], outline=COLORS['white'], width=2)
    draw.text((60, y+10), "THE PROBLEM: AI-GENERATED PHISHING", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((60, y+40), "• Large Language Models (LLMs) can generate", fill=COLORS['white'], font=fonts['small'])
    draw.text((60, y+55), "  convincing phishing content automatically", fill=COLORS['white'], font=fonts['small'])
    draw.text((60, y+75), "• Traditional ML models struggle to detect", fill=COLORS['white'], font=fonts['small'])
    draw.text((60, y+90), "  these novel, AI-created attacks", fill=COLORS['white'], font=fonts['small'])
    
    # Solution
    x = 600
    draw.rounded_rectangle([x, y, x+550, y+100], radius=10, fill=COLORS['green'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "OUR SOLUTION: Qwen2.5-3B-Instruct", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+10, y+40), "• 4-bit quantized for efficiency (~2GB VRAM)", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+55), "• Specialized prompt for phishing analysis", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+70), "• Context-aware content understanding", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+85), "• Detects AI-generated social engineering", fill=COLORS['bg'], font=fonts['small'])
    
    # Architecture
    y = 220
    draw.rounded_rectangle([50, y, 1100, y+200], radius=10, fill=COLORS['dark'], outline=COLORS['white'], width=2)
    draw.text((60, y+10), "LLM DETECTION PIPELINE", fill=COLORS['white'], font=fonts['subtitle'])
    
    pipeline = [
        ("URL Input", "User submits URL for analysis", 50),
        ("Content Fetch", "Web scraper gets page content", 50 + 50),
        ("ML Classification", "RF+XGB quick screening", 50 + 100),
        ("LLM Analysis (conditional)", "Only if ML uncertain (<80%)", 50 + 150),
        ("Result Synthesis", "Combine ML + LLM conclusions", 50 + 200),
    ]
    
    for label, desc, y_pos in pipeline:
        draw.text((80, y+y_pos), f"→ {label}", fill=COLORS['accent'], font=fonts['label'])
        draw.text((250, y+y_pos), desc, fill=COLORS['gray'], font=fonts['small'])
        if y_pos < 50 + 150:
            draw.line([420, y+y_pos+15, 450, y+y_pos+15], fill=COLORS['gray'], width=2)
    
    # Model Details
    x = 50
    y = 450
    draw.rounded_rectangle([x, y, x+350, y+220], radius=10, fill=COLORS['purple'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "MODEL SPECIFICATIONS", fill=COLORS['white'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "Base Model:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+55), "Qwen2.5-3B-Instruct", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+10, y+80), "Quantization:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+100), "4-bit AWQ", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+10, y+125), "VRAM Usage:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+145), "~2GB", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+10, y+170), "Inference:", fill=COLORS['white'], font=fonts['label'])
    draw.text((x+20, y+190), "Ollama / Transformers", fill=COLORS['gray'], font=fonts['small'])
    
    # Prompt Template
    x = 430
    draw.rounded_rectangle([x, y, x+350, y+220], radius=10, fill=COLORS['cyan'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "PROMPT TEMPLATE", fill=COLORS['bg'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "Analyze this URL for phishing:", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+10, y+55), "URL: {url}", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+10, y+75), "Content: {scraped_text}", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+10, y+100), "Consider:", fill=COLORS['bg'], font=fonts['small'])
    draw.text((x+20, y+120), "• Urgency tactics", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+20, y+135), "• Grammar errors", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+20, y+150), "• Suspicious domains", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+20, y+165), "• Generic greetings", fill=COLORS['gray'], font=fonts['small'])
    draw.text((x+20, y+180), "• Too-good-to-be-true", fill=COLORS['gray'], font=fonts['small'])
    
    # Results Integration
    x = 810
    draw.rounded_rectangle([x, y, x+340, y+220], radius=10, fill=COLORS['accent'], outline=COLORS['white'], width=2)
    draw.text((x+10, y+10), "RESULTS & INTEGRATION", fill=COLORS['dark'], font=fonts['subtitle'])
    draw.text((x+10, y+35), "Response JSON:", fill=COLORS['dark'], font=fonts['label'])
    draw.text((x+10, y+55), "{", fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+70), '"llm_classification":', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+85), '"AI_GENERATED_PHISHING",', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+100), '"confidence": 0.87,', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+115), '"reasoning": "...",', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+20, y+130), '"tactics_detected":', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+145), '["urgency",', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+30, y+160), ' "suspicious_domain"]', fill=COLORS['dark'], font=fonts['small'])
    draw.text((x+10, y+180), "}", fill=COLORS['dark'], font=fonts['small'])
    
    # Why Qwen
    y = 680
    draw.rounded_rectangle([50, y-10, 1100, y+10], radius=5, fill=COLORS['green'], outline=COLORS['white'])
    draw.text((width//2 - 200, y-5), "Why Qwen2.5? Open-source, efficient, excellent instruction-following, competitive with GPT-3.5", 
              fill=COLORS['bg'], font=fonts['small'])
    
    img.save('viva/pdf_images_v2/mllm_integration.png')
    print("✓ Created mllm_integration.png")

if __name__ == "__main__":
    create_api_architecture()
    create_browser_extension()
    create_tauri_gui()
    create_mllm_integration()
    print("\nAll component images created!")
