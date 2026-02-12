# 🛡️ Phishing Guard v2.0
## IEEE Final Year Project Presentation
### Multimodal AI-Based Phishing Detection System with Enhanced Security

**35 Professional Slides with Visual Diagrams & Speaker Notes**

---

# SECTION 1: INTRODUCTION (Slides 1-5)

---

## SLIDE 1: Title Slide

**Visual Design:**
- Background: Gradient deep blue (#1e3a8a to #3b82f6)
- Center: Large shield icon (🛡️) with AI brain overlay (🤖)
- Title: "PHISHING GUARD v2.0" (48pt, white, bold)
- Subtitle: "Multimodal AI-Based Phishing Detection System with Enhanced Security"
- Bottom: "Final Year IEEE Project | Production-Grade Security Solution"
- Student name, Institution, Date

**Layout:**
```
┌─────────────────────────────────────────┐
│                                         │
│              🛡️  🤖                     │
│                                         │
│        PHISHING GUARD v2.0              │
│                                         │
│   Multimodal AI-Based Phishing          │
│   Detection System with                 │
│   Enhanced Security                     │
│                                         │
│   ─────────────────────────────────     │
│                                         │
│   Final Year IEEE Project               │
│   Production-Grade Security Solution    │
│                                         │
│   [Your Name]                           │
│   [Institution Name]                    │
│   February 2025                         │
│                                         │
└─────────────────────────────────────────┘
```

**Speaker Notes:**
"Good morning everyone. Today I'm presenting Phishing Guard v2.0, a production-grade phishing detection system addressing critical gaps in cybersecurity. This isn't just an academic project—it's a deployable security system with enterprise-grade features including JWT authentication, SSRF protection, and 99.8% detection accuracy."

---

## SLIDE 2: Agenda / Presentation Roadmap

**Visual Design:**
- Vertical flowchart with 8 sections
- Icons for each section
- Color-coded path

**Content:**
```
PRESENTATION FLOW

1️⃣  INTRODUCTION        → Project overview & motivation
2️⃣  BACKGROUND          → Threat landscape & gaps        
3️⃣  OBJECTIVES          → Goals & innovations
4️⃣  METHODOLOGY         → Architecture & detection ⭐
5️⃣  TECHNOLOGIES        → Tech stack & tools
6️⃣  RESULTS             → Performance metrics ⭐
7️⃣  COMPARISON          → Competitive analysis
8️⃣  CONCLUSION          → Achievements & future work

⭐ = Major Technical Sections

KEY HIGHLIGHTS:
99.8% F1 Score | 93 ML Features | 4-Category Classification
```

**Speaker Notes:**
"I'll guide you through 8 sections. We'll spend significant time on methodology and results where our technical innovations lie. I've prepared live demos and will conclude with our roadmap for future enhancements."

---

## SLIDE 3: Abstract - Executive Summary

**Visual Design:**
- Four-quadrant layout
- Large metric cards at bottom
- Icons for each section

**Content:**
```
┌─────────────────────────────────────────────────────────┐
│                    PROJECT ABSTRACT                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  🎯 PROBLEM          │  💡 SOLUTION                     │
│  3.4B phishing       │  4-tier multimodal              │
│  emails/day          │  detection pipeline             │
│  $4.88M avg cost     │  99.8% F1 score                 │
│  ─────────────────   │  ─────────────────               │
│  AI-generated        │  IDN/Homograph                  │
│  attacks rising      │  detection (FIRST!)             │
│  Visual spoofing     │  AI-phishing classifier         │
│                      │  Production security            │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  📊 KEY METRICS                                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │  99.8%   │  │   93     │  │    4     │  │   8    │  │
│  │   F1     │  │ Features │  │ Categories│  │  CVEs  │  │
│  │  Score   │  │ (+365%)  │  │Classification│ Patched│  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
│                                                         │
│  🏆 INNOVATION: First system combining IDN detection   │
│     with AI-generated phishing classification           │
│     in a production-ready platform                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Speaker Notes:**
"Our abstract in one slide: We address 3.4 billion daily phishing emails using a 4-tier detection pipeline. Key innovation—detecting IDN homograph attacks using Cyrillic lookalikes and AI-generated phishing, both missed by current systems. Result: 99.8% F1 score with 93 features, a 365% improvement over typical 20-feature solutions."

---

## SLIDE 4: Motivation - Why This Matters

**Visual Design:**
- Split screen: Statistics (left) vs Attack Evolution (right)
- Large numbers with icons
- Timeline showing threat progression

**Content:**
```
THE PHISHING EPIDEMIC

┌────────────────────────┐  ┌─────────────────────────────┐
│    BY THE NUMBERS      │  │    ATTACK EVOLUTION         │
│                        │  │                             │
│  📧 3.4 Billion        │  │  2023: Basic Phishing       │
│     emails/day         │  │        ✅ Detectable        │
│                        │  │                             │
│  💰 $4.88 Million      │  │  2024: AI-Generated         │
│     avg cost/breach    │  │        ⚠️ Perfect grammar   │
│                        │  │        ❌ No typos          │
│  📈 +1,265%            │  │        ❌ Traditional ML    │
│     AI phishing surge  │  │            FAILS!           │
│                        │  │                             │
│  🎭 82.6%              │  │  2025: Visual Spoofing      │
│     contain AI content │  │        🔤 IDN Attacks       │
│                        │  │        раураl.com vs        │
│  ⚠️ 24.5%              │  │        paypal.com           │
│     human detection    │  │        ❌ Invisible!        │
│                        │  │                             │
│  Sources: APWG, IBM,   │  │  🆘 Next-gen detection      │
│  KnowBe4 2024-2025     │  │     NEEDED NOW!             │
└────────────────────────┘  └─────────────────────────────┘
```

**Speaker Notes:**
"The motivation is clear: 3.4 billion phishing emails daily costing $4.88 million per breach. But the threat is evolving. AI-generated phishing increased 1,265%—these attacks have perfect grammar, no typos, so traditional detection fails. And visual spoofing using IDN homographs—like Cyrillic 'раураl.com' spoofing PayPal—are invisible to users. Current solutions can't handle these next-gen attacks."

---

## SLIDE 5: Problem Statement

**Visual Design:**
- Three-column layout showing gaps
- Visual icons for each problem
- Red X marks for limitations

**Content:**
```
CRITICAL GAPS IN CURRENT SOLUTIONS

┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   ❌ GAP 1      │  │   ❌ GAP 2      │  │   ❌ GAP 3      │
│                 │  │                 │  │                 │
│  No IDN/        │  │  No AI-Gen      │  │  Binary Only    │
│  Homograph      │  │  Detection      │  │  Classification │
│  Protection     │  │                 │  │                 │
│                 │  │                 │  │                 │
│  • Miss visual  │  │  • Can't detect │  │  • Only: Safe/  │
│    spoofing     │  │    ChatGPT      │  │    Unsafe       │
│  • No Unicode   │  │    attacks      │  │  • No threat    │
│    analysis     │  │  • Fail on      │  │    granularity  │
│                 │  │    perfect      │  │                 │
│                 │  │    grammar      │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    ❌ GAP 4                             │
│              Inadequate Security                        │
│                                                         │
│  • No authentication            • No rate limiting      │
│  • Plaintext credentials        • No SSRF protection    │
│  • No input validation          • Not production-ready  │
└─────────────────────────────────────────────────────────┘

RESEARCH QUESTION:
How can we build a phishing detection system that addresses IDN attacks,
AI-generated content, provides granular classification, AND meets
enterprise security standards?
```

**Speaker Notes:**
"Current solutions have four critical gaps. First, no IDN protection—missing visual spoofing. Second, no AI-generated detection—failing on ChatGPT attacks. Third, binary classification only—no threat granularity. Fourth, inadequate security—not production-ready. Our research question: How to build a system addressing ALL these gaps?"

---

# SECTION 2: BACKGROUND & RELATED WORK (Slides 6-8)

---

## SLIDE 6: Phishing Threat Landscape

**Visual Design:**
- Infographic-style with attack types
- Icons for each attack vector
- Severity indicators

**Content:**
```
MODERN PHISHING ATTACK VECTORS

┌─────────────────────────────────────────────────────────┐
│                                                         │
│  🎣 TRADITIONAL          🤖 AI-POWERED                 │
│  ├─ Email spoofing       ├─ ChatGPT-generated          │
│  ├─ Typosquatting        ├─ Deepfake voice/video       │
│  ├─ Fake login pages     ├─ Perfect grammar/content    │
│  └─ Urgency tactics      └─ Adaptive social eng.       │
│                                                         │
│  🌐 TECHNICAL            📱 MOBILE-FIRST               │
│  ├─ IDN homographs       ├─ Smishing (SMS)            │
│  ├─ SSL/TLS abuse        ├─ QR code phishing          │
│  ├─ Phishing kits        ├─ App-based attacks         │
│  └─ Man-in-the-middle    └─ Mobile-optimized spoofs    │
│                                                         │
├─────────────────────────────────────────────────────────┤
│  ATTACKER TOOLKITS:                                     │
│  [Gophish] [Evilginx2] [HiddenEye] [SocialFish]         │
│  → Automated phishing campaign creation                 │
│  → Professional-looking fake sites                      │
│  → Built-in credential harvesting                       │
└─────────────────────────────────────────────────────────┘
```

**Speaker Notes:**
"Phishing attacks are becoming sophisticated. Traditional email spoofing now combines with AI-powered attacks using ChatGPT for perfect content, deepfakes for voice, and technical attacks like IDN homographs. Attackers use toolkits like Gophish and Evilginx2 for automated campaigns. Mobile-first attacks exploit small screens hiding malicious URLs."

---

## SLIDE 7: Existing Solutions & Limitations

**Visual Design:**
- Comparison table with 4 columns
- Checkmarks and X marks
- Color-coded performance

**Content:**
```
COMPARISON WITH EXISTING SOLUTIONS

┌─────────────────┬───────────┬──────────────┬──────────────┐
│    Feature      │ PhishTank │ Google Safe  │ Traditional  │
│                 │           │  Browsing    │ ML Systems   │
├─────────────────┼───────────┼──────────────┼──────────────┤
│ Real-time Scan  │     ❌    │      ❌      │      ✅      │
│ Blacklist-based │     ✅    │      ✅      │      ❌      │
│ ML Features     │    N/A    │     N/A      │     ~20      │
│ AI Detection    │     ❌    │      ❌      │      ❌      │
│ IDN Protection  │     ❌    │      ❌      │      ❌      │
│ 4-Category      │     ❌    │      ❌      │      ❌      │
│ Classification  │           │              │              │
│ Browser Ext     │     ❌    │      ✅      │      ❌      │
│ Security Hard.  │    N/A    │ Enterprise   │    Basic     │
│ Open Source     │     ✅    │      ❌      │    Varies    │
└─────────────────┴───────────┴──────────────┴──────────────┘

LEGEND: ✅ Supported  ❌ Not Supported  N/A Not Applicable

KEY INSIGHT: No existing solution combines ALL needed features!
```

**Speaker Notes:**
"Comparing existing solutions: PhishTank and Google Safe Browsing use blacklists—reactive, not proactive. Traditional ML systems have only ~20 features and lack AI detection, IDN protection, and granular classification. None combine real-time scanning, AI detection, IDN protection, 4-category classification, AND production security. This gap is our opportunity."

---

## SLIDE 8: Research Gap Analysis

**Visual Design:**
- Central diagram showing the gap
- Four pillars representing missed areas
- Arrow pointing to our solution

**Content:**
```
THE RESEARCH GAP

┌─────────────────────────────────────────────────────────┐
│                                                         │
│   CURRENT SYSTEMS          vs         IDEAL SYSTEM      │
│                                                         │
│   ┌──────────────┐                    ┌──────────────┐  │
│   │  20 Features │      GAP!          │  93 Features │  │
│   │  Binary      │  ═══════════════►  │  4-Category  │  │
│   │  No Security │                    │  Enterprise  │  │
│   └──────────────┘                    │  Security    │  │
│                                       └──────────────┘  │
│                                                         │
│   SPECIFIC GAPS:                                        │
│   ┌─────────────────────────────────────────────────┐   │
│   │  🔤 Visual Spoofing: No Unicode/IDN detection  │   │
│   │  🤖 AI Content: Can't detect GPT-generated     │   │
│   │  📊 Granularity: Binary only (safe/unsafe)     │   │
│   │  🔒 Security: Not production-ready             │   │
│   └─────────────────────────────────────────────────┘   │
│                                                         │
│   OUR CONTRIBUTION:                                     │
│   ✅ First unified system addressing ALL gaps          │
│   ✅ Novel IDN detection methodology                   │
│   ✅ AI-phishing classification innovation             │
│   ✅ Production-grade security implementation          │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Speaker Notes:**
"The research gap is clear. Current systems have limited features, binary classification, and no security hardening. The ideal system needs 93 features, 4-category classification, and enterprise security. Specific gaps: no visual spoofing detection, no AI content detection, no granularity, and not production-ready. Our contribution is the FIRST unified system addressing ALL these gaps."

---

# SECTION 3: OBJECTIVES (Slides 9-10)

---

## SLIDE 9: Primary Objectives

**Visual Design:**
- Four objective cards with icons
- Progress indicators
- Color-coded by category

**Content:**
```
PROJECT OBJECTIVES

┌─────────────────────────────────────────────────────────┐
│                                                         │
│  🎯 OBJECTIVE 1          🎯 OBJECTIVE 2                 │
│  Build 4-Tier            Detect AI-Generated           │
│  Detection Pipeline      Phishing Content              │
│                                                         │
│  • Static analysis       • MLLM integration            │
│  • ML classification     • Linguistic analysis         │
│  • MLLM reasoning        • Pattern recognition         │
│  • Web scraping          • Confidence scoring          │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  🎯 OBJECTIVE 3          🎯 OBJECTIVE 4                 │
│  Prevent IDN/Homograph   Production-Grade              │
│  Attacks                 Security                      │
│                                                         │
│  • Punycode detection    • JWT authentication          │
│  • Mixed script analysis • Rate limiting               │
│  • Confusable mapping    • SSRF protection             │
│  • Risk scoring          • Input validation            │
│                                                         │
└─────────────────────────────────────────────────────────┘

SUCCESS CRITERIA:
✓ F1 Score > 95%        ✓ 8 CVEs patched
✓ Latency < 2 seconds   ✓ 100% security coverage
```

**Speaker Notes:**
"Our four primary objectives. First, build a 4-tier detection pipeline combining multiple techniques. Second, detect AI-generated phishing using MLLM analysis. Third, prevent IDN homograph attacks through comprehensive Unicode analysis—this is our novel contribution. Fourth, implement production-grade security with JWT, rate limiting, and SSRF protection. Success criteria: F1 score above 95%, latency under 2 seconds, 8 CVEs patched, and 100% security coverage."

---

## SLIDE 10: Key Innovations & USPs

**Visual Design:**
- Five innovation pillars
- Unique visual for each
- Impact metrics

**Content:**
```
5 KEY INNOVATIONS (UNIQUE SELLING POINTS)

┌─────────────────────────────────────────────────────────┐
│                                                         │
│  🥇 USP 1: IDN Detection                               │
│  ─────────────────────────────                         │
│  • FIRST academic implementation                       │
│  • Detects Cyrillic/Greek lookalikes                   │
│  • 11 specialized features                             │
│  • Blocks visual spoofing attacks                      │
│                                                         │
│  🤖 USP 2: AI-Generated Classification                 │
│  ─────────────────────────────────────                 │
│  • Separate category for GPT attacks                   │
│  • Qwen2.5-3B MLLM analysis                            │
│  • Detects perfect grammar/content                     │
│  • Addresses emerging threat                           │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  📊 USP 3: 365% Feature Improvement                    │
│  ─────────────────────────────────                     │
│  • 93 features vs industry 20                          │
│  • 99.8% F1 score achieved                             │
│  • Comprehensive coverage                              │
│  • Advanced engineering                                │
│                                                         │
│  🔒 USP 4: Enterprise Security                         │
│  ─────────────────────────────                         │
│  • 8 CVE-level vulnerabilities patched                │
│  • Production-ready hardening                          │
│  • JWT, SSRF, TLS protection                           │
│  • Bridges research to deployment                      │
│                                                         │
│  🌐 USP 5: Multi-Modal Architecture                    │
│  ─────────────────────────────────                     │
│  • 4-tier ensemble pipeline                            │
│  • Latency-optimized (10ms to 2s)                      │
│  • 5 deployment interfaces                             │
│  • Novel ensemble approach                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Speaker Notes:**
"Five unique selling points. First, IDN detection—FIRST academic implementation detecting Cyrillic lookalikes. Second, AI-generated classification—separate category for GPT attacks using MLLM. Third, 365% feature improvement—93 vs typical 20 features. Fourth, enterprise security—8 CVEs patched, production-ready. Fifth, multi-modal architecture—4-tier ensemble with latency optimization. These innovations together make this IEEE-level research."

---

# SECTION 4: METHODOLOGY (Slides 11-20)

---

## SLIDE 11: System Architecture Overview

**Visual Design:**
- Layered architecture diagram
- Four distinct layers
- Data flow arrows

**Content:**
```
SYSTEM ARCHITECTURE - 4 LAYERS

┌─────────────────────────────────────────────────────────┐
│  LAYER 1: USER INTERFACES                               │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │   CLI    │ │  Web API │ │ Browser  │ │ Desktop  │   │
│  │          │ │          │ │    Ext   │ │   GUI    │   │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   │
│       └─────────────┴───────────┴─────────────┘         │
│                        │                                │
├────────────────────────┼────────────────────────────────┤
│  LAYER 2: API & SECURITY                                │
│  ┌─────────────────────────────────────────────────┐   │
│  │  FastAPI Server                                 │   │
│  │  ├─ JWT Authentication                         │   │
│  │  ├─ Rate Limiting (100 req/min)               │   │
│  │  ├─ Input Validation                           │   │
│  │  ├─ CORS Protection                            │   │
│  │  └─ OpenAPI Documentation                      │   │
│  └─────────────────────────────────────────────────┘   │
│                        │                                │
├────────────────────────┼────────────────────────────────┤
│  LAYER 3: DETECTION PIPELINE                            │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  Tier 1  │→│  Tier 2  │→│  Tier 3  │→│  Tier 4  │   │
│  │  Static  │ │    ML    │ │   MLLM   │ │  Scrape  │   │
│  │  10ms    │ │  100ms   │ │   2s     │ │ Variable │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                        │                                │
├────────────────────────┼────────────────────────────────┤
│  LAYER 4: DATA & MODELS                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │  Random  │ │  MLflow  │ │  Redis   │ │  Feature │   │
│  │  Forest  │ │ Registry │ │   Cache  │ │ Extractor│   │
│  │  Model   │ │          │ │          │ │  (93)    │   │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
└─────────────────────────────────────────────────────────┘
```

**Speaker Notes:**
"Our 4-layer architecture. Layer 1: Five user interfaces—CLI, Web API, Browser Extension, Desktop GUI, and Email Scanner. Layer 2: FastAPI server with enterprise security—JWT auth, rate limiting, input validation. Layer 3: The heart of our system—4-tier detection pipeline from static analysis to web scraping, optimized for latency. Layer 4: Data and models—Random Forest classifier, MLflow registry, Redis cache, and 93-feature extractor."

---

## SLIDE 12: 4-Tier Detection Pipeline

**Visual Design:**
- Horizontal flowchart
- Timing annotations
- Decision diamonds
- Color-coded by tier

**Content:**
```
4-TIER MULTIMODAL DETECTION PIPELINE

┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│   TIER 1     │      │   TIER 2     │      │   TIER 3     │
│   STATIC     │───▶  │     ML       │───▶  │    MLLM      │
│   ANALYSIS   │      │ CLASSIFIER   │      │   ANALYSIS   │
│              │      │              │      │  (Optional)  │
│   ~10ms      │      │   ~100ms     │      │    ~2s       │
└──────────────┘      └──────────────┘      └──────┬───────┘
       │                    │                       │
       ▼                    ▼                       ▼
┌─────────────────────────────────────────────────────────┐
│                    TIER 4                               │
│               WEB SCRAPING                              │
│           (If Online & High Risk)                       │
│                                                         │
│  • Playwright headless browser                          │
│  • Screenshot capture                                   │
│  • Form analysis                                        │
│  • Toolkit fingerprinting                               │
└─────────────────────────────────────────────────────────┘

TIER 1 - STATIC ANALYSIS:
✓ URL parsing & validation    ✓ Typosquatting detection
✓ IDN/Homograph detection     ✓ Whitelist check

TIER 2 - ML CLASSIFICATION:
✓ 93-feature extraction       ✓ Random Forest prediction
✓ Probability calculation     ✓ Feature importance

TIER 3 - MLLM ANALYSIS:
✓ Qwen2.5-3B model            ✓ AI content detection
✓ Linguistic patterns         ✓ Confidence adjustment

TIER 4 - WEB SCRAPING:
✓ Dynamic content analysis    ✓ Toolkit signature matching
```

**Speaker Notes:**
"Our 4-tier detection pipeline. Tier 1: Static analysis in 10ms—URL parsing, typosquatting, IDN detection. Tier 2: ML classifier in 100ms—93 features, Random Forest, 99.8% accuracy. Tier 3: MLLM analysis in 2 seconds—optional for high-risk URLs, uses Qwen2.5-3B to detect AI-generated content. Tier 4: Web scraping—dynamic analysis with Playwright, toolkit fingerprinting. Each tier adds confidence; lower tiers are fast filters, upper tiers provide deep analysis."

---

## SLIDE 13: Feature Extraction Engine

**Visual Design:**
- Feature category breakdown
- Comparison bar chart
- Highlight on novel features

**Content:**
```
93 ML FEATURES - 365% IMPROVEMENT

FEATURE BREAKDOWN BY CATEGORY:

IDN/Unicode      ████████████████████  11 features (NOVEL!)
Host Analysis    ████████████████████  10 features
URL Patterns     ████████████████████████████████████████  28 features
Security         ██████████   6 features
TLS/SSL          ████████████████████  11 features
Composite        ████████   3 features
Other            ████████████████████████  24 features
                 0    10    20    30

COMPARISON:
Traditional Systems:        20 features  ████████
Phishing Guard v2.0:        93 features  ████████████████████████████████  (+365%)

KEY NOVEL FEATURES:
┌────────────────────┬──────────────────────────────────────┐
│ has_punycode       │ Detects xn-- encoding (IDN)         │
│ mixed_scripts      │ Latin + Cyrillic/Greek detection    │
│ confusable_count   │ Lookalike character analysis        │
│ hsts_enabled       │ HTTP Strict Transport Security      │
│ ct_logs_found      │ Certificate Transparency logs       │
│ domain_age_days    │ Temporal analysis                   │
│ tls_version        │ TLS 1.3 enforcement                 │
│ ip_in_url          │ Direct IP detection                 │
└────────────────────┴──────────────────────────────────────┘

IMPACT: Comprehensive coverage = 99.8% F1 Score
```

**Speaker Notes:**
"Feature extraction is our strength. We have 93 features across 6 categories—a 365% improvement over typical 20-feature systems. Key novel features: has_punycode detects IDN encoding, mixed_scripts finds Latin+Cyrillic combinations, confusable_count identifies lookalike characters. HSTS and certificate transparency features for TLS analysis. Domain age for temporal analysis. This comprehensive feature engineering directly contributes to our 99.8% F1 score."

---

## SLIDE 14: IDN Detection Innovation

**Visual Design:**
- Before/After comparison
- Unicode character examples
- Risk scoring visualization

**Content:**
```
IDN/HOMOGRAPH ATTACK DETECTION - NOVEL CONTRIBUTION

THE PROBLEM:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  Legitimate:  paypal.com                                │
│               └── All ASCII (Latin script)              │
│                                                         │
│  Malicious:   раураl.com  ← LOOKS IDENTICAL!           │
│               └── р = Cyrillic U+0440 (not Latin p)    │
│               └── а = Cyrillic U+0430 (not Latin a)    │
│                                                         │
│  Punycode:    xn--pypal-4ve.com  ← Browser shows this │
│                                                         │
│  ⚠️  Traditional systems see "paypal.com"              │
│     ✅ Our system detects Unicode spoofing              │
│                                                         │
└─────────────────────────────────────────────────────────┘

OUR SOLUTION:
┌─────────────────────────────────────────────────────────┐
│  11 Specialized IDN Features:                           │
│                                                         │
│  1. has_punycode        → Detects xn-- prefix          │
│  2. mixed_scripts       → Latin + Cyrillic detection   │
│  3. confusable_count    → 25+ lookalike characters     │
│  4. unicode_category    → Letter/Mark/Number analysis  │
│  5. script_blocks       → Identifies all scripts used  │
│  6. idn_risk_score      → Composite threat score       │
│  7. homograph_ratio     → Suspicious character %       │
│  8. punycode_ratio      → Encoded character %          │
│  9. decoded_domain      → Original Unicode form        │
│  10. visual_similarity  → Confusion assessment         │
│  11. brand_confusion    │ Impersonation detection      │
│                                                         │
│  RESULT: Blocks visual spoofing attacks!               │
└─────────────────────────────────────────────────────────┘
```

**Speaker Notes:**
"Our novel IDN detection innovation. The problem: attackers use Cyrillic lookalikes—'раураl.com' looks identical to 'paypal.com' but uses Cyrillic 'р' and 'а'. Traditional systems miss this. Our solution: 11 specialized features. has_punycode detects the xn-- prefix. mixed_scripts identifies Latin+Cyrillic combinations. confusable_count tracks 25+ lookalike characters. Result: we block visual spoofing attacks that bypass all other filters. This is a FIRST in academic phishing detection."

---

## SLIDE 15: ML Classification

**Visual Design:**
- Model architecture diagram
- Performance metrics cards
- Feature importance visualization

**Content:**
```
MACHINE LEARNING CLASSIFICATION

MODEL ARCHITECTURE:
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  Input URL → Feature Extractor → StandardScaler        │
│                                              ↓         │
│                         Random Forest Classifier        │
│                              (n_estimators=200)         │
│                                     ↓                  │
│                    4-Class Probability Output           │
│              [Legit, Phishing, AI-Gen, Kit]            │
│                                     ↓                  │
│                         Classification Result           │
│                                                         │
└─────────────────────────────────────────────────────────┘

PERFORMANCE METRICS:
┌──────────────┬──────────────┬──────────────┬──────────────┐
│    F1 Score  │   Accuracy   │  Precision   │    Recall    │
├──────────────┼──────────────┼──────────────┼──────────────┤
│    99.8%     │    99.6%     │    99.7%     │    99.9%     │
│   ████████   │   ████████   │   ████████   │   ████████   │
└──────────────┴──────────────┴──────────────┴──────────────┘

4-CATEGORY CLASSIFICATION:
┌──────────────────┬──────────────────────────────────────┐
│   Legitimate     │  Safe URLs, whitelisted domains     │
├──────────────────┼──────────────────────────────────────┤
│   Phishing       │  Traditional spoofing attacks       │
├──────────────────┼──────────────────────────────────────┤
│  AI-Generated    │  ChatGPT/AI-created content (NEW)   │
├──────────────────┼──────────────────────────────────────┤
│   Phishing Kit   │  Toolkit-generated (Gophish, etc.)  │
└──────────────────┴──────────────────────────────────────┘

TOP FEATURE IMPORTANCE:
1. domain_age_days       (8.5%)
2. mixed_scripts         (7.2%)  ← IDN feature!
3. has_punycode          (6.8%)  ← IDN feature!
4. suspicious_tld        (6.5%)
5. tls_secure            (6.1%)
```

**Speaker Notes:**
"Our ML classification uses Random Forest with 200 estimators. Input URL goes through feature extraction, standard scaling, then classification into 4 categories—Legitimate, Phishing, AI-Generated, and Phishing Kit. This 4-category approach is novel; most systems use binary. Performance: 99.8% F1 score, 99.6% accuracy. Top features by importance: domain age at 8.5%, mixed_scripts at 7.2%—our IDN features are critical to performance."

---

*Due to length, the presentation continues in the next file...*

---

**END OF SECTIONS 1-4 (Slides 1-15)**

**Next:** Sections 5-8 (Slides 16-35) covering Technologies, Results, Comparison, and Conclusion

**File:** `docs/IEEE_PRESENTATION_SLIDES_16-35.md`
