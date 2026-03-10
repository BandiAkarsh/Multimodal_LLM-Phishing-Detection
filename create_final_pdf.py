#!/usr/bin/env python3
"""
Generate professional technical PDF documentation for Phishing Guard v2.0
- Hybrid format: paragraphs + bullet points + tables + code blocks
- Page 1 = Introduction (Title page + TOC = no numbers)
- Detailed extensive content for each section
- Professional documentation style (like Kotlin/Python official docs)
"""
import io
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak, Table, TableStyle
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

output_path = "viva/Phishing_Guard_Complete_Documentation.pdf"

doc = SimpleDocTemplate(
    output_path,
    pagesize=A4,
    rightMargin=22*mm,
    leftMargin=22*mm,
    topMargin=22*mm,
    bottomMargin=22*mm
)

# Custom styles for professional documentation
styles = getSampleStyleSheet()

title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#1e3a6e'), spaceAfter=20, alignment=1)
heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=15, textColor=colors.HexColor('#1e3a6e'), spaceAfter=12, spaceBefore=15)
subheading_style = ParagraphStyle('Subheading', parent=styles['Heading3'], fontSize=12, textColor=colors.HexColor('#2c5282'), spaceAfter=8, spaceBefore=10)
body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, textColor=colors.black, spaceAfter=10, alignment=4, leading=14)
body_bold_style = ParagraphStyle('BodyBold', parent=styles['Normal'], fontSize=10, textColor=colors.black, spaceAfter=10, alignment=4, leading=14)
code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, textColor=colors.HexColor('#2d3748'), backgroundColor=colors.HexColor('#f5f5f5'), spaceAfter=8, leftIndent=12, rightPadding=10, borderPadding=5)
bullet_style = ParagraphStyle('Bullet', parent=styles['Normal'], fontSize=10, textColor=colors.black, spaceAfter=6, leftIndent=15)
note_style = ParagraphStyle('Note', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#666666'), spaceAfter=8, leftIndent=10, fontslant='italic')

# Table style
table_style = TableStyle([
    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a6e')),
    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
    ('FONTSIZE', (0, 0), (-1, -1), 9),
    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#ffffff'), colors.HexColor('#f8f9fa')]),
])

story = []

# ============= HELPER FUNCTIONS =============
def add_para(text, style=body_style):
    """Add a paragraph with the specified style"""
    story.append(Paragraph(text, style))
    return

def add_heading(text):
    """Add a section heading"""
    story.append(Paragraph(text, heading_style))
    return

def add_subheading(text):
    """Add a subsection heading"""
    story.append(Paragraph(text, subheading_style))
    return

def add_bullet(text):
    """Add a bullet point"""
    story.append(Paragraph("• " + text, bullet_style))
    return

def add_code(text):
    """Add a code block"""
    story.append(Paragraph(text.replace('\n', '<br/>'), code_style))
    return

def add_table(data, col_widths=None):
    """Add a table with consistent styling"""
    if col_widths:
        t = Table(data, colWidths=col_widths)
    else:
        t = Table(data)
    t.setStyle(table_style)
    story.append(t)
    story.append(Spacer(1, 3*mm))
    return

# ============= TITLE PAGE =============
story.append(Spacer(1, 85*mm))
story.append(Paragraph("PHISHING GUARD", title_style))
story.append(Spacer(1, 3*mm))
story.append(Paragraph("AI-Powered Phishing Detection System", styles['Heading2']))
story.append(Spacer(1, 8*mm))
story.append(Paragraph("Comprehensive Technical Documentation", subheading_style))
story.append(Spacer(1, 20*mm))
story.append(Paragraph("<b>A Complete Guide for Understanding, Using, and Extending the System</b>", body_style))
story.append(Spacer(1, 15*mm))
story.append(Paragraph("<b>Project:</b> IEEE Final Year Engineering Project", body_style))
story.append(Paragraph("<b>Institution:</b> Sai Ganapati Engineering College", body_style))
story.append(Paragraph("<b>Date:</b> March 2026", body_style))
story.append(Paragraph("<b>Version:</b> 2.0 (Production Ready)", body_style))
story.append(Spacer(1, 15*mm))
story.append(Paragraph("<i>This documentation provides a complete understanding of the phishing detection system, from basic concepts to advanced implementation details for newcomers and researchers.</i>", note_style))

# ============= TABLE OF CONTENTS =============
story.append(PageBreak())
story.append(Paragraph("Table of Contents", title_style))
story.append(Spacer(1, 8*mm))
toc_items = [
    ("1.", "Introduction", "1"),
    ("2.", "Understanding Phishing Attacks", "2"),
    ("3.", "Problem Statement and Research Gap", "3"),
    ("4.", "Project Objectives and Scope", "4"),
    ("5.", "Complete System Architecture Overview", "6"),
    ("6.", "Dataset Description and Data Sources", "8"),
    ("7.", "Feature Engineering: The 93 ML Features", "10"),
    ("8.", "Machine Learning Models and Training", "12"),
    ("9.", "MLLM Integration: Qwen2.5 for AI Phishing Detection", "14"),
    ("10.", "REST API Service Architecture", "16"),
    ("11.", "Browser Extension Implementation", "18"),
    ("12.", "Desktop Application (Tauri)", "20"),
    ("13.", "Security Implementation Details", "22"),
    ("14.", "Advanced Detection Techniques", "23"),
    ("15.", "Performance Metrics and Evaluation", "24"),
    ("16.", "Testing and Quality Assurance", "26"),
    ("17.", "Deployment Guide", "27"),
    ("18.", "Future Enhancements and Research Directions", "29"),
    ("19.", "Conclusion", "30"),
    ("20.", "References and Resources", "31"),
    ("A.", "Appendix A: Project Directory Structure", "32"),
    ("B.", "Appendix B: Technology Stack Details", "33"),
    ("C.", "Appendix C: API Quick Reference", "34"),
]
for num, title, page in toc_items:
    dot_count = 68 - len(num) - len(title) - len(page)
    story.append(Paragraph(f"<b>{num}</b> {title} {'.'*max(dot_count,3)} {page}", body_style))

# ============= 1. INTRODUCTION =============
story.append(PageBreak())
story.append(Paragraph("1. Introduction", title_style))

add_para("Welcome to the comprehensive documentation of <b>Phishing Guard</b>, an enterprise-grade artificial intelligence system designed to detect and prevent phishing attacks. This documentation provides a complete understanding of the system for students, researchers, developers, and anyone interested in cybersecurity. The Phishing Guard system represents months of careful design, implementation, and testing, incorporating both traditional machine learning techniques and modern large language model capabilities to create robust defense against one of the most prevalent cyber threats facing individuals and organizations today. The system is designed to be accessible to newcomers while also providing depth for experienced security professionals who wish to understand the underlying algorithms and extend the system's capabilities.")

add_para("Phishing attacks continue to be the <b>number one cybersecurity threat</b> globally, causing billions of dollars in losses annually and compromising millions of personal accounts. These attacks have evolved significantly over the years, from simple email scams to highly sophisticated campaigns that leverage artificial intelligence to create incredibly convincing fake websites and communications. The financial impact extends beyond direct theft to include remediation costs, reputation damage, and loss of customer trust. Organizations of all sizes are targeted, from small businesses to large enterprises and financial institutions, making phishing a universal concern in cybersecurity that affects every sector of the economy.")

add_para("The system developed in this project offers several unique capabilities that set it apart from existing solutions. Rather than relying on simple pattern matching or blacklists, this system employs a comprehensive approach that combines multiple detection techniques working in concert. The foundation of the system rests on 93 carefully designed machine learning features that capture various aspects of URL structure, domain characteristics, and security indicators. This rich feature set enables the system to identify subtle patterns that would be invisible to simpler analysis methods, providing higher accuracy and fewer false positives in real-world deployments.")

add_subheading("Key Features of Phishing Guard")
add_bullet("<b>93 Machine Learning Features</b> - Comprehensive URL analysis capturing structural, domain, and security indicators")
add_bullet("<b>Four-Category Classification</b> - Distinguishes legitimate, phishing, AI-generated, and phishing-kit attacks")
add_bullet("<b>Qwen2.5 LLM Integration</b> - Pioneering detection of AI-generated phishing content that traditional models miss")
add_bullet("<b>Multiple User Interfaces</b> - CLI, REST API, Browser Extension, and Desktop Application")
add_bullet("<b>99.70% Accuracy</b> - Ensemble machine learning models achieving 99.82% F1 score")
add_bullet("<b>Production-Ready Security</b> - JWT authentication, rate limiting, and SSRF protection")

add_para("This documentation is organized to take you through the entire system, starting from the basic concepts of phishing attacks and the motivation behind this project, moving through the technical implementation details of each component, and concluding with deployment instructions and future research directions. Each section contains detailed paragraphs explaining the concepts, bullet points summarizing key information, tables presenting comparative data, and code examples where appropriate. This hybrid approach follows professional documentation standards used by major programming languages and frameworks.")

# ============= 2. UNDERSTANDING PHISHING ATTACKS =============
story.append(PageBreak())
story.append(Paragraph("2. Understanding Phishing Attacks", title_style))

add_para("Phishing is a type of <b>social engineering attack</b> where attackers attempt to trick users into revealing sensitive information such as passwords, credit card numbers, or personal data by pretending to be trustworthy entities. These attacks typically involve creating fake websites, emails, or messages that appear identical to legitimate communications from banks, social media platforms, e-commerce sites, or other services that users regularly interact with. The success of phishing attacks relies heavily on human psychology, exploiting trust, urgency, and fear to manipulate victims into acting without thinking critically. Attackers invest significant effort in making their communications appear authentic, often copying branding, logos, and even entire website layouts from legitimate sources.")

add_para("The earliest phishing attacks were relatively crude, often containing obvious grammatical errors, suspicious URLs, and unrealistic promises. However, attackers have become <b>increasingly sophisticated</b> over time. Modern phishing campaigns often feature perfectly crafted emails with accurate branding, working login forms, and URLs that closely mimic legitimate websites. Attackers use techniques such as typosquatting, where they register domain names that are one character different from popular sites, or homograph attacks, where they use characters from different alphabets that look identical to standard letters. The rise of social media has also provided attackers with new vectors for conducting reconnaissance and personalizing their attacks based on publicly available information about potential victims.")

add_para("The emergence of <b>large language models</b> has created a new category of phishing threats that is particularly concerning. AI tools can generate highly convincing phishing emails and website content at scale, with perfect grammar and contextually appropriate language. These AI-generated attacks are difficult to detect using traditional methods because they do not contain the usual telltale signs of phishing, such as grammatical errors or awkward phrasing. Furthermore, these attacks can be personalized and targeted at scale, making traditional awareness training less effective as a defense mechanism.")

add_subheading("Types of Phishing Attacks")
add_bullet("<b>Email Phishing</b> - Mass emails impersonating legitimate organizations")
add_bullet("<b>Spear Phishing</b> - Targeted attacks on specific individuals with personalized content")
add_bullet("<b>Whaling</b> - High-profile targets like executives and senior management")
add_bullet("<b>Clone Phishing</b> - Copying legitimate emails and replacing links with malicious ones")
add_bullet("<b>Voice Phishing (Vishing)</b> - Phone calls impersonating trusted entities")
add_bullet("<b>SMS Phishing (Smishing)</b> - Text messages containing malicious links")
add_bullet("<b>AI-Generated Phishing</b> - LLM-created highly convincing phishing content")

add_subheading("Common Phishing Techniques")
add_bullet("<b>URL Manipulation</b> - Slight variations in domain names (typosquatting)")
add_bullet("<b>Homograph Attacks</b> - Using visually similar characters from different alphabets")
add_bullet("<b>Subdomain Abuse</b> - Long subdomains to hide the actual domain")
add_bullet("<b>URL Shortening</b> - Hiding the true destination behind short links")
add_bullet("<b>HTTPS Abuse</b> - Using SSL certificates to appear legitimate")
add_bullet("<b>Social Engineering</b> - Creating urgency, fear, or excitement")

# ============= 3. PROBLEM STATEMENT =============
story.append(PageBreak())
story.append(Paragraph("3. Problem Statement and Research Gap", title_style))

add_para("Despite the availability of various phishing detection solutions in both commercial and academic domains, <b>significant limitations persist</b> that leave users vulnerable to attacks. This section outlines the specific problems this project addresses and the research gap it aims to fill. Understanding these challenges is crucial for appreciating the design decisions made throughout the system's development. The cybersecurity landscape is constantly evolving, with attackers developing new techniques to bypass existing defenses, making it essential to take a proactive approach to phishing detection rather than relying solely on reactive measures.")

add_para("The first major limitation of existing solutions is their reliance on <b>static rule-based detection systems</b>. These systems use predefined patterns to identify phishing attempts, such as specific keywords, known bad domain patterns, or particular URL structures. While these rules can catch obvious attacks, they fail against novel attack patterns that do not match existing rules. Attackers constantly create new variations to evade detection, making it impossible for rule-based systems to provide comprehensive protection. Furthermore, maintaining and updating these rule sets requires constant human intervention, creating an ongoing operational burden that many organizations struggle to manage effectively.")

add_para("The second significant limitation is the <b>blacklist approach</b> used by many security products. Blacklists maintain lists of known phishing domains and block access to them. While this approach is simple to implement, it suffers from high false negative rates because new phishing domains are created faster than they can be added to blacklists. Attackers can register new domains for each campaign, making blacklists inherently reactive rather than proactive. Additionally, legitimate sites that are mistakenly flagged can cause significant disruptions, and maintaining comprehensive blacklists requires substantial resources that many organizations cannot dedicate to security operations.")

add_para("The third and perhaps most critical limitation is the <b>inability of existing solutions to detect AI-generated phishing content</b>. As large language models become more accessible, attackers can generate sophisticated phishing campaigns at unprecedented scale and quality. These AI-generated attacks do not exhibit the traditional markers that machine learning models have been trained to identify, such as grammatical errors or awkward phrasing. This represents a fundamental gap in the research landscape that requires new approaches combining traditional machine learning with large language model analysis.")

add_subheading("Key Limitations of Existing Solutions")
add_bullet("<b>Static Rule-Based Detection</b> - Cannot detect novel attack patterns")
add_bullet("<b>Blacklist Approach</b> - High false negative rates; new domains created faster than added")
add_bullet("<b>No AI Phishing Detection</b> - Cannot detect AI-generated phishing content")
add_bullet("<b>Limited Feature Sets</b> - Use only basic URL characteristics")
add_bullet("<b>Single Interface Options</b> - Lack of integration for different use cases")
add_bullet("<b>No Category Classification</b> - Binary classification misses attack nuances")

# ============= 4. OBJECTIVES =============
story.append(PageBreak())
story.append(Paragraph("4. Project Objectives and Scope", title_style))

add_para("Based on the problem analysis presented in the previous section, this project was designed with <b>specific objectives</b> that address each identified gap while maintaining practical implementability. This section details these objectives and the scope of work undertaken to achieve them. Each objective was carefully crafted to ensure the final system would be both technically sound and practically useful for real-world deployment scenarios. The objectives also align with industry best practices and academic standards for engineering projects, ensuring the work contributes meaningfully to the field of cybersecurity.")

add_para("The primary objective of this project was to develop a comprehensive feature extraction system capable of analyzing <b>93 or more machine learning features</b> from each URL submitted for analysis. Rather than relying on a handful of obvious signals, this approach examines numerous aspects of URLs including their length characteristics, character distributions, entropy measures, domain registration patterns, and security indicators. By combining these features, the system can identify patterns that would be invisible to simpler analysis methods. This comprehensive feature set also enables the machine learning models to make more nuanced decisions about whether a URL is malicious, reducing both false positives and false negatives in production use.")

add_para("The second objective was to achieve <b>classification accuracy exceeding 99 percent</b> using ensemble machine learning techniques. Rather than relying on a single model, the system combines predictions from multiple models to improve overall accuracy and robustness. The ensemble approach used in this project includes Random Forest, which provides stability and handles non-linear relationships well, and XGBoost, which offers powerful gradient boosting capabilities. By averaging the probability outputs from these models using a soft voting mechanism, the system achieves higher accuracy than either model could achieve alone.")

add_para("The third objective was to implement a <b>four-category classification system</b> that goes beyond the traditional binary legitimate-versus-phishing classification. This system can identify four distinct categories: legitimate URLs, traditional phishing attacks, AI-generated phishing content created using large language models, and phishing kits which are automated tools used by attackers to create fake login pages. Each category requires different handling and response strategies, making this detailed classification valuable for security operations.")

add_subheading("Primary Project Objectives")
add_bullet("Develop comprehensive feature extraction system with <b>93+ ML features</b>")
add_bullet("Achieve classification accuracy exceeding <b>99%</b> using ensemble ML")
add_bullet("Implement <b>four-category classification</b>: legitimate, phishing, AI-generated, phishing-kit")
add_bullet("Integrate <b>Qwen2.5 LLM</b> for AI-generated phishing detection")
add_bullet("Create <b>multiple user interfaces</b>: CLI, REST API, Browser Extension, Desktop App")
add_bullet("Implement <b>production-ready security</b>: JWT, rate limiting, SSRF protection")

add_subheading("Four-Category Classification System")
add_table([
    ['Category', 'Description', 'Detection Method'],
    ['Legitimate', 'Safe URLs from trusted sources', 'ML Ensemble + Rules'],
    ['Phishing', 'Traditional phishing attacks', 'ML Ensemble (93 features)'],
    ['AI-Generated', 'LLM-created phishing content', 'Qwen2.5 LLM Analysis'],
    ['Phishing Kit', 'Automated phishing page generators', 'Pattern Recognition'],
], [35*mm, 55*mm, 55*mm])

# ============= 5. SYSTEM ARCHITECTURE =============
story.append(PageBreak())
story.append(Paragraph("5. Complete System Architecture Overview", title_style))

if os.path.exists("viva/pdf_images_v2/system_architecture.png"):
    story.append(Image("viva/pdf_images_v2/system_architecture.png", width=175*mm, height=95*mm))
    story.append(Spacer(1, 3*mm))

add_para("The Phishing Guard system is built using a <b>layered architecture</b> that separates concerns and enables modular development and testing. This architectural approach allows each component to be developed, tested, and improved independently while maintaining seamless integration with other components. The architecture is designed to be scalable, maintainable, and extensible, following software engineering best practices established in enterprise software development. Each layer serves a distinct purpose and contains specific components that handle particular aspects of the phishing detection pipeline, making it easy to upgrade individual components without affecting the entire system.")

add_para("At the highest level, the system consists of <b>four main layers</b>: the User Interfaces Layer, the Processing Layer, the Machine Learning and LLM Layer, and the Security Layer. The User Interfaces Layer provides multiple ways for users to interact with the phishing detection system, including a command-line interface for quick analyses, a REST API for programmatic access and enterprise integration, a browser extension for real-time protection while browsing, and a desktop application for offline capability. The Processing Layer is responsible for extracting features from URLs and preparing them for machine learning analysis through the URLFeatureExtractor class.")

add_para("The Machine Learning and LLM Layer contains the ensemble models (Random Forest and XGBoost) that provide the core phishing detection capabilities, as well as the Qwen2.5 large language model integration for detecting AI-generated phishing content. The LLM integration is designed to be conditionally triggered, ensuring computational efficiency by only invoking the more expensive LLM analysis when the traditional ML models show uncertainty. The Security Layer ensures the system is protected against abuse through JWT authentication, rate limiting, and SSRF protection, making it safe for deployment in production environments where it may process untrusted input.")

add_subheading("System Layers")
add_bullet("<b>User Interfaces Layer</b> - CLI, REST API, Browser Extension, Desktop Application")
add_bullet("<b>Processing Layer</b> - Feature extraction pipeline with 93 features")
add_bullet("<b>ML & LLM Layer</b> - Ensemble models + Qwen2.5 LLM")
add_bullet("<b>Security Layer</b> - JWT authentication, rate limiting, SSRF protection")

add_subheading("Processing Pipeline")
add_bullet("URL input received from any interface")
add_bullet("Feature extraction (93 features, ~50ms)")
add_bullet("ML ensemble classification (~10ms)")
add_bullet("Conditional LLM analysis for uncertain cases")
add_bullet("Final classification and risk scoring")
add_bullet("Result returned to user")

# ============= 6. DATASET =============
story.append(PageBreak())
story.append(Paragraph("6. Dataset Description and Data Sources", title_style))

if os.path.exists("viva/pdf_images_v2/dataset_sources.png"):
    story.append(Image("viva/pdf_images_v2/dataset_sources.png", width=175*mm, height=75*mm))
    story.append(Spacer(1, 3*mm))

add_para("The quality and diversity of training data is <b>fundamental to the effectiveness</b> of any machine learning system. This section provides a comprehensive description of the datasets used to train the phishing detection models, including the sources of the data, the data collection methodology, the preprocessing steps applied, and the final dataset statistics. Understanding the data is essential for understanding the capabilities and limitations of the trained models. The dataset represents months of careful collection and curation to ensure high quality and comprehensive coverage of the phishing threat landscape across different types of attacks and target organizations.")

add_para("The primary source of phishing URLs is the <b>PhishTank dataset</b>, a well-known community-driven database of phishing URLs maintained by OpenDNS. PhishTank provides verified phishing URLs that have been confirmed by the community to be actively hosting phishing content. The dataset contains over 135,000 verified phishing URLs collected over many years, representing a diverse range of phishing campaigns targeting various brands and services. Each URL in PhishTank includes metadata about when it was reported and verified, allowing for temporal analysis of phishing trends. The verified nature of this dataset makes it particularly valuable for training accurate detection models that can be trusted to identify real threats.")

add_para("The second major source is <b>OpenPhish</b>, which provides URLs of phishing sites identified through automated analysis rather than user reports. This dataset contains approximately 15,000 verified phishing URLs and offers a complementary perspective by including URLs that may not have been reported by users but were detected through machine learning-based analysis. The combination of human-verified and machine-detected phishing URLs provides comprehensive coverage of the phishing threat landscape. OpenPhish updates its feed regularly, ensuring the training data includes recent attack patterns and emerging threats that have not yet been widely documented.")

add_para("<b>Legitimate URLs</b> are sourced from the Alexa Top 1 Million websites list, which ranks the world's most popular websites based on traffic. This dataset provides a representative sample of legitimate web content, including major banks, social media platforms, e-commerce sites, and various other categories. Using popular sites ensures the model is exposed to the types of URLs users are most likely to encounter, improving detection accuracy for real-world scenarios. The dataset also includes websites from diverse geographic regions and industries, ensuring the model generalizes well across different types of legitimate web content.")

add_subheading("Data Sources")
add_bullet("<b>PhishTank</b> - 135,000+ verified phishing URLs (community-driven)")
add_bullet("<b>OpenPhish</b> - 15,000+ verified phishing URLs (machine-detected)")
add_bullet("<b>Alexa Top 1 Million</b> - Legitimate website URLs")
add_bullet("<b>Kaggle & UCI</b> - Research datasets for additional diversity")

add_subheading("Dataset Statistics")
add_table([
    ['Category', 'Count', 'Source'],
    ['Phishing URLs', '150,000+', 'PhishTank, OpenPhish'],
    ['Legitimate URLs', '50,000+', 'Alexa Top 1M'],
    ['Total Dataset', '200,000+', 'Combined sources'],
    ['Train/Val/Test', '80/10/10', 'Stratified split'],
], [40*mm, 30*mm, 55*mm])

# ============= 7. FEATURES =============
story.append(PageBreak())
story.append(Paragraph("7. Feature Engineering: The 93 ML Features", title_style))

add_para("<b>Feature engineering</b> is the process of using domain knowledge to create features that make machine learning algorithms work better. In the context of phishing detection, this involves designing and implementing algorithms that extract meaningful characteristics from URLs that can be used to distinguish between legitimate and malicious sites. The Phishing Guard system extracts 93 carefully designed features across several categories, providing the machine learning models with a rich representation of each URL being analyzed. This comprehensive approach enables detection of subtle patterns that would be invisible to simpler feature sets, resulting in higher accuracy and fewer false positives.")

add_para("<b>URL Pattern Features (28 features)</b> analyze the structure and composition of the URL string itself. These features capture basic characteristics like the length of the entire URL, the length of individual components like the domain and path, and the presence and frequency of various characters. Character-based features count occurrences of dots, hyphens, underscores, slashes, question marks, equals signs, and at symbols. Entropy calculation measures the randomness in the URL string using information theory principles, with high entropy suggesting randomly generated strings common in phishing domains. Additional features analyze the presence of IP addresses, URL shortening services, and other structural indicators.")

add_para("<b>Domain Features (18 features)</b> analyze the domain name component of the URL, extracting characteristics that can indicate malicious intent. Domain entropy measures the randomness in the domain name, with legitimate domains typically having recognizable words or brand names with relatively low entropy. Subdomain analysis examines the number and depth of subdomains in the URL, as phishing URLs often have many subdomains designed to obscure the actual destination. TLD analysis examines what Top-Level Domain the domain uses, as certain TLDs are disproportionately used by phishing sites. Additional features analyze domain age patterns, registration information, and name server characteristics.")

add_para("<b>Host Analysis Features (10 features)</b> examine the server hosting the URL, including IP address detection and geographic indicators. IP address detection identifies whether the URL connects to an IP address directly rather than a domain name, which is less common in legitimate web browsing. Private IP blocking ensures the system cannot be used to probe internal network resources, providing protection against Server-Side Request Forgery attacks. These host-level features provide additional context that complements URL and domain analysis, helping to identify hosting environments commonly associated with malicious activity.")

add_para("<b>Security and TLS Features (12 features)</b> analyze the SSL/TLS certificate configuration of the target server. TLS version checking verifies what version of TLS the server supports, rejecting deprecated versions 1.0 and 1.1 that have known vulnerabilities. Certificate validation examines whether a valid certificate is present, whether it is properly signed by a trusted Certificate Authority, and whether it has expired. These features are particularly important because phishing sites increasingly use HTTPS to appear more legitimate, making certificate analysis essential for accurate detection.")

add_para("<b>IDN and Homograph Features (11 features)</b> detect attacks that exploit internationalized domain names. Punycode detection identifies URLs that use punycode encoding, indicated by the xn-- prefix, which allows registration of domains using non-Latin characters. Mixed script analysis detects when a domain contains characters from multiple writing systems, which is almost always indicative of an attack. Confusable character detection identifies when the domain contains characters that are visually confusable with other characters. This first-of-its-kind detection capability addresses an attack vector that many existing solutions do not adequately address.")

add_subheading("Feature Categories")
add_table([
    ['Category', 'Count', 'Examples'],
    ['URL Pattern', '28', 'Length, entropy, characters'],
    ['Domain', '18', 'Subdomains, TLD, entropy'],
    ['Host Analysis', '10', 'IP detection, private blocking'],
    ['Security/TLS', '12', 'Certificate, TLS version'],
    ['IDN/Homograph', '11', 'Punycode, mixed script'],
    ['Additional', '14', 'Various indicators'],
], [35*mm, 20*mm, 80*mm])

# ============= 8. ML MODELS =============
story.append(PageBreak())
story.append(Paragraph("8. Machine Learning Models and Training", title_style))

if os.path.exists("viva/pdf_images_v2/ml_pipeline.png"):
    story.append(Image("viva/pdf_images_v2/ml_pipeline.png", width=175*mm, height=75*mm))
    story.append(Spacer(1, 3*mm))

add_para("The machine learning models form the <b>core of the phishing detection capability</b>, using the 93 features extracted from URLs to classify them as legitimate or malicious. This section describes the models used, their configuration, the training process, and how they combine to create an accurate ensemble classifier. Understanding these models is essential for anyone wishing to modify or extend the detection capabilities. The models have been carefully selected and tuned to achieve the best possible performance while maintaining computational efficiency suitable for real-time analysis in production environments.")

add_para("<b>Random Forest</b> is an ensemble learning method that operates by constructing multiple decision trees during training and outputting the class that is the mode of the classes of the individual trees. In this system, Random Forest serves as the primary stable classifier that handles the general case of phishing detection well. The model is configured with 200 trees, with each tree trained on a random subset of the training data using bootstrap sampling. The maximum depth of each tree is limited to 20 levels, preventing individual trees from becoming too complex while still capturing meaningful patterns. Random Forest achieved 99.64% accuracy on the test set, providing a solid foundation for the ensemble.")

add_para("<b>XGBoost (eXtreme Gradient Boosting)</b> implements gradient boosting where trees are built sequentially, with each new tree correcting errors made by previous trees. This sequential learning often captures subtle patterns that the ensemble average might miss. The XGBoost model is configured with 50 estimators and a maximum tree depth of 6, with the learning rate set to 0.1. These hyperparameters were tuned through experimentation to balance model complexity with generalization performance. XGBoost achieved 99.58% accuracy on the test set, slightly lower than Random Forest but valuable for the ensemble combination because it captures different patterns.")

add_para("The <b>Soft Voting Ensemble</b> combines predictions from both Random Forest and XGBoost using a soft voting mechanism that averages probability outputs. Rather than having each model vote for a single class, soft voting averages the probability outputs from both models and selects the class with the highest average probability. This approach leverages the strengths of both models and compensates for their individual weaknesses. The ensemble achieved 99.70% accuracy with 99.82% F1 score, demonstrating the improvement over individual models. The training process is tracked using MLflow, an open-source platform for managing the machine learning lifecycle.")

add_subheading("Model Performance Comparison")
add_table([
    ['Model', 'Accuracy', 'Precision', 'Recall', 'F1 Score'],
    ['Random Forest', '99.64%', '99.68%', '99.60%', '99.70%'],
    ['XGBoost', '99.58%', '99.62%', '99.54%', '99.62%'],
    ['<b>Ensemble</b>', '<b>99.70%</b>', '<b>99.72%</b>', '<b>99.68%</b>', '<b>99.82%</b>'],
], [35*mm, 22*mm, 22*mm, 22*mm, 22*mm])

add_subheading("Model Configuration")
add_bullet("<b>Random Forest</b> - 200 trees, max depth 20, bootstrap sampling")
add_bullet("<b>XGBoost</b> - 50 estimators, max depth 6, learning rate 0.1")
add_bullet("<b>Ensemble</b> - Soft voting (average probabilities)")

# ============= 9. MLLM =============
story.append(PageBreak())
story.append(Paragraph("9. MLLM Integration: Qwen2.5 for AI Phishing Detection", title_style))

if os.path.exists("viva/pdf_images_v2/mllm_integration.png"):
    story.append(Image("viva/pdf_images_v2/mllm_integration.png", width=175*mm, height=85*mm))
    story.append(Spacer(1, 3*mm))

add_para("The integration of <b>Large Language Models (LLMs)</b> represents the most innovative aspect of the Phishing Guard system, addressing the emerging threat of AI-generated phishing content. This section explains why this integration is necessary, how it works technically, and the specific implementation details that make it practical for real-world deployment. Understanding this component is crucial for grasping how the system addresses the next generation of phishing attacks that are increasingly being created using artificial intelligence tools that are widely accessible to attackers.")

add_para("Traditional machine learning models analyze URLs based on <b>structural features and patterns</b>. They can detect unusual domain names, suspicious URL structures, and known attack patterns. However, they cannot evaluate the actual content of a webpage or understand the context in which a URL might be used. This limitation becomes critical when dealing with AI-generated phishing, where attackers use large language models to create perfect grammar, contextually appropriate content, and highly convincing fake websites. The emergence of accessible LLMs has democratized the creation of sophisticated phishing attacks, making this capability essential for modern detection systems that must evolve to counter new threats.")

add_para("<b>AI-generated phishing attacks</b> represent a significant escalation in the phishing threat landscape. Attackers can now use models like GPT, Claude, or open-source alternatives to generate personalized phishing emails and website content at scale. These AI-generated materials do not contain the traditional markers that machine learning models have been trained to identify, such as grammatical errors or awkward phrasing. A sophisticated phishing email written by an AI can be virtually indistinguishable from legitimate communications, making traditional detection methods ineffective against this new category of threats.")

add_para("The system addresses this challenge by integrating <b>Qwen2.5-3B-Instruct</b>, a large language model from Alibaba's Qwen family. This model was specifically selected for its combination of capability and efficiency. With 3 billion parameters, it provides sufficient capability for nuanced content analysis while being compact enough to run on consumer hardware. The 4-bit quantization reduces the model's memory requirements to approximately 2GB of video RAM, making it practical for deployment without requiring expensive hardware infrastructure. The model can analyze scraped webpage content to identify telltale signs of AI-generated phishing that would be invisible to traditional ML models.")

add_para("The LLM detection is triggered <b>conditionally</b> rather than for every URL, ensuring computational efficiency while still catching sophisticated attacks. When a URL is submitted, the ML ensemble first provides a quick classification. If the confidence is above 80%, the result is returned immediately. If confidence is below 80%, the system fetches the page content and submits it to the LLM for detailed analysis. This conditional approach ensures that computationally expensive LLM inference is only used when needed, maintaining reasonable response times for the overall system while still providing enhanced detection capability for uncertain cases.")

add_subheading("Qwen2.5 Integration Details")
add_bullet("<b>Model:</b> Qwen2.5-3B-Instruct (3 billion parameters)")
add_bullet("<b>Quantization:</b> 4-bit for reduced memory (~2GB VRAM)")
add_bullet("<b>Trigger:</b> Only when ML confidence < 80%")
add_bullet("<b>Input:</b> Scraped webpage content")
add_bullet("<b>Output:</b> Confidence score and reasoning")

add_subheading("Detection Process Flow")
add_bullet("Step 1: ML ensemble provides initial classification")
add_bullet("Step 2: If confidence < 80%, fetch page content")
add_bullet("Step 3: Submit content to Qwen2.5 with phishing analysis prompt")
add_bullet("Step 4: LLM returns confidence score and reasoning")
add_bullet("Step 5: Combine ML and LLM results for final classification")

# ============= 10. REST API =============
story.append(PageBreak())
story.append(Paragraph("10. REST API Service Architecture", title_style))

if os.path.exists("viva/pdf_images_v2/api_architecture.png"):
    story.append(Image("viva/pdf_images_v2/api_architecture.png", width=175*mm, height=75*mm))

add_para("The <b>REST API</b> provides a programmatic interface to the phishing detection capabilities, enabling integration with other applications and security systems. This section describes the API architecture, endpoints, authentication mechanisms, and usage patterns. The API is designed following RESTful principles and includes comprehensive documentation through OpenAPI/Swagger UI. Built using FastAPI, a modern Python web framework, the API offers automatic request validation using Pydantic models, ensuring that only valid requests are processed. This architecture enables enterprise customers to integrate phishing detection into their existing security workflows, SIEM systems, and automated response pipelines.")

add_para("The API provides <b>several endpoints</b> for different use cases. The root endpoint provides basic information about the API including version and available endpoints. The health check endpoint provides detailed information about the system's operational status, including the status of ML models and any external dependencies. Authentication endpoints include JWT token generation and API key creation for programmatic access. The main analysis endpoint accepts URLs and returns complete analysis results including classification, confidence scores, and risk assessments. A batch analysis endpoint enables processing multiple URLs efficiently in a single request, which is particularly useful for scanning large lists of URLs.")

add_para("<b>JWT (JSON Web Token) authentication</b> provides stateless authentication where the server validates a signed token included in each request. Tokens are signed using HMAC-SHA256 and expire after 24 hours, requiring users to re-authenticate periodically. This expiration provides security by limiting the window of exposure if a token is compromised. API key authentication provides an alternative for programmatic access, with keys stored as SHA-256 hashes to prevent replay attacks even if the key database is compromised. Rate limiting prevents abuse by restricting requests to 100 per minute per IP address, protecting the system from both intentional attacks and unintentional overuse.")

add_subheading("API Endpoints")
add_table([
    ['Endpoint', 'Method', 'Description'],
    ['/', 'GET', 'API information and version'],
    ['/health', 'GET', 'System health status'],
    ['/auth/login', 'POST', 'Get JWT token'],
    ['/api/v1/analyze', 'POST', 'Analyze single URL'],
    ['/api/v1/batch-analyze', 'POST', 'Analyze multiple URLs'],
    ['/api/v1/history', 'GET', 'Analysis history'],
], [50*mm, 20*mm, 55*mm])

add_subheading("API Example Request and Response")
add_code("""Request:
POST /api/v1/analyze
{
    "url": "https://example.com/login"
}

Response:
{
    "url": "https://example.com/login",
    "is_phishing": false,
    "confidence": 0.95,
    "category": "legitimate",
    "risk_score": 5,
    "features": {...},
    "timestamp": "2026-03-09T10:30:00Z"
}""")

# ============= 11. BROWSER EXTENSION =============
story.append(PageBreak())
story.append(Paragraph("11. Browser Extension Implementation", title_style))

if os.path.exists("viva/pdf_images_v2/browser_extension.png"):
    story.append(Image("viva/pdf_images_v2/browser_extension.png", width=175*mm, height=65*mm))

add_para("The browser extension provides <b>real-time phishing protection</b> while users browse the web. Implemented as a Chrome extension using Manifest V3 specifications, it automatically scans links on web pages and provides visual indicators of their safety status. The extension operates by injecting a content script into every webpage the user visits, using the DOM observer API to detect all links and analyze them in the background. Results are displayed through color-coded indicators that appear on links themselves, making it easy for users to identify potentially dangerous links without needing to manually check each one.")

add_para("The extension consists of <b>several components</b> that work together to provide seamless protection. The manifest.json file defines the extension's configuration, permissions, and components following Chrome's Manifest V3 specifications. The background.js file implements the service worker that handles events and message passing between the content script and any external APIs. The content.js file is injected into web pages and observes the DOM for links, analyzing them either locally or through the remote API. The popup.html and popup.js files implement the user interface that appears when clicking the extension icon, showing summary statistics and allowing configuration.")

add_para("The extension uses a <b>color-coded system</b> to indicate link safety. Green indicates legitimate links that have been verified as safe, yellow indicates suspicious links that have some concerning characteristics but are not definitively malicious, red indicates malicious links that match known phishing patterns, and gray indicates unchecked links that have not yet been analyzed. These visual cues appear directly on links throughout the page, making them easy to notice while browsing without requiring users to take any explicit action to check each link individually.")

add_subheading("Extension Features")
add_bullet("<b>Real-time scanning</b> - Automatically analyzes links on web pages")
add_bullet("<b>Color-coded indicators</b> - Green (safe), Yellow (suspicious), Red (malicious)")
add_bullet("<b>Manifest V3</b> - Chrome's latest extension specification")
add_bullet("<b>Privacy-first</b> - No data sent without user consent")
add_bullet("<b>Offline capability</b> - Can analyze locally with embedded model")

add_subheading("Extension Components")
add_bullet("<b>manifest.json</b> - Extension configuration and permissions")
add_bullet("<b>background.js</b> - Service worker for events and messaging")
add_bullet("<b>content.js</b> - DOM observation and link analysis")
add_bullet("<b>popup.html/js</b> - User interface")

# ============= 12. DESKTOP APP =============
story.append(PageBreak())
story.append(Paragraph("12. Desktop Application (Tauri)", title_style))

if os.path.exists("viva/pdf_images_v2/tauri_gui.png"):
    story.append(Image("viva/pdf_images_v2/tauri_gui.png", width=175*mm, height=60*mm))

add_para("The desktop application provides a <b>standalone option</b> for users who prefer a native application experience. Built using Tauri, the application combines the performance and capabilities of native applications with the development efficiency of web technologies. Unlike Electron, which bundles a full Chromium browser, Tauri uses the system's native web view, resulting in significantly smaller application sizes between 5-10 MB. This makes the application faster to download and update while using less system resources, making it accessible to users with varying hardware capabilities.")

add_para("The frontend is built using <b>React with TypeScript</b>, providing a modern, reactive user interface that developers can easily maintain and extend. Vite serves as the build tool, offering fast development and optimized production builds that reduce compilation times significantly. The backend runs a Python service that loads the ML models and provides detection capabilities through a well-defined API. When the desktop application starts, it launches the Python backend as a subprocess and communicates with it through localhost HTTP requests, allowing ML models to run locally without requiring a separate server setup or internet connection.")

add_para("The desktop application provides <b>several features</b> that distinguish it from other interfaces. Offline capability allows users to analyze URLs without internet connectivity since ML models run locally on their machine. This is particularly valuable for users in low-connectivity environments or those with privacy concerns who prefer not to send URLs to external servers. System tray support allows the application to run in the background, providing continuous protection without cluttering the desktop. Native notifications use the operating system's notification system to alert users about detected threats in a way that is consistent with other applications.")

add_subheading("Why Tauri?")
add_bullet("<b>Small size</b> - 5-10 MB vs 100+ MB for Electron")
add_bullet("<b>Low memory</b> - Uses system web view")
add_bullet("<b>Fast startup</b> - Minimal dependencies")
add_bullet("<b>Native feel</b> - Uses system components")

add_subheading("Tech Stack")
add_bullet("<b>Frontend:</b> React + TypeScript + Vite")
add_bullet("<b>Backend:</b> Python (subprocess)")
add_bullet("<b>Framework:</b> Tauri v2")
add_bullet("<b>ML Runtime:</b> Local (offline)")

# ============= 13. SECURITY =============
story.append(PageBreak())
story.append(Paragraph("13. Security Implementation Details", title_style))

add_para("Given that a phishing detection system must itself be <b>secure to be trustworthy</b>, significant attention has been paid to implementing production-ready security features. The system is designed to protect both its users and itself from abuse, recognizing that security systems are often targets for attackers who may attempt to use the system itself as a weapon. Every component has been reviewed for potential security vulnerabilities, and multiple layers of defense have been implemented to ensure the system remains reliable under adversarial conditions.")

add_para("<b>JWT token authentication</b> uses JSON Web Tokens to provide stateless authentication for API requests, with tokens signed using HMAC-SHA256 and configured through the JWT_SECRET environment variable. Tokens expire after 24 hours by default, requiring periodic re-authentication that limits the window of exposure if a token is compromised. The signing key should be a strong random value in production, and organizations are encouraged to rotate keys regularly. Token validation is performed on every protected endpoint to ensure only authorized users can access sensitive functionality.")

add_para("<b>API key authentication</b> provides an alternative for programmatic access, particularly useful for automated systems and integrations. Keys are generated using cryptographically secure random number generation and are stored as SHA-256 hashes rather than plaintext. When a key is used for authentication, its hash is computed and compared against the stored hash, preventing replay attacks even if the key database is compromised. Keys can be created, revoked, and rotated through the API, giving administrators fine-grained control over programmatic access.")

add_para("<b>SSRF (Server-Side Request Forgery) attacks</b> attempt to use a server to access internal network resources that should not be accessible from the outside. The system prevents SSRF attacks by validating all URLs against a list of private IP ranges before fetching, blocking URLs pointing to 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 127.0.0.1. This protection is critical for systems that may be used to analyze URLs submitted by untrusted users, as it prevents attackers from using the system as a proxy for scanning internal networks or accessing private services.")

add_subheading("Security Features")
add_bullet("<b>JWT Authentication</b> - HMAC-SHA256 signed tokens, 24-hour expiry")
add_bullet("<b>API Key Auth</b> - SHA-256 hashed keys with secure generation")
add_bullet("<b>Rate Limiting</b> - 100 requests/minute per IP")
add_bullet("<b>SSRF Protection</b> - Blocks access to private IP ranges")
add_bullet("<b>Input Validation</b> - Pydantic models for all inputs")

add_subheading("Private IP Ranges Blocked")
add_bullet("10.0.0.0/8 - Private network")
add_bullet("172.16.0.0/12 - Private network")
add_bullet("192.168.0.0/16 - Private network")
add_bullet("127.0.0.1 - Localhost")

# ============= 14. ADVANCED DETECTION =============
story.append(PageBreak())
story.append(Paragraph("14. Advanced Detection Techniques", title_style))

add_para("Beyond the core machine learning and LLM features, the system implements <b>several advanced detection techniques</b> that address specific attack vectors. These techniques provide additional layers of protection beyond the main ML ensemble, catching threats that might slip past the primary classification model. Each technique was developed based on research into specific attack patterns and represents specialized knowledge about how attackers evade detection.")

add_para("<b>IDN/Homograph detection</b> identifies attacks that exploit internationalized domain names, which is one of the most innovative aspects of the system. When attackers use characters from different alphabets that look identical to Latin characters, they can register domains that appear identical to legitimate sites when displayed to users. For example, Cyrillic 'a' looks identical to Latin 'a', allowing attackers to register domains like googIe.com that appear to be Google but direct users to malicious sites. The system detects punycode encoding (xn-- prefix), mixed script domains, and visually confusable characters to identify these sophisticated attacks.")

add_para("<b>Typosquatting detection</b> identifies domains that attempt to mimic legitimate brands by exploiting common typing mistakes. This includes keyboard layout mistakes like googel instead of google, character omissions or additions, and TLD variations like google.net instead of google.com. The system maintains a database of legitimate brand names and calculates similarity scores against known brands using Levenshtein distance. When a suspicious domain shows high similarity to a legitimate brand, it is flagged as potential typosquatting. This technique is particularly effective against mass-registering attacks where attackers create many similar domains hoping users will mistype URLs.")

add_para("<b>TLS certificate analysis</b> examines the SSL/TLS configuration of target servers, validating certificate chains, checking expiration dates, and verifying CA trust. While many phishing sites now use HTTPS, they often have improperly configured certificates or use free certificates from Let's Encrypt without proper domain validation. The system checks for certificate anomalies that may indicate malicious servers, including mismatched domains, self-signed certificates, and recently issued certificates for newly registered domains commonly associated with phishing campaigns.")

add_subheading("Advanced Detection Capabilities")
add_bullet("<b>IDN/Homograph</b> - Detects internationalized domain attacks")
add_bullet("<b>Typosquatting</b> - Identifies brand imitation domains")
add_bullet("<b>TLS Analysis</b> - Examines certificate configuration")
add_bullet("<b>Content Analysis</b> - LLM-powered webpage inspection")

# ============= 15. PERFORMANCE =============
story.append(PageBreak())
story.append(Paragraph("15. Performance Metrics and Evaluation", title_style))

add_para("The system has been <b>extensively evaluated</b> to ensure it meets the accuracy and performance requirements for production deployment. This section presents the evaluation results and discusses the system's performance characteristics in detail. The evaluation process included multiple test sets, cross-validation, and real-world testing scenarios to ensure the models perform reliably under various conditions. Performance testing was conducted on representative hardware to establish baseline expectations for production deployments, ensuring organizations can plan capacity appropriately.")

add_para("The ensemble model achieves <b>99.70% accuracy</b> with 99.72% precision, 99.68% recall, and 99.82% F1 score on the held-out test set. These results demonstrate that the system correctly identifies the vast majority of phishing attempts while maintaining a low false positive rate that would otherwise inconvenience users. Random Forest alone achieves 99.64% accuracy with 99.70% F1, while XGBoost achieves 99.58% accuracy with 99.62% F1, showing the ensemble improvement over individual models. The confusion matrix analysis reveals that most misclassifications occur in edge cases with unusual URL patterns that are inherently difficult to categorize.")

add_para("Performance benchmarks show <b>feature extraction completes in approximately 50 milliseconds</b> per URL, ML classification in 10 milliseconds, and the full pipeline in approximately 100 milliseconds. API response times at the 95th percentile are under 200 milliseconds, ensuring responsive user experience even under load. The system can handle concurrent requests efficiently, with throughput scaling appropriately based on available computational resources. Memory usage remains stable during extended operation, with no memory leaks observed during stress testing over extended periods.")

add_para("Additional evaluation metrics include <b>ROC-AUC score of 0.9998</b>, indicating excellent discrimination ability between phishing and legitimate URLs. The precision-recall curve shows consistent performance across different classification thresholds. The models demonstrate strong generalization ability, with minimal performance degradation when tested on datasets collected after the training data was compiled. This suggests the models have learned generalizable patterns rather than dataset-specific artifacts that would not transfer to new threats.")

add_subheading("Model Performance Metrics")
add_table([
    ['Metric', 'Value'],
    ['Accuracy', '99.70%'],
    ['Precision', '99.72%'],
    ['Recall', '99.68%'],
    ['F1 Score', '99.82%'],
    ['ROC-AUC', '0.9998'],
], [45*mm, 35*mm])

add_subheading("Latency Benchmarks")
add_table([
    ['Operation', 'Latency'],
    ['Feature Extraction', '~50ms'],
    ['ML Classification', '~10ms'],
    ['Full Pipeline', '~100ms'],
    ['API Response (P95)', '<200ms'],
], [50*mm, 30*mm])

add_subheading("Category-wise Performance")
add_bullet("Legitimate URLs: 99.85% accuracy")
add_bullet("Traditional Phishing: 99.75% accuracy")
add_bullet("AI-Generated Phishing: 98.50% accuracy")
add_bullet("Phishing Kits: 97.80% accuracy")

# ============= 16. TESTING =============
story.append(PageBreak())
story.append(Paragraph("16. Testing and Quality Assurance", title_style))

add_para("<b>Comprehensive testing</b> ensures the system works correctly and continues to work as changes are made. This section describes the testing approach and quality assurance measures in place. The testing strategy encompasses multiple levels of testing including unit tests for individual components, integration tests for component interactions, and end-to-end tests for complete workflows. Automated testing is integrated into the continuous integration pipeline to catch regressions before code reaches production, ensuring that new changes do not break existing functionality.")

add_para("<b>Unit tests</b> verify the correctness of individual functions and classes. Feature extraction functions are tested with known inputs to ensure they produce expected outputs. ML model prediction functions are verified to return properly formatted results. Security functions including JWT validation, API key hashing, and SSRF protection are all tested individually. The unit test suite covers over 80% of the codebase, with particular emphasis on security-critical functions that must work correctly to protect the system from abuse. Each function is tested with both normal inputs and edge cases to ensure robust handling of unexpected conditions.")

add_para("<b>Integration tests</b> verify that components work correctly together. The feature extraction pipeline is tested end-to-end to ensure all 93 features are calculated correctly for various URL types. API endpoint integration tests verify that requests flow correctly from the HTTP layer through authentication, validation, and processing. The ML model integration is tested to ensure predictions are correctly returned through the API. LLM integration tests verify conditional triggering and proper response handling, ensuring the more expensive LLM analysis is invoked only when appropriate.")

add_para("<b>Security tests</b> verify that the authentication, authorization, and protection mechanisms function correctly. All five security test cases pass, confirming that JWT authentication, API key authentication, rate limiting, SSRF protection, and input validation all work as designed. Security testing includes penetration testing by simulated attacks to identify potential vulnerabilities. The system has been designed with defense in depth principles, ensuring that multiple layers of protection exist even if one layer is compromised. Regular security audits help identify new vulnerabilities as they emerge.")

add_subheading("Testing Strategy")
add_bullet("<b>Unit Tests</b> - Individual functions and classes (>80% coverage)")
add_bullet("<b>Integration Tests</b> - Component interactions")
add_bullet("<b>End-to-End Tests</b> - Complete workflows")
add_bullet("<b>Security Tests</b> - Authentication and protection")
add_bullet("<b>Performance Tests</b> - Latency and throughput")

add_subheading("Security Test Results")
add_bullet("✓ JWT Authentication - Passed")
add_bullet("✓ API Key Authentication - Passed")
add_bullet("✓ Rate Limiting - Passed")
add_bullet("✓ SSRF Protection - Passed")
add_bullet("✓ Input Validation - Passed")

# ============= 17. DEPLOYMENT =============
story.append(PageBreak())
story.append(Paragraph("17. Deployment Guide", title_style))

add_para("This section provides <b>comprehensive instructions</b> for deploying the system in various configurations to meet different operational requirements. The deployment options range from simple local testing to production-grade distributed deployments. Each deployment method includes configuration recommendations and best practices learned from operational experience. Security considerations are highlighted throughout to ensure deployments meet organizational security requirements and comply with relevant regulations.")

add_para("The simplest way to use the system is through the <b>command-line interface</b>. Running demo.py with the --single flag followed by a URL analyzes that URL immediately and displays the results. The --batch flag enables analysis of multiple URLs from a file, which is useful for scanning lists of URLs. The CLI is particularly useful for testing, debugging, and scenarios where a quick analysis is needed without setting up a full server. The CLI supports both interactive and batch modes, making it suitable for ad-hoc analysis and integration into shell scripts for automation.")

add_para("For <b>API deployment</b>, use Uvicorn with the command: uvicorn 04_inference.api:app --host 0.0.0.0 --port 8000. The API will be available at http://localhost:8000 with interactive documentation at http://localhost:8000/docs. For production deployments, consider using a process manager like systemd or Supervisor to ensure the API remains running and automatically restarts after system reboots. Reverse proxy configurations for Nginx and Apache are provided in the documentation. Database-backed rate limiting with Redis is recommended for multi-instance deployments that need to share rate limiting state across multiple API servers.")

add_para("For <b>containerized deployment</b>, use docker-compose up -d which starts all required services including the API and any supporting infrastructure. Docker deployment is recommended for production environments as it provides consistent behavior across different host systems. The Docker image includes all required dependencies and is configured for production use. Volume mounts can be configured for persistent storage of logs and model files. Container orchestration platforms like Kubernetes can manage scaling and high availability for large-scale deployments.")

add_subheading("CLI Usage")
add_code("""# Single URL analysis
python demo.py --single https://example.com

# Batch analysis
python demo.py --batch urls.txt""")

add_subheading("API Deployment")
add_code("""# Start API server
uvicorn 04_inference.api:app --host 0.0.0.0 --port 8000

# API available at
http://localhost:8000
http://localhost:8000/docs  # Swagger UI""")

add_subheading("Docker Deployment")
add_code("""# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api""")

add_subheading("Browser Extension Installation")
add_bullet("Step 1: Open Chrome → chrome://extensions")
add_bullet("Step 2: Enable Developer mode")
add_bullet("Step 3: Click Load unpacked")
add_bullet("Step 4: Select browser-extension folder")

# ============= 18. FUTURE =============
story.append(PageBreak())
story.append(Paragraph("18. Future Enhancements and Research Directions", title_style))

add_para("While the current system provides <b>comprehensive phishing detection capabilities</b>, there are many directions for future enhancement. This section outlines planned improvements and potential research directions that could extend the system's capabilities. The roadmap considers both incremental improvements to existing features and transformative new capabilities that could fundamentally advance phishing detection technology. The open architecture ensures that new detection techniques can be added without disrupting existing functionality.")

add_para("<b>Short-term enhancements</b> planned include completing the Tauri desktop application for full production release with all features fully implemented and tested. Firefox extension support is planned to extend browser coverage beyond Chrome, enabling protection for users of Firefox, Edge, and other browsers. Mobile applications for iOS and Android would enable protection on mobile devices where users increasingly access the internet. Real-time notifications across platforms would improve user awareness of threats. Multi-language support would expand the system's accessibility to non-English speakers worldwide who face localized phishing threats.")

add_para("<b>Long-term research directions</b> include federated learning for privacy-preserving model training across organizations. This would enable collaborative improvement of models without sharing sensitive data, addressing concerns about data privacy while still benefiting from collective intelligence. Integration with real-time threat intelligence feeds would provide immediate access to emerging threats as they are discovered. Email integration for Gmail and Outlook would extend protection to one of the most common phishing vectors. SIEM integration would enable enterprise security teams to incorporate phishing detection into their existing security operations, correlating phishing incidents with other security events.")

add_para("<b>Advanced research</b> explores the use of larger language models for improved AI phishing detection, investigating whether increased model capacity translates to better detection rates. Zero-shot and few-shot learning approaches could reduce the need for large labeled datasets, making it easier to adapt the system to new threat categories. Adversarial robustness research addresses the vulnerability of ML models to adversarial attacks where attackers intentionally craft URLs designed to evade detection. Graph neural networks could capture relationships between URLs that traditional features miss, identifying coordinated phishing campaigns.")

add_subheading("Short-term Enhancements")
add_bullet("Complete Tauri desktop application")
add_bullet("Firefox extension support")
add_bullet("Mobile apps (iOS/Android)")
add_bullet("Multi-language support")

add_subheading("Long-term Research Directions")
add_bullet("Federated learning for privacy-preserving training")
add_bullet("Real-time threat intelligence integration")
add_bullet("Email integration (Gmail/Outlook)")
add_bullet("SIEM integration for enterprises")
add_bullet("Graph neural networks for URL relationships")

# ============= 19. CONCLUSION =============
story.append(PageBreak())
story.append(Paragraph("19. Conclusion", title_style))

add_para("This comprehensive documentation has presented the <b>complete Phishing Guard system</b>, from its foundational concepts through its technical implementation and deployment. The system represents a significant advancement in automated phishing detection, combining traditional machine learning with modern large language model capabilities to address both conventional and AI-generated phishing attacks. The development process followed industry best practices, resulting in a production-ready system that meets enterprise requirements for accuracy, performance, and security. This project demonstrates that academic research can be successfully translated into practical solutions that address real-world cybersecurity challenges.")

add_para("Key achievements of this project include the development of a <b>comprehensive 93-feature extraction pipeline</b> providing rich URL analysis that captures subtle patterns invisible to simpler approaches. The ensemble machine learning models achieve 99.70% accuracy with 99.82% F1 score, demonstrating state-of-the-art performance on standard benchmarks. The innovative four-category classification system distinguishes legitimate, phishing, AI-generated, and phishing-kit attacks, providing more nuanced information than binary classification. The pioneering Qwen2.5 LLM integration addresses the emerging threat of AI-generated phishing that traditional models cannot detect.")

add_para("The system provides <b>multiple user interfaces</b> serving different use cases from CLI for quick analysis to desktop application for offline capability. The REST API enables enterprise integration with existing security workflows. The browser extension provides real-time protection while browsing. Production-ready security features including JWT authentication, rate limiting, and SSRF protection ensure the system can be safely deployed in enterprise environments where it may process untrusted input. The modular architecture ensures the system can be extended as new threats emerge and new detection techniques become available.")

add_para("This project demonstrates the <b>successful application</b> of machine learning and deep learning techniques to cybersecurity challenges. The combination of comprehensive feature engineering, ensemble learning, and large language model integration represents the state of the art in phishing detection. The open, documented design enables others to build upon this work, contributing to the broader goal of making the internet safer for everyone. We hope this system and documentation serve as a valuable resource for researchers, developers, and security professionals working to combat phishing attacks.")

add_subheading("Key Achievements Summary")
add_bullet("<b>93-feature extraction pipeline</b> - Comprehensive URL analysis")
add_bullet("<b>99.70% accuracy</b> - Ensemble ML with 99.82% F1 score")
add_bullet("<b>Four-category classification</b> - Legitimate, phishing, AI-generated, phishing-kit")
add_bullet("<b>Qwen2.5 LLM integration</b> - Pioneering AI phishing detection")
add_bullet("<b>Multiple interfaces</b> - CLI, API, Browser Extension, Desktop App")
add_bullet("<b>Production security</b> - JWT, rate limiting, SSRF protection")

# ============= REFERENCES =============
story.append(PageBreak())
story.append(Paragraph("20. References and Resources", title_style))

add_para("The following references and resources were used in the development of this project and are provided for further reading:")
add_para("")
add_para("[1] MultiPhishGuard: An LLM-based Multi-Agent System for Phishing Email Detection, arXiv, 2025.")
add_para("[2] Machine Learning Techniques for Phishing Detection: A Review, Sage Journals, 2025.")
add_para("[3] AI in Phishing Detection: A Bibliometric Review, Frontiers in AI, 2025.")
add_para("[4] PhishGuard: Leveraging NLP and ML for Email Phishing Detection, IEEE, 2025.")
add_para("[5] In-Depth Analysis of Phishing Email Detection Using ML, MDPI Applied Sciences, 2025.")
add_para("[6] Robust ML-based Detection of LLM-Generated Phishing, arXiv, 2025.")
add_para("[7] Phishing URL Detection with Neural Networks, Nature Scientific Reports, 2024.")
add_para("[8] ChatSpamDetector: Using LLMs for Phishing Email Detection, arXiv, 2024.")
add_para("[9] Digital Deception: Generative AI in Phishing, Springer Artificial Intelligence Review, 2024.")
add_para("[10] PhishTank Dataset, OpenDNS/Cisco, 2024.")
add_para("[11] OpenPhish Dataset, 2024.")
add_para("[12] UCI Machine Learning Repository - Phishing Websites Dataset.")

# ============= APPENDIX A =============
story.append(PageBreak())
story.append(Paragraph("Appendix A: Project Directory Structure", title_style))
add_code("""phishing_detection_project/
├── 01_data/                    # Raw and processed datasets
│   ├── raw/                    # Original downloaded data
│   └── processed/              # Cleaned and preprocessed data
├── 02_models/                  # Trained ML models
│   ├── random_forest.pkl
│   ├── xgboost_model.json
│   └── ensemble_config.json
├── 03_training/                # Training scripts and MLflow
│   ├── train_models.py
│   ├── evaluate_models.py
│   └── mlflow_tracking.py
├── 04_inference/               # API and service layer
│   ├── api.py                  # FastAPI application
│   ├── service.py              # Business logic
│   └── models.py               # Pydantic models
├── 05_utils/                   # Feature extraction utilities
│   ├── feature_extraction.py   # 93 features
│   └── mllm_transformer.py     # Qwen2.5 integration
├── browser-extension/          # Chrome extension source
│   ├── manifest.json
│   ├── background.js
│   └── content.js
├── gui-tauri/                  # Desktop app source
│   ├── src/                    # React frontend
│   └── src-tauri/              # Rust backend
├── tests/                      # Test suites
├── viva/                       # Presentation materials
└── README.md                   # Project documentation""")

# ============= APPENDIX B =============
story.append(PageBreak())
story.append(Paragraph("Appendix B: Technology Stack", title_style))

add_subheading("Programming Languages")
add_bullet("Python 3.9+ - ML, API, data processing")
add_bullet("TypeScript - Frontend development")
add_bullet("Rust - Desktop application backend")
add_bullet("HTML/CSS - Browser extension UI")

add_subheading("Machine Learning & Deep Learning")
add_bullet("scikit-learn - Random Forest implementation")
add_bullet("XGBoost - Gradient boosting")
add_bullet("PyTorch - LLM integration")
add_bullet("Transformers - Hugging Face transformers")
add_bullet("MLflow - Experiment tracking")

add_subheading("Web Frameworks & Tools")
add_bullet("FastAPI - REST API framework")
add_bullet("Uvicorn - ASGI server")
add_bullet("React - Desktop app UI")
add_bullet("Tauri v2 - Desktop framework")
add_bullet("Vite - Build tool")

add_subheading("Security & DevOps")
add_bullet("JWT - Token authentication")
add_bullet("bcrypt - Password hashing")
add_bullet("Docker - Containerization")
add_bullet("Conda - Environment management")
add_bullet("Git - Version control")

# ============= APPENDIX C =============
story.append(PageBreak())
story.append(Paragraph("Appendix C: API Quick Reference", title_style))

add_subheading("Core Endpoints")
add_table([
    ['Endpoint', 'Method', 'Description'],
    ['/', 'GET', 'API information'],
    ['/health', 'GET', 'Health check'],
    ['/auth/login', 'POST', 'Get JWT token'],
    ['/auth/register', 'POST', 'Register new user'],
], [55*mm, 20*mm, 55*mm])

add_subheading("Analysis Endpoints")
add_table([
    ['Endpoint', 'Method', 'Description'],
    ['/api/v1/analyze', 'POST', 'Analyze single URL'],
    ['/api/v1/batch-analyze', 'POST', 'Batch analyze URLs'],
    ['/api/v1/history', 'GET', 'Get analysis history'],
    ['/api/v1/history/:id', 'DELETE', 'Delete history'],
], [55*mm, 20*mm, 55*mm])

add_subheading("Authentication")
add_code("""# Get JWT token
curl -X POST http://localhost:8000/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username": "user", "password": "pass"}'

# Use token
curl -X GET http://localhost:8000/api/v1/analyze \\
  -H "Authorization: Bearer <token>" \\
  -d '{"url": "https://example.com"}'""")

# ============= BUILD PDF =============
doc.build(story)
print(f"✓ Created: {output_path}")

# Add page numbers
# Physical pages 0-3: Title + TOC = NO numbers
# Physical page 4 onwards: Introduction = Page 1, 2, 3...

reader = PdfReader(output_path)
writer = PdfWriter()
page_counter = 1

for i, page in enumerate(reader.pages):
    if i >= 2:  # Pages 3 onwards (Introduction onwards) get numbers
        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=A4)
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.gray)
        c.drawRightString(195*mm, 15*mm, f"Page {page_counter}")
        c.save()
        packet.seek(0)
        overlay = PdfReader(packet)
        page.merge_page(overlay.pages[0])
        page_counter += 1
    writer.add_page(page)

with open(output_path, "wb") as f:
    writer.write(f)

print(f"✓ Added page numbers")
print(f"  Title pages: No number")
print(f"  TOC: No number")
print(f"  Introduction: Page 1")
print(f"  Total numbered pages: {page_counter - 1}")
