#!/usr/bin/env python3
"""
Phishing URL Detector - Beautiful GUI Application

A modern, user-friendly desktop application for detecting phishing URLs.
Built with CustomTkinter for a beautiful dark-mode interface.

Features:
- INTERNET-AWARE: Automatically uses web scraping when online
- Real-time connectivity status indicator
- Visual risk score meter
- Detailed analysis breakdown
- Batch URL scanning
- History of scans

Usage:
    python gui.py

Requirements:
    pip install customtkinter
"""

import sys
import os
import asyncio
import threading
from datetime import datetime
from typing import Optional
import json

# Add project paths
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, '04_inference'))
sys.path.insert(0, os.path.join(project_root, '05_utils'))

try:
    import customtkinter as ctk
    from PIL import Image, ImageTk
except ImportError:
    print("Required packages not found. Installing...")
    os.system("pip install customtkinter Pillow")
    import customtkinter as ctk
    from PIL import Image, ImageTk

from service import PhishingDetectionService

# Import connectivity checker
try:
    from connectivity import check_internet_connection, get_connectivity_status
except ImportError:
    def check_internet_connection():
        return True
    def get_connectivity_status():
        return {'is_online': True, 'mode': 'online'}

# Configure CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class PhishingDetectorGUI(ctk.CTk):
    """Main GUI Application Window."""
    
    def __init__(self):
        super().__init__()
        
        # Window configuration
        self.title("Phishing URL Detector")
        self.geometry("900x700")
        self.minsize(800, 600)
        
        # Initialize service
        self.service = None
        self.is_loading = True
        self.is_online = False
        self.scan_history = []
        
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        
        # Build UI
        self._create_header()
        self._create_input_section()
        self._create_results_section()
        self._create_footer()
        
        # Start service loading in background
        self._load_service_async()
    
    def _create_header(self):
        """Create the header with title and status."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ctk.CTkLabel(
            header_frame,
            text="🔒 Phishing URL Detector",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.grid(row=0, column=0, sticky="w")
        
        # Subtitle
        subtitle_label = ctk.CTkLabel(
            header_frame,
            text="Multimodal LLM-based Phishing Detection System",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle_label.grid(row=1, column=0, sticky="w")
        
        # Status frame
        status_frame = ctk.CTkFrame(header_frame)
        status_frame.grid(row=0, column=1, rowspan=2, sticky="e", padx=10)
        
        # Connectivity status
        self.connectivity_label = ctk.CTkLabel(
            status_frame,
            text="⏳ Loading...",
            font=ctk.CTkFont(size=12)
        )
        self.connectivity_label.pack(padx=10, pady=5)
        
        # Mode indicator
        self.mode_label = ctk.CTkLabel(
            status_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.mode_label.pack(padx=10, pady=(0, 5))
    
    def _create_input_section(self):
        """Create the URL input section."""
        input_frame = ctk.CTkFrame(self)
        input_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)
        input_frame.grid_columnconfigure(0, weight=1)
        
        # URL Entry
        self.url_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter URL to scan (e.g., https://example.com)",
            font=ctk.CTkFont(size=14),
            height=45
        )
        self.url_entry.grid(row=0, column=0, sticky="ew", padx=(15, 10), pady=15)
        self.url_entry.bind("<Return>", lambda e: self._scan_url())
        
        # Scan Button
        self.scan_button = ctk.CTkButton(
            input_frame,
            text="🔍 SCAN",
            font=ctk.CTkFont(size=14, weight="bold"),
            width=120,
            height=45,
            command=self._scan_url,
            state="disabled"
        )
        self.scan_button.grid(row=0, column=1, padx=(0, 15), pady=15)
        
        # Progress bar (hidden by default)
        self.progress_bar = ctk.CTkProgressBar(input_frame)
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky="ew", padx=15, pady=(0, 10))
        self.progress_bar.set(0)
        self.progress_bar.grid_remove()
    
    def _create_results_section(self):
        """Create the results display section."""
        # Results container
        self.results_frame = ctk.CTkFrame(self)
        self.results_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(1, weight=1)
        
        # Create tabview
        self.tabview = ctk.CTkTabview(self.results_frame)
        self.tabview.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Add tabs
        self.tabview.add("Results")
        self.tabview.add("History")
        
        # Results tab content
        self._create_results_tab()
        
        # History tab content
        self._create_history_tab()
    
    def _create_results_tab(self):
        """Create the Results tab content."""
        results_tab = self.tabview.tab("Results")
        results_tab.grid_columnconfigure(0, weight=1)
        results_tab.grid_rowconfigure(2, weight=1)
        
        # Status card (Classification result)
        self.status_card = ctk.CTkFrame(results_tab)
        self.status_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        self.status_card.grid_columnconfigure(1, weight=1)
        
        # Status icon
        self.status_icon = ctk.CTkLabel(
            self.status_card,
            text="❓",
            font=ctk.CTkFont(size=48)
        )
        self.status_icon.grid(row=0, column=0, rowspan=2, padx=20, pady=15)
        
        # Status text
        self.status_text = ctk.CTkLabel(
            self.status_card,
            text="Enter a URL to scan",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.status_text.grid(row=0, column=1, sticky="w", pady=(15, 0))
        
        # Action recommendation
        self.action_label = ctk.CTkLabel(
            self.status_card,
            text="",
            font=ctk.CTkFont(size=14)
        )
        self.action_label.grid(row=1, column=1, sticky="w", pady=(0, 15))
        
        # Metrics frame
        metrics_frame = ctk.CTkFrame(results_tab)
        metrics_frame.grid(row=1, column=0, sticky="ew", pady=10)
        metrics_frame.grid_columnconfigure((0, 1, 2), weight=1)
        
        # Risk Score
        risk_frame = ctk.CTkFrame(metrics_frame)
        risk_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(
            risk_frame,
            text="RISK SCORE",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(pady=(10, 5))
        
        self.risk_score_label = ctk.CTkLabel(
            risk_frame,
            text="--",
            font=ctk.CTkFont(size=32, weight="bold")
        )
        self.risk_score_label.pack()
        
        self.risk_progress = ctk.CTkProgressBar(risk_frame, width=120)
        self.risk_progress.pack(pady=(5, 10))
        self.risk_progress.set(0)
        
        # Confidence
        confidence_frame = ctk.CTkFrame(metrics_frame)
        confidence_frame.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(
            confidence_frame,
            text="CONFIDENCE",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(pady=(10, 5))
        
        self.confidence_label = ctk.CTkLabel(
            confidence_frame,
            text="--%",
            font=ctk.CTkFont(size=32, weight="bold")
        )
        self.confidence_label.pack(pady=(0, 10))
        
        # Analysis Mode
        mode_frame = ctk.CTkFrame(metrics_frame)
        mode_frame.grid(row=0, column=2, padx=10, pady=10, sticky="ew")
        
        ctk.CTkLabel(
            mode_frame,
            text="ANALYSIS MODE",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(pady=(10, 5))
        
        self.analysis_mode_label = ctk.CTkLabel(
            mode_frame,
            text="--",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.analysis_mode_label.pack(pady=(0, 10))
        
        # Explanation box
        explanation_label = ctk.CTkLabel(
            results_tab,
            text="Analysis Details",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        explanation_label.grid(row=2, column=0, sticky="w", pady=(10, 5))
        
        self.explanation_text = ctk.CTkTextbox(
            results_tab,
            font=ctk.CTkFont(size=13),
            wrap="word"
        )
        self.explanation_text.grid(row=3, column=0, sticky="nsew", pady=(0, 10))
        results_tab.grid_rowconfigure(3, weight=1)
    
    def _create_history_tab(self):
        """Create the History tab content."""
        history_tab = self.tabview.tab("History")
        history_tab.grid_columnconfigure(0, weight=1)
        history_tab.grid_rowconfigure(0, weight=1)
        
        # History list
        self.history_frame = ctk.CTkScrollableFrame(history_tab)
        self.history_frame.grid(row=0, column=0, sticky="nsew")
        self.history_frame.grid_columnconfigure(0, weight=1)
        
        # Placeholder
        self.history_placeholder = ctk.CTkLabel(
            self.history_frame,
            text="No scan history yet.\nScanned URLs will appear here.",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.history_placeholder.grid(row=0, column=0, pady=50)
    
    def _create_footer(self):
        """Create the footer with additional options."""
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 15))
        footer_frame.grid_columnconfigure(1, weight=1)
        
        # Refresh connectivity button
        refresh_btn = ctk.CTkButton(
            footer_frame,
            text="🔄 Refresh Connection",
            width=150,
            height=32,
            command=self._refresh_connectivity
        )
        refresh_btn.grid(row=0, column=0)
        
        # Version info
        version_label = ctk.CTkLabel(
            footer_frame,
            text="v2.0 | ML Model: Random Forest (99.8% F1)",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        version_label.grid(row=0, column=2)
    
    def _load_service_async(self):
        """Load the detection service in background."""
        def load():
            try:
                self.service = PhishingDetectionService(load_mllm=False, load_ml_model=True)
                self.is_online = self.service.is_online
                self.after(0, self._on_service_loaded)
            except Exception as e:
                self.after(0, lambda: self._on_service_error(str(e)))
        
        thread = threading.Thread(target=load, daemon=True)
        thread.start()
    
    def _on_service_loaded(self):
        """Called when service is loaded."""
        self.is_loading = False
        self.scan_button.configure(state="normal")
        self._update_connectivity_status()
    
    def _on_service_error(self, error: str):
        """Called when service fails to load."""
        self.is_loading = False
        self.connectivity_label.configure(text="❌ Error", text_color="red")
        self.mode_label.configure(text=error[:50])
    
    def _update_connectivity_status(self):
        """Update the connectivity status display."""
        if self.service:
            self.is_online = self.service.is_online
        
        if self.is_online:
            self.connectivity_label.configure(
                text="🌐 Online",
                text_color="green"
            )
            self.mode_label.configure(text="Full Analysis Mode")
        else:
            self.connectivity_label.configure(
                text="📴 Offline",
                text_color="orange"
            )
            self.mode_label.configure(text="Static Analysis Mode")
    
    def _refresh_connectivity(self):
        """Refresh connectivity status."""
        if self.service:
            self.service.refresh_connectivity()
            self._update_connectivity_status()
    
    def _scan_url(self):
        """Scan the entered URL."""
        url = self.url_entry.get().strip()
        
        if not url:
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Show loading state
        self.scan_button.configure(state="disabled", text="⏳ Scanning...")
        self.progress_bar.grid()
        self.progress_bar.start()
        
        # Run scan in background
        def scan():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    self.service.analyze_url_async(url, force_mllm=self.is_online)
                )
                loop.close()
                self.after(0, lambda: self._display_result(result))
            except Exception as e:
                self.after(0, lambda: self._display_error(str(e)))
        
        thread = threading.Thread(target=scan, daemon=True)
        thread.start()
    
    def _display_result(self, result: dict):
        """Display the scan result."""
        # Reset loading state
        self.scan_button.configure(state="normal", text="🔍 SCAN")
        self.progress_bar.stop()
        self.progress_bar.grid_remove()
        
        classification = result['classification']
        risk_score = result['risk_score']
        confidence = result['confidence']
        explanation = result['explanation']
        action = result['recommended_action']
        analysis_mode = result.get('analysis_mode', 'unknown')
        
        # Update status card
        if classification == 'phishing':
            self.status_card.configure(fg_color=("#ffebee", "#4a1c1c"))
            self.status_icon.configure(text="⚠️")
            self.status_text.configure(
                text="PHISHING DETECTED",
                text_color=("#c62828", "#ef5350")
            )
        else:
            self.status_card.configure(fg_color=("#e8f5e9", "#1b3d1b"))
            self.status_icon.configure(text="✅")
            self.status_text.configure(
                text="LEGITIMATE",
                text_color=("#2e7d32", "#66bb6a")
            )
        
        # Update action
        action_text = {
            'block': "🚫 Recommended: BLOCK this URL",
            'warn': "⚠️ Recommended: WARN user",
            'allow': "✓ Recommended: ALLOW access"
        }
        self.action_label.configure(text=action_text.get(action, ""))
        
        # Update metrics
        self.risk_score_label.configure(text=f"{int(risk_score)}")
        self.risk_progress.set(risk_score / 100)
        
        # Color the risk bar
        if risk_score >= 70:
            self.risk_progress.configure(progress_color="red")
        elif risk_score >= 40:
            self.risk_progress.configure(progress_color="orange")
        else:
            self.risk_progress.configure(progress_color="green")
        
        self.confidence_label.configure(text=f"{confidence*100:.1f}%")
        
        mode_display = {
            'online': "🌐 ONLINE",
            'offline': "📴 OFFLINE",
            'whitelist': "✓ TRUSTED",
            'online_failed': "⚠️ SCRAPE FAILED"
        }
        self.analysis_mode_label.configure(
            text=mode_display.get(analysis_mode, analysis_mode.upper())
        )
        
        # Update explanation
        self.explanation_text.delete("1.0", "end")
        
        explanation_full = f"URL: {result['url']}\n\n"
        explanation_full += f"Classification: {classification.upper()}\n"
        explanation_full += f"Risk Score: {risk_score}/100\n"
        explanation_full += f"Confidence: {confidence*100:.1f}%\n"
        explanation_full += f"Analysis Mode: {analysis_mode}\n"
        
        if result.get('scraped'):
            proof = result.get('scrape_proof', {})
            explanation_full += f"\n📸 Scraped Content:\n"
            explanation_full += f"  - Title: {proof.get('title', 'N/A')}\n"
            explanation_full += f"  - HTML Size: {proof.get('html_size_bytes', 0)} bytes\n"
            explanation_full += f"  - Links: {proof.get('num_links', 0)}\n"
        
        typo = result['features'].get('typosquatting', {})
        if typo.get('is_typosquatting'):
            explanation_full += f"\n⚠️ Typosquatting Detected:\n"
            explanation_full += f"  - Method: {typo.get('detection_method')}\n"
            if typo.get('impersonated_brand'):
                explanation_full += f"  - Impersonated Brand: {typo.get('impersonated_brand').upper()}\n"
        
        explanation_full += f"\n📋 Analysis:\n{explanation}"
        
        self.explanation_text.insert("1.0", explanation_full)
        
        # Add to history
        self._add_to_history(result)
    
    def _display_error(self, error: str):
        """Display an error message."""
        self.scan_button.configure(state="normal", text="🔍 SCAN")
        self.progress_bar.stop()
        self.progress_bar.grid_remove()
        
        self.status_card.configure(fg_color=("#fff3e0", "#4a3520"))
        self.status_icon.configure(text="❌")
        self.status_text.configure(text="ERROR", text_color="orange")
        self.action_label.configure(text=error[:100])
    
    def _add_to_history(self, result: dict):
        """Add a scan result to history."""
        # Remove placeholder
        if self.history_placeholder.winfo_exists():
            self.history_placeholder.grid_remove()
        
        # Create history item
        item_frame = ctk.CTkFrame(self.history_frame)
        item_frame.grid(row=len(self.scan_history), column=0, sticky="ew", pady=5, padx=5)
        item_frame.grid_columnconfigure(1, weight=1)
        
        # Status icon
        icon = "⚠️" if result['classification'] == 'phishing' else "✅"
        icon_color = "red" if result['classification'] == 'phishing' else "green"
        
        ctk.CTkLabel(
            item_frame,
            text=icon,
            font=ctk.CTkFont(size=20)
        ).grid(row=0, column=0, padx=10, pady=10)
        
        # URL (truncated)
        url_text = result['url'][:50] + "..." if len(result['url']) > 50 else result['url']
        ctk.CTkLabel(
            item_frame,
            text=url_text,
            font=ctk.CTkFont(size=13),
            anchor="w"
        ).grid(row=0, column=1, sticky="w")
        
        # Score
        ctk.CTkLabel(
            item_frame,
            text=f"{int(result['risk_score'])}/100",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).grid(row=0, column=2, padx=10)
        
        # Add to history list
        self.scan_history.append(result)


def main():
    """Run the GUI application."""
    app = PhishingDetectorGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
