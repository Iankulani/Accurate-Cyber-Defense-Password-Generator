import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib
import os
import random
import string
import secrets
import pyperclip
import time
import json
import webbrowser
from datetime import datetime
import sys
import platform
import socket
import threading
import cryptography
from cryptography.fernet import Fernet
import base64
import zlib
import qrcode
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import pandas as pd
import sqlite3
import logging
import inspect
import uuid
import binascii
import hmac
import argon2
import bcrypt
import pbkdf2

# Constants
VERSION = "2.0.0"
APP_NAME = "Accurate Cyber Defense Password Generator"
DEVELOPER = "Ian Carter Kulani"
BLUE_THEME = {
    'primary': '#1E88E5',
    'secondary': '#64B5F6',
    'dark': '#0D47A1',
    'light': '#BBDEFB',
    'text': '#FFFFFF',
    'background': '#E3F2FD'
}

# Configure logging
logging.basicConfig(
    filename='password_guardian.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("1000x700")
        self.root.minsize(900, 650)
        self.root.configure(bg=BLUE_THEME['background'])
        
        # Initialize security parameters
        self.security_level = tk.IntVar(value=3)
        self.password_length = tk.IntVar(value=16)
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_special = tk.BooleanVar(value=True)
        self.include_spaces = tk.BooleanVar(value=False)
        self.salt_length = tk.IntVar(value=32)
        self.hash_algorithm = tk.StringVar(value='SHA-256')
        self.encryption_enabled = tk.BooleanVar(value=True)
        self.password_history = []
        self.saved_passwords = []
        self.master_password = None
        self.fernet_key = None
        
        # Setup encryption
        self.setup_encryption()
        
        # Load saved passwords
        self.load_saved_passwords()
        
        # Setup UI
        self.setup_ui()
        
        # Security check
        self.perform_security_check()
        
        # Register exit handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)
    
    def setup_encryption(self):
        """Initialize encryption system"""
        key_file = 'encryption.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.fernet_key = f.read()
        else:
            self.fernet_key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.fernet_key)
    
    def encrypt_data(self, data):
        """Encrypt sensitive data"""
        if not self.encryption_enabled.get():
            return data
        fernet = Fernet(self.fernet_key)
        return fernet.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data):
        """Decrypt sensitive data"""
        if not self.encryption_enabled.get():
            return encrypted_data
        fernet = Fernet(self.fernet_key)
        return fernet.decrypt(encrypted_data.encode()).decode()
    
    def load_saved_passwords(self):
        """Load saved passwords from encrypted storage"""
        try:
            if os.path.exists('passwords.db'):
                conn = sqlite3.connect('passwords.db')
                cursor = conn.cursor()
                cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                              (id INTEGER PRIMARY KEY AUTOINCREMENT,
                               service TEXT,
                               username TEXT,
                               password TEXT,
                               salt TEXT,
                               algorithm TEXT,
                               notes TEXT,
                               created_at TEXT)''')
                conn.commit()
                
                cursor.execute("SELECT * FROM passwords")
                rows = cursor.fetchall()
                for row in rows:
                    try:
                        decrypted_password = self.decrypt_data(row[3])
                        decrypted_salt = self.decrypt_data(row[4])
                        self.saved_passwords.append({
                            'id': row[0],
                            'service': row[1],
                            'username': row[2],
                            'password': decrypted_password,
                            'salt': decrypted_salt,
                            'algorithm': row[5],
                            'notes': row[6],
                            'created_at': row[7]
                        })
                    except Exception as e:
                        logging.error(f"Error decrypting password {row[0]}: {str(e)}")
                conn.close()
        except Exception as e:
            logging.error(f"Error loading saved passwords: {str(e)}")
            messagebox.showerror("Error", "Failed to load saved passwords")
    
    def save_password_to_db(self, password_data):
        """Save password to encrypted database"""
        try:
            encrypted_password = self.encrypt_data(password_data['password'])
            encrypted_salt = self.encrypt_data(password_data['salt'])
            
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()
            cursor.execute('''INSERT INTO passwords
                          (service, username, password, salt, algorithm, notes, created_at)
                          VALUES (?, ?, ?, ?, ?, ?, ?)''',
                          (password_data['service'],
                           password_data['username'],
                           encrypted_password,
                           encrypted_salt,
                           password_data['algorithm'],
                           password_data['notes'],
                           datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logging.error(f"Error saving password: {str(e)}")
            return False
    
    def setup_ui(self):
        """Setup the main user interface"""
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.style.configure('TFrame', background=BLUE_THEME['background'])
        self.style.configure('TLabel', background=BLUE_THEME['background'], foreground='black')
        self.style.configure('TButton', background=BLUE_THEME['primary'], foreground=BLUE_THEME['text'])
        self.style.configure('TEntry', fieldbackground='white')
        self.style.configure('TCombobox', fieldbackground='white')
        self.style.configure('TCheckbutton', background=BLUE_THEME['background'])
        self.style.configure('Blue.TFrame', background=BLUE_THEME['primary'])
        self.style.configure('Blue.TLabel', background=BLUE_THEME['primary'], foreground=BLUE_THEME['text'])
        self.style.configure('Blue.TButton', background=BLUE_THEME['dark'], foreground=BLUE_THEME['text'])
        self.style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'), background=BLUE_THEME['primary'], foreground=BLUE_THEME['text'])
        
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.header_frame = ttk.Frame(self.main_frame, style='Blue.TFrame')
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.title_label = ttk.Label(
            self.header_frame,
            text=f"{APP_NAME} v{VERSION}",
            style='Title.TLabel'
        )
        self.title_label.pack(side=tk.LEFT, padx=10, pady=10)
        
        self.menu_button = ttk.Button(
            self.header_frame,
            text="Menu",
            command=self.show_menu,
            style='Blue.TButton'
        )
        self.menu_button.pack(side=tk.RIGHT, padx=10, pady=10)
        
        # Main content area
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Password Generator Tab
        self.setup_password_generator_tab()
        
        # Password Manager Tab
        self.setup_password_manager_tab()
        
        # Security Analyzer Tab
        self.setup_security_analyzer_tab()
        
        # Settings Tab
        self.setup_settings_tab()
        
        # Status bar
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.status_label = ttk.Label(
            self.status_frame,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X)
    
    def setup_password_generator_tab(self):
        """Setup the password generator tab"""
        self.pwgen_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.pwgen_frame, text="Password Generator")
        
        # Configuration frame
        config_frame = ttk.LabelFrame(self.pwgen_frame, text="Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Security level
        ttk.Label(config_frame, text="Security Level:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.security_level_slider = ttk.Scale(
            config_frame,
            from_=1,
            to=5,
            variable=self.security_level,
            command=lambda e: self.update_security_level()
        )
        self.security_level_slider.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        self.security_level_label = ttk.Label(config_frame, text="Medium")
        self.security_level_label.grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        
        # Password length
        ttk.Label(config_frame, text="Password Length:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.length_slider = ttk.Scale(
            config_frame,
            from_=8,
            to=64,
            variable=self.password_length,
            command=lambda e: self.update_length_label()
        )
        self.length_slider.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        
        self.length_label = ttk.Label(config_frame, text="16")
        self.length_label.grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        
        # Salt length
        ttk.Label(config_frame, text="Salt Length:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.salt_slider = ttk.Scale(
            config_frame,
            from_=8,
            to=64,
            variable=self.salt_length,
            command=lambda e: self.update_salt_label()
        )
        self.salt_slider.grid(row=2, column=1, sticky=tk.EW, padx=5, pady=2)
        
        self.salt_label = ttk.Label(config_frame, text="32")
        self.salt_label.grid(row=2, column=2, sticky=tk.W, padx=5, pady=2)
        
        # Character sets
        charsets_frame = ttk.Frame(config_frame)
        charsets_frame.grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        ttk.Checkbutton(
            charsets_frame,
            text="Uppercase (A-Z)",
            variable=self.include_uppercase
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            charsets_frame,
            text="Lowercase (a-z)",
            variable=self.include_lowercase
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            charsets_frame,
            text="Digits (0-9)",
            variable=self.include_digits
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            charsets_frame,
            text="Special (!@#...)",
            variable=self.include_special
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            charsets_frame,
            text="Spaces",
            variable=self.include_spaces
        ).pack(side=tk.LEFT, padx=5)
        
        # Hash algorithm
        ttk.Label(config_frame, text="Hash Algorithm:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        self.algorithm_combo = ttk.Combobox(
            config_frame,
            textvariable=self.hash_algorithm,
            values=['SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-512', 'BLAKE2b', 'BLAKE2s', 'Argon2', 'bcrypt', 'PBKDF2', 'scrypt'],
            state='readonly'
        )
        self.algorithm_combo.grid(row=4, column=1, sticky=tk.EW, padx=5, pady=2)
        
        # Generation frame
        gen_frame = ttk.LabelFrame(self.pwgen_frame, text="Generate Password", padding=10)
        gen_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Password display
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            gen_frame,
            textvariable=self.password_var,
            font=('Courier', 12),
            state='readonly'
        )
        self.password_entry.pack(fill=tk.X, padx=5, pady=5)
        
        # Salt display
        self.salt_var = tk.StringVar()
        self.salt_entry = ttk.Entry(
            gen_frame,
            textvariable=self.salt_var,
            font=('Courier', 12),
            state='readonly'
        )
        self.salt_entry.pack(fill=tk.X, padx=5, pady=5)
        
        # Hashed password display
        self.hashed_var = tk.StringVar()
        self.hashed_entry = ttk.Entry(
            gen_frame,
            textvariable=self.hashed_var,
            font=('Courier', 10),
            state='readonly'
        )
        self.hashed_entry.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(gen_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            buttons_frame,
            text="Generate Password",
            command=self.generate_password,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Copy Password",
            command=self.copy_password,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Copy Salt",
            command=self.copy_salt,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Copy Hashed",
            command=self.copy_hashed,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Save Password",
            command=self.save_password_dialog,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # Strength meter
        self.strength_frame = ttk.Frame(gen_frame)
        self.strength_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.strength_frame, text="Strength:").pack(side=tk.LEFT, padx=5)
        
        self.strength_meter = ttk.Progressbar(
            self.strength_frame,
            orient=tk.HORIZONTAL,
            length=200,
            mode='determinate'
        )
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.strength_label = ttk.Label(self.strength_frame, text="")
        self.strength_label.pack(side=tk.LEFT, padx=5)
        
        # Entropy display
        self.entropy_var = tk.StringVar(value="Entropy: 0 bits")
        ttk.Label(
            gen_frame,
            textvariable=self.entropy_var,
            font=('Helvetica', 9)
        ).pack(anchor=tk.W, padx=5)
    
    def setup_password_manager_tab(self):
        """Setup the password manager tab"""
        self.pwman_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.pwman_frame, text="Password Manager")
        
        # Search frame
        search_frame = ttk.Frame(self.pwman_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(
            search_frame,
            textvariable=self.search_var
        )
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_entry.bind('<KeyRelease>', self.search_passwords)
        
        # Password list
        columns = ('service', 'username', 'password', 'algorithm', 'created')
        self.password_tree = ttk.Treeview(
            self.pwman_frame,
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        self.password_tree.heading('service', text="Service", anchor=tk.W)
        self.password_tree.heading('username', text="Username", anchor=tk.W)
        self.password_tree.heading('password', text="Password", anchor=tk.W)
        self.password_tree.heading('algorithm', text="Algorithm", anchor=tk.W)
        self.password_tree.heading('created', text="Created", anchor=tk.W)
        
        self.password_tree.column('service', width=150, stretch=tk.NO)
        self.password_tree.column('username', width=150, stretch=tk.NO)
        self.password_tree.column('password', width=200, stretch=tk.NO)
        self.password_tree.column('algorithm', width=100, stretch=tk.NO)
        self.password_tree.column('created', width=120, stretch=tk.NO)
        
        self.password_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            self.password_tree,
            orient=tk.VERTICAL,
            command=self.password_tree.yview
        )
        self.password_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.pwman_frame)
        buttons_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            buttons_frame,
            text="View Details",
            command=self.view_password_details,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Edit",
            command=self.edit_password,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Delete",
            command=self.delete_password,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Refresh",
            command=self.refresh_password_list,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Export",
            command=self.export_passwords,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Import",
            command=self.import_passwords,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # Populate password list
        self.refresh_password_list()
    
    def setup_security_analyzer_tab(self):
        """Setup the security analyzer tab"""
        self.analyzer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.analyzer_frame, text="Security Analyzer")
        
        # Password input frame
        input_frame = ttk.Frame(self.analyzer_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Password to analyze:").pack(side=tk.LEFT, padx=5)
        
        self.analyze_var = tk.StringVar()
        self.analyze_entry = ttk.Entry(
            input_frame,
            textvariable=self.analyze_var,
            show="*"
        )
        self.analyze_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        ttk.Button(
            input_frame,
            text="Analyze",
            command=self.analyze_password,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # Analysis results
        results_frame = ttk.LabelFrame(self.analyzer_frame, text="Analysis Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Strength meter
        strength_frame = ttk.Frame(results_frame)
        strength_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(strength_frame, text="Strength:").pack(side=tk.LEFT, padx=5)
        
        self.analyzer_meter = ttk.Progressbar(
            strength_frame,
            orient=tk.HORIZONTAL,
            length=200,
            mode='determinate'
        )
        self.analyzer_meter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        self.analyzer_label = ttk.Label(strength_frame, text="")
        self.analyzer_label.pack(side=tk.LEFT, padx=5)
        
        # Entropy
        self.analyzer_entropy = ttk.Label(
            results_frame,
            text="Entropy: ",
            font=('Helvetica', 10)
        )
        self.analyzer_entropy.pack(anchor=tk.W, padx=5, pady=2)
        
        # Crack time
        self.analyzer_crack_time = ttk.Label(
            results_frame,
            text="Time to crack: ",
            font=('Helvetica', 10)
        )
        self.analyzer_crack_time.pack(anchor=tk.W, padx=5, pady=2)
        
        # Common patterns
        self.analyzer_patterns = ttk.Label(
            results_frame,
            text="Common patterns: ",
            font=('Helvetica', 10)
        )
        self.analyzer_patterns.pack(anchor=tk.W, padx=5, pady=2)
        
        # Detailed analysis
        details_frame = ttk.Frame(results_frame)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.analyzer_details = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            width=60,
            height=10,
            font=('Courier', 9)
        )
        self.analyzer_details.pack(fill=tk.BOTH, expand=True)
        
        # Password statistics
        stats_frame = ttk.LabelFrame(self.analyzer_frame, text="Password Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        
        # Create a figure for the plot
        self.figure = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        
        # Create canvas for the plot
        self.canvas = FigureCanvasTkAgg(self.figure, stats_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initial plot
        self.update_stats_plot()
    
    def setup_settings_tab(self):
        """Setup the settings tab"""
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        # General settings
        general_frame = ttk.LabelFrame(self.settings_frame, text="General Settings", padding=10)
        general_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Theme settings
        ttk.Label(general_frame, text="Theme:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.theme_var = tk.StringVar(value='blue')
        ttk.Combobox(
            general_frame,
            textvariable=self.theme_var,
            values=['blue', 'dark', 'light'],
            state='readonly'
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Auto-clear clipboard
        self.autoclear_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            general_frame,
            text="Auto-clear clipboard after 30 seconds",
            variable=self.autoclear_var
        ).grid(row=1, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        # Security settings
        security_frame = ttk.LabelFrame(self.settings_frame, text="Security Settings", padding=10)
        security_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Master password
        ttk.Label(security_frame, text="Master Password:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.master_pw_entry = ttk.Entry(
            security_frame,
            show="*"
        )
        self.master_pw_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        
        ttk.Button(
            security_frame,
            text="Set Master Password",
            command=self.set_master_password,
            style='Blue.TButton'
        ).grid(row=0, column=2, padx=5, pady=2)
        
        # Encryption
        ttk.Label(security_frame, text="Encryption:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Checkbutton(
            security_frame,
            text="Enable encryption for stored passwords",
            variable=self.encryption_enabled
        ).grid(row=1, column=1, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        # Password generation settings
        gen_frame = ttk.LabelFrame(self.settings_frame, text="Password Generation Defaults", padding=10)
        gen_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Default length
        ttk.Label(gen_frame, text="Default Length:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.default_length_var = tk.IntVar(value=16)
        ttk.Spinbox(
            gen_frame,
            from_=8,
            to=64,
            textvariable=self.default_length_var
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Default algorithm
        ttk.Label(gen_frame, text="Default Algorithm:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.default_algorithm_var = tk.StringVar(value='SHA-256')
        ttk.Combobox(
            gen_frame,
            textvariable=self.default_algorithm_var,
            values=['SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-512', 'BLAKE2b', 'BLAKE2s', 'Argon2', 'bcrypt', 'PBKDF2', 'scrypt'],
            state='readonly'
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Buttons frame
        buttons_frame = ttk.Frame(self.settings_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Save Settings",
            command=self.save_settings,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Reset to Defaults",
            command=self.reset_settings,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Backup Data",
            command=self.backup_data,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Restore Data",
            command=self.restore_data,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        # About section
        about_frame = ttk.LabelFrame(self.settings_frame, text="About", padding=10)
        about_frame.pack(fill=tk.X, padx=5, pady=5)
        
        about_text = f"""{APP_NAME} v{VERSION}
Developed by {DEVELOPER}
        
A comprehensive password management and security tool designed to help you create and manage strong, unique passwords for all your accounts.
        
© 2025 Accurate Cyber Defense. All rights reserved."""
        
        ttk.Label(
            about_frame,
            text=about_text,
            justify=tk.LEFT
        ).pack(anchor=tk.W)
        
        ttk.Button(
            about_frame,
            text="Check for Updates",
            command=self.check_for_updates,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(
            about_frame,
            text="View License",
            command=self.view_license,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(
            about_frame,
            text="Documentation",
            command=self.view_documentation,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5, pady=5)
    
    def update_security_level(self):
        """Update security level based on slider"""
        level = self.security_level.get()
        if level == 1:
            text = "Low"
            self.password_length.set(12)
            self.include_uppercase.set(True)
            self.include_lowercase.set(True)
            self.include_digits.set(True)
            self.include_special.set(False)
            self.include_spaces.set(False)
            self.hash_algorithm.set('SHA-256')
        elif level == 2:
            text = "Medium"
            self.password_length.set(16)
            self.include_uppercase.set(True)
            self.include_lowercase.set(True)
            self.include_digits.set(True)
            self.include_special.set(True)
            self.include_spaces.set(False)
            self.hash_algorithm.set('SHA-256')
        elif level == 3:
            text = "High"
            self.password_length.set(20)
            self.include_uppercase.set(True)
            self.include_lowercase.set(True)
            self.include_digits.set(True)
            self.include_special.set(True)
            self.include_spaces.set(True)
            self.hash_algorithm.set('SHA-512')
        elif level == 4:
            text = "Very High"
            self.password_length.set(24)
            self.include_uppercase.set(True)
            self.include_lowercase.set(True)
            self.include_digits.set(True)
            self.include_special.set(True)
            self.include_spaces.set(True)
            self.hash_algorithm.set('SHA3-512')
        else:  # level == 5
            text = "Maximum"
            self.password_length.set(32)
            self.include_uppercase.set(True)
            self.include_lowercase.set(True)
            self.include_digits.set(True)
            self.include_special.set(True)
            self.include_spaces.set(True)
            self.hash_algorithm.set('Argon2')
        
        self.security_level_label.config(text=text)
        self.update_length_label()
    
    def update_length_label(self):
        """Update password length label"""
        length = self.password_length.get()
        self.length_label.config(text=str(length))
    
    def update_salt_label(self):
        """Update salt length label"""
        length = self.salt_length.get()
        self.salt_label.config(text=str(length))
    
    def generate_password(self):
        """Generate a random password with salt and hash"""
        try:
            # Get character sets based on user selection
            chars = ''
            if self.include_lowercase.get():
                chars += string.ascii_lowercase
            if self.include_uppercase.get():
                chars += string.ascii_uppercase
            if self.include_digits.get():
                chars += string.digits
            if self.include_special.get():
                chars += string.punctuation
            if self.include_spaces.get():
                chars += ' '
            
            if not chars:
                messagebox.showerror("Error", "At least one character set must be selected")
                return
            
            # Generate password
            length = self.password_length.get()
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
            # Generate salt
            salt_length = self.salt_length.get()
            salt = secrets.token_hex(salt_length)
            
            # Hash the password with salt
            algorithm = self.hash_algorithm.get()
            hashed = self.hash_password(password, salt, algorithm)
            
            # Update UI
            self.password_var.set(password)
            self.salt_var.set(salt)
            self.hashed_var.set(hashed)
            
            # Calculate and display strength
            entropy = self.calculate_entropy(password)
            self.entropy_var.set(f"Entropy: {entropy:.2f} bits")
            
            strength = self.calculate_strength(password)
            self.strength_meter['value'] = strength
            if strength < 40:
                self.strength_label.config(text="Weak", foreground='red')
            elif strength < 70:
                self.strength_label.config(text="Medium", foreground='orange')
            else:
                self.strength_label.config(text="Strong", foreground='green')
            
            # Add to history
            self.password_history.append({
                'password': password,
                'salt': salt,
                'hashed': hashed,
                'algorithm': algorithm,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            # Auto-copy if enabled
            if hasattr(self, 'autocopy_var') and self.autocopy_var.get():
                pyperclip.copy(password)
                self.status_label.config(text="Password copied to clipboard")
                
                # Schedule clipboard clear if enabled
                if self.autoclear_var.get():
                    self.root.after(30000, self.clear_clipboard)
            
        except Exception as e:
            logging.error(f"Error generating password: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
    
    def hash_password(self, password, salt, algorithm):
        """Hash a password with the specified algorithm"""
        try:
            if algorithm == 'SHA-256':
                return hashlib.sha256((password + salt).encode()).hexdigest()
            elif algorithm == 'SHA-512':
                return hashlib.sha512((password + salt).encode()).hexdigest()
            elif algorithm == 'SHA3-256':
                return hashlib.sha3_256((password + salt).encode()).hexdigest()
            elif algorithm == 'SHA3-512':
                return hashlib.sha3_512((password + salt).encode()).hexdigest()
            elif algorithm == 'BLAKE2b':
                return hashlib.blake2b((password + salt).encode()).hexdigest()
            elif algorithm == 'BLAKE2s':
                return hashlib.blake2s((password + salt).encode()).hexdigest()
            elif algorithm == 'Argon2':
                # Requires argon2-cffi package
                return argon2.low_level.hash_secret(
                    password.encode(),
                    salt.encode(),
                    time_cost=3,
                    memory_cost=65536,
                    parallelism=4,
                    hash_len=32,
                    type=argon2.low_level.Type.ID
                ).decode()
            elif algorithm == 'bcrypt':
                # Requires bcrypt package
                return bcrypt.hashpw((password + salt).encode(), bcrypt.gensalt()).decode()
            elif algorithm == 'PBKDF2':
                # Using SHA-256 as the underlying hash for PBKDF2
                return pbkdf2.PBKDF2(
                    password + salt,
                    salt.encode(),
                    iterations=100000,
                    digestmodule=hashlib.sha256
                ).hexread(32)
            elif algorithm == 'scrypt':
                # Requires scrypt package
                return binascii.hexlify(scrypt.hash(
                    password.encode(),
                    salt.encode(),
                    N=2**14,
                    r=8,
                    p=1,
                    dklen=32
                )).decode()
            else:
                return hashlib.sha256((password + salt).encode()).hexdigest()
        except Exception as e:
            logging.error(f"Error hashing password: {str(e)}")
            return f"Error: {str(e)}"
    
    def calculate_entropy(self, password):
        """Calculate the entropy of a password in bits"""
        if not password:
            return 0.0
        
        # Determine the pool of possible characters
        pool = 0
        if any(c in string.ascii_lowercase for c in password):
            pool += 26
        if any(c in string.ascii_uppercase for c in password):
            pool += 26
        if any(c in string.digits for c in password):
            pool += 10
        if any(c in string.punctuation for c in password):
            pool += 32
        if ' ' in password:
            pool += 1
        
        if pool == 0:
            return 0.0
        
        # Calculate entropy
        length = len(password)
        entropy = length * (math.log(pool) / math.log(2))
        
        return entropy
    
    def calculate_strength(self, password):
        """Calculate password strength as a percentage"""
        if not password:
            return 0
        
        length = len(password)
        entropy = self.calculate_entropy(password)
        
        # Score based on length
        length_score = min(100, length * 4)
        
        # Score based on entropy
        entropy_score = min(100, entropy * 2)
        
        # Bonus for mixed character sets
        sets = 0
        if any(c in string.ascii_lowercase for c in password):
            sets += 1
        if any(c in string.ascii_uppercase for c in password):
            sets += 1
        if any(c in string.digits for c in password):
            sets += 1
        if any(c in string.punctuation for c in password):
            sets += 1
        if ' ' in password:
            sets += 1
        
        sets_score = (sets - 1) * 10
        
        # Penalty for common patterns
        penalty = 0
        common_patterns = [
            '123', 'abc', 'qwerty', 'password', 'admin', 'welcome',
            'letmein', 'monkey', 'sunshine', 'iloveyou', 'football'
        ]
        
        lower_pwd = password.lower()
        for pattern in common_patterns:
            if pattern in lower_pwd:
                penalty += 20
        
        # Calculate final score
        score = (length_score * 0.5 + entropy_score * 0.3 + sets_score * 0.2) - penalty
        return max(0, min(100, score))
    
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            self.status_label.config(text="Password copied to clipboard")
            
            # Schedule clipboard clear if enabled
            if self.autoclear_var.get():
                self.root.after(30000, self.clear_clipboard)
        else:
            self.status_label.config(text="No password to copy")
    
    def copy_salt(self):
        """Copy salt to clipboard"""
        salt = self.salt_var.get()
        if salt:
            pyperclip.copy(salt)
            self.status_label.config(text="Salt copied to clipboard")
            
            # Schedule clipboard clear if enabled
            if self.autoclear_var.get():
                self.root.after(30000, self.clear_clipboard)
        else:
            self.status_label.config(text="No salt to copy")
    
    def copy_hashed(self):
        """Copy hashed password to clipboard"""
        hashed = self.hashed_var.get()
        if hashed:
            pyperclip.copy(hashed)
            self.status_label.config(text="Hashed password copied to clipboard")
            
            # Schedule clipboard clear if enabled
            if self.autoclear_var.get():
                self.root.after(30000, self.clear_clipboard)
        else:
            self.status_label.config(text="No hashed password to copy")
    
    def clear_clipboard(self):
        """Clear the clipboard"""
        try:
            pyperclip.copy('')
            self.status_label.config(text="Clipboard cleared")
        except Exception as e:
            logging.error(f"Error clearing clipboard: {str(e)}")
    
    def save_password_dialog(self):
        """Show dialog to save password"""
        password = self.password_var.get()
        salt = self.salt_var.get()
        hashed = self.hashed_var.get()
        
        if not password:
            messagebox.showerror("Error", "No password to save")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Save Password")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Service
        ttk.Label(dialog, text="Service:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        service_entry = ttk.Entry(dialog)
        service_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Username
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        username_entry = ttk.Entry(dialog)
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Password (readonly)
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        password_entry = ttk.Entry(dialog, textvariable=self.password_var, state='readonly')
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Salt (readonly)
        ttk.Label(dialog, text="Salt:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        salt_entry = ttk.Entry(dialog, textvariable=self.salt_var, state='readonly')
        salt_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Algorithm (readonly)
        ttk.Label(dialog, text="Algorithm:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        algorithm_entry = ttk.Entry(dialog, textvariable=self.hash_algorithm, state='readonly')
        algorithm_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Notes
        ttk.Label(dialog, text="Notes:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.NE)
        notes_text = tk.Text(dialog, width=30, height=5)
        notes_text.grid(row=5, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        buttons_frame = ttk.Frame(dialog)
        buttons_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Save",
            command=lambda: self.save_password(
                service_entry.get(),
                username_entry.get(),
                password,
                salt,
                self.hash_algorithm.get(),
                notes_text.get("1.0", tk.END).strip(),
                dialog
            ),
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Cancel",
            command=dialog.destroy,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        dialog.columnconfigure(1, weight=1)
    
    def save_password(self, service, username, password, salt, algorithm, notes, dialog):
        """Save password to database"""
        if not service:
            messagebox.showerror("Error", "Service name is required")
            return
        
        password_data = {
            'service': service,
            'username': username,
            'password': password,
            'salt': salt,
            'algorithm': algorithm,
            'notes': notes
        }
        
        if self.save_password_to_db(password_data):
            self.saved_passwords.append(password_data)
            self.refresh_password_list()
            dialog.destroy()
            messagebox.showinfo("Success", "Password saved successfully")
        else:
            messagebox.showerror("Error", "Failed to save password")
    
    def refresh_password_list(self):
        """Refresh the password list in the manager"""
        self.password_tree.delete(*self.password_tree.get_children())
        
        for pwd in self.saved_passwords:
            # Display masked password
            masked_pwd = self.mask_password(pwd['password'])
            
            self.password_tree.insert('', tk.END, values=(
                pwd['service'],
                pwd['username'],
                masked_pwd,
                pwd['algorithm'],
                pwd.get('created_at', 'N/A')
            ))
    
    def mask_password(self, password):
        """Mask password for display"""
        if len(password) <= 4:
            return '*' * len(password)
        return password[:2] + '*' * (len(password) - 4) + password[-2:]
    
    def view_password_details(self):
        """View details of selected password"""
        selected = self.password_tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "No password selected")
            return
        
        item = self.password_tree.item(selected)
        service = item['values'][0]
        
        # Find the password in saved passwords
        password_data = None
        for pwd in self.saved_passwords:
            if pwd['service'] == service:
                password_data = pwd
                break
        
        if not password_data:
            messagebox.showerror("Error", "Password data not found")
            return
        
        # Create details dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Password Details - {service}")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Service
        ttk.Label(dialog, text="Service:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        ttk.Label(dialog, text=password_data['service']).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Username
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        ttk.Label(dialog, text=password_data['username']).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Password
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        
        password_var = tk.StringVar(value=self.mask_password(password_data['password']))
        password_entry = ttk.Entry(dialog, textvariable=password_var, state='readonly')
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        def toggle_password():
            if password_var.get() == self.mask_password(password_data['password']):
                password_var.set(password_data['password'])
            else:
                password_var.set(self.mask_password(password_data['password']))
        
        ttk.Button(
            dialog,
            text="Show/Hide",
            command=toggle_password,
            style='Blue.TButton'
        ).grid(row=2, column=2, padx=5, pady=5)
        
        # Salt
        ttk.Label(dialog, text="Salt:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        salt_var = tk.StringVar(value=self.mask_password(password_data['salt']))
        salt_entry = ttk.Entry(dialog, textvariable=salt_var, state='readonly')
        salt_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        def toggle_salt():
            if salt_var.get() == self.mask_password(password_data['salt']):
                salt_var.set(password_data['salt'])
            else:
                salt_var.set(self.mask_password(password_data['salt']))
        
        ttk.Button(
            dialog,
            text="Show/Hide",
            command=toggle_salt,
            style='Blue.TButton'
        ).grid(row=3, column=2, padx=5, pady=5)
        
        # Algorithm
        ttk.Label(dialog, text="Algorithm:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        ttk.Label(dialog, text=password_data['algorithm']).grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Created At
        ttk.Label(dialog, text="Created:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.E)
        ttk.Label(dialog, text=password_data.get('created_at', 'N/A')).grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Notes
        ttk.Label(dialog, text="Notes:").grid(row=6, column=0, padx=5, pady=5, sticky=tk.NE)
        notes_text = tk.Text(dialog, width=40, height=5, wrap=tk.WORD)
        notes_text.insert(tk.END, password_data.get('notes', ''))
        notes_text.config(state='disabled')
        notes_text.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        buttons_frame = ttk.Frame(dialog)
        buttons_frame.grid(row=7, column=0, columnspan=3, pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Copy Password",
            command=lambda: self.copy_to_clipboard(password_data['password']),
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Copy Salt",
            command=lambda: self.copy_to_clipboard(password_data['salt']),
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Close",
            command=dialog.destroy,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        dialog.columnconfigure(1, weight=1)
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard and show status"""
        pyperclip.copy(text)
        self.status_label.config(text="Copied to clipboard")
        
        # Schedule clipboard clear if enabled
        if self.autoclear_var.get():
            self.root.after(30000, self.clear_clipboard)
    
    def edit_password(self):
        """Edit selected password"""
        selected = self.password_tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "No password selected")
            return
        
        item = self.password_tree.item(selected)
        service = item['values'][0]
        
        # Find the password in saved passwords
        password_data = None
        for pwd in self.saved_passwords:
            if pwd['service'] == service:
                password_data = pwd
                break
        
        if not password_data:
            messagebox.showerror("Error", "Password data not found")
            return
        
        # Create edit dialog
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Edit Password - {service}")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Service
        ttk.Label(dialog, text="Service:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        service_entry = ttk.Entry(dialog)
        service_entry.insert(0, password_data['service'])
        service_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Username
        ttk.Label(dialog, text="Username:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        username_entry = ttk.Entry(dialog)
        username_entry.insert(0, password_data['username'])
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Password
        ttk.Label(dialog, text="Password:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        password_entry = ttk.Entry(dialog)
        password_entry.insert(0, password_data['password'])
        password_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Generate button
        ttk.Button(
            dialog,
            text="Generate",
            command=lambda: self.generate_for_edit(password_entry),
            style='Blue.TButton'
        ).grid(row=2, column=2, padx=5, pady=5)
        
        # Salt
        ttk.Label(dialog, text="Salt:").grid(row=3, column=0, padx=5, pady=5, sticky=tk.E)
        salt_entry = ttk.Entry(dialog)
        salt_entry.insert(0, password_data['salt'])
        salt_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Algorithm
        ttk.Label(dialog, text="Algorithm:").grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)
        algorithm_combo = ttk.Combobox(
            dialog,
            values=['SHA-256', 'SHA-512', 'SHA3-256', 'SHA3-512', 'BLAKE2b', 'BLAKE2s', 'Argon2', 'bcrypt', 'PBKDF2', 'scrypt'],
            state='readonly'
        )
        algorithm_combo.set(password_data['algorithm'])
        algorithm_combo.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Notes
        ttk.Label(dialog, text="Notes:").grid(row=5, column=0, padx=5, pady=5, sticky=tk.NE)
        notes_text = tk.Text(dialog, width=40, height=5, wrap=tk.WORD)
        notes_text.insert(tk.END, password_data.get('notes', ''))
        notes_text.grid(row=5, column=1, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        buttons_frame = ttk.Frame(dialog)
        buttons_frame.grid(row=6, column=0, columnspan=3, pady=10)
        
        def save_changes():
            # Update password data
            password_data['service'] = service_entry.get()
            password_data['username'] = username_entry.get()
            password_data['password'] = password_entry.get()
            password_data['salt'] = salt_entry.get()
            password_data['algorithm'] = algorithm_combo.get()
            password_data['notes'] = notes_text.get("1.0", tk.END).strip()
            
            # Update database
            try:
                conn = sqlite3.connect('passwords.db')
                cursor = conn.cursor()
                
                encrypted_password = self.encrypt_data(password_data['password'])
                encrypted_salt = self.encrypt_data(password_data['salt'])
                
                cursor.execute('''UPDATE passwords
                              SET service=?, username=?, password=?, salt=?, algorithm=?, notes=?
                              WHERE id=?''',
                              (password_data['service'],
                               password_data['username'],
                               encrypted_password,
                               encrypted_salt,
                               password_data['algorithm'],
                               password_data['notes'],
                               password_data['id']))
                
                conn.commit()
                conn.close()
                
                self.refresh_password_list()
                dialog.destroy()
                messagebox.showinfo("Success", "Password updated successfully")
            except Exception as e:
                logging.error(f"Error updating password: {str(e)}")
                messagebox.showerror("Error", f"Failed to update password: {str(e)}")
        
        ttk.Button(
            buttons_frame,
            text="Save",
            command=save_changes,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Cancel",
            command=dialog.destroy,
            style='Blue.TButton'
        ).pack(side=tk.LEFT, padx=5)
        
        dialog.columnconfigure(1, weight=1)
    
    def generate_for_edit(self, password_entry):
        """Generate password for edit dialog"""
        # Get current settings
        length = self.password_length.get()
        
        chars = ''
        if self.include_lowercase.get():
            chars += string.ascii_lowercase
        if self.include_uppercase.get():
            chars += string.ascii_uppercase
        if self.include_digits.get():
            chars += string.digits
        if self.include_special.get():
            chars += string.punctuation
        if self.include_spaces.get():
            chars += ' '
        
        if not chars:
            messagebox.showerror("Error", "At least one character set must be selected")
            return
        
        # Generate password
        password = ''.join(secrets.choice(chars) for _ in range(length))
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
    
    def delete_password(self):
        """Delete selected password"""
        selected = self.password_tree.focus()
        if not selected:
            messagebox.showwarning("Warning", "No password selected")
            return
        
        item = self.password_tree.item(selected)
        service = item['values'][0]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Delete password for {service}?"):
            return
        
        # Find the password in saved passwords
        password_data = None
        for pwd in self.saved_passwords:
            if pwd['service'] == service:
                password_data = pwd
                break
        
        if not password_data:
            messagebox.showerror("Error", "Password data not found")
            return
        
        # Delete from database
        try:
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM passwords WHERE id=?", (password_data['id'],))
            
            conn.commit()
            conn.close()
            
            # Remove from list
            self.saved_passwords = [pwd for pwd in self.saved_passwords if pwd['service'] != service]
            self.refresh_password_list()
            
            messagebox.showinfo("Success", "Password deleted successfully")
        except Exception as e:
            logging.error(f"Error deleting password: {str(e)}")
            messagebox.showerror("Error", f"Failed to delete password: {str(e)}")
    
    def search_passwords(self, event=None):
        """Search passwords based on query"""
        query = self.search_var.get().lower()
        
        if not query:
            self.refresh_password_list()
            return
        
        self.password_tree.delete(*self.password_tree.get_children())
        
        for pwd in self.saved_passwords:
            if (query in pwd['service'].lower() or 
                query in pwd['username'].lower() or 
                query in pwd.get('notes', '').lower()):
                
                masked_pwd = self.mask_password(pwd['password'])
                
                self.password_tree.insert('', tk.END, values=(
                    pwd['service'],
                    pwd['username'],
                    masked_pwd,
                    pwd['algorithm'],
                    pwd.get('created_at', 'N/A')
                ))
    
    def export_passwords(self):
        """Export passwords to a file"""
        if not self.saved_passwords:
            messagebox.showwarning("Warning", "No passwords to export")
            return
        
        # Ask for master password if set
        if self.master_password:
            dialog = tk.Toplevel(self.root)
            dialog.title("Enter Master Password")
            dialog.transient(self.root)
            dialog.grab_set()
            
            ttk.Label(dialog, text="Master Password:").pack(padx=10, pady=5)
            
            pw_entry = ttk.Entry(dialog, show="*")
            pw_entry.pack(padx=10, pady=5)
            
            def verify():
                if pw_entry.get() == self.master_password:
                    dialog.destroy()
                    self.perform_export()
                else:
                    messagebox.showerror("Error", "Incorrect master password")
            
            ttk.Button(
                dialog,
                text="Verify",
                command=verify,
                style='Blue.TButton'
            ).pack(padx=10, pady=10)
            
            dialog.wait_window()
        else:
            self.perform_export()
    
    def perform_export(self):
        """Perform the actual export"""
        try:
            # Create export data
            export_data = {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'passwords': []
            }
            
            for pwd in self.saved_passwords:
                export_data['passwords'].append({
                    'service': pwd['service'],
                    'username': pwd['username'],
                    'password': self.encrypt_data(pwd['password']),
                    'salt': self.encrypt_data(pwd['salt']),
                    'algorithm': pwd['algorithm'],
                    'notes': pwd.get('notes', ''),
                    'created_at': pwd.get('created_at', '')
                })
            
            # Ask for file location
            from tkinter import filedialog
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Export passwords to file"
            )
            
            if not file_path:
                return
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Success", f"Passwords exported to {file_path}")
        except Exception as e:
            logging.error(f"Error exporting passwords: {str(e)}")
            messagebox.showerror("Error", f"Failed to export passwords: {str(e)}")
    
    def import_passwords(self):
        """Import passwords from a file"""
        # Ask for master password if set
        if self.master_password:
            dialog = tk.Toplevel(self.root)
            dialog.title("Enter Master Password")
            dialog.transient(self.root)
            dialog.grab_set()
            
            ttk.Label(dialog, text="Master Password:").pack(padx=10, pady=5)
            
            pw_entry = ttk.Entry(dialog, show="*")
            pw_entry.pack(padx=10, pady=5)
            
            def verify():
                if pw_entry.get() == self.master_password:
                    dialog.destroy()
                    self.perform_import()
                else:
                    messagebox.showerror("Error", "Incorrect master password")
            
            ttk.Button(
                dialog,
                text="Verify",
                command=verify,
                style='Blue.TButton'
            ).pack(padx=10, pady=10)
            
            dialog.wait_window()
        else:
            self.perform_import()
    
    def perform_import(self):
        """Perform the actual import"""
        try:
            # Ask for file location
            from tkinter import filedialog
            file_path = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Select password file to import"
            )
            
            if not file_path:
                return
            
            # Read file
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            # Verify version
            if import_data.get('version') != VERSION:
                if not messagebox.askyesno("Warning", "File version differs from current version. Continue?"):
                    return
            
            # Import passwords
            imported = 0
            skipped = 0
            
            for pwd in import_data['passwords']:
                # Check if password already exists
                exists = any(sp['service'] == pwd['service'] and sp['username'] == pwd['username'] 
                          for sp in self.saved_passwords)
                
                if exists:
                    skipped += 1
                    continue
                
                # Decrypt password and salt
                try:
                    decrypted_password = self.decrypt_data(pwd['password'])
                    decrypted_salt = self.decrypt_data(pwd['salt'])
                except:
                    # If decryption fails, assume data is not encrypted
                    decrypted_password = pwd['password']
                    decrypted_salt = pwd['salt']
                
                password_data = {
                    'service': pwd['service'],
                    'username': pwd['username'],
                    'password': decrypted_password,
                    'salt': decrypted_salt,
                    'algorithm': pwd['algorithm'],
                    'notes': pwd.get('notes', ''),
                    'created_at': pwd.get('created_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                }
                
                if self.save_password_to_db(password_data):
                    self.saved_passwords.append(password_data)
                    imported += 1
                else:
                    skipped += 1
            
            self.refresh_password_list()
            messagebox.showinfo("Import Complete", 
                              f"Successfully imported {imported} passwords\nSkipped {skipped} duplicates")
        except Exception as e:
            logging.error(f"Error importing passwords: {str(e)}")
            messagebox.showerror("Error", f"Failed to import passwords: {str(e)}")
    
    def analyze_password(self):
        """Analyze password strength"""
        password = self.analyze_var.get()
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to analyze")
            return
        
        # Calculate strength
        strength = self.calculate_strength(password)
        self.analyzer_meter['value'] = strength
        
        if strength < 40:
            self.analyzer_label.config(text="Weak", foreground='red')
        elif strength < 70:
            self.analyzer_label.config(text="Medium", foreground='orange')
        else:
            self.analyzer_label.config(text="Strong", foreground='green')
        
        # Calculate entropy
        entropy = self.calculate_entropy(password)
        self.analyzer_entropy.config(text=f"Entropy: {entropy:.2f} bits")
        
        # Estimate crack time
        crack_time = self.estimate_crack_time(entropy, len(password))
        self.analyzer_crack_time.config(text=f"Time to crack: {crack_time}")
        
        # Check for common patterns
        patterns = self.check_common_patterns(password)
        self.analyzer_patterns.config(text=f"Common patterns: {', '.join(patterns) if patterns else 'None found'}")
        
        # Detailed analysis
        analysis = self.get_detailed_analysis(password)
        self.analyzer_details.delete('1.0', tk.END)
        self.analyzer_details.insert(tk.END, analysis)
        
        # Update statistics plot
        self.update_stats_plot()
    
    def estimate_crack_time(self, entropy, length):
        """Estimate time to crack password"""
        # Very rough estimates based on entropy and length
        guesses_per_second = 1e9  # 1 billion guesses per second
        
        # Calculate possible combinations
        combinations = 2 ** entropy
        
        # Calculate time in seconds
        seconds = combinations / guesses_per_second
        
        # Convert to human-readable time
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 3153600000:
            return f"{seconds/31536000:.1f} years"
        else:
            return f"{seconds/3153600000:.1f} centuries"
    
    def check_common_patterns(self, password):
        """Check for common password patterns"""
        patterns = []
        lower_pwd = password.lower()
        
        # Common sequences
        common_sequences = [
            '123', '234', '345', '456', '567', '678', '789', '890',
            'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr', 'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
            'qwerty', 'asdfgh', 'zxcvbn', 'password', 'admin', 'welcome', 'letmein', 'monkey', 'sunshine', 'iloveyou', 'football'
        ]
        
        for seq in common_sequences:
            if seq in lower_pwd:
                patterns.append(seq)
        
        # Repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns.append("repeated characters")
        
        # Keyboard patterns
        keyboard_patterns = [
            '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik,', '9ol.', '0p;/',
            'qwer', 'wert', 'erty', 'rtyu', 'tyui', 'yuio', 'uiop', 'asdf', 'sdfg', 'dfgh', 'fghj', 'ghjk', 'hjkl', 'zxcv', 'xcvb', 'cvbn', 'vbnm'
        ]
        
        for pat in keyboard_patterns:
            if pat in lower_pwd:
                patterns.append("keyboard pattern")
                break
        
        return patterns
    
    def get_detailed_analysis(self, password):
        """Generate detailed password analysis"""
        analysis = []
        
        # Length
        length = len(password)
        analysis.append(f"Password Length: {length} characters")
        analysis.append("")
        
        # Character composition
        analysis.append("Character Composition:")
        
        lowercase = sum(1 for c in password if c in string.ascii_lowercase)
        uppercase = sum(1 for c in password if c in string.ascii_uppercase)
        digits = sum(1 for c in password if c in string.digits)
        special = sum(1 for c in password if c in string.punctuation)
        spaces = sum(1 for c in password if c == ' ')
        other = length - (lowercase + uppercase + digits + special + spaces)
        
        analysis.append(f"- Lowercase letters: {lowercase}")
        analysis.append(f"- Uppercase letters: {uppercase}")
        analysis.append(f"- Digits: {digits}")
        analysis.append(f"- Special characters: {special}")
        analysis.append(f"- Spaces: {spaces}")
        if other > 0:
            analysis.append(f"- Other characters: {other}")
        analysis.append("")
        
        # Character distribution
        analysis.append("Character Distribution:")
        char_counts = {}
        for c in password:
            char_counts[c] = char_counts.get(c, 0) + 1
        
        # Top 5 most common characters
        sorted_counts = sorted(char_counts.items(), key=lambda x: x[1], reverse=True)
        analysis.append(f"Most common characters: {', '.join(f'{c} ({count}x)' for c, count in sorted_counts[:5])}")
        
        # Unique characters
        unique_chars = len(char_counts)
        analysis.append(f"Unique characters: {unique_chars} ({unique_chars/length:.1%} of total)")
        analysis.append("")
        
        # Security analysis
        analysis.append("Security Analysis:")
        
        # Entropy
        entropy = self.calculate_entropy(password)
        analysis.append(f"- Entropy: {entropy:.2f} bits")
        
        # Strength
        strength = self.calculate_strength(password)
        analysis.append(f"- Strength score: {strength:.1f}/100")
        
        # Recommendations
        analysis.append("")
        analysis.append("Recommendations:")
        
        if length < 12:
            analysis.append("- Use a longer password (at least 12 characters)")
        if uppercase == 0:
            analysis.append("- Include uppercase letters")
        if lowercase == 0:
            analysis.append("- Include lowercase letters")
        if digits == 0:
            analysis.append("- Include digits")
        if special == 0:
            analysis.append("- Include special characters")
        if entropy < 50:
            analysis.append("- Increase randomness/variety of characters")
        
        return "\n".join(analysis)
    
    def update_stats_plot(self):
        """Update the password statistics plot"""
        # Clear previous plot
        self.ax.clear()
        
        # Get password lengths
        lengths = [len(pwd['password']) for pwd in self.saved_passwords] if self.saved_passwords else [0]
        
        # Create histogram
        self.ax.hist(lengths, bins=range(0, max(lengths + [32]) + 2, 2), color=BLUE_THEME['primary'])
        self.ax.set_title('Password Length Distribution')
        self.ax.set_xlabel('Password Length')
        self.ax.set_ylabel('Frequency')
        
        # Redraw canvas
        self.canvas.draw()
    
    def set_master_password(self):
        """Set or change master password"""
        password = self.master_pw_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Master password cannot be empty")
            return
        
        # Confirm password
        dialog = tk.Toplevel(self.root)
        dialog.title("Confirm Master Password")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Confirm Master Password:").pack(padx=10, pady=5)
        
        confirm_entry = ttk.Entry(dialog, show="*")
        confirm_entry.pack(padx=10, pady=5)
        
        def verify():
            if confirm_entry.get() == password:
                self.master_password = password
                dialog.destroy()
                messagebox.showinfo("Success", "Master password set successfully")
                
                # Hash and store the master password
                salt = secrets.token_hex(16)
                hashed = hashlib.sha256((password + salt).encode()).hexdigest()
                
                try:
                    with open('master.key', 'w') as f:
                        json.dump({'hash': hashed, 'salt': salt}, f)
                except Exception as e:
                    logging.error(f"Error saving master password: {str(e)}")
            else:
                messagebox.showerror("Error", "Passwords do not match")
        
        ttk.Button(
            dialog,
            text="Confirm",
            command=verify,
            style='Blue.TButton'
        ).pack(padx=10, pady=10)
    
    def save_settings(self):
        """Save application settings"""
        try:
            settings = {
                'theme': self.theme_var.get(),
                'autoclear': self.autoclear_var.get(),
                'default_length': self.default_length_var.get(),
                'default_algorithm': self.default_algorithm_var.get(),
                'encryption_enabled': self.encryption_enabled.get()
            }
            
            with open('settings.json', 'w') as f:
                json.dump(settings, f, indent=2)
            
            messagebox.showinfo("Success", "Settings saved successfully")
        except Exception as e:
            logging.error(f"Error saving settings: {str(e)}")
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            self.theme_var.set('blue')
            self.autoclear_var.set(True)
            self.default_length_var.set(16)
            self.default_algorithm_var.set('SHA-256')
            self.encryption_enabled.set(True)
            
            messagebox.showinfo("Success", "Settings reset to defaults")
    
    def backup_data(self):
        """Backup application data"""
        try:
            # Create backup data
            backup = {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'passwords': [],
                'settings': {}
            }
            
            # Add passwords
            for pwd in self.saved_passwords:
                backup['passwords'].append({
                    'service': pwd['service'],
                    'username': pwd['username'],
                    'password': self.encrypt_data(pwd['password']),
                    'salt': self.encrypt_data(pwd['salt']),
                    'algorithm': pwd['algorithm'],
                    'notes': pwd.get('notes', ''),
                    'created_at': pwd.get('created_at', '')
                })
            
            # Add settings
            backup['settings'] = {
                'theme': self.theme_var.get(),
                'autoclear': self.autoclear_var.get(),
                'default_length': self.default_length_var.get(),
                'default_algorithm': self.default_algorithm_var.get(),
                'encryption_enabled': self.encryption_enabled.get()
            }
            
            # Ask for file location
            from tkinter import filedialog
            file_path = filedialog.asksaveasfilename(
                defaultextension=".backup",
                filetypes=[("Backup files", "*.backup"), ("All files", "*.*")],
                title="Backup data to file"
            )
            
            if not file_path:
                return
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(backup, f, indent=2)
            
            messagebox.showinfo("Success", f"Backup created at {file_path}")
        except Exception as e:
            logging.error(f"Error creating backup: {str(e)}")
            messagebox.showerror("Error", f"Failed to create backup: {str(e)}")
    
    def restore_data(self):
        """Restore application data from backup"""
        # Ask for master password if set
        if self.master_password:
            dialog = tk.Toplevel(self.root)
            dialog.title("Enter Master Password")
            dialog.transient(self.root)
            dialog.grab_set()
            
            ttk.Label(dialog, text="Master Password:").pack(padx=10, pady=5)
            
            pw_entry = ttk.Entry(dialog, show="*")
            pw_entry.pack(padx=10, pady=5)
            
            def verify():
                if pw_entry.get() == self.master_password:
                    dialog.destroy()
                    self.perform_restore()
                else:
                    messagebox.showerror("Error", "Incorrect master password")
            
            ttk.Button(
                dialog,
                text="Verify",
                command=verify,
                style='Blue.TButton'
            ).pack(padx=10, pady=10)
            
            dialog.wait_window()
        else:
            self.perform_restore()
    
    def perform_restore(self):
        """Perform the actual restore"""
        try:
            # Ask for file location
            from tkinter import filedialog
            file_path = filedialog.askopenfilename(
                filetypes=[("Backup files", "*.backup"), ("All files", "*.*")],
                title="Select backup file to restore"
            )
            
            if not file_path:
                return
            
            # Read file
            with open(file_path, 'r') as f:
                backup = json.load(f)
            
            # Verify version
            if backup.get('version') != VERSION:
                if not messagebox.askyesno("Warning", "Backup version differs from current version. Continue?"):
                    return
            
            # Confirm restore
            if not messagebox.askyesno("Confirm", "This will overwrite all current data. Continue?"):
                return
            
            # Restore passwords
            self.saved_passwords = []
            
            conn = sqlite3.connect('passwords.db')
            cursor = conn.cursor()
            
            # Clear existing passwords
            cursor.execute("DELETE FROM passwords")
            
            # Add passwords from backup
            for pwd in backup.get('passwords', []):
                # Decrypt password and salt
                try:
                    decrypted_password = self.decrypt_data(pwd['password'])
                    decrypted_salt = self.decrypt_data(pwd['salt'])
                except:
                    # If decryption fails, assume data is not encrypted
                    decrypted_password = pwd['password']
                    decrypted_salt = pwd['salt']
                
                password_data = {
                    'service': pwd['service'],
                    'username': pwd['username'],
                    'password': decrypted_password,
                    'salt': decrypted_salt,
                    'algorithm': pwd['algorithm'],
                    'notes': pwd.get('notes', ''),
                    'created_at': pwd.get('created_at', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                }
                
                # Save to database
                encrypted_password = self.encrypt_data(password_data['password'])
                encrypted_salt = self.encrypt_data(password_data['salt'])
                
                cursor.execute('''INSERT INTO passwords
                              (service, username, password, salt, algorithm, notes, created_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?)''',
                              (password_data['service'],
                               password_data['username'],
                               encrypted_password,
                               encrypted_salt,
                               password_data['algorithm'],
                               password_data['notes'],
                               password_data['created_at']))
                
                # Add to list
                self.saved_passwords.append(password_data)
            
            conn.commit()
            conn.close()
            
            # Restore settings
            settings = backup.get('settings', {})
            self.theme_var.set(settings.get('theme', 'blue'))
            self.autoclear_var.set(settings.get('autoclear', True))
            self.default_length_var.set(settings.get('default_length', 16))
            self.default_algorithm_var.set(settings.get('default_algorithm', 'SHA-256'))
            self.encryption_enabled.set(settings.get('encryption_enabled', True))
            
            # Refresh UI
            self.refresh_password_list()
            
            messagebox.showinfo("Success", "Data restored successfully")
        except Exception as e:
            logging.error(f"Error restoring data: {str(e)}")
            messagebox.showerror("Error", f"Failed to restore data: {str(e)}")
    
    def check_for_updates(self):
        """Check for application updates"""
        # Placeholder for actual update check
        messagebox.showinfo("Update Check", "You have the latest version")
    
    def view_license(self):
        """Show license information"""
        license_text = """Advanced Password Guardian - License Agreement

1. This software is provided "as is" without warranty of any kind.
2. You may use this software for personal or commercial purposes.
3. You may not redistribute this software without permission.
4. The developers are not responsible for any data loss or security breaches.
5. Use this software at your own risk.

© 2023 CyberSec Solutions. All rights reserved."""
        
        dialog = tk.Toplevel(self.root)
        dialog.title("License Agreement")
        dialog.transient(self.root)
        dialog.grab_set()
        
        text = scrolledtext.ScrolledText(dialog, width=60, height=15, wrap=tk.WORD)
        text.insert(tk.END, license_text)
        text.config(state='disabled')
        text.pack(padx=10, pady=10)
        
        ttk.Button(
            dialog,
            text="Close",
            command=dialog.destroy,
            style='Blue.TButton'
        ).pack(pady=10)
    
    def view_documentation(self):
        """Open documentation in browser"""
        webbrowser.open("https://github.com/cybersecsolutions/password-guardian/wiki")
    
    def show_menu(self):
        """Show application menu"""
        menu = tk.Menu(self.root, tearoff=0)
        
        menu.add_command(label="Generate Password", command=lambda: self.notebook.select(self.pwgen_frame))
        menu.add_command(label="Password Manager", command=lambda: self.notebook.select(self.pwman_frame))
        menu.add_command(label="Security Analyzer", command=lambda: self.notebook.select(self.analyzer_frame))
        menu.add_command(label="Settings", command=lambda: self.notebook.select(self.settings_frame))
        menu.add_separator()
        menu.add_command(label="Exit", command=self.on_exit)
        
        try:
            menu.tk_popup(self.menu_button.winfo_rootx(), 
                         self.menu_button.winfo_rooty() + self.menu_button.winfo_height())
        finally:
            menu.grab_release()
    
    def perform_security_check(self):
        """Perform initial security checks"""
        # Check if master password file exists but no master password is set
        if os.path.exists('master.key') and not self.master_password:
            try:
                with open('master.key', 'r') as f:
                    data = json.load(f)
                
                # Ask for master password
                dialog = tk.Toplevel(self.root)
                dialog.title("Enter Master Password")
                dialog.transient(self.root)
                dialog.grab_set()
                
                ttk.Label(dialog, text="Master Password:").pack(padx=10, pady=5)
                
                pw_entry = ttk.Entry(dialog, show="*")
                pw_entry.pack(padx=10, pady=5)
                
                def verify():
                    # Verify password
                    salt = data['salt']
                    hashed = hashlib.sha256((pw_entry.get() + salt).encode()).hexdigest()
                    
                    if hashed == data['hash']:
                        self.master_password = pw_entry.get()
                        dialog.destroy()
                    else:
                        messagebox.showerror("Error", "Incorrect master password")
                
                ttk.Button(
                    dialog,
                    text="Verify",
                    command=verify,
                    style='Blue.TButton'
                ).pack(padx=10, pady=10)
                
                dialog.wait_window()
            except Exception as e:
                logging.error(f"Error loading master password: {str(e)}")
        
        # Check for weak default settings
        if self.password_length.get() < 12:
            self.status_label.config(text="Warning: Default password length is less than 12 characters", foreground='orange')
    
    def on_exit(self):
        """Handle application exit"""
        if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
            # Clear clipboard if enabled
            if self.autoclear_var.get():
                self.clear_clipboard()
            
            self.root.destroy()

# Main application
if __name__ == "__main__":
    import math
    import re
    
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()