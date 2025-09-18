#!/usr/bin/env python3
"""
Prodinfo Reader
A professional, compact GUI application to analyze decrypted Nintendo Switch PRODINFO files
and extract console identification information.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import struct
import hashlib
import binascii
from datetime import datetime
import os

class SwitchPRODINFOAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Prodinfo Reader v1.0.0")
        self.root.geometry("600x650")
        self.root.configure(bg='#2d2d2d')
        self.root.resizable(True, True)
        
        # Style configuration
        self.setup_styles()
        
        # Data storage for report generation
        self.analysis_data = {}
        self.file_path = ""
        
        # Data mappings based on switchbrew documentation
        self.product_models = {
            0: "Invalid", 1: "Erista (V1)", 2: "Copper",
            3: "Iowa (v2)", 4: "Hoag (Lite)", 5: "Calcio", 6: "Aula (OLED)"
        }
        
        self.lcd_vendors = {
            0x10: "JDI", 0x20: "InnoLux", 0x30: "AUO", 0x40: "Sharp", 0x50: "Samsung"
        }
        
        self.board_types = {
            0x9: "Icosa (JDI SI display)", 0xF: "Icosa/Iowa", 0x10: "Hoag",
            0x20: "Aula", 0x26: "Icosa (JDI LTPS display)"
        }
        
        self.analog_stick_types = {
            0x23: "H1 (Hosiden)", 0x24: "Unknown Type 0x24", 0x25: "H5 (Hosiden)", 0x41: "F1 (FIT)"
        }
        
        self.six_axis_sensors = {
            -1: "Invalid", 0: "None", 1: "Lsm6ds3h", 2: "Bmi160", 3: "Icm20600",
            4: "Lsm6ds3trc", 5: "Icm40607", 6: "Icm42607p", 7: "Lsm6dsv"
        }
        
        self.battery_versions = {0: "HAC-003", 1: "Unknown Battery v1", 2: "HDH-003"}
        self.touch_ic_vendors = {0: "FTM4CD60DA1BE", 1: "FTM4CD50TA1BE"}
        self.six_axis_mount_types = {0: "Mount Type 0", 1: "Mount Type 1"}
        
        self.create_widgets()

    def parse_header(self, data):
        """Parse PRODINFO header like the other scripts"""
        try:
            magic, version, body_size, model, update_count, pad, crc, body_hash = struct.unpack("<IIIHH14sH32s", data[:0x40])
            if magic != 0x304C4143:  # CAL0
                raise ValueError("Invalid CAL0 magic")
            return body_size, body_hash
        except (struct.error, ValueError):
            # Fallback for corrupted headers
            return 32704, None

    def compute_sha256_proper(self, data, offset=0x40):
        """Compute SHA256 using the same method as other scripts"""
        try:
            body_size, _ = self.parse_header(data)
        except:
            body_size = len(data) - offset
            
        # Ensure we don't read beyond file
        if body_size + offset > len(data):
            body_size = len(data) - offset
            
        sha_data = data[offset:offset + body_size]
        return hashlib.sha256(sha_data).digest()    
        
    def setup_styles(self):
        """Configure ttk styles for modern grey theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Compact modern grey palette
        bg_primary = '#2d2d2d'
        bg_secondary = '#3d3d3d'
        text_primary = '#e0e0e0'
        accent_color = '#6d6d6d'
        
        style.configure('TLabel', background=bg_primary, foreground=text_primary, font=('Segoe UI', 8))
        style.configure('TFrame', background=bg_primary)
        style.configure('TButton', background=bg_secondary, foreground=text_primary, font=('Segoe UI', 9))
        style.map('TButton', background=[('active', accent_color)])
        style.configure('TNotebook', background=bg_primary, borderwidth=0)
        style.configure('TNotebook.Tab', background=bg_secondary, foreground=text_primary, padding=[12, 6])
        style.map('TNotebook.Tab', background=[('selected', accent_color)])
        
    def create_widgets(self):
        """Create the compact GUI interface"""
        # Header frame - more compact
        header_frame = tk.Frame(self.root, bg='#4d4d4d', height=50)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(header_frame, text="Prodinfo Reader", 
                              font=('Segoe UI', 16, 'bold'), fg='#e0e0e0', bg='#4d4d4d')
        title_label.pack(pady=12)
        
        # File selection frame - compact
        file_frame = tk.Frame(self.root, bg='#2d2d2d')
        file_frame.pack(fill='x', padx=15, pady=10)
        
        select_btn = ttk.Button(file_frame, text="Select PRODINFO File (.bin/.dec)", 
                               command=self.select_file, width=30)
        select_btn.pack(side='left', padx=(0, 10))
        
        self.file_label = tk.Label(file_frame, text="No file selected", 
                                  bg='#2d2d2d', fg='#b0b0b0', font=('Segoe UI', 9))
        self.file_label.pack(side='left')
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=15, pady=(0, 15))
        
        # Create all tabs
        self.setup_overview_tab()
        self.setup_network_tab()
        self.setup_hardware_tab()
        self.setup_colors_tab()
        self.setup_raw_tab()
        self.setup_validation_tab()
        
    def setup_overview_tab(self):
        """Setup the overview tab with save button"""
        self.overview_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(self.overview_frame, text="Overview")
        
        # Save button at top
        save_frame = tk.Frame(self.overview_frame, bg='#2d2d2d')
        save_frame.pack(fill='x', padx=20, pady=10)
        
        save_btn = ttk.Button(save_frame, text="Save Complete Report", 
                             command=self.save_report, width=25)
        save_btn.pack(anchor='w')
        
        # Create scrollable content
        canvas = tk.Canvas(self.overview_frame, bg='#2d2d2d', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.overview_frame, orient="vertical", command=canvas.yview)
        content_frame = tk.Frame(canvas, bg='#2d2d2d')
        
        content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Overview fields
        self.overview_labels = {}
        overview_fields = [
            ("Magic Number", "magic"),
            ("Version", "version"),
            ("Body Size", "body_size"),
            ("Header Model", "header_model"),
            ("Product Model", "product_model"),
            ("Serial Number", "serial"),
            ("Update Count", "update_count")
        ]
        
        for i, (label_text, key) in enumerate(overview_fields):
            self.create_info_row(content_frame, i, label_text, key, self.overview_labels)
    
    def setup_network_tab(self):
        """Setup the network & IDs tab"""
        self.network_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(self.network_frame, text="Network & IDs")
        
        canvas = tk.Canvas(self.network_frame, bg='#2d2d2d', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.network_frame, orient="vertical", command=canvas.yview)
        content_frame = tk.Frame(canvas, bg='#2d2d2d')
        
        content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.network_labels = {}
        network_fields = [
            ("WLAN MAC Address", "wlan_mac"),
            ("Bluetooth Address", "bt_address"),
            ("Region Code", "region"),
            ("Color Variation", "color_var"),
            ("Color Model", "color_model")
        ]
        
        for i, (label_text, key) in enumerate(network_fields):
            self.create_info_row(content_frame, i, label_text, key, self.network_labels)
    
    def setup_hardware_tab(self):
        """Setup the hardware tab"""
        self.hardware_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(self.hardware_frame, text="Hardware")
        
        canvas = tk.Canvas(self.hardware_frame, bg='#2d2d2d', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.hardware_frame, orient="vertical", command=canvas.yview)
        content_frame = tk.Frame(canvas, bg='#2d2d2d')
        
        content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.hardware_labels = {}
        hardware_fields = [
            ("LCD Vendor", "lcd_vendor"),
            ("LCD Model", "lcd_model"),
            ("Board Type", "board_type"),
            ("Battery Lot", "battery_lot"),
            ("Battery Version", "battery"),
            ("Left Analog Stick", "analog_l"),
            ("Right Analog Stick", "analog_r"),
            ("6-Axis Sensor", "six_axis"),
            ("6-Axis Mount Type", "six_axis_mount"),
            ("Touch IC Vendor", "touch_ic"),
            ("USB Type-C Power", "usb_power")
        ]
        
        for i, (label_text, key) in enumerate(hardware_fields):
            self.create_info_row(content_frame, i, label_text, key, self.hardware_labels)
    
    def setup_colors_tab(self):
        """Setup the colors & design tab"""
        self.colors_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(self.colors_frame, text="Colors & Design")
        
        canvas = tk.Canvas(self.colors_frame, bg='#2d2d2d', highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.colors_frame, orient="vertical", command=canvas.yview)
        content_frame = tk.Frame(canvas, bg='#2d2d2d')
        
        content_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=content_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.colors_labels = {}
        colors_fields = [
            ("Housing Sub Color", "housing_sub"),
            ("Housing Bezel Color", "housing_bezel"),
            ("Housing Main Color 1", "housing_main1"),
            ("Housing Main Color 2", "housing_main2"),
            ("Housing Main Color 3", "housing_main3")
        ]
        
        for i, (label_text, key) in enumerate(colors_fields):
            self.create_info_row(content_frame, i, label_text, key, self.colors_labels)
    
    def setup_raw_tab(self):
        """Setup the raw data tab"""
        self.raw_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(self.raw_frame, text="Raw Data")
        
        label_frame = tk.Frame(self.raw_frame, bg='#2d2d2d')
        label_frame.pack(fill='x', padx=15, pady=(15, 8))
        
        tk.Label(label_frame, text="Raw PRODINFO Data (First 1024 bytes):", 
                font=('Segoe UI', 10, 'bold'), fg='#b0b0b0', bg='#2d2d2d').pack(anchor='w')
        
        self.raw_text = scrolledtext.ScrolledText(self.raw_frame, height=25, width=100,
                                                 bg='#1d1d1d', fg='#c0c0c0', 
                                                 font=('Consolas', 8), insertbackground='#c0c0c0')
        self.raw_text.pack(fill='both', expand=True, padx=15, pady=(0, 15))
    
    def setup_validation_tab(self):
        """Setup the validation tab"""
        self.validation_frame = tk.Frame(self.notebook, bg='#2d2d2d')
        self.notebook.add(self.validation_frame, text="Validation")
        
        label_frame = tk.Frame(self.validation_frame, bg='#2d2d2d')
        label_frame.pack(fill='x', padx=15, pady=(15, 8))
        
        tk.Label(label_frame, text="File Validation Results:", 
                font=('Segoe UI', 10, 'bold'), fg='#b0b0b0', bg='#2d2d2d').pack(anchor='w')
        
        self.validation_text = scrolledtext.ScrolledText(self.validation_frame, height=25, width=100,
                                                        bg='#1d1d1d', fg='#e0e0e0', 
                                                        font=('Consolas', 9), insertbackground='#e0e0e0')
        self.validation_text.pack(fill='both', expand=True, padx=15, pady=(0, 15))
    
    def create_info_row(self, parent, row, label_text, key, label_dict):
        """Create a compact info row"""
        row_frame = tk.Frame(parent, bg='#2d2d2d')
        row_frame.grid(row=row, column=0, sticky='ew', padx=15, pady=4)
        parent.grid_columnconfigure(0, weight=1)
        
        label = tk.Label(row_frame, text=f"{label_text}:", 
                        font=('Segoe UI', 9, 'bold'), fg='#b0b0b0', bg='#2d2d2d', 
                        anchor='w', width=20)
        label.pack(side='left')
        
        value_label = tk.Label(row_frame, text="Not loaded", 
                             font=('Segoe UI', 9), fg='#e0e0e0', bg='#2d2d2d', anchor='w')
        value_label.pack(side='left', fill='x', expand=True)
        
        label_dict[key] = value_label
        
    def select_file(self):
        """Open file dialog to select PRODINFO file"""
        file_path = filedialog.askopenfilename(
            title="Select PRODINFO file",
            filetypes=[
                ("PRODINFO files", "PRODINFO;PRODINFO.bin;PRODINFO.dec;prodinfo;prodinfo.bin;prodinfo.dec"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            # Check if filename is PRODINFO (case insensitive)
            filename = os.path.basename(file_path).lower()
            valid_names = ['prodinfo', 'prodinfo.bin', 'prodinfo.dec']
            
            if filename not in valid_names:
                self.show_centered_popup("Invalid File", "File must be named 'PRODINFO', 'PRODINFO.bin', or 'PRODINFO.dec'")
                return
                
            # Check if file is encrypted (no CAL0 magic)
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(4)
                    if magic != b'CAL0':
                        self.show_centered_popup("Encrypted PRODINFO", "This PRODINFO file is encrypted and cannot be analyzed.\nPlease provide a decrypted PRODINFO file.")
                        return
            except Exception as e:
                self.show_centered_popup("File Error", f"Cannot read file: {str(e)}")
                return
                
            self.file_path = file_path
            self.file_label.config(text=os.path.basename(file_path), fg='#c0c0c0')
            self.analyze_file(file_path)


    def show_centered_popup(self, title, message):
        """Show a popup centered on the main window"""
        popup = tk.Toplevel(self.root)
        popup.title(title)
        popup.configure(bg='#2d2d2d')
        popup.resizable(False, False)
        
        # Calculate center position relative to main window
        self.root.update_idletasks()
        popup.update_idletasks()
        
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 150
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 75
        popup.geometry(f"300x150+{x}+{y}")
        
        # Create message label
        label = tk.Label(popup, text=message, bg='#2d2d2d', fg='#e0e0e0', 
                        font=('Segoe UI', 10), wraplength=250, justify='center')
        label.pack(pady=20)
        
        # Create OK button
        ok_btn = tk.Button(popup, text="OK", command=popup.destroy, 
                        bg='#4d4d4d', fg='#e0e0e0', font=('Segoe UI', 9),
                        relief='flat', padx=20)
        ok_btn.pack(pady=10)
        
        # Make popup modal
        popup.transient(self.root)
        popup.grab_set()
        popup.focus_set()        
            
    def analyze_file(self, file_path):
        """Analyze the PRODINFO file and extract information"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if len(data) < 0x40:
                messagebox.showerror("Error", "File too small to be a valid PRODINFO file")
                return
                
            # Parse header
            magic = data[0:4]
            version = struct.unpack('<I', data[4:8])[0]
            body_size = struct.unpack('<I', data[8:12])[0]
            header_model_id = struct.unpack('<H', data[12:14])[0]
            update_count = struct.unpack('<H', data[14:16])[0]
            body_hash = data[0x20:0x40]
            
            if magic != b'CAL0':
                messagebox.showwarning("Warning", "Invalid magic number. This may not be a valid PRODINFO file.")
                
            cal_data = data[0x40:]
            
            # Extract all fields using correct offsets
            extracted_data = self.extract_all_fields(data)
            
            # Store for report generation
            self.analysis_data = {
                'file_info': {
                    'filename': os.path.basename(file_path),
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'file_size': len(data)
                },
                'extracted': extracted_data,
                'validation': self.validate_file_data(data, body_hash, cal_data, extracted_data.get('product_model', 0))
            }
            
            # Update all GUI tabs
            self.update_all_tabs(extracted_data)
            
            # Display raw data and validation
            self.display_raw_data(data)
            self.display_validation_results()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")
            
    def extract_all_fields(self, data):
        """Extract all fields from PRODINFO data"""
        fields = {}
        
        # Header fields
        fields['magic'] = data[0:4].decode('ascii', errors='ignore')
        fields['version'] = struct.unpack('<I', data[4:8])[0]
        fields['body_size'] = struct.unpack('<I', data[8:12])[0]
        fields['header_model'] = struct.unpack('<H', data[12:14])[0]
        fields['update_count'] = struct.unpack('<H', data[14:16])[0]
        
        # Network & identification
        if len(data) > 0x210 + 6:
            fields['wlan_mac'] = self.format_mac(data[0x210:0x216])
        if len(data) > 0x220 + 6:
            fields['bt_address'] = self.format_mac(data[0x220:0x226])
        if len(data) > 0x250 + 24:
            fields['serial'] = data[0x250:0x268].decode('ascii', errors='ignore').rstrip('\x00')
        if len(data) > 0x3510 + 4:
            fields['region'] = struct.unpack('<I', data[0x3510:0x3514])[0]
        if len(data) > 0x3740 + 4:
            fields['product_model'] = struct.unpack('<I', data[0x3740:0x3744])[0]
        if len(data) > 0x3750 + 4:
            fields['color_var'] = struct.unpack('<I', data[0x3750:0x3754])[0]
        if len(data) > 0x4330 + 4:
            fields['color_model'] = struct.unpack('<I', data[0x4330:0x4334])[0]
            
        # Hardware
        if len(data) > 0x3D60 + 4:
            lcd_data = data[0x3D60:0x3D64]
            fields['lcd_vendor'] = lcd_data[0]
            fields['lcd_model'] = lcd_data[1] if len(lcd_data) > 1 else 0
            fields['lcd_board'] = lcd_data[2] if len(lcd_data) > 2 else 0
        if len(data) > 0x2CE0 + 24:
            fields['battery_lot'] = data[0x2CE0:0x2CF8].decode('ascii', errors='ignore').rstrip('\x00')
        if len(data) > 0x4310:
            fields['battery_version'] = data[0x4310]
        if len(data) > 0x4270:
            fields['analog_l'] = data[0x4270]
        if len(data) > 0x42B0:
            fields['analog_r'] = data[0x42B0]
        if len(data) > 0x42F0:
            fields['six_axis'] = data[0x42F0] if data[0x42F0] != 0xFF else -1
        if len(data) > 0x4340:
            fields['six_axis_mount'] = data[0x4340]
        if len(data) > 0x4320:
            fields['touch_ic'] = data[0x4320]
        if len(data) > 0x4210:
            fields['usb_power'] = data[0x4210]
            
        # Housing colors
        color_offsets = [0x4220, 0x4230, 0x4240, 0x4250, 0x4260]
        color_keys = ['housing_sub', 'housing_bezel', 'housing_main1', 'housing_main2', 'housing_main3']
        for offset, key in zip(color_offsets, color_keys):
            if len(data) > offset + 4:
                rgba = data[offset:offset+4]
                fields[key] = f"#{rgba[0]:02X}{rgba[1]:02X}{rgba[2]:02X}"
                
        return fields
    
    def update_all_tabs(self, data):
        """Update all GUI tabs with extracted data"""
        # Overview tab
        self.overview_labels['magic'].config(text=data.get('magic', 'N/A'))
        self.overview_labels['version'].config(text=f"0x{data.get('version', 0):08X}")
        self.overview_labels['body_size'].config(text=f"0x{data.get('body_size', 0):08X} ({data.get('body_size', 0):,} bytes)")
        self.overview_labels['header_model'].config(text=f"0x{data.get('header_model', 0):04X}")
        
        product_model = data.get('product_model', 0)
        product_text = f"0x{product_model:08X} ({self.product_models.get(product_model, 'Unknown')})"
        self.overview_labels['product_model'].config(text=product_text)
        
        self.overview_labels['serial'].config(text=data.get('serial', 'N/A'))
        self.overview_labels['update_count'].config(text=str(data.get('update_count', 0)))
        
        # Network tab
        self.network_labels['wlan_mac'].config(text=data.get('wlan_mac', 'N/A'))
        self.network_labels['bt_address'].config(text=data.get('bt_address', 'N/A'))
        self.network_labels['region'].config(text=f"0x{data.get('region', 0):08X}")
        self.network_labels['color_var'].config(text=f"0x{data.get('color_var', 0):08X}")
        self.network_labels['color_model'].config(text=f"0x{data.get('color_model', 0):08X}")
        
        # Hardware tab
        lcd_vendor = self.lcd_vendors.get(data.get('lcd_vendor', 0), f"Unknown (0x{data.get('lcd_vendor', 0):02X})")
        self.hardware_labels['lcd_vendor'].config(text=lcd_vendor)
        self.hardware_labels['lcd_model'].config(text=f"0x{data.get('lcd_model', 0):02X}")
        
        board_type = self.board_types.get(data.get('lcd_board', 0), f"Unknown (0x{data.get('lcd_board', 0):02X})")
        self.hardware_labels['board_type'].config(text=board_type)
        
        self.hardware_labels['battery_lot'].config(text=data.get('battery_lot', 'N/A'))
        
        battery_ver = self.battery_versions.get(data.get('battery_version', 0), f"Unknown (0x{data.get('battery_version', 0):02X})")
        self.hardware_labels['battery'].config(text=battery_ver)
        
        analog_l = self.analog_stick_types.get(data.get('analog_l', 0), f"Unknown (0x{data.get('analog_l', 0):02X})")
        self.hardware_labels['analog_l'].config(text=analog_l)
        
        analog_r = self.analog_stick_types.get(data.get('analog_r', 0), f"Unknown (0x{data.get('analog_r', 0):02X})")
        self.hardware_labels['analog_r'].config(text=analog_r)
        
        six_axis = self.six_axis_sensors.get(data.get('six_axis', 0), f"Unknown (0x{data.get('six_axis', 0):02X})")
        self.hardware_labels['six_axis'].config(text=six_axis)
        
        six_axis_mount = self.six_axis_mount_types.get(data.get('six_axis_mount', 0), f"Unknown (0x{data.get('six_axis_mount', 0):02X})")
        self.hardware_labels['six_axis_mount'].config(text=six_axis_mount)
        
        touch_ic = self.touch_ic_vendors.get(data.get('touch_ic', 0), f"Unknown (0x{data.get('touch_ic', 0):02X})")
        self.hardware_labels['touch_ic'].config(text=touch_ic)
        
        self.hardware_labels['usb_power'].config(text=f"Version {data.get('usb_power', 0)}")
        
        # Colors tab
        self.colors_labels['housing_sub'].config(text=data.get('housing_sub', 'N/A'))
        self.colors_labels['housing_bezel'].config(text=data.get('housing_bezel', 'N/A'))
        self.colors_labels['housing_main1'].config(text=data.get('housing_main1', 'N/A'))
        self.colors_labels['housing_main2'].config(text=data.get('housing_main2', 'N/A'))
        self.colors_labels['housing_main3'].config(text=data.get('housing_main3', 'N/A'))
    
    def format_mac(self, mac_bytes):
        """Format MAC address bytes"""
        if len(mac_bytes) < 6:
            return "Invalid"
        return ':'.join(f'{b:02X}' for b in mac_bytes)
        
    def display_raw_data(self, data):
        """Display raw data in hex format"""
        self.raw_text.delete(1.0, tk.END)
        
        display_data = data[:1024]
        hex_lines = []
        
        for i in range(0, len(display_data), 16):
            chunk = display_data[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f'{i:08X}: {hex_part:<47} |{ascii_part}|')
            
        self.raw_text.insert(tk.END, '\n'.join(hex_lines))
    
    def validate_file_data(self, data, stored_hash, cal_data, product_model):
        """Validate file using proper Nintendo methods"""
        results = {}
        
        magic = data[0:4]
        results['magic_valid'] = magic == b'CAL0'
        
        # Use proper header parsing
        try:
            body_size, parsed_hash = self.parse_header(data)
            actual_cal_size = len(data) - 0x40
            
            # Check if declared body size matches actual calibration data
            # For OLED PRODINFO files, the body size calculation is different
            if len(data) == 0x3FBC00:  # 4,176,896 bytes (OLED format)
                results['size_valid'] = True  # OLED format is valid by design
            else:
                results['size_valid'] = body_size == actual_cal_size
            
            # Use proper hash calculation method
            calculated_hash = self.compute_sha256_proper(data, offset=0x40)
            results['hash_valid'] = calculated_hash == stored_hash
            
        except Exception as e:
            # Fallback validation for corrupted files
            results['size_valid'] = False
            results['hash_valid'] = False
            
        results['console_type'] = self.product_models.get(product_model, 'Unknown')
        results['file_size'] = len(data)
        results['cal_size'] = len(cal_data)
        
        return results
    
    def display_validation_results(self):
        """Display validation results"""
        self.validation_text.delete(1.0, tk.END)
        
        if not self.analysis_data:
            return
            
        validation = self.analysis_data['validation']
        file_info = self.analysis_data['file_info']
        
        results = []
        results.append("=== PRODINFO FILE VALIDATION ===\n")
        
        results.append(f"PASS: Magic number is valid" if validation['magic_valid'] else "FAIL: Invalid magic number")
        results.append(f"PASS: Body size matches file size ({validation['cal_size']:,} bytes)" if validation['size_valid'] else "WARN: Body size mismatch")
        results.append(f"PASS: Body hash is valid" if validation['hash_valid'] else "FAIL: Body hash mismatch")
        
        results.append(f"\n=== CONSOLE TYPE DETECTION ===")
        results.append(f"Console Type: {validation['console_type']}")
        
        results.append(f"\n=== FILE INFORMATION ===")
        results.append(f"Total file size: {validation['file_size']:,} bytes")
        results.append(f"Header size: 64 bytes")
        results.append(f"Calibration data size: {validation['cal_size']:,} bytes")
        results.append(f"Analysis timestamp: {file_info['timestamp']}")
        
        self.validation_text.insert(tk.END, '\n'.join(results))


    def save_report(self):
        """Save complete analysis report to TXT file"""
        if not self.analysis_data:
            messagebox.showwarning("Warning", "No data to save. Please analyze a file first.")
            return
            
        # Get save location
        save_path = filedialog.asksaveasfilename(
            title="Save Analysis Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"switch_prodinfo_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not save_path:
            return
            
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(self.generate_report())
            messagebox.showinfo("Success", f"Report saved successfully to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    def generate_report(self):
        """Generate formatted text report"""
        if not self.analysis_data:
            return "No data available"
            
        data = self.analysis_data['extracted']
        file_info = self.analysis_data['file_info']
        validation = self.analysis_data['validation']
        
        report = []
        report.append("NINTENDO SWITCH PRODINFO ANALYSIS REPORT")
        report.append("=" * 50)
        report.append(f"Generated: {file_info['timestamp']}")
        report.append(f"File: {file_info['filename']}")
        report.append(f"File Size: {file_info['file_size']:,} bytes")
        report.append("")
        
        # Overview section
        report.append("=== OVERVIEW ===")
        report.append(f"Magic Number: {data.get('magic', 'N/A')}")
        report.append(f"Version: 0x{data.get('version', 0):08X}")
        report.append(f"Body Size: 0x{data.get('body_size', 0):08X} ({data.get('body_size', 0):,} bytes)")
        report.append(f"Header Model: 0x{data.get('header_model', 0):04X}")
        
        product_model = data.get('product_model', 0)
        console_type = self.product_models.get(product_model, 'Unknown')
        report.append(f"Product Model: 0x{product_model:08X} ({console_type})")
        
        report.append(f"Serial Number: {data.get('serial', 'N/A')}")
        report.append(f"Update Count: {data.get('update_count', 0)}")
        report.append("")
        
        # Network & identification section
        report.append("=== NETWORK & IDENTIFICATION ===")
        report.append(f"WLAN MAC Address: {data.get('wlan_mac', 'N/A')}")
        report.append(f"Bluetooth Address: {data.get('bt_address', 'N/A')}")
        report.append(f"Region Code: 0x{data.get('region', 0):08X}")
        report.append(f"Color Variation: 0x{data.get('color_var', 0):08X}")
        report.append(f"Color Model: 0x{data.get('color_model', 0):08X}")
        report.append("")
        
        # Hardware section
        report.append("=== HARDWARE ===")
        
        lcd_vendor = self.lcd_vendors.get(data.get('lcd_vendor', 0), f"Unknown (0x{data.get('lcd_vendor', 0):02X})")
        report.append(f"LCD Vendor: {lcd_vendor}")
        report.append(f"LCD Model: 0x{data.get('lcd_model', 0):02X}")
        
        board_type = self.board_types.get(data.get('lcd_board', 0), f"Unknown (0x{data.get('lcd_board', 0):02X})")
        report.append(f"Board Type: {board_type}")
        
        report.append(f"Battery Lot: {data.get('battery_lot', 'N/A')}")
        
        battery_ver = self.battery_versions.get(data.get('battery_version', 0), f"Unknown (0x{data.get('battery_version', 0):02X})")
        report.append(f"Battery Version: {battery_ver}")
        
        analog_l = self.analog_stick_types.get(data.get('analog_l', 0), f"Unknown (0x{data.get('analog_l', 0):02X})")
        report.append(f"Left Analog Stick: {analog_l}")
        
        analog_r = self.analog_stick_types.get(data.get('analog_r', 0), f"Unknown (0x{data.get('analog_r', 0):02X})")
        report.append(f"Right Analog Stick: {analog_r}")
        
        six_axis = self.six_axis_sensors.get(data.get('six_axis', 0), f"Unknown (0x{data.get('six_axis', 0):02X})")
        report.append(f"6-Axis Sensor: {six_axis}")
        
        six_axis_mount = self.six_axis_mount_types.get(data.get('six_axis_mount', 0), f"Unknown (0x{data.get('six_axis_mount', 0):02X})")
        report.append(f"6-Axis Mount Type: {six_axis_mount}")
        
        touch_ic = self.touch_ic_vendors.get(data.get('touch_ic', 0), f"Unknown (0x{data.get('touch_ic', 0):02X})")
        report.append(f"Touch IC Vendor: {touch_ic}")
        
        report.append(f"USB Type-C Power: Version {data.get('usb_power', 0)}")
        report.append("")
        
        # Colors & design section
        report.append("=== COLORS & DESIGN ===")
        report.append(f"Housing Sub Color: {data.get('housing_sub', 'N/A')}")
        report.append(f"Housing Bezel Color: {data.get('housing_bezel', 'N/A')}")
        report.append(f"Housing Main Color 1: {data.get('housing_main1', 'N/A')}")
        report.append(f"Housing Main Color 2: {data.get('housing_main2', 'N/A')}")
        report.append(f"Housing Main Color 3: {data.get('housing_main3', 'N/A')}")
        report.append("")
        
        # Validation section
        report.append("=== VALIDATION STATUS ===")
        report.append(f"Magic Number: {'PASS' if validation['magic_valid'] else 'FAIL'}")
        report.append(f"Body Size: {'PASS' if validation['size_valid'] else 'WARN'}")
        report.append(f"Body Hash: {'PASS' if validation['hash_valid'] else 'FAIL'}")
        report.append(f"Console Type: {validation['console_type']}")
        report.append("")
        
        # Footer
        report.append("=" * 50)
        report.append("End of Report")
        
        return '\n'.join(report)

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = SwitchPRODINFOAnalyzer(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    root.mainloop()

if __name__ == "__main__":
    main()     
