import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import hashlib
import os
import time
import threading
import requests
import webbrowser

# CONFIGURATION
API_KEY = 'VIRUSTOTAL API KEY'  # <--- PASTE YOUR KEY HERE
VT_FILE_URL = 'https://www.virustotal.com/gui/file/'

class VTScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal Folder Scanner (Auto-Upload)")
        self.root.geometry("900x600")

        # Top Bar
        frame_top = tk.Frame(root, pady=10)
        frame_top.pack(fill='x', padx=10)

        self.btn_browse = tk.Button(frame_top, text="Select Folder to Scan", command=self.browse_folder)
        self.btn_browse.pack(side='left')

        self.lbl_status = tk.Label(frame_top, text="Ready", fg="gray")
        self.lbl_status.pack(side='left', padx=10)

        # Progress Bar
        self.progress = ttk.Progressbar(root, orient='horizontal', mode='determinate')
        self.progress.pack(fill='x', padx=10, pady=5)

        # Results Table (Treeview)
        cols = ('File', 'Status', 'Detections', 'Link')
        self.tree = ttk.Treeview(root, columns=cols, show='headings')
        self.tree.heading('File', text='Filename')
        self.tree.heading('Status', text='Analysis Status')
        self.tree.heading('Detections', text='Malicious/Total')
        self.tree.heading('Link', text='Report Link')

        self.tree.column('File', width=200)
        self.tree.column('Status', width=150)
        self.tree.column('Detections', width=100)
        self.tree.column('Link', width=350)

        self.tree.pack(fill='both', expand=True, padx=10, pady=10)
        self.tree.bind("<Double-1>", self.on_double_click)

    def browse_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            # Clear previous results
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Start scanning in a separate thread
            threading.Thread(target=self.start_scan, args=(folder_path,), daemon=True).start()

    def calculate_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def check_vt(self, file_hash):
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": API_KEY}
        try:
            response = requests.get(url, headers=headers)
            return response
        except Exception:
            return None

    def upload_file(self, filepath):
        """Uploads a file to VirusTotal and returns the analysis link."""
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": API_KEY}
        
        # VT Free API limit is usually 32MB for standard upload
        try:
            if os.path.getsize(filepath) > 32 * 1024 * 1024:
                return False, "File too large (>32MB)"

            with open(filepath, 'rb') as file_obj:
                files = {'file': (os.path.basename(filepath), file_obj)}
                response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                # The response gives an analysis ID
                analysis_id = response.json()['data']['id']
                # Construct the GUI link for the analysis
                return True, f"https://www.virustotal.com/gui/file-analysis/{analysis_id}" 
            elif response.status_code == 429:
                return False, "Rate Limit Exceeded"
            else:
                return False, f"Upload Failed: {response.status_code}"
        except Exception as e:
            return False, str(e)

    def start_scan(self, folder_path):
        files_to_scan = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        self.root.after(0, lambda: self.progress.configure(maximum=total_files, value=0))

        for index, filepath in enumerate(files_to_scan):
            filename = os.path.basename(filepath)
            self.root.after(0, lambda m=f"Scanning {index+1}/{total_files}: {filename}": self.lbl_status.configure(text=m))

            try:
                # 1. Hash file locally
                file_hash = self.calculate_hash(filepath)
                if not file_hash:
                    self.insert_result(filename, "Read Error", "N/A", "Check Permissions", "black")
                    continue

                # 2. Check VT (Hash Lookup)
                response = self.check_vt(file_hash)

                if response and response.status_code == 200:
                    # File exists on VT
                    data = response.json()['data']['attributes']
                    stats = data['last_analysis_stats']
                    malicious = stats['malicious']
                    total = sum(stats.values())

                    status_text = "Clean" if malicious == 0 else "MALICIOUS"
                    color = "green" if malicious == 0 else "red"
                    link = f"{VT_FILE_URL}{file_hash}"

                    self.insert_result(filename, status_text, f"{malicious}/{total}", link, color)

                elif response and response.status_code == 404:
                    # File NOT found -> UPLOAD IT
                    self.insert_result(filename, "Uploading...", "...", "Please Wait", "blue")
                    
                    success, result_link = self.upload_file(filepath)
                    
                    if success:
                        # Success: Provide link to the analysis queue
                        self.insert_result(filename, "Uploaded (Queued)", "Pending", result_link, "orange")
                    else:
                        # Failure (Size limit, net error, etc)
                        self.insert_result(filename, "Upload Failed", "Error", result_link, "red")

                elif response and response.status_code == 429:
                    self.insert_result(filename, "Rate Limited", "Retry later", "N/A", "blue")
                    # Wait longer if rate limited
                    time.sleep(60)
                else:
                    self.insert_result(filename, "API Error", "Error", "N/A", "black")

            except Exception as e:
                print(f"Error scanning {filename}: {e}")

            # Update Progress
            self.root.after(0, lambda v=index+1: self.progress.configure(value=v))

            # RATE LIMITER
            # Public API: 4 requests/min = 15s wait.
            # If you have a Premium Key, you can lower this (e.g., 0.1).
            time.sleep(16)

        self.root.after(0, lambda: self.lbl_status.configure(text="Scan Complete"))

    def insert_result(self, name, status, detections, link, color):
        def _update():
            # Check if item exists (by filename) to update it, or insert new
            # Simple approach: just insert. (Optimized approach would update the "Uploading" row)
            self.tree.insert('', 'end', values=(name, status, detections, link))
        self.root.after(0, _update)

    def on_double_click(self, event):
        item = self.tree.selection()[0]
        url = self.tree.item(item, "values")[3]
        if "http" in url:
            webbrowser.open(url)

if __name__ == "__main__":
    root = tk.Tk()
    app = VTScannerApp(root)
    root.mainloop()
