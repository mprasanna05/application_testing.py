# professional_web_vuln_scanner_mobile.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import threading
import pandas as pd

# ---------------- Global Variables ----------------
results_list = []
scan_in_progress = False

# ---------------- Vulnerability Scanners ----------------
def scan_xss(url):
    payloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"]
    for payload in payloads:
        if not scan_in_progress: return
        test_url = f"{url}?test={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            status = "Vulnerable" if payload in r.text else "Not Vulnerable"
        except:
            status = "Error"
        results_list.append({"Type":"XSS", "URL":test_url, "Payload":payload, "Status":status})
        update_table()
        update_status(f"XSS Test: {test_url} => {status}")

def scan_sqli(url):
    payloads = ["' OR '1'='1", "' OR 1=1--"]
    for payload in payloads:
        if not scan_in_progress: return
        test_url = f"{url}?id={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            status = "Vulnerable" if "error" in r.text.lower() or "mysql" in r.text.lower() else "Not Vulnerable"
        except:
            status = "Error"
        results_list.append({"Type":"SQLi", "URL":test_url, "Payload":payload, "Status":status})
        update_table()
        update_status(f"SQLi Test: {test_url} => {status}")

def scan_lfi(url):
    payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    for payload in payloads:
        if not scan_in_progress: return
        test_url = f"{url}?file={payload}"
        try:
            r = requests.get(test_url, timeout=5)
            status = "Vulnerable" if "root:" in r.text or "[extensions]" in r.text else "Not Vulnerable"
        except:
            status = "Error"
        results_list.append({"Type":"LFI", "URL":test_url, "Payload":payload, "Status":status})
        update_table()
        update_status(f"LFI Test: {test_url} => {status}")

def scan_open_dir(url):
    paths = ["/admin/", "/uploads/", "/backup/", "/files/"]
    for path in paths:
        if not scan_in_progress: return
        test_url = url.rstrip("/") + path
        try:
            r = requests.get(test_url, timeout=5)
            status = "Accessible" if r.status_code == 200 else "Not Accessible"
        except:
            status = "Error"
        results_list.append({"Type":"Open Directory", "URL":test_url, "Payload":"N/A", "Status":status})
        update_table()
        update_status(f"Open Dir Test: {test_url} => {status}")

# ---------------- GUI Table Update ----------------
def update_table():
    for row in tree.get_children():
        tree.delete(row)
    for res in results_list[-50:]:
        tree.insert("", "end", values=(res["Type"], res["URL"], res["Payload"], res["Status"]),
                    tags=(res["Type"],))

# ---------------- Status Bar ----------------
def update_status(msg):
    status_var.set(msg)
    root.update_idletasks()

# ---------------- Scan Runner ----------------
def run_scan(selected_modules=None):
    global scan_in_progress
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Input Required", "Please enter a target URL!")
        return
    
    results_list.clear()
    update_table()
    scan_in_progress = True
    threading.Thread(target=lambda: scan_all(url, selected_modules), daemon=True).start()

def scan_all(url, selected_modules=None):
    modules = selected_modules or ["XSS","SQLi","LFI","OpenDir"]
    if "XSS" in modules: scan_xss(url)
    if "SQLi" in modules: scan_sqli(url)
    if "LFI" in modules: scan_lfi(url)
    if "OpenDir" in modules: scan_open_dir(url)
    update_status(f"Scan Completed for {url}")
    messagebox.showinfo("Scan Complete", f"Scanning finished for {url}")
    global scan_in_progress
    scan_in_progress = False

def stop_scan():
    global scan_in_progress
    scan_in_progress = False
    update_status("Scan Stopped by User")

# ---------------- CSV Export ----------------
def export_csv():
    if not results_list:
        messagebox.showwarning("Export", "No results to export!")
        return
    df = pd.DataFrame(results_list)
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files","*.csv")])
    if file_path:
        df.to_csv(file_path, index=False)
        update_status(f"Exported {len(df)} results to {file_path}")
        messagebox.showinfo("Export", f"Saved {len(df)} results to {file_path}")

# ---------------- Help ----------------
def show_help():
    msg = ("Web App Vulnerability Scanner Usage:\n"
           "1. Enter the target URL (with http:// or https://)\n"
           "2. Click Scan to start scanning\n"
           "3. Results appear in the table\n"
           "4. Export results to CSV if needed\n"
           "Press ESC to exit fullscreen mode.")
    messagebox.showinfo("Help", msg)

def show_about():
    messagebox.showinfo("About", "Mini Web Vulnerability Scanner v1.2\nDeveloped by Prasanna")

# ---------------- GUI ----------------
root = tk.Tk()
root.title("Mobile Web Vulnerability Scanner")

# Fullscreen for mobile
root.attributes("-fullscreen", True)

# Exit fullscreen on ESC
def exit_fullscreen(event=None):
    root.attributes("-fullscreen", False)
root.bind("<Escape>", exit_fullscreen)

# ---------------- Top Frame ----------------
top_frame = tk.Frame(root, padx=5, pady=5)
top_frame.pack(fill="x")

# URL Entry
tk.Label(top_frame, text="Target URL:", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
url_entry = tk.Entry(top_frame, font=("Arial", 12))
url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
top_frame.columnconfigure(1, weight=1)

# Buttons Frame
btn_frame = tk.Frame(top_frame)
btn_frame.grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="Scan", bg="green", fg="white", font=("Arial", 11), command=run_scan).pack(side="left", padx=2)
tk.Button(btn_frame, text="Export CSV", bg="purple", fg="white", font=("Arial", 11), command=export_csv).pack(side="left", padx=2)
tk.Button(btn_frame, text="Stop", bg="red", fg="white", font=("Arial", 11), command=stop_scan).pack(side="left", padx=2)

# ---------------- Table ----------------
columns = ("Type", "URL", "Payload", "Status")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, anchor="center")
tree.pack(expand=True, fill="both", padx=5, pady=5)

tree.tag_configure("XSS", background="#f0c6c6")
tree.tag_configure("SQLi", background="#f0e68c")
tree.tag_configure("LFI", background="#c6f0f0")
tree.tag_configure("Open Directory", background="#c6f0c6")

# ---------------- Status Bar ----------------
status_var = tk.StringVar()
status_var.set("Ready")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief="sunken", anchor="w")
status_bar.pack(side="bottom", fill="x")

# ---------------- Menu ----------------
menu_bar = tk.Menu(root)
root.config(menu=menu_bar)

file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Export CSV", command=export_csv)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.destroy)
menu_bar.add_cascade(label="File", menu=file_menu)

help_menu = tk.Menu(menu_bar, tearoff=0)
help_menu.add_command(label="Usage", command=show_help)
help_menu.add_command(label="About", command=show_about)
menu_bar.add_cascade(label="Help", menu=help_menu)

root.mainloop()