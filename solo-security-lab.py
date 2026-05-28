import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import socket


# shared list — the server writes here, the GUI reads from it
shared_log = []

# counters for the scoreboard
stats = {
    "flood":   0,
    "dir":     0,
    "scanner": 0,
    "recon":   0,
    "total":   0,
}

server_running = False


# fake server that receives requests and logs them
class FakeServerHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        timestamp = datetime.now().strftime("%H:%M:%S")
        agent = self.headers.get("User-Agent", "Unknown")

        # known paths return 200, everything else is 404
        known_paths = ["/", "/index.html", "/favicon.ico", "/robots.txt",
                       "/sitemap.xml", "/README", "/LICENSE", "/CHANGELOG",
                       "/server-status"]
        if self.path in known_paths:
            code = 200
            code_label = "200 OK"
        else:
            code = 404
            code_label = "404 NOT FOUND"

        # figure out what type of request this is
        if any(s in agent.lower() for s in ["nikto", "sqlmap", "masscan", "zgrab", "nmap"]):
            tag = "SCANNER"
        elif code == 404:
            tag = "BRUTE"
        elif any(s in self.path for s in [".env", "CHANGELOG", "LICENSE", "README",
                                           "server-status", "shell"]):
            tag = "RECON"
        else:
            tag = "FLOOD"

        log_line = (
            f"[{timestamp}] [{tag}] "
            f'GET {self.path} → {code_label}  '
            f'| Agent: {agent[:45]}'
        )

        shared_log.append((log_line, tag))

        # update the counters
        stats["total"] += 1
        if tag == "FLOOD":   stats["flood"]   += 1
        if tag == "BRUTE":   stats["dir"]     += 1
        if tag == "SCANNER": stats["scanner"] += 1
        if tag == "RECON":   stats["recon"]   += 1

        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"<html><body>Solo Lab Fake Server</body></html>")

    # silence the default server terminal output
    def log_message(self, fmt, *args):
        pass


def start_fake_server():
    global server_running
    try:
        server = HTTPServer(("127.0.0.1", 8080), FakeServerHandler)
        server_running = True
        server.serve_forever()
    except OSError:
        # port 8080 is already being used by something else
        server_running = False

# start the server in the background
server_thread = threading.Thread(target=start_fake_server, daemon=True)
server_thread.start()
time.sleep(0.4)


# 20 rapid requests to the homepage
def attack_flood():
    for i in range(20):
        try:
            urllib.request.urlopen("http://127.0.0.1:8080/", timeout=2)
        except:
            pass
        time.sleep(0.15)


# probe common hidden paths — simulates a directory scanner
def attack_dirbrute():
    paths = [
        "/admin", "/login", "/wp-admin", "/config",
        "/backup", "/dashboard", "/secret", "/api",
        "/uploads", "/private", "/.env", "/shell",
        "/phpmyadmin", "/old"
    ]
    for path in paths:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:8080{path}", timeout=2)
        except:
            pass
        time.sleep(0.3)


# send requests with real scanner tool names as the user agent
def attack_scanner():
    agents = [
        "Mozilla/5.00 (Nikto/2.1.5)",
        "sqlmap/1.0-dev (https://sqlmap.org)",
        "Nmap Scripting Engine",
        "masscan/1.0 tbot",
        "zgrab/0.x"
    ]
    for agent in agents:
        try:
            req = urllib.request.Request(
                "http://127.0.0.1:8080/",
                headers={"User-Agent": agent}
            )
            urllib.request.urlopen(req, timeout=2)
        except:
            pass
        time.sleep(0.4)


# slow and quiet — checks sensitive files with long pauses between each
def attack_recon():
    pages = [
        "/robots.txt", "/sitemap.xml", "/README",
        "/CHANGELOG", "/.env", "/server-status",
        "/LICENSE", "/favicon.ico"
    ]
    for page in pages:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:8080{page}", timeout=3)
        except:
            pass
        for countdown in [2, 1]:
            status.config(
                text=f"▶  Slow Recon running — next probe in {countdown}s...",
                fg="#f39c12"
            )
            time.sleep(1)


# runs all 4 attacks one after another
def attack_combo():
    attack_flood()
    time.sleep(1)
    attack_dirbrute()
    time.sleep(1)
    attack_scanner()
    time.sleep(1)
    attack_recon()


# helper that runs any attack on a background thread
def launch(fn, label):
    if not server_running:
        messagebox.showerror(
            "Server Error",
            "The fake server failed to start.\n"
            "Port 8080 may already be in use.\n"
            "Close any other program using port 8080 and restart."
        )
        return

    # disable all buttons while an attack is running
    for b in all_buttons:
        b.config(state=tk.DISABLED)

    status.config(text=f"▶  Running: {label} — watch the log pane!", fg="#f39c12")

    def run():
        fn()
        for b in all_buttons:
            b.config(state=tk.NORMAL)
        status.config(text=f"✓  {label} complete. Study the log pane below.", fg="#00cc66")
        update_scoreboard()

    threading.Thread(target=run, daemon=True).start()


# checks for new log entries every 600ms and adds them to the log pane
last_seen = [0]

def refresh_log():
    current = len(shared_log)
    if current > last_seen[0]:
        new_entries = shared_log[last_seen[0]:current]
        log_pane.config(state=tk.NORMAL)
        for line, tag in new_entries:
            log_pane.insert(tk.END, line + "\n", tag)
        log_pane.see(tk.END)
        log_pane.config(state=tk.DISABLED)
        last_seen[0] = current
    window.after(600, refresh_log)


def update_scoreboard():
    lbl_flood.config(text=f"{stats['flood']:>4}")
    lbl_dir.config(  text=f"{stats['dir']:>4}")
    lbl_scan.config( text=f"{stats['scanner']:>4}")
    lbl_recon.config(text=f"{stats['recon']:>4}")
    lbl_total.config(text=f"Total requests logged: {stats['total']}")


def save_logs():
    if not shared_log:
        messagebox.showinfo("Nothing to Save", "Run an attack first to generate some logs.")
        return
    filename = datetime.now().strftime("solo_lab_log_%Y%m%d_%H%M%S.txt")
    with open(filename, "w") as f:
        f.write(f"Solo Lab — Log saved at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"  HTTP Flood requests : {stats['flood']}\n")
        f.write(f"  Dir Brute paths     : {stats['dir']}\n")
        f.write(f"  Scanner Agent hits  : {stats['scanner']}\n")
        f.write(f"  Slow Recon probes   : {stats['recon']}\n")
        f.write(f"  Total logged        : {stats['total']}\n\n")
        f.write("=" * 70 + "\n\n")
        for line, _ in shared_log:
            f.write(line + "\n")
    status.config(text=f"✓  Log saved → {filename}", fg="#00cc66")
    messagebox.showinfo("Log Saved", f"Your log was saved as:\n\n{filename}")


def clear_logs():
    if not shared_log:
        return
    if not messagebox.askyesno("Clear Log", "Clear all log entries and reset counters?"):
        return
    shared_log.clear()
    last_seen[0] = 0
    for k in stats:
        stats[k] = 0
    log_pane.config(state=tk.NORMAL)
    log_pane.delete("1.0", tk.END)
    log_pane.config(state=tk.DISABLED)
    update_scoreboard()
    status.config(text="Log cleared. Ready for a new run.", fg="#888888")


def show_help():
    help_text = (
        "SOLO SECURITY LAB — QUICK GUIDE\n"
        "=" * 40 + "\n\n"
        "This tool is 100% safe.\n"
        "All traffic goes to 127.0.0.1 (your own\n"
        "computer only). Nothing reaches the internet.\n\n"
        "HOW IT WORKS:\n"
        "  A fake web server starts automatically\n"
        "  on port 8080 when you run the script.\n"
        "  Each button sends a different pattern\n"
        "  of HTTP requests to that server.\n"
        "  The log pane shows every request live.\n\n"
        "THE 4 ATTACK TYPES:\n"
        "  RED   HTTP Flood    — 20 rapid requests\n"
        "  AMBER Dir Brute     — probes hidden paths\n"
        "  BLUE  Scanner Agent — fake tool headers\n"
        "  TEAL  Slow Recon    — stealthy slow scan\n"
        "  WHITE Full Combo    — runs all 4 in order\n\n"
        "LOG COLOURS:\n"
        "  Red    = FLOOD   requests\n"
        "  Amber  = BRUTE   requests\n"
        "  Blue   = SCANNER requests\n"
        "  Teal   = RECON   requests\n\n"
        "SAVE LOG saves a .txt file you can study\n"
        "later — just like real SIEM log analysis."
    )
    messagebox.showinfo("Help — How to Use This Tool", help_text)


# colour palette
BG     = "#0f0f1a"
BG2    = "#1a1a2e"
BG3    = "#16213e"
FG     = "#e0e0ff"
GREEN  = "#00e676"
ACCENT = "#00cc66"
ORANGE = "#f39c12"
GRAY   = "#555577"
BORDER = "#2a2a4a"

window = tk.Tk()
window.title("Solo Security Lab  v1.0  —  127.0.0.1:8080")
window.geometry("600x680")
window.configure(bg=BG)
window.resizable(False, False)

# header
header = tk.Frame(window, bg="#0a0a14", pady=10)
header.pack(fill="x")

tk.Label(header, text="⬡  SOLO SECURITY LAB",
         font=("Courier", 15, "bold"), fg="#7c83fd", bg="#0a0a14").pack()

srv_colour = ACCENT if server_running else "#e74c3c"
srv_text   = "● Fake server running on  127.0.0.1:8080" if server_running \
             else "✗ Server failed — port 8080 in use"
tk.Label(header, text=srv_text,
         font=("Courier", 9), fg=srv_colour, bg="#0a0a14").pack(pady=(2, 0))

tk.Label(header, text="All traffic stays on your computer  •  100% safe  •  For education only",
         font=("Courier", 8), fg=GRAY, bg="#0a0a14").pack(pady=(1, 0))

# scoreboard
score_outer = tk.Frame(window, bg=BORDER, padx=1, pady=1)
score_outer.pack(fill="x", padx=12, pady=(10, 4))

score_frame = tk.Frame(score_outer, bg=BG3, pady=6)
score_frame.pack(fill="x")

tk.Label(score_frame, text="REQUESTS LOGGED",
         font=("Courier", 8, "bold"), fg=GRAY, bg=BG3).pack()

cols = tk.Frame(score_frame, bg=BG3)
cols.pack(pady=4)

def make_stat_col(parent, label, colour):
    f = tk.Frame(parent, bg=BG3, padx=14)
    f.pack(side="left")
    tk.Label(f, text=label, font=("Courier", 8), fg=colour, bg=BG3).pack()
    num = tk.Label(f, text="   0", font=("Courier", 14, "bold"), fg=colour, bg=BG3)
    num.pack()
    return num

lbl_flood = make_stat_col(cols, "FLOOD",   "#e74c3c")
lbl_dir   = make_stat_col(cols, "BRUTE",   "#f39c12")
lbl_scan  = make_stat_col(cols, "SCANNER", "#3498db")
lbl_recon = make_stat_col(cols, "RECON",   "#1abc9c")

lbl_total = tk.Label(score_frame, text="Total requests logged: 0",
                     font=("Courier", 8), fg=GRAY, bg=BG3)
lbl_total.pack(pady=(2, 0))

# attack buttons
tk.Label(window, text="SELECT AN ATTACK",
         font=("Courier", 8, "bold"), fg=GRAY, bg=BG).pack(pady=(10, 4))

btn_frame = tk.Frame(window, bg=BG)
btn_frame.pack()

bs = dict(
    font=("Courier", 10, "bold"), fg="white",
    activeforeground="white", relief="flat",
    padx=10, pady=10, cursor="hand2", width=17
)

btn_flood = tk.Button(btn_frame, text="▶  HTTP Flood",
                      bg="#922b21", activebackground="#c0392b",
                      command=lambda: launch(attack_flood, "HTTP Flood"), **bs)
btn_flood.grid(row=0, column=0, padx=5, pady=4)

btn_dir = tk.Button(btn_frame, text="▶  Dir Brute-Force",
                    bg="#784212", activebackground="#a04000",
                    command=lambda: launch(attack_dirbrute, "Dir Brute-Force"), **bs)
btn_dir.grid(row=0, column=1, padx=5, pady=4)

btn_scan = tk.Button(btn_frame, text="▶  Scanner Agent",
                     bg="#154360", activebackground="#1a5276",
                     command=lambda: launch(attack_scanner, "Scanner Agent"), **bs)
btn_scan.grid(row=1, column=0, padx=5, pady=4)

btn_recon = tk.Button(btn_frame, text="▶  Slow Recon",
                      bg="#0e6655", activebackground="#117a65",
                      command=lambda: launch(attack_recon, "Slow Recon"), **bs)
btn_recon.grid(row=1, column=1, padx=5, pady=4)

btn_combo = tk.Button(btn_frame, text="★  FULL COMBO  (all 4 attacks)",
                      bg="#2c2c54", activebackground="#40407a",
                      font=("Courier", 10, "bold"), fg="#e0e0ff",
                      activeforeground="white", relief="flat",
                      padx=10, pady=10, cursor="hand2",
                      command=lambda: launch(attack_combo, "Full Combo"))
btn_combo.grid(row=2, column=0, columnspan=2, padx=5, pady=4, sticky="ew")

all_buttons = [btn_flood, btn_dir, btn_scan, btn_recon, btn_combo]

# status bar
status = tk.Label(window,
                  text="Status: Fake server running. Pick an attack above.",
                  font=("Courier", 9), fg="#888888", bg=BG)
status.pack(pady=(8, 2))

# live log pane
log_header = tk.Frame(window, bg=BG)
log_header.pack(fill="x", padx=12)

tk.Label(log_header, text=" LIVE SERVER LOG",
         font=("Courier", 9, "bold"), fg=GRAY, bg=BG, anchor="w").pack(side="left")
tk.Label(log_header, text="auto-refreshes every 0.6s ",
         font=("Courier", 8), fg=GRAY, bg=BG, anchor="e").pack(side="right")

log_pane = scrolledtext.ScrolledText(
    window, height=12,
    font=("Courier", 9),
    bg="#080810", fg=GREEN,
    state=tk.DISABLED,
    relief="flat", wrap=tk.WORD,
    insertbackground=GREEN
)
log_pane.pack(fill="x", padx=12, pady=(4, 6))

# colour each log entry by attack type
log_pane.tag_config("FLOOD",   foreground="#e74c3c")
log_pane.tag_config("BRUTE",   foreground="#f39c12")
log_pane.tag_config("SCANNER", foreground="#5dade2")
log_pane.tag_config("RECON",   foreground="#1abc9c")

# utility buttons
util_frame = tk.Frame(window, bg=BG)
util_frame.pack(pady=(0, 14))

util_style = dict(
    font=("Courier", 9, "bold"), bg="#1c1c3a", fg=FG,
    activebackground="#2a2a50", activeforeground=FG,
    relief="flat", padx=14, pady=6, cursor="hand2"
)

tk.Button(util_frame, text="💾  Save Log",  command=save_logs,  **util_style).pack(side="left", padx=5)
tk.Button(util_frame, text="🗑   Clear Log", command=clear_logs, **util_style).pack(side="left", padx=5)
tk.Button(util_frame, text="?   Help",       command=show_help,  **util_style).pack(side="left", padx=5)

window.after(600, refresh_log)
window.mainloop()
