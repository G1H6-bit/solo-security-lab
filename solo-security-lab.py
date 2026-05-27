

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading      #  packet capture in the background
import time           # Timer
import csv            # Export Files
import datetime       # Formats timestamps


# main packet-capture library
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw



# Matplotlib 
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

packet_list        = []   # Stores  packets
packet_count       = 0    # Running packets
is_sniffing        = False  # Flag: True while capture is running

# Protocol counters – incremented every time we see that type
stats = {
    "TCP"  : 0,
    "UDP"  : 0,
    "ICMP" : 0,
    "DNS"  : 0,
    "HTTP" : 0,
    "Other": 0,
}


def detect_protocol(packet):
    """
    Look inside a packet and return a human-readable protocol name.
    A packet can contain multiple layers, so we check from the most
    specific (DNS, HTTP) down to the most general (TCP, UDP, ICMP).
    """
    # DNS runs over UDP port 53 – check for it first
    if packet.haslayer(DNS):
        return "DNS"

    # HTTP usually runs on TCP port 80 (unencrypted web traffic)
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            return "HTTP"
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    return "Other"


def process_packet(packet):
    """
    Called automatically by Scapy for every captured packet.
    We extract useful fields, update counters, and push the
    data into the GUI table.
    """
    global packet_count, is_sniffing

    # If the user pressed Stop, ignore any late-arriving packets
    if not is_sniffing:
        return

    # We only care about packets that have an IP layer
    # (some low-level frames, like ARP, do not)
    if not packet.haslayer(IP):
        return

    packet_count += 1  # Increment 

    # Pull the IP layer out 
    ip_layer = packet[IP]

    src_ip   = ip_layer.src          # the packet came from
    dst_ip   = ip_layer.dst          # Where it is going
    protocol = detect_protocol(packet)
    length   = len(packet)           # Size in bytes
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    # Update the correct counter in our stats dictionary
    if protocol in stats:
        stats[protocol] += 1
    else:
        stats["Other"] += 1

    # Build a small dictionary representing this one packet
    packet_info = {
        "number"   : packet_count,
        "time"     : timestamp,
        "src"      : src_ip,
        "dst"      : dst_ip,
        "protocol" : protocol,
        "length"   : length,
    }

    # Save to our master list (used later for CSV export)
    packet_list.append(packet_info)

    # Apply the IP filter if the user typed one in
    ip_filter = ip_filter_var.get().strip()
    if ip_filter and ip_filter not in (src_ip, dst_ip):
        return   # Skip packets that don't match the filter

    # Apply the protocol dropdown filter
    proto_filter = proto_filter_var.get()
    if proto_filter != "All" and proto_filter != protocol:
        return   # Skip packets that don't match the chosen protocol

    # Schedule a GUI update on the main thread (Tkinter is not thread-safe)
    root.after(0, lambda info=packet_info: insert_row(info))
    root.after(0, update_stats_bar)


def insert_row(info):
    """
    Insert one packet row into the Treeview table.
    Rows are color-coded by protocol so they are easy to scan.
    """
    color_tag = info["protocol"]  # We defined color tags in setup_treeview()

    packet_table.insert(
        "",                # Parent item – empty string means top level
        "end",             # Append to the bottom of the list
        values=(
            info["number"],
            info["time"],
            info["src"],
            info["dst"],
            info["protocol"],
            f"{info['length']} B",
        ),
        tags=(color_tag,)  # Apply the color tag
    )

    # Auto-scroll to the newest entry so the user always sees live data
    packet_table.yview_moveto(1)



# SNIFFING CONTROL

def start_sniffing():
    """
    Begin capturing packets on a background thread so the GUI
    stays responsive. We pass `process_packet` as the callback
    so Scapy calls it for every captured frame.
    """
    global is_sniffing

    if is_sniffing:
        messagebox.showinfo("Already Running", "Packet capture is already active.")
        return

    is_sniffing = True
    status_label.config(text="● CAPTURING", fg="#00ff88")
    start_btn.config(state="disabled")
    stop_btn.config(state="normal")

    # Build the Scapy BPF filter string based on the protocol dropdown
    bpf = build_bpf_filter()

    # Run sniff() in a daemon thread so it dies when the window closes
    sniff_thread = threading.Thread(
        target=run_sniff,
        args=(bpf,),
        daemon=True
    )
    sniff_thread.start()


def run_sniff(bpf_filter):
    """
    Full Npcap / Layer-2 sniff call. Runs on a background thread.

    Npcap puts the network card into PROMISCUOUS MODE which means
    Scapy can see ALL packets on the local network segment, not just
    packets addressed to this machine. This is the industry-standard
    way to do packet capture (used by Wireshark, tcpdump, etc.).

    BPF (Berkeley Packet Filter) strings are evaluated by the Npcap
    driver in the OS kernel BEFORE the packet even reaches Python,
    making filtering extremely fast and efficient.
    """
    try:
        sniff(
            filter=bpf_filter if bpf_filter else None,  # Kernel-level BPF filter
            prn=process_packet,                          # Our callback per packet
            store=False,                                 # Don't buffer in RAM
            stop_filter=lambda p: not is_sniffing,       # Clean shutdown flag
        )
    except Exception as err:
        # Surface errors in the GUI instead of silently crashing the thread
        root.after(0, lambda e=err: messagebox.showerror(
            "Capture Error",
            f"Could not start packet capture:\n\n{e}\n\n"
            "Make sure:\n"
            "  1. Npcap is installed (https://npcap.com)\n"
            "  2. Terminal is running as Administrator"
        ))
        root.after(0, stop_sniffing)


def stop_sniffing():
    """Set the flag to False. The stop_filter in run_sniff() will see
    this and cause Scapy to stop looping."""
    global is_sniffing

    if not is_sniffing:
        return

    is_sniffing = False
    status_label.config(text="● STOPPED", fg="#ff4444")
    start_btn.config(state="normal")
    stop_btn.config(state="disabled")


def build_bpf_filter():
    """
    Convert the dropdown selection into a Berkeley Packet Filter (BPF)
    string that Scapy / libpcap understands.
    BPF filters are evaluated by the OS kernel – they are very efficient.
    """
    proto = proto_filter_var.get()
    bpf_map = {
        "All" : "",
        "TCP" : "tcp",
        "UDP" : "udp",
        "ICMP": "icmp",
        "HTTP": "tcp port 80",
        "DNS" : "udp port 53",
    }
    return bpf_map.get(proto, "")



# UI 

def clear_results():
    """Remove all rows from the table and reset all counters."""
    global packet_count, packet_list, stats

    # Ask for confirmation before deleting
    confirm = messagebox.askyesno("Clear Results", "Clear all captured packets?")
    if not confirm:
        return

    # Clear the Treeview
    for row in packet_table.get_children():
        packet_table.delete(row)

    # Reset counters
    packet_count = 0
    packet_list  = []
    for key in stats:
        stats[key] = 0

    update_stats_bar()


def update_stats_bar():
    """Refresh the bottom statistics labels with current counts."""
    total = sum(stats.values())
    stats_label.config(
        text=(
            f"Total: {total}   |   "
            f"TCP: {stats['TCP']}   "
            f"UDP: {stats['UDP']}   "
            f"ICMP: {stats['ICMP']}   "
            f"DNS: {stats['DNS']}   "
            f"HTTP: {stats['HTTP']}   "
            f"Other: {stats['Other']}"
        )
    )


def export_csv():
    """Save all captured packets to a CSV file chosen by the user."""
    if not packet_list:
        messagebox.showwarning("No Data", "No packets to export yet.")
        return

    # Open a Save-As dialog so the user picks where to save
    filepath = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")],
        title="Save capture as CSV"
    )
    if not filepath:
        return  # User cancelled the dialog

    with open(filepath, "w", newline="") as csvfile:
        fieldnames = ["number", "time", "src", "dst", "protocol", "length"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_list)

    messagebox.showinfo("Export Complete", f"Saved {len(packet_list)} packets to:\n{filepath}")


def show_chart():
    """
    Open a popup window that draws a pie chart of protocol distribution
    using Matplotlib embedded inside a Tkinter window.
    """
    # Filter out protocols with zero packets so the chart stays clean
    labels  = [k for k, v in stats.items() if v > 0]
    sizes   = [v for v in stats.values() if v > 0]

    if not sizes:
        messagebox.showinfo("No Data", "Capture some packets first!")
        return

    # Create a new top-level window
    chart_win = tk.Toplevel(root)
    chart_win.title("Protocol Distribution Chart")
    chart_win.configure(bg="#0d1117")
    chart_win.geometry("520x420")

    # Create the Matplotlib figure
    fig, ax = plt.subplots(figsize=(5, 4), facecolor="#0d1117")
    colors = ["#00ff88", "#4fc3f7", "#ff8a65", "#ba68c8", "#ffb74d", "#90a4ae"]
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=labels,
        colors=colors[:len(labels)],
        autopct="%1.1f%%",
        startangle=140,
        textprops={"color": "white", "fontsize": 11},
    )
    ax.set_title("Live Protocol Distribution", color="white", fontsize=13, pad=14)
    fig.tight_layout()

    # Embed the chart inside the Tkinter window
    canvas = FigureCanvasTkAgg(fig, master=chart_win)
    canvas.draw()
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=10)


# GUI SETUP

def setup_treeview(parent):
    """
    Create the main packet table using ttk.Treeview.
    Each row = one captured packet.
    """
    global packet_table

    columns = ("#", "Time", "Source IP", "Destination IP", "Protocol", "Length")

    # Frame to hold the table + scrollbar together
    frame = tk.Frame(parent, bg="#0d1117")
    frame.pack(fill="both", expand=True, padx=10, pady=(0, 5))

    # Style the Treeview (dark theme)
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview",
        background="#161b22",
        foreground="#c9d1d9",
        fieldbackground="#161b22",
        rowheight=22,
        font=("Consolas", 9),
    )
    style.configure("Treeview.Heading",
        background="#21262d",
        foreground="#58a6ff",
        font=("Segoe UI", 9, "bold"),
    )
    style.map("Treeview", background=[("selected", "#264f78")])

    # Scrollbars
    y_scroll = ttk.Scrollbar(frame, orient="vertical")
    x_scroll = ttk.Scrollbar(frame, orient="horizontal")

    packet_table = ttk.Treeview(
        frame,
        columns=columns,
        show="headings",
        yscrollcommand=y_scroll.set,
        xscrollcommand=x_scroll.set,
        selectmode="browse",
    )

    y_scroll.config(command=packet_table.yview)
    x_scroll.config(command=packet_table.xview)

    # Column widths
    widths = [50, 80, 140, 140, 80, 80]
    for col, width in zip(columns, widths):
        packet_table.heading(col, text=col)
        packet_table.column(col, width=width, anchor="center")

    # Color tags – each protocol gets its own row color
    packet_table.tag_configure("TCP",   background="#0f2533", foreground="#4fc3f7")
    packet_table.tag_configure("UDP",   background="#1a2a1a", foreground="#00ff88")
    packet_table.tag_configure("ICMP",  background="#2a1a1a", foreground="#ff8a65")
    packet_table.tag_configure("DNS",   background="#1e1a2e", foreground="#ba68c8")
    packet_table.tag_configure("HTTP",  background="#2a2510", foreground="#ffb74d")
    packet_table.tag_configure("Other", background="#1c1c1c", foreground="#90a4ae")

    # Layout
    packet_table.grid(row=0, column=0, sticky="nsew")
    y_scroll.grid(row=0, column=1, sticky="ns")
    x_scroll.grid(row=1, column=0, sticky="ew")

    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)


def build_gui():
    """
    Construct the entire GUI:
      - Header (title + description)
      - Controls (Start / Stop / Clear / Export / Chart / Exit)
      - Filter bar (protocol dropdown + IP input)
      - Packet table
      - Status bar + statistics bar
    """
    global root, proto_filter_var, ip_filter_var
    global start_btn, stop_btn, status_label, stats_label

    # ---------- Root window ----------
    root = tk.Tk()
    root.title("Network Packet Sniffer")
    root.geometry("900x620")
    root.minsize(800, 550)
    root.configure(bg="#0d1117")

    # ---------- Header ----------
    header_frame = tk.Frame(root, bg="#161b22", pady=10)
    header_frame.pack(fill="x")

    tk.Label(
        header_frame,
        text="🛡  Network Packet Sniffer & Traffic Analyzer",
        font=("Segoe UI", 16, "bold"),
        bg="#161b22", fg="#58a6ff",
    ).pack()

    tk.Label(
        header_frame,
        text="Educational tool — capture & inspect live network traffic for defensive cybersecurity learning",
        font=("Segoe UI", 9),
        bg="#161b22", fg="#8b949e",
    ).pack()

    # ---------- Controls row ----------
    ctrl_frame = tk.Frame(root, bg="#0d1117", pady=6)
    ctrl_frame.pack(fill="x", padx=10)

    btn_cfg = dict(font=("Segoe UI", 9, "bold"), relief="flat", cursor="hand2",
                   padx=12, pady=5, bd=0)

    start_btn = tk.Button(ctrl_frame, text="▶  Start Capture",
        bg="#238636", fg="white", activebackground="#2ea043",
        command=start_sniffing, **btn_cfg)
    start_btn.pack(side="left", padx=4)

    stop_btn = tk.Button(ctrl_frame, text="■  Stop Capture",
        bg="#da3633", fg="white", activebackground="#f85149",
        command=stop_sniffing, state="disabled", **btn_cfg)
    stop_btn.pack(side="left", padx=4)

    tk.Button(ctrl_frame, text="🗑  Clear",
        bg="#30363d", fg="#c9d1d9", activebackground="#484f58",
        command=clear_results, **btn_cfg).pack(side="left", padx=4)

    tk.Button(ctrl_frame, text="💾  Export CSV",
        bg="#1f6feb", fg="white", activebackground="#388bfd",
        command=export_csv, **btn_cfg).pack(side="left", padx=4)

    tk.Button(ctrl_frame, text="📊  Protocol Chart",
        bg="#6e40c9", fg="white", activebackground="#8957e5",
        command=show_chart, **btn_cfg).pack(side="left", padx=4)

    tk.Button(ctrl_frame, text="✕  Exit",
        bg="#21262d", fg="#ff4444", activebackground="#30363d",
        command=root.destroy, **btn_cfg).pack(side="right", padx=4)

    # ---------- Filter row ----------
    filter_frame = tk.Frame(root, bg="#161b22", pady=5)
    filter_frame.pack(fill="x", padx=10, pady=(0, 4))

    tk.Label(filter_frame, text="Protocol:", bg="#161b22",
             fg="#8b949e", font=("Segoe UI", 9)).pack(side="left", padx=(6, 2))

    proto_filter_var = tk.StringVar(value="All")
    proto_menu = ttk.Combobox(
        filter_frame,
        textvariable=proto_filter_var,
        values=["All", "TCP", "UDP", "ICMP", "HTTP", "DNS"],
        state="readonly", width=8,
        font=("Segoe UI", 9),
    )
    proto_menu.pack(side="left", padx=4)

    tk.Label(filter_frame, text="Filter by IP:",
             bg="#161b22", fg="#8b949e", font=("Segoe UI", 9)).pack(side="left", padx=(14, 2))

    ip_filter_var = tk.StringVar()
    ip_entry = tk.Entry(
        filter_frame, textvariable=ip_filter_var,
        bg="#21262d", fg="#c9d1d9", insertbackground="white",
        font=("Consolas", 9), relief="flat", width=18,
    )
    ip_entry.pack(side="left", padx=4, ipady=3)

    tk.Label(filter_frame, text="(leave blank = all IPs)",
             bg="#161b22", fg="#484f58", font=("Segoe UI", 8)).pack(side="left")

    # ---------- Status indicator (top-right of filter row) ----------
    status_label = tk.Label(filter_frame, text="● IDLE",
        bg="#161b22", fg="#8b949e", font=("Segoe UI", 9, "bold"))
    status_label.pack(side="right", padx=10)

    # ---------- Packet table ----------
    setup_treeview(root)

    # ---------- Statistics bar ----------
    stats_frame = tk.Frame(root, bg="#161b22", pady=5)
    stats_frame.pack(fill="x", side="bottom")

    stats_label = tk.Label(
        stats_frame,
        text="Total: 0   |   TCP: 0   UDP: 0   ICMP: 0   DNS: 0   HTTP: 0   Other: 0",
        bg="#161b22", fg="#58a6ff",
        font=("Consolas", 9),
    )
    stats_label.pack()

    # Handle window close – make sure sniffing stops
    root.protocol("WM_DELETE_WINDOW", on_close)

    return root


def on_close():
    """Gracefully stop sniffing before the window closes."""
    global is_sniffing
    is_sniffing = False
    root.destroy()


# ENTRY POINT

if __name__ == "__main__":
    app = build_gui()
    app.mainloop()   # Tkinter's event loop – keeps the window alive
