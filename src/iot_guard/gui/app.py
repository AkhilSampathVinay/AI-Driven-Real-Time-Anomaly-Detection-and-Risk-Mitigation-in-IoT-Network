"""Tkinter desktop dashboard."""

import ipaddress
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Dict, List, Optional

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from scapy.layers.inet import IP
from scapy.utils import wrpcap

from ..detection import Severity
from ..monitor import Monitor
from ..scanner import Device, NetworkInfo, arp_scan, demo_devices, get_network_info
from ..sources import LiveSource, demo_source
from . import format as fmt

POLL_MS = 200
COLORS = {
    Severity.CRITICAL: "#c62828", Severity.WARNING: "#e65100",
    Severity.NOTICE: "#6a1b9a", Severity.BLOCKED: "#757575",
}
DURATIONS = {"1 min": 60, "5 min": 300, "15 min": 900, "1 hour": 3600, "24 hours": 86400}


class Dashboard(tk.Tk):
    def __init__(self, monitor: Monitor, net: NetworkInfo, devices: List[Device],
                 demo: bool, enforce: bool = False):
        super().__init__()
        self.monitor = monitor
        self.net = net
        self.demo = demo
        self.enforce = enforce
        self.known: Dict[str, Device] = {d.ip: d for d in devices}
        self.alert_rows: Dict[tuple, dict] = {}
        self.device_windows: Dict[str, "DeviceWindow"] = {}
        self.scan_results: "queue.Queue" = queue.Queue()
        self._last_slow = 0.0

        self.title("IoT Guard - AI-driven anomaly detection & risk mitigation"
                   + ("  [DEMO]" if demo else ""))
        self.geometry("1280x800")
        self.minsize(1000, 640)
        self._build()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(POLL_MS, self._poll)

    # ------------------------------------------------------------- layout
    def _build(self):
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=24)
        style.configure("Banner.TLabel", background="#fff3cd", foreground="#664d03",
                        padding=6)
        style.configure("Status.TLabel", padding=(8, 3))

        if self.demo:
            ttk.Label(self, style="Banner.TLabel",
                      text="DEMO MODE: replaying a simulated smart-home network with scripted "
                           "attacks (port scan, Mirai, SYN/UDP floods, DNS tunneling). "
                           "Firewall actions are dry-run: logged, not applied.",
                      ).pack(fill=tk.X)
        elif not self.enforce:
            ttk.Label(self, style="Banner.TLabel",
                      text="LIVE MODE (dry-run): mitigation shows the firewall commands "
                           "without applying them. Restart with --enforce to apply them.",
                      ).pack(fill=tk.X)

        info = ttk.Frame(self, padding=(10, 6))
        info.pack(fill=tk.X)
        for text in (f"Network: {self.net.ssid}", f"Your IP: {self.net.my_ip}",
                     f"Gateway: {self.net.gateway or '?'}", f"Subnet: {self.net.subnet}"):
            ttk.Label(info, text=text).pack(side=tk.LEFT, padx=(0, 18))

        bar = ttk.Frame(self, padding=(10, 0))
        bar.pack(fill=tk.X)
        self.start_btn = ttk.Button(bar, text="▶ Start monitoring", command=self.start)
        self.start_btn.pack(side=tk.LEFT)
        self.stop_btn = ttk.Button(bar, text="■ Stop", command=self.stop)
        self.stop_btn.pack(side=tk.LEFT, padx=4)
        if not self.demo:
            ttk.Button(bar, text="Scan network", command=self.scan).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Mitigate threat…", command=lambda: self.open_mitigation()
                   ).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Save graph", command=self.save_graph).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="Export report", command=self.export_report
                   ).pack(side=tk.LEFT, padx=4)

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # Devices
        left = ttk.LabelFrame(panes, text="Devices (double-click to inspect)", padding=4)
        cols = ("ip", "name", "packets", "threats", "status")
        self.dev_tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, w, label in (("ip", 105, "IP address"), ("name", 150, "Device / MAC"),
                            ("packets", 62, "Packets"), ("threats", 58, "Threats"),
                            ("status", 132, "Status")):
            self.dev_tree.heading(c, text=label)
            self.dev_tree.column(c, width=w, anchor=tk.W if c in ("ip", "name") else tk.CENTER)
        for tag, color in (("malicious", COLORS[Severity.CRITICAL]),
                           ("targeted", COLORS[Severity.WARNING]),
                           ("blocked", COLORS[Severity.BLOCKED])):
            self.dev_tree.tag_configure(tag, foreground=color)
        self.dev_tree.pack(fill=tk.BOTH, expand=True)
        self.dev_tree.bind("<Double-1>", self._open_device)
        panes.add(left, weight=1)

        right = ttk.PanedWindow(panes, orient=tk.VERTICAL)
        panes.add(right, weight=2)

        chart = ttk.LabelFrame(right, text="Live traffic (last 60 s)", padding=4)
        self.fig = Figure(figsize=(5.8, 2.6), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.fig.subplots_adjust(left=0.08, right=0.98, top=0.92, bottom=0.18)
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        right.add(chart, weight=2)

        alerts = ttk.LabelFrame(right, text="Threat alerts (grouped by source and type)",
                                padding=4)
        cols = ("time", "sev", "type", "src", "dst", "count", "msg")
        self.alert_tree = ttk.Treeview(alerts, columns=cols, show="headings")
        for c, w, label in (("time", 90, "Last seen"), ("sev", 75, "Severity"),
                            ("type", 85, "Type"), ("src", 110, "Source"),
                            ("dst", 110, "Target"), ("count", 55, "Pkts"),
                            ("msg", 260, "Details")):
            self.alert_tree.heading(c, text=label)
            self.alert_tree.column(c, width=w, anchor=tk.W, stretch=(c == "msg"))
        for sev, color in COLORS.items():
            self.alert_tree.tag_configure(sev.name, foreground=color)
        sb = ttk.Scrollbar(alerts, command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.alert_tree.pack(fill=tk.BOTH, expand=True)
        self.alert_tree.bind("<Double-1>", self._alert_mitigate)
        right.add(alerts, weight=3)

        self.status = ttk.Label(self, style="Status.TLabel", relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(fill=tk.X, side=tk.BOTTOM)
        self._refresh_devices()
        self._draw_chart()

    # ------------------------------------------------------------- control
    def start(self):
        try:
            self.monitor.start()
        except Exception as e:  # e.g. permission denied, no Npcap
            messagebox.showerror("Capture failed", f"Could not start capture:\n{e}")

    def stop(self):
        self.monitor.stop()

    def scan(self):
        self.status.config(text="Scanning network…")

        def work():
            try:
                self.scan_results.put(arp_scan(self.net.subnet, self.net.iface))
            except Exception as e:
                self.scan_results.put(e)
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------------- polling (main thread)
    def _poll(self):
        batch = self.monitor.drain()
        if batch:
            self._update_alerts(batch)
            for w in list(self.device_windows.values()):
                w.feed(batch)
        try:
            res = self.scan_results.get_nowait()
            if isinstance(res, Exception):
                messagebox.showerror("Scan failed", f"{res}\n\nARP scanning needs root/admin.")
            else:
                for d in res:
                    self.known.setdefault(d.ip, d)
                self.status.config(text=f"Scan complete: {len(res)} devices found")
        except queue.Empty:
            pass

        now = time.time()
        if now - self._last_slow > 1.0:
            self._last_slow = now
            for msg in self.monitor.tick():
                self._toast(msg)
            self._refresh_devices()
            self._draw_chart()
            self._refresh_status()
        self.after(POLL_MS, self._poll)

    def _update_alerts(self, batch):
        for pkt, v in batch:
            for a in v.alerts:
                if a.severity < Severity.WARNING or a.severity == Severity.BLOCKED:
                    continue
                key = (a.src, a.category)
                row = self.alert_rows.get(key)
                ts = float(pkt.time)
                if row and ts - row["last"] < 15:
                    row["count"] += 1
                    row["last"] = ts
                    row["targets"].add(a.dst)
                else:
                    iid = self.alert_tree.insert("", 0, tags=(a.severity.name,))
                    row = self.alert_rows[key] = {"iid": iid, "count": 1, "last": ts,
                                                  "targets": {a.dst}}
                targets = row["targets"]
                target = next(iter(targets)) if len(targets) == 1 else f"{len(targets)} hosts"
                self.alert_tree.item(row["iid"], values=(
                    fmt.clock(ts)[:8], a.severity.name, a.category, a.src, target or "",
                    row["count"], a.message))

    def _status_of(self, ip: str, offenders: set) -> tuple:
        for b in self.monitor.mitigation.blocks():
            if b.ip == ip:
                return f"BLOCKED: {b.mode}", "blocked"
        if ip in offenders:
            return "MALICIOUS", "malicious"
        d = self.monitor.devices.get(ip)
        if d and d.attacks:
            return "Targeted", "targeted"
        return "OK", ""

    def _refresh_devices(self):
        offenders = {o.ip for o in self.monitor.engine.offenders()}
        ips = set(self.known)
        for ip, st in self.monitor.devices.items():
            try:
                # only list hosts that actually sent traffic (not addresses a scanner probed)
                if st.sent and ipaddress.ip_address(ip).is_private:
                    ips.add(ip)
            except ValueError:
                pass
        for ip in sorted(ips, key=lambda x: ipaddress.ip_address(x)):
            dev = self.known.get(ip)
            stats = self.monitor.devices.get(ip)
            name = (dev.name or dev.mac) if dev else "(seen in traffic)"
            status, tag = self._status_of(ip, offenders)
            vals = (ip, name, stats.packets if stats else 0, stats.attacks if stats else 0,
                    status)
            if self.dev_tree.exists(ip):
                self.dev_tree.item(ip, values=vals, tags=(tag,))
            else:
                self.dev_tree.insert("", tk.END, iid=ip, values=vals, tags=(tag,))

    def _draw_chart(self):
        ax = self.ax
        ax.clear()
        tl = list(self.monitor.timeline)
        if tl:
            end = tl[-1][0]
            pts = {s: (p, a) for s, p, a in tl if s > end - 60}
            xs = list(range(-59, 1))
            pk = [pts.get(end + x, (0, 0))[0] for x in xs]
            at = [pts.get(end + x, (0, 0))[1] for x in xs]
            ax.plot(xs, pk, color="#1565c0", linewidth=1.4, label="packets/s")
            ax.fill_between(xs, at, color=COLORS[Severity.CRITICAL], alpha=0.45,
                            label="attack packets/s")
            ax.set_ylim(0, max(10, max(pk) * 1.15))
        ax.set_xlim(-59, 0)
        ax.set_xlabel("seconds ago", fontsize=8)
        ax.tick_params(labelsize=8)
        ax.grid(alpha=0.25)
        if tl:
            ax.legend(loc="upper left", fontsize=8, frameon=False)
        self.canvas.draw_idle()

    def _refresh_status(self):
        ml = self.monitor.engine.ml
        if ml is None:
            ml_txt = "ML off"
        elif ml.trained:
            ml_txt = "ML model: trained"
        else:
            ml_txt = f"ML model: learning baseline ({len(ml.buffer)}/{ml.t.ml_warmup_packets})"
        state = "● Monitoring" if self.monitor.running else "○ Stopped"
        blocks = len(self.monitor.mitigation.blocks())
        self.status.config(text=(
            f"{state}   |   packets: {self.monitor.total:,}   |   attack packets: "
            f"{self.monitor.total_attacks:,}   |   blocked IPs: {blocks}   |   {ml_txt}"
            + (f"   |   dropped (overload): {self.monitor.dropped}" if self.monitor.dropped
               else "")))

    def _toast(self, msg: str):
        self.status.config(text=msg)

    # ------------------------------------------------------------- windows / actions
    def _open_device(self, _event=None):
        sel = self.dev_tree.selection()
        if not sel:
            return
        ip = sel[0]
        win = self.device_windows.get(ip)
        if win and win.winfo_exists():
            win.lift()
            return
        self.device_windows[ip] = DeviceWindow(self, ip)

    def _alert_mitigate(self, _event=None):
        sel = self.alert_tree.selection()
        if sel:
            self.open_mitigation(self.alert_tree.item(sel[0], "values")[3])

    def open_mitigation(self, ip: Optional[str] = None):
        MitigationDialog(self, ip)

    def save_graph(self):
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[
            ("PNG", "*.png"), ("PDF", "*.pdf"), ("SVG", "*.svg")])
        if path:
            self.fig.savefig(path, dpi=200, bbox_inches="tight")
            self._toast(f"Graph saved to {path}")

    def export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text", "*.txt")])
        if not path:
            return
        lines = [f"IoT Guard report - {time.strftime('%Y-%m-%d %H:%M:%S')}",
                 f"Packets analysed: {self.monitor.total:,}",
                 f"Attack packets: {self.monitor.total_attacks:,}", "", "Offenders:"]
        for o in self.monitor.engine.offenders():
            cats = ", ".join(f"{c}={n}" for c, n in o.categories.most_common())
            lines.append(f"  {o.ip:<16} {o.worst.name:<9} {o.alerts} alerts ({cats})")
        lines += ["", "Mitigation log:"] + [f"  {e}" for e in self.monitor.mitigation.events]
        lines += ["", "Firewall commands:"] + [f"  {c}" for c in self.monitor.firewall.history]
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self._toast(f"Report exported to {path}")

    def on_close(self):
        if self.monitor.mitigation.blocks() and not self.monitor.firewall.dry_run:
            if not messagebox.askyesno("Exit", "Remove all firewall rules added by IoT Guard "
                                               "and exit?"):
                return
        self.monitor.shutdown()
        self.destroy()


class DeviceWindow(tk.Toplevel):
    """Per-device packet inspector."""

    MAX_ROWS = 2000

    def __init__(self, dash: Dashboard, ip: str):
        super().__init__(dash)
        self.dash = dash
        self.ip = ip
        self.packets: list = []
        self.paused = tk.BooleanVar(value=False)
        dev = dash.known.get(ip)
        self.title(f"Packets - {ip}" + (f" ({dev.name})" if dev and dev.name else ""))
        self.geometry("1150x650")

        top = ttk.Frame(self, padding=6)
        top.pack(fill=tk.X)
        ttk.Checkbutton(top, text="Pause view", variable=self.paused).pack(side=tk.LEFT)
        ttk.Button(top, text="Save PCAP", command=self.save_pcap).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Export text", command=self.export_text).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Mitigate…", command=lambda: dash.open_mitigation(ip)
                   ).pack(side=tk.LEFT, padx=4)
        self.counter = ttk.Label(top, text="")
        self.counter.pack(side=tk.RIGHT)

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        lf = ttk.Frame(panes)
        self.listbox = tk.Listbox(lf, font="TkFixedFont", activestyle="none",
                                  selectbackground="#0078d7")
        sb = ttk.Scrollbar(lf, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.pack(fill=tk.BOTH, expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.show_details)
        panes.add(lf, weight=3)
        self.detail = scrolledtext.ScrolledText(panes, font="TkFixedFont", wrap=tk.WORD,
                                                width=60)
        panes.add(self.detail, weight=2)

        stats = dash.monitor.devices.get(ip)
        if stats:
            self._append(list(stats.recent))

    def _append(self, items):
        for pkt, v in items:
            self.packets.append((pkt, v))
            self.listbox.insert(tk.END, fmt.summary(pkt, v))
            color = COLORS.get(v.severity)
            if color:
                self.listbox.itemconfig(tk.END, foreground=color)
        overflow = len(self.packets) - self.MAX_ROWS
        if overflow > 0:
            del self.packets[:overflow]
            self.listbox.delete(0, overflow - 1)
        if not self.listbox.curselection():
            self.listbox.see(tk.END)
        self.counter.config(text=f"{len(self.packets)} packets shown")

    def feed(self, batch):
        if not self.winfo_exists() or self.paused.get():
            return
        mine = [(p, v) for p, v in batch
                if p.haslayer(IP) and self.ip in (p[IP].src, p[IP].dst)]
        if mine:
            self._append(mine)

    def show_details(self, _event=None):
        sel = self.listbox.curselection()
        if not sel:
            return
        pkt, v = self.packets[sel[0]]
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, fmt.details(pkt, v))
        self.detail.configure(state=tk.DISABLED)

    def save_pcap(self):
        if not self.packets:
            return messagebox.showwarning("Nothing to save", "No packets captured yet.",
                                          parent=self)
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".pcap",
                                            filetypes=[("PCAP", "*.pcap")])
        if path:
            wrpcap(path, [p for p, _ in self.packets])
            messagebox.showinfo("Saved", f"Saved {len(self.packets)} packets.", parent=self)

    def export_text(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".txt",
                                            filetypes=[("Text", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                for p, v in self.packets:
                    f.write(fmt.summary(p, v) + "\n" + fmt.details(p, v) + "\n\n")

    def destroy(self):
        self.dash.device_windows.pop(self.ip, None)
        super().destroy()


class MitigationDialog(tk.Toplevel):
    def __init__(self, dash: Dashboard, ip: Optional[str]):
        super().__init__(dash)
        self.dash = dash
        self.title("Risk mitigation")
        self.geometry("620x520")
        self.transient(dash)
        mon = dash.monitor

        offenders = mon.engine.offenders()
        choices = [o.ip for o in offenders]
        if ip and ip not in choices:
            choices.insert(0, ip)
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Target IP:").grid(row=0, column=0, sticky=tk.W)
        self.ip_var = tk.StringVar(value=ip or (choices[0] if choices else ""))
        ttk.Combobox(frm, textvariable=self.ip_var, values=choices, width=22
                     ).grid(row=0, column=1, sticky=tk.W, pady=4)
        if offenders:
            o = offenders[0]
            ttk.Label(frm, foreground=COLORS[Severity.CRITICAL],
                      text=f"Top offender: {o.ip} - {o.alerts} alerts "
                           f"({', '.join(o.categories)})").grid(row=1, column=0, columnspan=3,
                                                                sticky=tk.W)

        self.mode = tk.StringVar(value="auto")
        modes = [("auto", "Auto-block: block now, release automatically once attacks stop "
                          f"for {int(mon.mitigation.auto_quiet_period)} s"),
                 ("temporary", "Temporary block for:"),
                 ("permanent", "Isolate: block until manually unblocked")]
        for i, (val, text) in enumerate(modes):
            ttk.Radiobutton(frm, text=text, value=val, variable=self.mode
                            ).grid(row=2 + i, column=0, columnspan=2, sticky=tk.W, pady=2)
        self.duration = ttk.Combobox(frm, values=list(DURATIONS), width=10, state="readonly")
        self.duration.current(1)
        self.duration.grid(row=3, column=2, sticky=tk.W)

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=3, sticky=tk.W, pady=10)
        ttk.Button(btns, text="Apply block", command=self.apply).pack(side=tk.LEFT)
        ttk.Button(btns, text="Unblock", command=self.unblock).pack(side=tk.LEFT, padx=6)

        ttk.Label(frm, text="Active blocks:").grid(row=6, column=0, sticky=tk.W)
        self.blocks = tk.Listbox(frm, height=4, font="TkFixedFont")
        self.blocks.grid(row=7, column=0, columnspan=3, sticky=tk.EW)
        ttk.Label(frm, text="Firewall commands" + (" (dry-run)" if mon.firewall.dry_run
                                                   else "") + ":"
                  ).grid(row=8, column=0, columnspan=2, sticky=tk.W, pady=(8, 0))
        self.log = tk.Text(frm, height=8, font="TkFixedFont", wrap=tk.NONE)
        self.log.grid(row=9, column=0, columnspan=3, sticky=tk.NSEW)
        frm.columnconfigure(2, weight=1)
        frm.rowconfigure(9, weight=1)
        self.refresh()

    def refresh(self):
        mon = self.dash.monitor
        self.blocks.delete(0, tk.END)
        for b in mon.mitigation.blocks():
            extra = (f", expires in {int(b.expires_at - mon.latest_ts)} s"
                     if b.expires_at else "")
            self.blocks.insert(tk.END, f"{b.ip:<16} {b.mode}{extra}")
        self.log.delete("1.0", tk.END)
        self.log.insert(tk.END, "\n".join(mon.firewall.history[-50:]))
        self.log.see(tk.END)

    def apply(self):
        ip = self.ip_var.get().strip()
        try:
            msg = self.dash.monitor.mitigation.block(
                ip, self.mode.get(), now=self.dash.monitor.latest_ts,
                duration=DURATIONS[self.duration.get()], reason="user action")
        except ValueError:
            return messagebox.showerror("Invalid IP", f"'{ip}' is not a valid IP address",
                                        parent=self)
        self.dash._toast(msg)
        self.refresh()

    def unblock(self):
        msg = self.dash.monitor.mitigation.unblock(self.ip_var.get().strip())
        self.dash._toast(msg)
        self.refresh()


# ----------------------------------------------------------------- entry points

def _is_admin() -> bool:
    if os.name == "nt":
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def run_demo(speed: float = 2.0):
    from ..simulator import GATEWAY
    net = NetworkInfo(ssid="DEMO-SmartHome (simulated)", my_ip="192.168.1.100",
                      gateway=GATEWAY, subnet="192.168.1.0/24")
    monitor = Monitor(lambda: demo_source(speed=speed), dry_run=True,
                      protected_ips={GATEWAY, net.my_ip})
    app = Dashboard(monitor, net, demo_devices(), demo=True)
    app.after(500, app.start)
    app.mainloop()


def run_live(enforce: bool = False):
    if not _is_admin():
        print("Live capture needs root (Linux/macOS: sudo) or an Administrator terminal on "
              "Windows with Npcap installed.\nTip: run `iot-guard demo` to try it without "
              "privileges.", file=sys.stderr)
        sys.exit(1)
    net = get_network_info()
    monitor = Monitor(lambda: LiveSource(bpf_filter="ip", iface=net.iface),
                      dry_run=not enforce,
                      protected_ips={ip for ip in (net.my_ip, net.gateway) if ip})
    app = Dashboard(monitor, net, [], demo=False, enforce=enforce)
    app.after(300, app.scan)
    app.after(800, app.start)
    app.mainloop()
