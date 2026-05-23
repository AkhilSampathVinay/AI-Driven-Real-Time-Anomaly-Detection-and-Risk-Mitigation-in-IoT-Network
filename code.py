import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import subprocess
import re
import socket
import threading
import platform
import time
import numpy as np
import queue
from collections import deque
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
from scapy.all import srp, Ether, ARP, conf
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.layers.http import HTTPRequest
import textwrap
import random
from sklearn.ensemble import IsolationForest
import warnings
warnings.filterwarnings('ignore')

# Suppress Scapy warnings
conf.verb = 0


class EnhancedTrafficAnalyzer:
    def __init__(self):
        self.packet_buffer = deque(maxlen=1000)
        self.flow_stats = {}
        self.model = None
        self.model_trained = False
        self.last_model_update = 0
        self.target_ip = None

        # Security tracking attributes
        self.blocked_devices = {}
        self.silent_blocked_ips = set()
        self.malicious_devices = {}
        self.known_devices = set()
        self.unblock_monitor = {}  # Track devices for auto-unblock

        # Threat detection parameters
        self.mirai_ports = {23, 2323, 7547, 5555, 666, 6666, 6667}
        self.mirai_keywords = {
            "root", "admin", "password", "login", "shell", "busybox",
            "/bin/sh", "cd /tmp", "wget", "tftp", "chmod", "exec"
        }
        self.mirai_patterns = [
            re.compile(r"^root\s*:\s*[^:]*:0:0:"),
            re.compile(r"POST /login.cgi"),
            re.compile(r"GET /shell")
        ]

        # Thresholds and baselines
        self.thresholds = {
            'tcp_syn': {'rate': 50, 'window': 10},
            'udp': {'rate': 200, 'window': 5},
            'dns': {'rate': 100, 'window': 5},
            'size': {'tcp': 1500, 'udp': 1024}
        }
        self.baselines = {
            'packet_sizes': {'mean': 500, 'std': 200},
            'inter_arrival': {'mean': 0.1, 'std': 0.05}
        }

    def check_for_auto_unblock(self, ip):
        """Check if a silently blocked IP should be unblocked based on activity"""
        if ip not in self.unblock_monitor:
            return False

        monitor = self.unblock_monitor[ip]
        current_time = time.time()

        # Unblock if no malicious activity for 5 minutes and at least 100 clean packets
        if (current_time - monitor['last_malicious'] > 300 and
                monitor['clean_period'] > 100):
            self.mitigate_device(ip, "unblock")
            if ip in self.silent_blocked_ips:
                self.silent_blocked_ips.remove(ip)
            if ip in self.unblock_monitor:
                del self.unblock_monitor[ip]
            return True
        return False

    def _silent_analysis(self, packet, ip):
        """Silently analyze packets from blocked IPs"""
        self.analysis_buffer.append(packet)

        if ip not in self.unblock_monitor:
            self.unblock_monitor[ip] = {
                'last_malicious': time.time(),
                'clean_period': 0,
                'last_checked': time.time()
            }

        is_malicious = False
        mirai_alert = self.detect_mirai(packet)
        if mirai_alert:
            is_malicious = True

        if is_malicious:
            self.unblock_monitor[ip]['last_malicious'] = time.time()
            self.unblock_monitor[ip]['clean_period'] = 0
        else:
            self.unblock_monitor[ip]['clean_period'] += 1

        self.unblock_monitor[ip]['last_checked'] = time.time()

    def update_flow_stats(self, packet):
        if not packet.haslayer(IP):
            return None

        src = packet[IP].src
        dst = packet[IP].dst
        proto = None

        if packet.haslayer(TCP):
            proto = 'tcp'
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = 'udp'
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            return None

        flow_key = f"{src}:{sport}-{dst}:{dport}-{proto}"

        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'count': 0,
                'start_time': time.time(),
                'last_time': time.time(),
                'sizes': [],
                'syn_count': 0,
                'flags': set(),
                'payload_patterns': set()
            }

        flow = self.flow_stats[flow_key]
        flow['count'] += 1
        flow['last_time'] = time.time()
        flow['sizes'].append(len(packet))

        if packet.haslayer(TCP):
            flags = self._get_tcp_flags(packet[TCP].flags)
            flow['flags'].update(flags)
            if 'SYN' in flags and 'ACK' not in flags:
                flow['syn_count'] += 1

        if packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if len(payload) > 10:
                flow['payload_patterns'].add(payload[:50])

        return flow_key

    def _get_tcp_flags(self, flags):
        flag_names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        return [flag_names[i] for i in range(8) if flags & (1 << i)]

    def detect_flow_anomalies(self, flow_key):
        flow = self.flow_stats.get(flow_key)
        if not flow:
            return None

        current_time = time.time()
        duration = current_time - flow['start_time']
        rate = flow['count'] / max(1, duration)
        alerts = []

        if 'tcp' in flow_key and flow['syn_count'] > self.thresholds['tcp_syn']['rate']:
            syn_rate = flow['syn_count'] / max(1, duration)
            if syn_rate > self.thresholds['tcp_syn']['rate'] / self.thresholds['tcp_syn']['window']:
                alerts.append(f"SYN flood detected (rate: {syn_rate:.1f} pkts/sec)")

        if 'udp' in flow_key and rate > self.thresholds['udp']['rate']:
            alerts.append(f"UDP flood detected (rate: {rate:.1f} pkts/sec)")

        avg_size = np.mean(flow['sizes']) if flow['sizes'] else 0
        proto = 'tcp' if 'tcp' in flow_key else 'udp'
        if avg_size > self.thresholds['size'][proto]:
            alerts.append(f"Oversized {proto.upper()} packets (avg: {avg_size:.1f} bytes)")

        if 'tcp' in flow_key:
            unusual_flags = {'FIN', 'RST', 'URG', 'PSH'} - flow['flags']
            if unusual_flags:
                alerts.append(f"Unusual TCP flags: {', '.join(flow['flags'])}")

        return alerts if alerts else None

    def detect_mirai(self, packet):
        if packet.haslayer(TCP) and packet[TCP].dport in self.mirai_ports:
            if packet.haslayer(Raw):
                payload = str(packet[Raw].load).lower()
                if any(keyword in payload for keyword in self.mirai_keywords):
                    return "Mirai Botnet: Brute-force attempt detected"
                if any(pattern.search(payload) for pattern in self.mirai_patterns):
                    return "Mirai Botnet: Known exploit pattern detected"

        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            if not packet.haslayer(IP):
                return None
            src_ip = packet[IP].src
            if src_ip not in self.known_devices:
                return "Mirai-like SYN Scan from unknown device"

        if packet.haslayer(UDP) and packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if len(payload) > 50 and "|sh" in payload:
                return "Mirai-like command injection attempt"

        return None

    def train_behavior_model(self):
        if len(self.packet_buffer) < 500:
            return False

        sizes = []
        times = []
        protocols = []

        for i in range(1, len(self.packet_buffer)):
            sizes.append(len(self.packet_buffer[i]))
            times.append(self.packet_buffer[i].time - self.packet_buffer[i-1].time)
            proto = 0
            if self.packet_buffer[i].haslayer(TCP):
                proto = 1
            elif self.packet_buffer[i].haslayer(UDP):
                proto = 2
            elif self.packet_buffer[i].haslayer(DNS):
                proto = 3
            protocols.append(proto)

        features = np.column_stack((
            sizes[:len(times)],
            times,
            protocols[:len(times)]
        ))

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self.model.fit(features)
        self.model_trained = True
        self.last_model_update = time.time()
        return True

    def detect_behavioral_anomalies(self, packet):
        if not self.model_trained or time.time() - self.last_model_update > 300:
            if not self.train_behavior_model():
                return None

        if len(self.packet_buffer) < 2:
            return None

        prev_packet = self.packet_buffer[-1]
        size = len(packet)
        inter_arrival = packet.time - prev_packet.time
        proto = 0
        if packet.haslayer(TCP):
            proto = 1
        elif packet.haslayer(UDP):
            proto = 2
        elif packet.haslayer(DNS):
            proto = 3

        features = np.array([[size, inter_arrival, proto]])
        prediction = self.model.predict(features)

        if prediction[0] == -1:
            score = self.model.decision_function(features)[0]
            return f"Behavioral anomaly detected (score: {score:.2f})"

        return None

    def analyze(self, packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src

            if src_ip in self.blocked_devices:
                return ("BLOCKED", "Packet blocked by mitigation rule")
            elif src_ip in self.silent_blocked_ips:
                return ("SILENT_BLOCK", None)

        mirai_alert = self.detect_mirai(packet)
        if mirai_alert:
            self._track_malicious_device(packet, mirai_alert)
            return ("CRITICAL", mirai_alert)

        self.packet_buffer.append(packet)
        flow_key = self.update_flow_stats(packet)

        if flow_key:
            flow_alerts = self.detect_flow_anomalies(flow_key)
            if flow_alerts:
                return ("WARNING", " | ".join(flow_alerts))

        behavior_alert = self.detect_behavioral_anomalies(packet)
        if behavior_alert:
            return ("WARNING", behavior_alert)

        if len(self.packet_buffer) >= 50:
            sizes = [len(p) for p in list(self.packet_buffer)[-50:]]
            avg_size = np.mean(sizes)
            std_size = np.std(sizes)

            if len(packet) > avg_size + 3 * std_size:
                return ("WARNING", f"Oversized packet ({len(packet)} bytes, avg: {avg_size:.1f}±{std_size:.1f})")

            if std_size > 2 * self.baselines['packet_sizes']['std']:
                return ("NOTICE", f"Unstable traffic (size deviation: {std_size:.1f} bytes)")

        return ("NORMAL", "Traffic within expected parameters")

    def _track_malicious_device(self, packet, alert):
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

        if src_ip not in self.malicious_devices:
            self.malicious_devices[src_ip] = {
                'count': 1,
                'first_seen': time.time(),
                'last_seen': time.time(),
                'threat_level': 'CRITICAL',
                'alerts': [alert]
            }
        else:
            self.malicious_devices[src_ip]['count'] += 1
            self.malicious_devices[src_ip]['last_seen'] = time.time()
            self.malicious_devices[src_ip]['alerts'].append(alert)

    def mitigate_device(self, ip, action, duration=None):
        silent = False
        if isinstance(action, str) and "_silent" in action:
            silent = True
            action = action.replace("_silent", "")

        if action == "isolate":
            self.block_ip_address(ip, "block")
            if silent:
                self.silent_blocked_ips.add(ip)
            else:
                self.blocked_devices[ip] = {
                    'action': 'isolate',
                    'timestamp': time.time(),
                    'duration': float('inf'),
                    'active': True
                }
            return f"Device {ip} isolated {'silently' if silent else ''}"

        elif action == "temporary_block":
            if duration is None:
                duration = 3600
            self.block_ip_address(ip, "block")
            if silent:
                self.silent_blocked_ips.add(ip)
            else:
                self.blocked_devices[ip] = {
                    'action': 'temporary_block',
                    'timestamp': time.time(),
                    'duration': duration,
                    'active': True
                }
            return f"Device {ip} blocked for {duration} seconds ({'silent' if silent else 'visible'})"

        elif action == "auto_block":
            self.block_ip_address(ip, "block")
            self.silent_blocked_ips.add(ip)
            return f"Device {ip} in auto-block mode"

        elif action == "unblock":
            if ip in self.blocked_devices:
                del self.blocked_devices[ip]
            if ip in self.silent_blocked_ips:
                self.silent_blocked_ips.remove(ip)
            self.block_ip_address(ip, "unblock")
            return f"Device {ip} unblocked"

        return "Unknown action"

    def block_ip_address(self, ip, action):
        system = platform.system()
        try:
            if system == "Linux":
                if action == "block":
                    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                else:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
            elif system == "Windows":
                if action == "block":
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    f"name=Block_{ip}", "dir=in", "action=block",
                                    "remoteip=" + ip], check=True)
                else:
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                    f"name=Block_{ip}"], check=True)
            elif system == "Darwin":  # macOS
                if action == "block":
                    subprocess.run(["pfctl", "-t", "blocked", "-T", "add", ip], check=True)
                else:
                    subprocess.run(["pfctl", "-t", "blocked", "-T", "delete", ip], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error {action}ing IP {ip}: {str(e)}")
            return False
        return True


class PacketCaptureWindow(tk.Toplevel):
    def __init__(self, parent, target_ip, target_mac):
        super().__init__(parent)
        self.title(f"Advanced Packet Capture - {target_ip}")
        self.geometry("1200x800")
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.attack_count = 0
        self.traffic_analyzer = EnhancedTrafficAnalyzer()
        self.traffic_analyzer.target_ip = target_ip
        self.traffic_analyzer.known_devices = {target_ip}

        # Initialize all attributes
        self.silent_block_var = tk.BooleanVar(value=False)
        self.auto_unblock_var = tk.BooleanVar(value=True)
        self.has_malicious = False

        self.packet_data = {
            'timestamps': np.zeros(10000, dtype=np.float64),
            'sizes': np.zeros(10000, dtype=np.int16),
            'types': np.zeros(10000, dtype=np.uint8)
        }
        self.data_index = 0
        self.packet_cache = {}

        self.create_widgets()
        self.setup_mitigation_controls()
        self.start_capture()
        self.start_monitor_thread()

    def create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Information frame
        info_frame = ttk.Frame(main_frame)
        info_frame.pack(fill=tk.X, pady=5)

        ttk.Label(info_frame,
                  text=f"Capturing ALL packets for {self.target_ip} ({self.target_mac})",
                  font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT, padx=10)

        self.attack_label = ttk.Label(info_frame,
                                      text="Malicious Packets Detected: 0",
                                      foreground="red",
                                      font=('Helvetica', 10, 'bold'))
        self.attack_label.pack(side=tk.RIGHT, padx=10)

        # Graph frame
        graph_frame = ttk.Frame(main_frame)
        graph_frame.pack(fill=tk.X, pady=5)

        self.fig, self.ax = plt.subplots(figsize=(10, 3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.line, = self.ax.plot([], [], 'b-', alpha=0.7, linewidth=0.5)
        self.ax.set_title("Incoming Packet Flow", pad=10)
        self.ax.set_xlabel("Time (seconds)", labelpad=5)
        self.ax.set_ylabel("Packet Size (bytes)", labelpad=5)
        self.ax.grid(True, alpha=0.2)
        self.ax.set_xlim(0, 10)
        self.ax.set_ylim(0, 1500)

        self.x_min = 0
        self.x_max = 10
        self.y_min = 0
        self.y_max = 1500

        # Packet list and details
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        list_frame = ttk.Frame(paned_window)
        scroll_y = ttk.Scrollbar(list_frame)
        scroll_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL)

        self.packet_list = tk.Listbox(
            list_frame,
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set,
            width=70,
            height=25,
            font=('Consolas', 8),
            selectbackground='#0078d7',
            selectforeground='white'
        )
        self.packet_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_y.config(command=self.packet_list.yview)
        scroll_x.config(command=self.packet_list.xview)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)

        detail_frame = ttk.Frame(paned_window)
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame,
            wrap=tk.WORD,
            font=('Consolas', 9),
            padx=10,
            pady=10,
            width=80
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        paned_window.add(list_frame, weight=1)
        paned_window.add(detail_frame, weight=1)

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Start", command=self.start_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Stop", command=self.stop_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear", command=self.clear_capture).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save PCAP", command=self.save_pcap).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export Text", command=self.export_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Download Graph", command=self.download_graph).pack(side=tk.LEFT, padx=5)

        self.packet_list.bind('<<ListboxSelect>>', self.show_packet_details)

    def setup_mitigation_controls(self):
        self.mitigation_frame = ttk.Frame(self)
        self.mitigation_frame.pack(fill=tk.X, pady=5)

        self.mitigate_button = ttk.Button(
            self.mitigation_frame,
            text="Mitigate Threat",
            command=self.show_mitigation_options,
            state=tk.DISABLED
        )
        self.mitigate_button.pack(side=tk.LEFT, padx=5)

        self.block_status = ttk.Label(
            self.mitigation_frame,
            text="",
            foreground="red"
        )
        self.block_status.pack(side=tk.LEFT, padx=10)

    def update_graph(self):
        valid_idx = min(10000, self.data_index)
        if valid_idx == 0:
            return

        x = self.packet_data['timestamps'][:valid_idx]
        y = self.packet_data['sizes'][:valid_idx]

        if len(x) == 0:
            return

        x = x - x[0]  # Normalize timestamps

        new_x_min = max(0, x[-1] - 30)
        new_x_max = x[-1] + 2

        if new_x_max > self.x_max or new_x_min < self.x_min:
            self.x_min, self.x_max = new_x_min, new_x_max
            self.ax.set_xlim(self.x_min, self.x_max)

        if len(y) > 0:
            visible_mask = (x >= self.x_min) & (x <= self.x_max)
            visible_y = y[visible_mask]
            if len(visible_y) > 0:
                new_y_max = max(visible_y) * 1.2
                if abs(new_y_max - self.y_max) > (0.1 * self.y_max):
                    self.y_max = new_y_max
                    self.ax.set_ylim(self.y_min, self.y_max)

        self.line.set_data(x, y)
        self.ax.relim()
        self.ax.autoscale_view(scalex=False, scaley=False)
        self.canvas.draw_idle()

    def _process_packet(self, packet):
        try:
            timestamp = time.time()
            size = len(packet)
            severity, alert = self.traffic_analyzer.analyze(packet)

            if severity == "SILENT_BLOCK":
                return

            ptype = 4
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                ptype = 2
            elif packet.haslayer(HTTPRequest):
                ptype = 3
            elif packet.haslayer(TCP):
                ptype = 0
            elif packet.haslayer(UDP):
                ptype = 1

            summary = self._create_packet_summary(packet, timestamp, size)

            if severity in ["CRITICAL", "WARNING"]:
                summary = f"[{severity}] " + summary

            if severity == "CRITICAL":
                self.attack_count += 1
                self.attack_label.config(text=f"Malicious Packets Detected: {self.attack_count}")
                self.has_malicious = True
                self.mitigate_button.config(state=tk.NORMAL)

            self.packet_queue.put((timestamp, size, ptype, packet, summary))
        except Exception as e:
            print(f"Packet processing error: {e}")

    def _run_capture(self, filter_str):
        sniff(
            filter=filter_str,
            prn=self._process_packet,
            store=False,
            stop_filter=lambda _: not self.running
        )

    def start_capture(self):
        if not self.running:
            self.running = True
            filter_str = f"host {self.target_ip}"

            self.capture_thread = threading.Thread(
                target=self._run_capture,
                args=(filter_str,),
                daemon=True
            )
            self.capture_thread.start()

            self.gui_thread = threading.Thread(
                target=self._update_gui,
                daemon=True
            )
            self.gui_thread.start()

    def _update_gui(self):
        last_update = time.time()
        batch = []

        while self.running:
            try:
                while len(batch) < 200 and not self.packet_queue.empty():
                    batch.append(self.packet_queue.get_nowait())

                if batch and (time.time() - last_update > 0.1 or len(batch) >= 200):
                    self._process_batch(batch)
                    batch = []
                    last_update = time.time()

                time.sleep(0.01)
            except Exception as e:
                print(f"GUI update error: {e}")
                break

    def _process_batch(self, batch):
        for timestamp, size, ptype, packet, summary in batch:
            idx = self.data_index % 10000
            self.packet_data['timestamps'][idx] = timestamp
            self.packet_data['sizes'][idx] = size
            self.packet_data['types'][idx] = ptype
            self.data_index += 1

            self.packet_cache[summary] = packet
            self.packet_list.insert(tk.END, summary)

            if "[CRITICAL]" in summary:
                self.packet_list.itemconfig(tk.END, {'fg': 'red'})
            elif "[WARNING]" in summary:
                self.packet_list.itemconfig(tk.END, {'fg': 'orange'})
            elif "[BLOCKED]" in summary:
                self.packet_list.itemconfig(tk.END, {'fg': 'gray'})

            self.packet_list.yview(tk.END)
            self.update_graph()

            if random.random() < 0.1:
                self.update_block_status()

    def update_block_status(self):
        ip = self.target_ip
        if ip in self.traffic_analyzer.silent_blocked_ips:
            status = "SILENTLY BLOCKED (analyzing)"
            color = "orange"
        elif ip in self.traffic_analyzer.blocked_devices:
            status = "VISIBLY BLOCKED"
            color = "red"
        else:
            status = "MONITORING"
            color = "green"

        self.block_status.config(text=status, foreground=color)

    def start_monitor_thread(self):
        def monitor():
            while self.running:
                try:
                    for ip in list(self.traffic_analyzer.silent_blocked_ips):
                        if self.traffic_analyzer.check_for_auto_unblock(ip):
                            self.after(0, lambda: messagebox.showinfo(
                                "Auto-Unblock",
                                f"Device {ip} has been automatically unblocked"
                            ))
                            self.after(0, self.update_block_status)
                    time.sleep(10)
                except Exception as e:
                    print(f"Monitor thread error: {e}")

        threading.Thread(target=monitor, daemon=True).start()

    def show_mitigation_options(self):
        if not self.has_malicious:
            return

        popup = tk.Toplevel(self)
        popup.title("Mitigation Options")
        popup.geometry("400x300")
        popup.resizable(False, False)

        ttk.Label(popup, text="Select Mitigation Action:",
                  font=('Helvetica', 10, 'bold')).pack(pady=10)

        # Blocking type selection
        block_frame = ttk.Frame(popup)
        block_frame.pack(pady=5)

        ttk.Checkbutton(
            block_frame,
            text="Silent Block (hide from GUI)",
            variable=self.silent_block_var
        ).pack(side=tk.LEFT, padx=5)

        ttk.Checkbutton(
            block_frame,
            text="Auto-Unblock When Safe",
            variable=self.auto_unblock_var
        ).pack(side=tk.LEFT, padx=5)

        # Action buttons
        ttk.Button(
            popup,
            text="1. Isolate Device (Block All Traffic)",
            command=lambda: self.apply_mitigation("isolate"),
            width=40
        ).pack(pady=5)

        # Temporary block with duration selection
        time_frame = ttk.Frame(popup)
        time_frame.pack(pady=5)
        ttk.Label(time_frame, text="Block for:").pack(side=tk.LEFT)

        self.block_time = ttk.Combobox(time_frame,
                                       values=["5 min", "15 min", "1 hour", "4 hours", "24 hours"])
        self.block_time.pack(side=tk.LEFT, padx=5)
        self.block_time.current(2)  # Default to 1 hour

        ttk.Button(
            popup,
            text="2. Temporary Block",
            command=lambda: self.apply_mitigation("temporary_block"),
            width=40
        ).pack(pady=5)

        ttk.Button(
            popup,
            text="3. Auto-Block (Unblock When Safe)",
            command=lambda: self.apply_mitigation("auto_block"),
            width=40
        ).pack(pady=5)

        ttk.Button(
            popup,
            text="Unblock Device",
            command=lambda: self.apply_mitigation("unblock"),
            width=40,
            style='danger.TButton'
        ).pack(pady=5)

    def apply_mitigation(self, action):
        duration = None
        if action == "temporary_block":
            time_str = self.block_time.get()
            duration = {
                "5 min": 300,
                "15 min": 900,
                "1 hour": 3600,
                "4 hours": 14400,
                "24 hours": 86400
            }[time_str]

        silent = self.silent_block_var.get()
        if silent and action in ["isolate", "temporary_block"]:
            action = f"{action}_silent"
        elif action == "auto_block":
            silent = True

        result = self.traffic_analyzer.mitigate_device(
            self.target_ip,
            action,
            duration
        )
        messagebox.showinfo("Mitigation Applied", result)
        self.update_block_status()

    def _create_packet_summary(self, packet, timestamp, size):
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            return f"{time_str} DNS: {packet[DNSQR].qname.decode(errors='ignore')} ({size} bytes)"
        elif packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            host = http.Host.decode() if http.Host else ""
            path = http.Path.decode() if http.Path else ""
            return f"{time_str} HTTP: {host}{path} ({size} bytes)"
        elif packet.haslayer(IP):
            ip = packet[IP]
            proto = ""
            if packet.haslayer(TCP):
                proto = f"TCP {ip.src}:{packet[TCP].sport}→{ip.dst}:{packet[TCP].dport}"
            elif packet.haslayer(UDP):
                proto = f"UDP {ip.src}:{packet[UDP].sport}→{ip.dst}:{packet[UDP].dport}"
            return f"{time_str} {proto} ({size} bytes)"

        return f"{time_str} {packet.summary()} ({size} bytes)"

    def show_packet_details(self, event):
        selection = self.packet_list.curselection()
        if not selection:
            return

        summary = self.packet_list.get(selection[0])
        packet = self.packet_cache.get(summary)

        if packet:
            self.detail_text.config(state=tk.NORMAL)
            self.detail_text.delete(1.0, tk.END)
            analysis = self._analyze_packet(packet)
            self.detail_text.insert(tk.END, analysis.split('\n')[0] + '\n')

            if "MALWARE DETECTION" in analysis:
                parts = analysis.split("MALWARE DETECTION")
                self.detail_text.insert(tk.END, parts[0])
                self.detail_text.insert(tk.END, "MALWARE DETECTION", 'red')
                self.detail_text.tag_config('red', foreground='red')
                self.detail_text.insert(tk.END, parts[1])
            else:
                self.detail_text.insert(tk.END, analysis)

            self.detail_text.config(state=tk.DISABLED)

    def _analyze_packet(self, packet):
        output = []
        output.append("=== Complete Packet Analysis ===")
        output.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        output.append(f"Total Size: {len(packet)} bytes")

        mirai_alert = self.traffic_analyzer.detect_mirai(packet)
        if mirai_alert:
            output.append("\n⚠️⚠️⚠️ MALWARE DETECTION ⚠️⚠️⚠️")
            output.append(f"THREAT: {mirai_alert}")
            output.append("ACTION: Consider blocking this traffic immediately!")

        output.append("\n--- Protocol Layers ---")

        if Ether in packet:
            eth = packet[Ether]
            output.append("\n[Ethernet]")
            output.append(f"Source: {eth.src}")
            output.append(f"Destination: {eth.dst}")
            output.append(f"Type: 0x{eth.type:04x}")

        if IP in packet:
            ip = packet[IP]
            output.append("\n[IP]")
            output.append(f"Source: {ip.src}")
            output.append(f"Destination: {ip.dst}")
            output.append(f"Protocol: {ip.proto}")
            output.append(f"TTL: {ip.ttl}")

        if TCP in packet:
            tcp = packet[TCP]
            output.append("\n[TCP]")
            output.append(f"Source Port: {tcp.sport}")
            output.append(f"Dest Port: {tcp.dport}")
            output.append(f"Flags: {self._get_tcp_flags(tcp.flags)}")
        elif UDP in packet:
            udp = packet[UDP]
            output.append("\n[UDP]")
            output.append(f"Source Port: {udp.sport}")
            output.append(f"Dest Port: {udp.dport}")

        if DNS in packet:
            output.append("\n[DNS]")
            if packet.haslayer(DNSQR):
                output.append(f"Query: {packet[DNSQR].qname.decode(errors='ignore')}")

        if HTTPRequest in packet:
            http = packet[HTTPRequest]
            output.append("\n[HTTP Request]")
            output.append(f"Method: {http.Method.decode()}")
            output.append(f"Host: {http.Host.decode() if http.Host else ''}")
            output.append(f"Path: {http.Path.decode() if http.Path else ''}")

        if Raw in packet:
            payload = packet[Raw].load
            output.append("\n[Payload]")
            if len(payload) > 0:
                try:
                    text = payload.decode('utf-8', errors='replace')
                    if len(text) > 0:
                        output.append("Text Content:")
                        output.append(textwrap.indent(text, '  '))
                except Exception:
                    output.append(f"Binary Data ({len(payload)} bytes):")
                    output.append(textwrap.indent(payload.hex()[:200], '  '))
            else:
                output.append("Empty payload")

        return '\n'.join(output)

    def _get_tcp_flags(self, flags):
        flag_names = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        active_flags = [flag_names[i] for i in range(8) if flags & (1 << i)]
        return ', '.join(active_flags) if active_flags else 'None'

    def stop_capture(self):
        self.running = False
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join(timeout=1)

    def clear_capture(self):
        self.packet_list.delete(0, tk.END)
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.config(state=tk.DISABLED)
        self.data_index = 0
        for key in self.packet_data:
            self.packet_data[key].fill(0)
        self.line.set_data([], [])
        self.ax.set_xlim(0, 10)
        self.ax.set_ylim(0, 1500)
        self.x_min = 0
        self.x_max = 10
        self.y_min = 0
        self.y_max = 1500
        self.canvas.draw_idle()

    def save_pcap(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if file_path:
            from scapy.all import wrpcap
            packets = list(self.packet_cache.values())
            if packets:
                wrpcap(file_path, packets)
                messagebox.showinfo("Success", f"Saved {len(packets)} packets to {file_path}")
            else:
                messagebox.showwarning("Warning", "No packets to save")

    def export_text(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, 'w') as f:
                for summary in self.packet_cache:
                    packet = self.packet_cache[summary]
                    analysis = self._analyze_packet(packet)
                    f.write(f"=== Packet: {summary} ===\n")
                    f.write(analysis)
                    f.write("\n\n")
            messagebox.showinfo("Success", f"Exported packet details to {file_path}")

    def download_graph(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("PDF files", "*.pdf"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            try:
                self.fig.savefig(file_path, dpi=300, bbox_inches='tight')
                messagebox.showinfo("Success", f"Graph saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save graph: {str(e)}")

    def destroy(self):
        self.stop_capture()
        super().destroy()


class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.current_network = self.get_current_network()

    def get_current_network(self):
        network_info = {
            "SSID": "Unknown",
            "Gateway": "192.168.1.1",
            "Your_IP": "127.0.0.1",
            "Subnet": "192.168.1.0/24"
        }
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"]
                ).decode('utf-8', errors='ignore')
                ssid_match = re.search(r"SSID\s+:\s(.+)", output)
                if ssid_match:
                    network_info["SSID"] = ssid_match.group(1).strip()
            else:
                output = subprocess.check_output(["iwgetid", "-r"]).decode('utf-8').strip()
                if output:
                    network_info["SSID"] = output

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            network_info["Your_IP"] = s.getsockname()[0]
            s.close()

            gateway_ip = network_info["Your_IP"].rsplit('.', 1)[0] + '.1'
            network_info["Gateway"] = gateway_ip
            network_info["Subnet"] = f"{gateway_ip}/24"

        except Exception as e:
            print(f"Error getting network info: {e}")

        return network_info

    def fast_arp_scan(self):
        try:
            arp = ARP(pdst=self.current_network["Subnet"])
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=2, verbose=0)[0]
            self.devices = [{
                'ip': received.psrc,
                'mac': received.hwsrc,
                'active': 'Active',
                'secure': 'Secure'
            } for sent, received in result]
        except Exception as e:
            print(f"Scanning error: {e}")
            self.devices = []


class IoTDashboard(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IoT Security Analyzer - Complete Packet Capture")
        self.geometry("1100x750")
        self.scanner = NetworkScanner()
        self.active_windows = {}
        self.create_widgets()
        self.update_devices()
        self.configure_styles()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def configure_styles(self):
        style = ttk.Style()
        style.configure('danger.TButton', foreground='white', background='red')
        style.map('danger.TButton',
                  foreground=[('active', 'white'), ('disabled', 'gray')],
                  background=[('active', 'darkred'), ('disabled', 'lightgray')])

    def create_widgets(self):
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)

        info_frame = ttk.Frame(self)
        info_frame.pack(pady=5, fill=tk.X, padx=10)

        ttk.Label(info_frame,
                  text=f"Network: {self.scanner.current_network['SSID']}",
                  font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT, padx=10)
        ttk.Label(info_frame,
                  text=f"Your IP: {self.scanner.current_network['Your_IP']}").pack(side=tk.LEFT, padx=10)
        ttk.Label(info_frame,
                  text=f"Gateway: {self.scanner.current_network['Gateway']}").pack(side=tk.LEFT, padx=10)

        self.device_tree = ttk.Treeview(self, columns=('IP', 'MAC', 'Status'), show='headings')
        self.device_tree.heading('IP', text='IP Address')
        self.device_tree.heading('MAC', text='MAC Address')
        self.device_tree.heading('Status', text='Status')
        self.device_tree.column('IP', width=150, anchor=tk.CENTER)
        self.device_tree.column('MAC', width=175, anchor=tk.CENTER)
        self.device_tree.column('Status', width=100, anchor=tk.CENTER)
        self.device_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.device_tree.bind('<Double-1>', self.show_device_analysis)

        control_frame = ttk.Frame(self)
        control_frame.pack(pady=5)

        ttk.Button(control_frame, text="Scan Network", command=self.update_devices).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Rescan", command=self.rescan_network).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Exit", command=self.on_close).pack(side=tk.LEFT, padx=5)

    def rescan_network(self):
        self.scanner = NetworkScanner()
        self.update_devices()

    def update_devices(self):
        threading.Thread(target=self.scanner.fast_arp_scan, daemon=True).start()
        self.device_tree.delete(*self.device_tree.get_children())
        for device in self.scanner.devices:
            self.device_tree.insert("", 'end', values=(
                device['ip'],
                device['mac'],
                device['active']
            ))

    def show_device_analysis(self, event):
        item = self.device_tree.selection()
        if not item:
            return

        item = item[0]
        ip, mac, status = self.device_tree.item(item, 'values')

        if ip in self.active_windows:
            try:
                if self.active_windows[ip].winfo_exists():
                    self.active_windows[ip].lift()
                    return
            except tk.TclError:
                del self.active_windows[ip]

        self.active_windows[ip] = PacketCaptureWindow(self, ip, mac)
        self.active_windows[ip].protocol("WM_DELETE_WINDOW",
                                          lambda: self.on_window_close(ip))

    def on_window_close(self, ip):
        if ip in self.active_windows:
            self.active_windows[ip].destroy()
            del self.active_windows[ip]

    def on_close(self):
        for ip in list(self.active_windows.keys()):
            self.on_window_close(ip)
        self.destroy()


if __name__ == "__main__":
    app = IoTDashboard()
    app.mainloop()
