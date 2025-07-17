import threading
from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk

captured_packets = []
sniffing = False
sniffer_thread = None

def process_packet(packet):
    global captured_packets
    if IP in packet:
        ip_layer = packet[IP]
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        if protocol_filter.get() != "All" and protocol_filter.get() != proto:
            return  # Skip this packet

        packet_info = f"{ip_layer.src} -> {ip_layer.dst} | Protocol: {proto}\n"
        text_box.insert(tk.END, packet_info)
        text_box.see(tk.END)
        captured_packets.append(packet)

def start_sniffing():
    global sniffing, sniffer_thread, captured_packets
    if sniffing:
        return
    sniffing = True
    captured_packets = []
    text_box.insert(tk.END, "[+] Starting sniffing...\n")

    sniffer_thread = threading.Thread(target=lambda: sniff(prn=process_packet, store=0, stop_filter=lambda x: not sniffing))
    sniffer_thread.daemon = True
    sniffer_thread.start()

def stop_sniffing():
    global sniffing
    if sniffing:
        sniffing = False
        text_box.insert(tk.END, "[!] Stopping sniffing...\n")

def save_to_file():
    if not captured_packets:
        messagebox.showinfo("No Packets", "No packets captured to save.")
        return

    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP Files", "*.pcap")])
    if file_path:
        wrpcap(file_path, captured_packets)
        messagebox.showinfo("Saved", f"Packets saved to {file_path}")
root = tk.Tk()
root.title("Python Network Sniffer")
root.geometry("850x600")

top_frame = tk.Frame(root)
top_frame.pack(pady=10)

tk.Label(top_frame, text="Protocol Filter:").pack(side=tk.LEFT, padx=5)
protocol_filter = ttk.Combobox(top_frame, values=["All", "TCP", "UDP"], state="readonly")
protocol_filter.current(0)
protocol_filter.pack(side=tk.LEFT, padx=5)

start_button = tk.Button(top_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_button.pack(side=tk.LEFT, padx=10)

stop_button = tk.Button(top_frame, text="Stop", command=stop_sniffing, bg="red", fg="white")
stop_button.pack(side=tk.LEFT, padx=10)

save_button = tk.Button(top_frame, text="Save to PCAP", command=save_to_file, bg="blue", fg="white")
save_button.pack(side=tk.LEFT, padx=10)

text_box = scrolledtext.ScrolledText(root, width=110, height=30, bg="black", fg="lime", font=("Courier", 10))
text_box.pack(padx=10, pady=10)

root.mainloop()
