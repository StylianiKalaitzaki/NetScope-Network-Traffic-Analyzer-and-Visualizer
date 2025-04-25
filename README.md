# 📡 NetScope: Network Traffic Analyzer and Visualizer

A Python-based tool to analyze and visualize network traffic from compressed `.pcap` files.  
NetScope extracts protocol-level packet data, summarizes traffic flows, and creates clear visualizations to help understand network behavior—ideal for cybersecurity, data analysis, or educational use.

---

## 🔍 Features

- 📦 **Reads `.pcap` files** from `.tar.gz` archives using `dpkt`
- 🌐 **Protocol parsing**: TCP, UDP, ICMP, ARP
- 📊 **Traffic analysis**: Packet size, flow size, per-protocol stats
- 📈 **Visualizations**: Histograms, pie charts, bar graphs, and CDFs
- 🧠 **Statistical summaries**: For both packet-level and flow-level data
- 🔐 **Security insight**: Ideal for analyzing traffic patterns, suspicious flows, and protocol distribution

---

## 🛠️ Tech Stack

- **Language**: Python  
- **Libraries**: `dpkt`, `Pandas`, `NumPy`, `Matplotlib`, `socket`, `tarfile`, `io`

---

## 📂 How It Works

1. **Read `.pcap` files** from a `.tar.gz` archive
2. **Parse each packet** to extract metadata (IP, ports, protocol, size)
3. **Group packets into flows** (source/destination IP & port + protocol)
4. **Summarize traffic** per protocol (count, volume, percentage)
5. **Visualize data** using bar plots, histograms, pie charts, and CDFs
