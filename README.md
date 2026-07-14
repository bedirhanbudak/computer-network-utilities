# Network Analysis and Security Utilities

A comprehensive suite of custom networking tools developed in C and Python. This repository demonstrates practical implementations of low-level network protocol manipulation, secure communications, packet filtering, and network performance analysis.

All modules are fully organized with their own `Makefile` for automated building, testing, and dependency management.

## 📂 Repository Structure

```text
.
├── DNS_Forwarder/
│   ├── dns_forwarder.c
│   └── Makefile
├── HTTP_Downloader/
│   ├── http_downloader.c
│   └── Makefile
├── TCP_Traceroute/
│   ├── tcp_traceroute.c
│   └── Makefile
├── Ping_Traceroute_Analyzer
│   ├── pingstats.py
│   ├── trstats.py
│   ├── requirements.txt
│   └── PingVsTraceroute.txt
└── README.md
```

## 🛠️ Projects & Usage

### 1. TCP Traceroute (`/TCP_Traceroute`)
A custom traceroute implementation utilizing raw sockets to send TCP SYN packets. By targeting a specific port (e.g., 80 or 443), it effectively maps network paths while bypassing standard ICMP echo-request blocking firewalls.

* **Build:**
  ```bash
  cd TCP_Traceroute && make
  ```
* **Usage:** *(Requires root privileges for raw sockets)*
  ```bash
  sudo ./tcp_traceroute [-m MAX_HOPS] [-p DST_PORT] -t TARGET
  
  # Example:
  sudo ./tcp_traceroute -m 30 -p 80 -t google.com
  ```

### 2. DNS Forwarder with DoH (`/DNS_Forwarder`)
A robust DNS forwarder that intercepts incoming DNS queries, validates them against a customizable blocklist, and securely routes allowed queries using standard UDP or DNS-over-HTTPS (DoH) via `libcurl`. 

* **Build:**
  ```bash
  cd DNS_Forwarder && make
  ```
* **Usage:**
  ```bash
  ./dns_forwarder [-d DST_IP] -f DENY_LIST_FILE [-l LOG_FILE] [-p PORT] [-b BIND_IP] [--doh] [--doh_server DOH_SERVER]

  # Example (Using DoH with Cloudflare):
  ./dns_forwarder -f deny_list.txt --doh --doh_server 1.1.1.1 -p 5333 -b 127.0.0.1
  ```

### 3. Multi-threaded HTTP/HTTPS Downloader (`/HTTP_Downloader`)
A high-performance file downloader that leverages POSIX threads and the HTTP `Range` header to fetch different parts of a file concurrently over secure SSL/TLS connections, automatically merging the chunks upon completion.

* **Build:**
  ```bash
  cd HTTP_Downloader && make
  ```
* **Usage:**
  ```bash
  ./http_downloader -u HTTPS_URL -n NUM_PARTS -o OUTPUT_FILE
  
  # Example:
  ./http_downloader -u https://example.com/largefile.zip -n 4 -o downloaded_file.zip
  ```

### 4. Ping & Traceroute Analyzer (`/Ping_Traceroute_Analyzer`)
A Python-based suite of network analysis utilities designed to monitor, parse, and visualize network statistics.
* `pingstats.py`: Automates ICMP ping execution, parses latency data, and generates a visual boxplot.
* `trstats.py`: Executes traceroute runs over specified intervals, aggregates path discovery statistics, and logs metrics.

* **Environment Setup:**
  Using the provided `Makefile` to automatically set up a Python virtual environment and install requirements:
  ```bash
  cd Ping_Traceroute_Analyzer && make
  ```
  *(Alternatively, run `pip install -r requirements.txt`)*

* **Usage:**
  ```bash
  # Ping Stats Analyzer
  python3 pingstats.py -d WAIT_INTERVAL -m MAX_PACKETS -o OUT_JSON -g OUT_PDF -t TARGET
  
  # Traceroute Stats Analyzer
  python3 trstats.py -t TARGET -n NUM_RUNS -m MAX_HOPS -d DELAY -o OUT_JSON -g OUT_PDF
  ```

## ⚙️ General Prerequisites
Before building the C utilities, ensure your Linux/Unix environment has the necessary development libraries:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev libcurl4-openssl-dev python3 python3-pip python3-venv
```

## ⚠️ Academic Integrity Disclaimer
These utilities were developed as part of academic coursework and research in Computer Science. If you are a student, please adhere strictly to your institution's honor code. Do not use or submit this code to bypass course assignments.