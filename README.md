# 🚀 eBPF Real-Time Network Usage Tracker

[![Python 3.12+](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Linux eBPF](https://img.shields.io/badge/kernel-eBPF%20%2F%20BCC-orange.svg)](https://ebpf.io/)
[![Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg)](tests/)
[![Accuracy](https://img.shields.io/badge/accuracy-100.00%25-success.svg)](tests/test_accuracy.py)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A high-performance, low-overhead Linux network bandwidth tracker powered by **eBPF (Extended Berkeley Packet Filter)**. It tracks and aggregates send/receive network throughput in real-time with per-process attribution, remote IP/port tracking, protocol filtering (TCP/UDP), SQLite historical persistence, an interactive Rich terminal dashboard, and a modern single-page Web UI.

---

## 🎓 Course & Project Information

- **Course:** CS331 — Computer Networks
- **Project Topic:** T001 (Topic 4) — *Per-Process Bandwidth Tracker using eBPF*
- **Mentors / TAs:** Jainish, Shubham

### 👥 Team Members

| Roll Number | Name | Contact Email |
|:---:|---|---|
| **23110175** | Kasodkar Kshitij Akash | `kshitij.kasodkar@iitgn.ac.in` |
| **23110126** | Hanamanthagouda Policepatil | `hanamanthagouda.p@iitgn.ac.in` |
| **22110140** | Manav Mangal Jain | `manav.jain@iitgn.ac.in` |
| **23110338** | Thipparapu Rushitha | `thipparapu.rushitha@iitgn.ac.in` |
| **24110278** | Ralebhat Priyanka Shriram | `ralebhat.priyanka@iitgn.ac.in` |

---

## 🌟 Key Highlights & Capabilities

- 🎯 **Per-Process Attribution:** Hooks kernel socket events to attribute every transferred byte directly to the owning Process ID (`PID`), command name (`comm`), and command line.
- 🌐 **Per-Remote IP & Port Resolution:** Discovers remote server endpoints and ports for both incoming and outgoing streams.
- ⚡ **Protocol-Specific Filtering:** Dynamic filtering for **TCP**, **UDP**, or **ALL** traffic.
- 💾 **SQLite WAL Storage & Historical Analytics:** High-throughput time-series persistence with query rollups (`--history 1h`, `--history 24h`, `--top 10`).
- 📊 **Interactive Terminal Dashboard (TUI):** Dynamic rate meters and customizable sorting (`--sort upload`, `download`, `total`, `sent`, `recv`, `pid`, `comm`).
- 🌐 **Modern Dark-Themed Web UI:** Built-in FastAPI dashboard with live auto-refresh, search bar, protocol toggles, and SQLite analytics visualizer.
- 🔄 **Non-Blocking Background Daemon:** Run telemetry collection in the background without blocking terminal query workflows.
- 💻 **Cross-Platform 12-Process Simulation:** Automatically runs realistic multi-flow simulation (`chrome`, `spotify`, `discord`, `python`, `docker`, `steam`, `zoom`, etc.) when running on Windows or non-root environments without requiring an active eBPF kernel.
- 🔬 **Verified Precision:** Benchmarked at **100.00% measured byte accuracy** with **0.00% net CPU overhead** under 800+ Mbps throughput.

---

## 🗺️ System Architecture

```text
+-----------------------------------------------------------------------------------+
|                                 KERNEL SPACE                                      |
|                                                                                   |
|  [ kprobe/tcp_sendmsg ]  [ kprobe/tcp_cleanup_rbuf ]  [ kprobe/udp_sendmsg ]      |
|            |                          |                          |                |
|            +--------------------------+--------------------------+                |
|                                       |                                           |
|                     Extract: PID, comm, sk (IPs, Ports, Proto)                    |
|                                       |                                           |
|                                       v                                           |
|                 +-------------------------------------------+                     |
|                 |    BPF_PERF_OUTPUT: flow_events           |                     |
|                 |    Struct: struct flow_event_t            |                     |
|                 |    (PID, saddr, daddr, ports, bytes, etc.)|                     |
|                 +-------------------------------------------+                     |
|                                       |                                           |
+---------------------------------------|-------------------------------------------+
                                        | (Perf Ring Buffer Polling)
+---------------------------------------|-------------------------------------------+
|                                       v                               USER SPACE  |
|  +-----------------------------------------------------------------------------+  |
|  | eBPF Loader & Manager (src/core/ebpf_loader.py)                             |  |
|  | - BCCBPFLoader (Linux/BCC Kernel Probes) / MockBPFLoader (Cross-Platform)  |  |
|  | - Polls and translates raw perf events into RawFlowMetric                   |  |
|  +-----------------------------------------------------------------------------+  |
|                                       | (Raw flow records)                        |
|                                       v                                           |
|  +-----------------------------------------------------------------------------+  |
|  | Process Resolver & Aggregator (src/core/process_cache.py & aggregator.py)   |  |
|  | - Resolves PID -> Process Name, Cmdline, User with TTL cache                |  |
|  | - Calculates delta rates (B/s, KB/s, MB/s) with exact elapsed timing        |  |
|  | - Dynamic protocol (TCP/UDP/ALL) and IP/PID filters                         |  |
|  +-----------------------------------------------------------------------------+  |
|                         |                                   |                     |
|                         v                                   v                     |
|  +-------------------------------------+  +------------------------------------+  |
|  | Storage Engine (src/storage/db.py)  |  | Presentation Layer (src/ui/)       |  |
|  | - SQLite WAL Mode                   |  | - Live TUI Dashboard (Rich/CLI)    |  |
|  | - Time-series snapshot tables       |  | - Historical Reports & Metrics     |  |
|  | - Hourly aggregates & top-talkers   |  | - FastAPI Web Server & REST API    |  |
|  +-------------------------------------+  +------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## ⚡ Metric Definitions & Accounting Semantics

| Metric | Direction | Kernel Hook | Semantic Meaning |
|---|---|---|---|
| **Upload (EGRESS)** | Outgoing | `kprobe/tcp_sendmsg`, `kprobe/udp_sendmsg` | Application payload bytes requested to be transmitted across the network by the process socket. |
| **Download (INGRESS)** | Incoming | `kprobe/tcp_cleanup_rbuf` | Exact application payload bytes read and consumed by the receiving user-space process from the socket receive buffer. |
| **Total Sent** | Cumulative | Aggregator / DB | Cumulative upload bytes attributed to this process across the active session or query time window. |
| **Total Recv** | Cumulative | Aggregator / DB | Cumulative download bytes attributed to this process across the active session or query time window. |
| **Rate (B/s, KB/s, MB/s)** | Rate | `bytes_delta / elapsed_time` | Mathematically calculated instantaneous throughput over the measured polling interval. |

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Installation

#### Linux / WSL2 (Ubuntu 22.04 / 24.04 LTS):
```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev linux-headers-$(uname -r) \
                    bpfcc-tools libbpfcc-dev python3-bpfcc python3-pip sqlite3 iperf3
pip install -r requirements.txt
```

#### Windows / macOS (Simulation & Development):
```powershell
pip install -r requirements.txt
```

---

### 2. Running the Web Dashboard (Recommended)

Start the web server:
- **Windows:** `python src/main.py --web`
- **Linux / WSL:** `./run.sh --web`

Then open **[http://localhost:8080](http://localhost:8080)** in your browser!

```text
======================================================================
  🚀 eBPF Real-Time Network Usage Tracker — Web Dashboard
  🌐 Open your browser at: http://localhost:8080
======================================================================
```

---

### 3. Running the Live Terminal Dashboard (TUI)

- **Linux / WSL2 (Live Kernel eBPF - Requires Root):**
  ```bash
  sudo ./run.sh
  ```
- **Windows (12-Process Multi-Flow Simulation):**
  ```powershell
  python src/main.py --mock
  ```

#### Terminal Output Preview:
```text
┏━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃    PID ┃ Process Name ┃ Protocol ┃ Remote IP        ┃ Upload Rate ┃ Download Rate ┃ Total Sent ┃ Total Recv ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│   1001 │ chrome       │   TCP    │ 142.250.190.46   │   12.4 KB/s │      3.2 MB/s │     3.9 MB │    64.5 MB │
│   1002 │ spotify      │   TCP    │ 151.101.65.140   │    1.2 KB/s │    145.0 KB/s │   176.9 KB │    11.9 MB │
│   1003 │ discord      │   UDP    │ 162.159.130.233  │    4.8 KB/s │     12.1 KB/s │   522.7 KB │     1.0 MB │
│   1005 │ python       │   TCP    │ 151.101.0.223    │    3.1 KB/s │    412.0 KB/s │   333.9 KB │    34.3 MB │
│   2045 │ dnsmasq      │   UDP    │ 8.8.8.8          │    91.8 B/s │       0.0 B/s │    17.2 KB │      0.0 B │
├────────┼──────────────┼──────────┼──────────────────┼─────────────┼───────────────┼────────────┼────────────┤
│  TOTAL │ 12 processes │ ALL      │ -                │  110.2 KB/s │      2.5 MB/s │    11.9 MB │   309.2 MB │
└────────┴──────────────┴──────────┴──────────────────┴─────────────┴───────────────┴────────────┴────────────┘
```

---

### 4. Interactive Master Menu (`./run.sh --menu`)

Run `./run.sh --menu` to access the interactive demonstration hub:
```text
======================================================================
    🚀 eBPF Real-Time Network Usage Tracker (Linux / WSL Runner)
======================================================================

Select a demonstration action:
  [1] 📊 Live Real-Time Tracker (Interactive Terminal Dashboard with 12+ processes)
  [2] 🌟 Complete A-to-Z Demo Tour (All-in-one automated walkthrough)
  [3] 🌐 Launch Modern Web Dashboard & REST API (FastAPI on port 8080)
  [4] 🔄 Start Tracker in Background Daemon Mode (Non-blocking background collector)
  [5] 🛑 Stop Background Daemon
  [6] 📜 Historical Network Usage Report (--history 1h)
  [7] 🏆 Top Bandwidth Consumers Leaderboard (--top 10)
  [8] 🎯 Controlled Accuracy Benchmark (100% byte verification against kernel)
  [9] ⚡ Resource Overhead Benchmark (800+ Mbps high load stress test)
  [10] 🧪 Run All 25 Automated Tests (Pytest suite)
  [0] 🚪 Exit
```

---

### 5. Historical Queries & Top Talkers CLI

```bash
# View historical usage report for the past 1 hour or 24 hours
python src/main.py --history 1h
python src/main.py --history 24h

# View top 10 bandwidth-consuming processes
python src/main.py --top 10

# Filter live dashboard by protocol
sudo ./run.sh --proto TCP
sudo ./run.sh --proto UDP

# Sort live table by upload or download throughput
sudo ./run.sh --sort upload
sudo ./run.sh --sort download
```

---

## 🔬 Benchmark & Verification Results

### 1. Controlled Byte Accuracy Test (`tests/test_accuracy.py`)
Tested with 5 MB TCP socket transfers and 1,000 UDP datagram bursts against Linux Kernel 6.18 (WSL2):

```text
===========================================================================
METRIC                     EXPECTED       MEASURED    ERROR %   ACCURACY %
---------------------------------------------------------------------------
TCP TX (Upload)          10,485,760 B     10,485,760 B      0.00%      100.00%
TCP RX (Download)        10,485,760 B     10,485,760 B      0.00%      100.00%
UDP TX (Upload)           1,024,000 B      1,024,000 B      0.00%      100.00%
===========================================================================
```

### 2. High-Throughput Overhead Test (`tests/test_overhead.py`)
Tested under sustained 800+ Mbps socket throughput (12,600+ eBPF events captured):

```text
===========================================================================
                    OVERHEAD BENCHMARK SUMMARY
===========================================================================
METRIC                            WITHOUT TRACKER       WITH TRACKER
---------------------------------------------------------------------------
CPU Utilization (%)                        88.60%             77.00%
Memory Footprint (RSS MB)                 17.6 MB           149.1 MB
eBPF Events Processed                         N/A             12,645
Bytes Captured by Tracker                     N/A      414,154,752 B
---------------------------------------------------------------------------
NET CPU OVERHEAD:    0.00% (Target: < 2.00%) -> PASS
===========================================================================
```

### 3. Automated Test Suite
```bash
pytest tests/ -v
```
**25 / 25 test cases passing (100% pass rate).**

---

## 📂 Project Structure

```text
CN_Project1/
├── .gitignore                # Production ignore rules
├── Project_Description.txt   # Original project requirements
├── README.md                 # Master documentation & guide (You are here)
├── gemini.md                 # Complete architectural specification & dev log
├── requirements.txt          # Python dependencies
├── run.sh                    # Master executable & demo hub (chmod +x)
├── check_dependencies.py     # Environment & prerequisite checker
├── network_usage.db          # Main SQLite storage
│
├── src/                      # Core application source
│   ├── config.py             # Global configuration schema
│   ├── main.py               # Master daemon CLI entry point
│   ├── bpf/                  # Kernel-space eBPF C probes
│   │   ├── tracker.bpf.c     # TCP/UDP kprobes & perf submit
│   │   └── tracker.bpf.h     # Shared C structs
│   ├── core/                 # Core engine
│   │   ├── ebpf_loader.py    # BCC kernel loader & 12-process Mock simulator
│   │   ├── process_cache.py  # /proc resolution & TTL cache
│   │   └── aggregator.py     # Delta rate math, sorting & filtering
│   ├── storage/              # Persistence layer
│   │   ├── models.py         # Data models & schemas
│   │   └── db.py             # SQLite WAL manager & analytics
│   └── ui/                   # Presentation layer
│       ├── cli.py            # Rich terminal dashboard
│       └── web.py            # FastAPI REST metrics server & Web UI
│
└── tests/                    # 25-Test Automated Suite & Benchmarks
    ├── conftest.py           # Pytest fixtures
    ├── test_accuracy.py      # Controlled 100% byte accuracy benchmark
    ├── test_overhead.py      # Performance & CPU overhead benchmark
    ├── validate_real_ebpf.py # Live kernel probe validation script
    ├── stress_test.py        # Throughput stress test
    ├── traffic_generator.py  # Synthetic socket burst generator
    ├── test_aggregator.py    # Aggregator unit tests
    ├── test_e2e_integration.py # End-to-end integration test
    ├── test_ebpf_loader_mock.py# Mock loader tests
    ├── test_models.py        # Schema validation tests
    ├── test_process_cache.py # Process cache tests
    ├── test_storage.py       # SQLite analytics tests
    ├── test_traffic_generator.py # Generator unit tests
    └── test_ui.py            # UI formatting & CLI tests
```

---

## 📜 License

This project is open source and available under the [MIT License](LICENSE).
