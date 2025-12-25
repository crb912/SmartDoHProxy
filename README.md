# DNS over HTTPS (DoH) Server

A lightweight Python implementation of a DNS over HTTPS (DoH) proxy server that supports receiving DNS requests, querying DNS from upstream DoH servers, and returning the results.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone git@github.com:crb912/SmartDoHProxy.git
# 2. Configure
nano config.toml  # Edit DNS port and DoH servers
# 3. Run
sudo python3 /path_to_file/dns_doh_python/doh.py

# If DNS sever bind error: [Errno 98] Address already in use. 
# sudo ss -tulnp | grep :53 

```

Popular DoH Providers

| Provider | URL | Region |
|----------|-----|--------|
| Google | `https://8.8.8.8/dns-query` | Global |
| Cloudflare | `https://1.1.1.1/dns-query` | Global |
| Quad9 | `https://9.9.9.9/dns-query` | Global |
| Alibaba | `https://dns.alidns.com/dns-query` | China |
| DNSPod | `https://doh.pub/dns-query` | China |
                    

## 🧪 Test and Benchmark with dnsperf
Test
```bash
# Test DNS resolution
dig @127.0.0.1 -p 5553 www.google.com   
dig @127.0.0.1 -p 5553 test.com

```

#### 1. Benchmark with dnsperf (cache hit)
```
sudo apt-get install dnsperf
cat > queries.txt << EOF
www.google.com A
www.github.com A
www.stackoverflow.com A
www.reddit.com A
baidu.com A
douyin.com A
taobao.com A
EOF
```

Run benchmark
```
dnsperf -s 127.0.0.1 -p 5553 -t 10 -d q2.txt -Q 10000 -c 5 -l 60

Expected results (Python)
Run time (s):  60, Queries per second:   2644
Average Latency (s): 0.0377
Queries lost:         0 (0.00%)
```

#### 2. Benchmark with dnsperf (cache miss)
`dnsperf -s 127.0.0.1 -p 5553 -t 10 -d x.txt -Q 10000 -c 30 -l 60`

Expected results (Python)  QPS: 132

## 🏗️ Architecture

```
┌─────────────┐         ┌──────────────┐    ┌──────────────┐         ┌─────────────┐
│   Client    │         │   DNS Server │    │  DoH Client  │         │ DoH Provider│
│  (dig/app)  │ ──UDP──>│ 127.0.0.1:53 │ ──>│ 127.0.0.1    │ ─HTTPS─>│  (8.8.8.8)  │
└─────────────┘         └──────────────┘    └──────────────┘         └─────────────┘
                              │
                              ↓
                        ┌──────────┐
                        │  Cache   │
                        │ (5M max) │
                        └──────────┘
```

How It Works

1. **Client Query**: Your app sends a DNS query to `127.0.0.1:53`
2. **Cache Check**: Server checks local cache first
3. **Cache Hit**: Returns cached result immediately, refreshes in background
4. **Cache Miss**: Queries DoH provider(s) over HTTPS
5. **Response**: Returns result and caches for future queries
6. **Persistence**: Cache auto-saves every 3 days


## 🎯 Deploy as systemd Service (Linux)

```bash
sudo nano /etc/systemd/system/smart_doh_proxy.service
```
Service File

```text
[Unit]
Description=DoH DNS Proxy Server
After=network.target

[Service]
Type=simple
User=bing
WorkingDirectory=/home/bing/work_dev/smart_doh_proxy
ExecStart=/usr/bin/python3 /home/bing/work_dev/smart_doh_proxy/doh.py
Restart=always
RestartSec=10
StandardOutput=null
StandardError=null
SyslogIdentifier=smart_doh_proxy
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target

```


```
sudo systemctl daemon-reload
sudo systemctl start smart_doh_proxy
# auto run
sudo systemctl enable smart_doh_proxy
sudo systemctl status smart_doh_proxy
```

## References
- [DNS response msg format -HuaWeo](https://support.huawei.com/enterprise/zh/doc/EDOC1100174722/f917b5d7)
