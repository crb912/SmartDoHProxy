# DNS over HTTPS (DoH) Proxy · DNS over HTTPS (DoH)
A lightweight Python implementation of a DNS over HTTPS (DoH) proxy server that supports receiving DNS requests, querying DNS from upstream DoH servers, and returning the results.
一个轻量级的 Python 实现的 DNS over HTTPS 代理服务器，支持接收来自本地的DNS请求，向上游 DoH 服务商查询，并返回查询结果。
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

## 🚀 Quick Start · 快速开始
```bash
# 1. Clone the repository
git clone git@github.com:crb912/SmartDoHProxy.git
# 2. Configure
nano config.toml # Edit DNS port and DoH servers
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
6. **Persistence**: Cache auto-saves


## 🎯 Deploy as systemd Service (Linux)  · 部署

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
Command: 
```bash
sudo systemctl daemon-reload
sudo systemctl start smart_doh_proxy
# auto run
sudo systemctl enable smart_doh_proxy
sudo systemctl status smart_doh_proxy
```

Main Features

- Single-threaded, multi-coroutine asynchronous, lightweight design.
The entire server operates in a single thread using asyncio, resulting in low resource consumption and high efficiency.
Instant response on cache hit.
- If a valid cached result (with unexpired TTL) is available, the server responds immediately. When the TTL expires, the cache entry is automatically refreshed in the background without delaying the client response.
DNS query routing (splitting).
- By default, queries are sent to the DoH servers listed in the direct servers group in the configuration file. If the queried domain matches the proxy rules (typically based on GFWList), the query is routed to the DoH servers in the proxy servers group.
Bootstrap support.
- Allows resolution of upstream DoH server domain names using a separate bootstrap DNS resolver.
Deduplication of in-flight queries.
- If a query for a specific domain is already in progress, any new identical query for the same domain is discarded immediately, preventing unnecessary upstream requests and reducing overhead.
Negative caching support.
- When an upstream DoH server returns NXDOMAIN (domain does not exist), the negative response is cached. No further queries for that domain will be sent until the negative cache TTL expires.
Speed-optimized IP selection.
- For domains that resolve to multiple IP addresses, the server performs TCP pings to all IPs and caches only the fastest-connecting one for future use. (This feature currently does not support proxy groups.)
- Blacklist and whitelist support.
Domains can be blocked or forced into specific routing by directly editing the designated JSON cache file; the program automatically detects and applies changes. Blacklist/whitelist functionality can be further enhanced in the future if needed.

主要特性：

- 单线程，多协程异步，轻量化的设计。
- 缓存命中，即可响应。如果TTL过期，则后台自动更新缓存的结果。
- 支持DNS分流。DNS默认查询直连组（配置文件中 direct servers）的DoH服务器 ; 如果当前待查询的域名与代理规则匹配（通常是GWFlist），则查询代理组(proxy servers)的DoH。
- 支持Bootstrap。
- 丢弃在进行中的重复查询。对于一个域名查询，如果查询任务已经进行，新进入的相同的查询任务会直接被丢弃，避免不必要的查询开销。
- 支持负缓存。对于已经认定不存在的域名，即DoH 返回了NXDOMAIN的域名，缓存该负响应（Negative Caching）在TTL过期前不再查询。
- 速度最优。用TCP ping同一个域名的多个IP，只缓存连接速度最快的IP。（该特性目前不支持代理组）
- 支持黑名单和白名单，直接修改制定的json缓存文件即可，程序会自动读取。如果有需求，可后续优化黑白名单的功能。

## References

- [DNS response msg format -HuaWei](https://support.huawei.com/enterprise/zh/doc/EDOC1100174722/f917b5d7)


