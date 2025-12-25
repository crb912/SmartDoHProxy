from tarfile import SUPPORTED_TYPES
from typing import Tuple
import requests
import socket
import struct
import asyncio
import time
import ipaddress

from config import cf, mainlog, querylog
from config import cache_db, negative_cache, traffic_clsifier


HOST: str = cf.get("dns").get("host", "127.0.0.1")
PORT: int = cf.get("dns").get("port", 53)

# -----------------------------------------------------------------------------
#       DNS Message decode and encode
# -----------------------------------------------------------------------------
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
SOA = 6
OPT = 41
SUPPORTED_QTYPES = (QTYPE_A, QTYPE_AAAA, QTYPE_CNAME)

QDOMAIN_PTR = b'\xc0\x0c' # The pointer points to offset 12 (domain.name)
QCLASS = 1
MINIMUM_TTL = 300

RCODE_MAPPING = {
    0: "NOERROR (Query successful)",
    1: "FORMERR (Format error)",
    2: "SERVFAIL (Server failure)",
    3: "NXDOMAIN (Non-existent domain)",
    4: "NOTIMP (Not implemented)",
    5: "REFUSED (Server refused the request)",
    6: "YXDOMAIN (Domain name exists, used for dynamic updates)",
    7: "YXRRSET (Resource record set exists)",
    8: "NXRRSET (Resource record set does not exist)",
    9: "NOTAUTH (Not an authoritative server)",
    10: "NOTZONE (Operation out of zone scope)",
    11: "RCODE_11 (Reserved/Undefined)",
    12: "RCODE_12 (Reserved/Undefined)",
    13: "RCODE_13 (Reserved/Undefined)",
    14: "RCODE_14 (Reserved/Undefined)",
    15: "RCODE_15 (Reserved/Undefined)"
}

QTYPE_MAPPING={
    QTYPE_A: 'ip',
    QTYPE_AAAA: 'ipv6',
    QTYPE_CNAME: 'cname',
}

class DnsMessage:
    """
    DNS Message:
        Header: transaction_id, flags, qdcount, ancount, nscount, arcount
        Question = QNAME + QTYPE(2) + QCLASE(2)
        Answer (Resource Records):
            NAME, TYPE(2), Class(2, IN), TTL(4), RELENGTH(2), RDATA
    """

    def __init__(self, data, from_response=False, nulldata=False):
        self.dns_packet = data
        self.q_end_offset = 0
        self.response_ttl = 0
        self.from_response = from_response
        self.tid = 0
        self.qdcount = 0  # Question
        self.ancount = 0  # Answer
        self.nscount = 0  # Authority
        self.arcount = 0  # Additional
        self.qdomain = ''
        self.qtype = 0
        self.rr_records = []
        self.cache_value = ''
        self.nx_domain = False  # non-existent domain
        if not nulldata:
            self._unpack()

    # -------------- Unpack DNS message ---------------------------------------
    def _unpack(self):
        """unpack dns message"""
        try:
            if len(self.dns_packet) < 16:
                raise ValueError(f"DNS unpack err, msg too short: {len(self.dns_packet)}")
            self._unpack_header()
            self._unpack_question()
            if self.from_response:
                offset = self._unpack_answer()
                _, offset = self._unpack_authority(offset)
                _, _ = self._unpack_additionals(offset)
        except ValueError as e:
                mainlog.error(e)

    def _unpack_header(self):
        transaction_id, qflags, qdcount, ancount, _, _ = struct.unpack('!HHHHHH', self.dns_packet[:12])
        self.tid, self.qdcount, self.ancount = transaction_id, qdcount, ancount
        flags = struct.unpack('!H', self.dns_packet[2:4])[0]
        rcode = flags & 0x000F   # the last 2 bytes
        meaning = RCODE_MAPPING.get(rcode, f"unknown rcode: {rcode}")
        if self.from_response and rcode == 3 and ancount == 0:
            self.nx_domain = True  # non-existent domain
            return
        if rcode > 0:
            raise ValueError(f'DNS unpack err, rcode: {rcode}, {meaning}')

    def _unpack_question(self):
        q_start_offset = 12
        self.qdomain, offset = self._unpack_name(q_start_offset, q_section=True)
        self._unpack_question_qtype(offset)
        self.q_end_offset = offset + 4

    def _unpack_question_qtype(self, start_offset):
        end_offset = start_offset + 4
        if end_offset <= len(self.dns_packet):
            self.qtype, qclass = struct.unpack('!HH', self.dns_packet[start_offset:end_offset])
            return
        else:
            raise ValueError('DNS unpack err, msg question too short')

    def _unpack_answer(self):
        answers, offset = self._unpack_rr_section(self.ancount, self.q_end_offset)
        self._save_rr_records(answers)
        return offset

    def _unpack_authority(self, start_offset):
        authority, offset = self._unpack_rr_section(self.nscount, start_offset)
        return authority, offset

    def _unpack_additionals(self, start_offset):
        additionals, offset = self._unpack_rr_section(self.arcount, start_offset)
        self._save_rr_records(additionals)
        return additionals, offset

    def _unpack_rr_section(self, count: int, start_offset: int):
        """genel parse RR section（Answer/Authority/Additional）"""
        rr_records = []
        offset = start_offset
        for _ in range(count):
            name, offset = self._unpack_name(offset, q_section=False)
            if offset + 10 > len(self.dns_packet):
                raise ValueError("DNS unpack err, fixed field too short in RR")
            type_, class_, ttl, rdlength = struct.unpack('!HHIH', self.dns_packet[offset:offset + 10])
            offset += 10
            if offset + rdlength > len(self.dns_packet):
                raise ValueError("DNS unpack err, fixed field too short in RR")
            rdata_bytes = self.dns_packet[offset:offset + rdlength]
            offset += rdlength

            # parse RDATA
            if type_ == QTYPE_A:  # A
                rdata = '.'.join(str(b) for b in rdata_bytes)
            elif type_ == QTYPE_AAAA:  # AAAA
                rdata = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
            elif type_ == QTYPE_CNAME:  # CNAME 等别名
                rdata, _ = self._unpack_name(offset - rdlength, q_section=False)
            elif type_ == SOA:
                rdata = MINIMUM_TTL  # negative cache set default value
            elif type_ == OPT:  # OPT (EDNS)
                udp_size = class_
                ext_rcode = (ttl >> 24) & 0xFF
                version = (ttl >> 16) & 0xFF
                do_bit = (ttl >> 15) & 1
                rdata = (f"UDP Payload Size: {udp_size}, Version: {version}, "
                         f"DO bit: {do_bit}, Extended RCODE: {ext_rcode}, "
                         f"Options: {rdata_bytes.hex()}")
            else:
                rdata = rdata_bytes.hex()

            rr_records.append({
                'name': name,
                'type': type_,
                'class_or_udp_size': class_,
                'ttl': ttl,
                'rdata': rdata
            })
        return rr_records, offset

    def _unpack_name(self, start_offset: int, q_section=False):
        """
        RFC 1035 §4.1.4（Message compression）:
        Pointers may not be used in the QNAME of a question section.
        :param q_section: if parse question section, True; else, False
        """
        offset = start_offset
        domain_parts = []
        visited = set()  # No recursion, to prevent circular references.
        while offset < len(self.dns_packet):
            length = self.dns_packet[offset]
            offset += 1
            if length == 0:
                break
            if q_section is True and length > 63:
                raise ValueError(f"DNS unpack err, qname label > 63")
            # answer section: compression pointer
            if q_section is False and length >= 192:
                pointer = ((length & 0x3F) << 8) | self.dns_packet[offset]
                offset += 1
                if pointer in visited:
                    raise ValueError("DNS unpack err, compression ptr loop")
                visited.add(pointer)
                jumped_name, _ = self._unpack_name(pointer, q_section)
                if jumped_name:
                    domain_parts.append(jumped_name)
                break
            else:
                label = self.dns_packet[offset:offset + length].decode('ascii', errors='ignore')
                domain_parts.append(label)
                offset += length

        name = '.'.join(domain_parts) if domain_parts else ''
        return name, offset

    def _save_rr_records(self, records):
        """Cache only the necessary records."""
        for item in records:
            type_ = item.get('type')
            data = item.get('rdata')
            if type_ in SUPPORTED_QTYPES and data is not None:
                self.rr_records.append(item)

    # -------------- Build DNS reponse message --------------------------------
    def response(self, value: str, ttl_expired_time: int):
        """when cache hit, build dns reponse message"""
        self.cache_value = value
        try:
            header = self._build_header()
            # query message question section = response message question section
            question = self.dns_packet[12: self.q_end_offset]
            answer = self._build_response_answer(ttl_expired_time)
            return header + question + answer
        except ValueError as e:
            mainlog.error(f"{e}")
            return b''

    def response_err(self) -> bytes:
        """build an NXDOMAIN response message"""
        header = self._build_error_header()
        question = self.dns_packet[12: self.q_end_offset]
        return header + question

    def _build_header(self) -> bytes:
        tid = self.tid
        flags = 0x8180  # standard response, no error.
        qdcount, ancount = 1, 1
        return struct.pack('!HHHHHH', tid, flags, qdcount, ancount, 0, 0)

    def _build_error_header(self):
        tid = self.tid
        flags = 0x8183  # non-extist domain
        qdcount, ancount = 1, 0
        return struct.pack('!HHHHHH', tid, flags, qdcount, ancount, 0, 0)

    def _build_response_answer(self, ttl) -> bytes:
        fiex_part = QDOMAIN_PTR
        fiex_part += struct.pack('!HH', self.qtype, QCLASS)
        fiex_part += struct.pack('!I', self._build_answer_ttl(ttl))
        if self.qtype in SUPPORTED_QTYPES:
            rdata = self._build_answer_rdata()
        else:
            raise ValueError(f"build response err, unsupported qtype: {self.qtype}")
        rd_length = struct.pack('!H', len(rdata))
        return fiex_part + rd_length + rdata

    def _build_answer_ttl(self, ttl: int) -> int:
        ttl_expired_time = ttl
        ttl = ttl_expired_time - int(time.time())
        if ttl < 0:
            ttl = MINIMUM_TTL
        return ttl

    def _build_answer_rdata(self) -> bytes:
        if QTYPE_A == self.qtype:
            return socket.inet_pton(socket.AF_INET, self.cache_value)
        if QTYPE_AAAA == self.qtype:
            return socket.inet_pton(socket.AF_INET6, self.cache_value)
        if QTYPE_CNAME == self.qtype:
            return self._build_domain_name(self.cache_value)
        return b''

    # -------------- Build DNS query message ----------------------------------
    def build_query(self, domain):
        """build dns query message"""
        header = self._build_query_header()
        quetion = self._build_query_question(domain)
        return header + quetion

    def _build_query_header(self) -> bytes:
        tid = 0x1234
        flags = 0x0100  # standard query
        qdcount = 1
        return struct.pack('!HHHHHH', tid, flags, qdcount, 0, 0, 0)

    def _build_query_question(self, domain) -> bytes:
        qtype = 1
        question = self._build_domain_name(domain)
        question += b'\x00'  # 结束
        question += struct.pack('!HH', qtype, 1)
        return question

    def _build_domain_name(self, name: str) -> bytes:
        """Encode domain string into the DNS RDATA format (QNAME field standard).
        """
        encoded = b''
        for label in name.split('.'):
            encoded += struct.pack('B', len(label)) + label.encode('ascii')
        return encoded
    # -------------------------------------------------------------------------



_upd_message = DnsMessage(b'', nulldata=True)
build_udp_query = _upd_message.build_query   # bind

# -----------------------------------------------------------------------------
#       DoH DNS client
# -----------------------------------------------------------------------------
DoH_DIRECT_SERVERS = cf.get_direct_servers()
DoH_PROXY_SERVERS = cf.get_proxy_servers()
BOOTSTRAP_SERVER = cf.get_bootstrap_server()

ALL_DoH_HOSTNAMES = cf.get_doh_hostnames()

CACHE_HIT = True
CACHE_MISS = False
TTL_VALID = True
TTL_INVALID = False

TIMEOUT = 20
MAX_LANTENCY = 1000000

PROXY_RULES_HIT = True
PROXY_RULES_MISS = False

class DohProxyClient:
    def __init__(self, data: bytes, addr: Tuple[str, int], transport) -> None:
        self.data = data
        self.addr = addr
        self.transport = transport
        self.data_parsed = None
        self.qdomain = None
        self._pasre()
        self.proxy = {}

    def _pasre(self):
        dns = DnsMessage(self.data, from_response=False)
        if dns is None:
            raise ValueError('Invalid dns message from local，parse error.')
        self.dns = dns
        self.qdomain = self.dns.qdomain

    # ----------- DNS query DoH or return cached value ---------------------
    async def query(self):
        doh_server, self.proxy = self._get_servers_and_proxy(self.dns.qdomain)
        if self.dns.qtype not in (QTYPE_A, QTYPE_AAAA):
            await self._query_doh_tasks(self.dns.qdomain, doh_server)
            return

        value, cache_status, ttl_status = self._cache_query()

        if CACHE_HIT == cache_status:
            ttl = cache_db[self.dns.qdomain].get('ttl', 0)
            response_data = self.dns.response(value, ttl)
            self.transport.sendto(response_data, self.addr)
            if TTL_INVALID == ttl_status:
                await self._query_doh_tasks(self.dns.qdomain, doh_server)
            return

        if  self.dns.qdomain in negative_cache:
            t = negative_cache[self.dns.qdomain] - int(time.time())
            if  t > 0:
                self.transport.sendto(self.dns.response_err(), self.addr)
                return

        if self.dns.qdomain in ALL_DoH_HOSTNAMES:
            self._bootstrap(self.dns.qdomain)
            return
        await self._query_doh_tasks(self.dns.qdomain, doh_server)

    def _get_servers_and_proxy(self, domain):
        """If the proxy rules match, return the proxy DoH;
        otherwise, return the direct DoH."""
        if not cf.get_proxy_status():
            return DoH_DIRECT_SERVERS, {}
        if traffic_clsifier.contains(domain):
            return DoH_PROXY_SERVERS, cf.get_proxies()
        return DoH_DIRECT_SERVERS, {}

    async def _query_doh_tasks(self, domain, doh_servers: list):
        tasks = []
        for server in doh_servers:
            tasks.append(asyncio.wait_for(self._query_doh(domain, server), timeout=TIMEOUT))

        first = 0
        records = []
        for coro in asyncio.as_completed(tasks):
            dns_result = await coro
            first += 1
            if 1 == first:
                # always send the first response to client
                self.transport.sendto(dns_result, self.addr)

            dns = DnsMessage(dns_result, from_response=True)
            records.extend(dns.rr_records)

        self._nega_cache_save(records)
        self._cache_save(domain, records)


    async def _query_doh(self, domain, doh_server) -> bytes:
        """Perform a single DNS query to the upstream DoH server"""
        headers = {
            'content-type': 'application/dns-message',
            'accept': 'application/dns-message',
        }
        try:
            response = requests.post(
                doh_server,
                data=self.data,
                headers=headers,
                timeout=TIMEOUT,
                proxies=self.proxy
            )
            response.raise_for_status()
            return response.content
        except requests.exceptions.RequestException as e:
            querylog.error(f'DoH query error:{domain} -> {doh_server}, {e}')
            return b''

    # ----------- Boot Strap -------------------------------------------------------
    def _bootstrap(self, doh_hostname):
        if self._is_ip(doh_hostname):
            return
        query_msg = build_udp_query(doh_hostname)
        udp_response = self._query_udp(BOOTSTRAP_SERVER, query_msg)
        dns = DnsMessage(udp_response, from_response=True)
        self._cache_save(doh_hostname, dns.rr_records)
        if not dns.rr_records:
            querylog.error(f'bootstrap query error:{doh_hostname}')

    def _query_udp(self, server, query_msg) -> bytes:
        """Perform a single DNS query to the upstream DNS server(port 53)"""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(query_msg, (server, 53))
            data, _ = sock.recvfrom(512)
            return data

    def get_qdomain(self) -> str:
        if not self.qdomain:
            mainlog.error('null qdomain from local')
            return ''
        return self.qdomain

    # ----------- cache -------------------------------------------------------
    def _cache_query(self):
        """Query data from DNS cache"""
        qdomain = self.dns.qdomain
        cache_item = cache_db.get(qdomain, {})
        keyname = QTYPE_MAPPING.get(self.dns.qtype, '')
        value = cache_item.get(keyname, '')
        if not cache_item or not value:
            proxy = False
            if self.proxy: proxy = True
            querylog.info(f'cache miss, {qdomain}, proxy: {proxy}')
            return '', CACHE_MISS, TTL_VALID

        ttl_expire_time = cache_item.get('ttl', 0)
        enable_proxy = False
        if self.proxy:
            enable_proxy = True
        querylog.info(f'cache hit, {qdomain} -> {value}, ttl: {TTL_VALID}, proxy: {enable_proxy}')
        if ttl_expire_time > int(time.time()):
            return value, CACHE_HIT, TTL_VALID
        return value, CACHE_HIT, TTL_INVALID

    def _cache_save(self, domain: str, records: list):
        ttl = 0
        cnames = set()
        ip4_list = set()
        ip6_list = set()
        for rdat in records:
            name = rdat.get('name')
            data = rdat.get('rdata')
            if not name or not data:
                continue
            type_ = rdat.get('type')
            if type_ == QTYPE_A:
                ttl = rdat.get('ttl')
                ip4_list.add(data)
            if type_ == QTYPE_AAAA:
                ip6_list.add(data)
            elif type_ == QTYPE_CNAME:
                cnames.add(data)

        expire_time = int(time.time()) + ttl
        if len(ip4_list) > 0:
            fast_ip, expire_time = self._cache_fast_ip(domain, ttl, ip4_list)
            if cnames:
                self._cache_save_cname_ip(cnames, fast_ip, expire_time)
        if ip6_list:
            self._cache_save_ip6(domain, ip6_list[0], expire_time)

    def _cache_fast_ip(self, domain: str, ttl: int, ip_list: set):
        """Save the fastest IP for the queried domain."""
        expire_time = int(time.time()) + ttl
        if len(ip_list) == 1:
            ip = next(iter(ip_list))
            cache_db.update({domain: {'ip': ip, 'ttl': expire_time}})
            querylog.info(f'cache save, {domain} -> {ip}')
            return ip, expire_time
        else:
            fast_ip= self._get_fast_ip(ip_list)
            cache_db.update({domain: {'ip': fast_ip, 'ttl': expire_time}})
            fast_tag = "[fast]"
            if self.proxy:
                fast_tag = ''
            querylog.info(f'cache save, {domain} -> {fast_ip}{fast_tag}')
            return fast_ip, expire_time

    def _cache_save_cname_ip(self, cnames, ip4, ttl_expire_time):
        for cname in cnames:
            cache_db.update({cname: {'ip': ip4, 'ttl': ttl_expire_time}})
            querylog.info(f'cache save, {cname} -> {ip4}')

    def _cache_save_ip6(self, domain, ip6: str, ttl_expire_time: int):
        cache_db.update({domain: {'ipv6': ip6, 'ttl': ttl_expire_time}})
        querylog.info(f'cache save, {domain} -> {ip6}')

    def _nega_cache_save(self, records):
        """Negative Caching"""
        if not self.dns.nx_domain:
            return
        for item in records:
            type_ = item.get('type')
            name = item.get('name')
            if SOA != type_ or not name:
                continue
            ttl_expire_time = item.get('rdata', MINIMUM_TTL) + int(time.time())
            negative_cache[name] =  ttl_expire_time

    # -------------------------------------------------------------------------
    def _is_ip(self, domain) -> bool:
        try:
            ipaddress.ip_address(domain)  # skip ip
            return True
        except ValueError:
            return False

    def _get_fast_ip(self, ip_list: set):
        lowest_latency = MAX_LANTENCY
        fastip = next(iter(ip_list), '')
        for ip in ip_list:
            # NOTE: Fastest IP selection is not supported in proxy mode.
            if self.proxy:
                return ip
            latency = self._tcp_ping_latency(ip)
            if latency < lowest_latency:
                fastip = ip
                lowest_latency = latency
        return fastip

    def _tcp_ping_latency(self, host, port=443, timeout=3):
        start = time.perf_counter()  # High-resolution timer
        try:
            with socket.create_connection((host, port), timeout=timeout):
                end = time.perf_counter()
                return int((end - start)) * 1000  # Convert to milliseconds
        except (socket.timeout, OSError):
            return MAX_LANTENCY

# -----------------------------------------------------------------------------
#       DoH DNS client coroutine
# -----------------------------------------------------------------------------

async def doh_proxy(data: bytes, addr: Tuple[str, int], transport, active_tasks):
    """Coroutine interface: Create and run DoHProxy."""
    try:
        client = DohProxyClient(data, addr, transport)
        task = client.get_qdomain()
        # Ignore duplicate DNS query packets at the same time
        if task in active_tasks:
            mainlog.debug(f'Duplicate DNS query ignored during query of {task}')
            return
        active_tasks.add(task)
        await client.query()
        active_tasks.remove(task)
    except Exception as e:
        mainlog.error(f'DoHProxy error: {e}', exc_info=True)

# -----------------------------------------------------------------------------
#       Local DNS server coroutine, event loop
# -----------------------------------------------------------------------------

class DnsProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        self.active_tasks = set()

    def datagram_received(self, data, addr):
        mainlog.debug(f"Received {len(data)} bytes from {addr}")
        # Create a separate coroutine to handle each received UDP query.
        asyncio.create_task(doh_proxy(data, addr, self.transport, self.active_tasks))


async def dns_server():
    asyncio.create_task(cache_db.start_periodic_save())
    asyncio.create_task(negative_cache.start_periodic_save())

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DnsProtocol(),
        local_addr=(HOST, PORT)
    )
    mainlog.info(f"DNS Server started on {HOST}:{PORT}")
    try:
        await asyncio.Future()   # run forever
    except asyncio.CancelledError:
        mainlog.info("DNS server was terminated.")
        cache_db.save()
        negative_cache.save()
    finally:
        transport.close()
        mainlog.info("DNS Server stopped.")


if __name__ == "__main__":
    # Start an asynchronous event loop, run a top-level coroutine
    asyncio.run(dns_server())
