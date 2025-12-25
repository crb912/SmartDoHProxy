from pathlib import Path
from typing import Dict, Any
import tomllib  # Python 3.11+
import logging
from urllib.parse import urlparse
from logging.handlers import RotatingFileHandler
from collections import OrderedDict
import json
import base64
import asyncio
import requests
import re
from typing import Set
from threading import Lock


# -----------------------------------------------------------------------------
#       Config loader
# -----------------------------------------------------------------------------
class ConfigLoader:
    def __init__(self, config_path: str = "config.toml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """load TOML file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"TOML file not found: {self.config_path}")

        with open(self.config_path, "rb") as f:
            return tomllib.load(f)

    def get_proxy_status(self) -> bool:
        proxy_config = self.config.get("proxy", {})
        enable_proxy = proxy_config.get("enable_proxy", False)
        return enable_proxy

    def get_proxies(self) -> Dict[str, str]:
        if not self.get_proxy_status():
            return {}
        proxy_config = self.config.get("proxy", {})
        return {
            "http": proxy_config.get("http", ""),
            "https": proxy_config.get("https", "")
        }

    def get_proxies_rules_file(self) -> str:
        proxy_config = self.config.get("proxy", {})
        return proxy_config.get("rule_file", "")

    def get_proxies_rules_file_url(self) -> str:
        proxy_config = self.config.get("proxy", {})
        return proxy_config.get("rule_file_url", "")

    def get_direct_servers(self):
        doh_servers = self.config.get("doh_servers", {})
        return doh_servers.get("direct_servers", {})

    def get_proxy_servers(self):
        doh_servers = self.config.get("doh_servers", {})
        return doh_servers.get("proxy_servers", {})

    def get_all_doh_servers(self):
        all_doh = []
        doh_servers = self.config.get("doh_servers", {})
        for _, server in doh_servers.items():
            all_doh.append(server)
        return all_doh

    def get_bootstrap_server(self):
        doh_servers = self.config.get("doh_servers", {})
        return doh_servers.get("bootstrap_servers", '')

    def get_doh_hostnames(self) -> set:
        servers = self.config.get("doh_servers", {})
        doh_servers = set()
        direct_doh = self.get_direct_servers()
        proxy_doh = self.get_proxy_servers()
        total = direct_doh + proxy_doh
        for url in total:
            hostname =  urlparse(url).hostname
            doh_servers.add(hostname)
        return doh_servers

    def get_cache_size(self) -> int:
        return self.config.get("cache").get("max_size")

    def get_cache_path(self) -> str:
        pathname = self.config.get("cache").get("path")
        if not pathname:
            pathname = 'dns_cache_back.json'
        if Path(pathname).exists():
            return str(Path(pathname))
        else:
            return str(Path(__file__).parent.resolve().joinpath(pathname))

    def get_cache_save_interval(self) -> int:
        return self.config.get("cache", {}).get("save_interval", 72)

    def get_logging_config(self) -> Dict[str, str]:
        return self.config.get("logging", {"level": "WARNING"})

    def get(self, key: str, default: Any = None) -> Any:
        """获取任意配置项"""
        keys = key.split(".")
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value


cf = ConfigLoader("config.toml")
LOG_CONFIG = cf.get_logging_config()

# -----------------------------------------------------------------------------
#       set log
# -----------------------------------------------------------------------------

def get_logger(log_name, level=logging.INFO):
    logger = logging.getLogger(log_name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = RotatingFileHandler(
            log_name,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding='utf-8'
        )
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


_default_log_level = LOG_CONFIG.get("default_log_level", 'WARNING')
_query_log_level = LOG_CONFIG.get("query_log_level", "INFO")
querylog = get_logger('query.log', logging.getLevelName(_query_log_level))
mainlog = get_logger('main.log', logging.getLevelName(_default_log_level))


# -----------------------------------------------------------------------------
#       DNS cache database
# -----------------------------------------------------------------------------
CACHE_SIZE = cf.get("cache").get("max_size")
CACHE_PATH = cf.get_cache_path()

NEGA_CACHE_SIZE = 1000
NEGA_CACHE_PATH = "negative_cache.json"

class LimitedPersistentDict:
    """
    A dictionary with key-value limit, automatic cleanup, and periodic persistence.
    Features:
    - Maximum capacity limit (default 5 million records)
    - Automatically deletes the oldest half of the data when the capacity is full
    - Automatically saves to a JSON file periodically (default 7 days)
    - Automatically loads historical data on startup
    """

    def __init__(self, persist_file: str, max_size: int = 5_000_000,
                 auto_save_interval: int = 3 * 24 * 3600):
        self.max_size = max_size
        self.filepath = Path(persist_file)
        self.auto_save_interval = auto_save_interval
        self._data = OrderedDict()
        self._lock = Lock()
        self._save_timer = None
        self._load()

    def __setitem__(self, key: str, value: dict):
        with self._lock:
            if len(self._data) > self.max_size:
                self._cleanup()
            if key in self._data:
                del self._data[key]
            self._data[key] = value

    def __getitem__(self, key: str) -> dict:
        with self._lock:
            return self._data[key]

    def __delitem__(self, key: str):
        with self._lock:
            del self._data[key]

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __str__(self):
        if not self._data:
            return "{}"  # 空字典显示为 {}
        items_str = ",\n  ".join(
            f"'{k}': {repr(v)}" for k, v in self._data.items()
        )
        return f"{{\n  {items_str}\n}}"

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def update(self, items: dict):
        with self._lock:
            for key, value in items.items():
                self._data[key] = value

    def _load(self):
        if not self.filepath.exists():
            mainlog.info(f"DB file {self.filepath} not found.")
            return
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            with self._lock:
                self._data = OrderedDict(data)
                mainlog.info(f"DB load from {self.filepath}, num:{len(self._data)}")

                if len(self._data) > self.max_size:
                    mainlog.warning(f"load data ({len(self._data)} > maxsize，clean")
                    self._cleanup()
        except Exception as e:
            mainlog.error(f"load DNS db err: {e}")

    def save(self):
        if not self.filepath.exists():
            mainlog.info(f"DB file not found, try create.")
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, 'w', encoding='utf-8') as f:
                json.dump(dict(self._data), f, ensure_ascii=False, indent=2)

            mainlog.info(f"DB file save ok. path:{self.filepath}，Num: {len(self._data)}")
        except Exception as e:
            mainlog.error(f'DB file save failed,{e}')

    async def start_periodic_save(self):
        mainlog.info(
            f'DB persistence task created. {self.filepath}, periodic: {int(self.auto_save_interval / 3600)} hours')
        while True:
            await asyncio.sleep(self.auto_save_interval)
            self.save()

    def _cleanup(self):
        """Clean up the earliest half of the data"""
        with self._lock:
            remove_count = len(self._data) // 2
            mainlog.info(f"db full ({len(self._data)}/{self.max_size}")
            for _ in range(remove_count):
                self._data.popitem(last=False)  # FIFO


SAVE_INTERVAL = cf.get_cache_save_interval() * 3600

cache_db = LimitedPersistentDict(CACHE_PATH, CACHE_SIZE, SAVE_INTERVAL)
negative_cache =  LimitedPersistentDict(NEGA_CACHE_PATH, NEGA_CACHE_SIZE, SAVE_INTERVAL)

# -----------------------------------------------------------------------------
#       DNS Traffic Classifier    |   基于gfwlist的DNS分流
# -----------------------------------------------------------------------------
RULE_FILE = cf.get_proxies_rules_file()
RULE_FILE_URL = cf.get_proxies_rules_file_url()


class TrafficClassifier:
    def __init__(self, filepath = RULE_FILE, url: str = RULE_FILE_URL):
        self.filepath = filepath
        self.proxy_domains: Set[str] = set()
        self.url = url
        self._load_and_parse()

    def _load_and_parse(self) -> None:
        if not cf.get_proxy_status():
            return
        content = self._read_file(self.filepath)
        if not content:
            content = self._download_file()

        if content:
            self._load_data(content)
            mainlog.info(f'Rule set load success, nums: {len(self.proxy_domains)}')
            self._save_file(content)
        return

    def _read_file(self, filepath):
        path = Path(filepath)
        if path.is_file():
            data_bytes = path.read_bytes()
            mainlog.info(f'Rule set load from {self.filepath}')
            try:
                return base64.b64decode(data_bytes).decode('utf-8')
            except Exception as e:
                return data_bytes.decode('utf-8')
        return None

    def _save_file(self, decode_data):
        with open(self.filepath, "w") as f:
            f.write(decode_data)

    def _download_file(self):
        """Download the file and return the decoded text"""
        try:
            response = requests.get(self.url, timeout=30)
            response.raise_for_status()
            content = response.text.strip()
            decode = base64.b64decode(content).decode('utf-8')
            mainlog.info(f'Rule set load from file {self.filepath}')
            if decode:
                return decode
        except Exception as e:
            mainlog.error(f"Download rule file failed: {e}")
            return None

    def _load_data(self, decoded_bytes):
        """
        Extract all domain names from rule lines.
        Supported formats:
        - Lines starting with '||' (e.g., '||example.com')
        - Lines starting with '|' followed by a URL (e.g., '|h\ttp://example.com')
        - Plain domain names (e.g., 'example.com')
        The following are ignored:
        - Comment lines starting with '!'
        - Header sections such as '[AutoProxy ...]'
        """
        domain_pattern = re.compile(
            r'(?:\|\||\|)?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*)'
        )
        for line in decoded_bytes.splitlines():
            line = line.strip()
            if 'Whitelist' in line:
                break
            if not line or line.startswith('!') or line.startswith('['):
                continue  # 跳过空行、注释、头部
            matches = domain_pattern.findall(line)
            for domain in matches:
                # 去除可能的前缀如 http:// https://
                domain = domain.lower()
                if domain.startswith('http://'):
                    domain = domain[7:]
                elif domain.startswith('https://'):
                    domain = domain[8:]
                self.proxy_domains.add(domain)

    def contains(self, test_domain: str) -> bool:
        """Check if the domain is in the rule set"""
        test = test_domain.lower().strip()
        if test.startswith('http://'):
            test = test[7:]
        elif test.startswith('https://'):
            test = test[8:]
        # Support subdomain matching
        for domain in self.proxy_domains:
            if test == domain or test.endswith('.' + domain):
                return True
        return False


def test_traffic_clsifier():
    tests = [
        'zoominfo.com',
        'blog.zoominfo.com',  # subdomain matching
        'google.com',
        'notexists.example',
        'ptwxz.com',
        'baidu.com'
    ]

    for t in tests:
        result = traffic_clsifier.contains(t)
        print(f"{t:30} -> {result}")


traffic_clsifier = TrafficClassifier()


if __name__ == '__main__':
    test_traffic_clsifier()
