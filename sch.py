#!/usr/bin/env python3
"""
sch.py — DarkRecon (single-file standalone recon toolkit + interactive dashboard)

This is a single-file, all-in-one recon toolkit. It's long by design — one file you can drop
into a repo and run. It mixes a menu-driven interactive dashboard and CLI flags so you can use
it in scripts or interactively.

Features included (all in this file):
- DNS lookup (A, AAAA, CNAME, MX, TXT)
- WHOIS lookup
- IP geolocation (ip-api.com)
- HTTP header/title grab
- SSL certificate info
- Async TCP port scanner + banner grabbing
- Subdomain discovery (crt.sh + wordlist DNS brute + passive JS/HTML parsing)
- Directory brute force (simple wordlist) and link crawl (BeautifulSoup)
- Technology fingerprinting (basic regex heuristics)
- JSON report export + pretty console (colorama / rich-like minimal)
- Interactive command-based dashboard with ASCII banner and colored output

Requirements (install once):
    pip install requests dnspython python-whois beautifulsoup4 colorama tqdm

Usage examples:
    Interactive:
        python3 sch.py

    CLI (full recon):
        python3 sch.py --target example.com --full --json report.json --wordlist words.txt --dir-wordlist dirs.txt

LEGAL: Only scan targets you own or have explicit permission to test.
"""

from __future__ import annotations
import sys
import os
import re
import json
import time
import socket
import ssl
import argparse
import asyncio
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any, Optional

# Attempt imports for third-party libraries; collect missing ones to instruct user
_missing_pkgs = []
try:
    import requests
except Exception:
    _missing_pkgs.append('requests')
try:
    import dns.resolver
except Exception:
    _missing_pkgs.append('dnspython')
try:
    import whois as whoislib
except Exception:
    _missing_pkgs.append('python-whois')
try:
    from bs4 import BeautifulSoup
except Exception:
    _missing_pkgs.append('beautifulsoup4')
try:
    from colorama import init as colorama_init, Fore, Style
except Exception:
    _missing_pkgs.append('colorama')
try:
    from tqdm import tqdm
except Exception:
    _missing_pkgs.append('tqdm')

if _missing_pkgs:
    print('\nMissing required packages:')
    for m in sorted(set(_missing_pkgs)):
        print(f"  - {m}")
    print('\nInstall with: pip install ' + ' '.join(sorted(set(_missing_pkgs))))
    print('After installing, re-run this script.')
    sys.exit(1)

# init colorama
colorama_init(autoreset=True)

# ----------------- Small UI Helpers -----------------
ASCII_BANNER = r"""
  ____ _   _ ___   ____                      
 / ___| | | |_ _| |  _ \  ___  _ __   __ _ _ __ ___  ___ ___
| |   | | | || |  | | | |/ _ \| '_ \ / _` | '__/ _ \/ __/ __|
| |___| |_| || |  | |_| | (_) | | | | (_| | | |  __/\__ \__ \
 \____|\___/|___| |____/ \___/|_| |_|\__, |_|  \___||___/___/
                                     |___/                  
      DarkRecon — sch.py (single-file recon toolkit)
"""

def now_iso():
    return datetime.utcnow().isoformat() + 'Z'


def printc(s: str, color: Optional[str] = None, bold: bool = False):
    out = s
    if color:
        out = color + out + Style.RESET_ALL
    if bold:
        out = Style.BRIGHT + out + Style.RESET_ALL
    print(out)


def save_json(path: str, data: Dict[str, Any]):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        printc(f"[+] JSON report saved to {path}", Fore.GREEN)
    except Exception as e:
        printc(f"Failed to save JSON: {e}", Fore.YELLOW)

# ----------------- DNS & WHOIS -----------------

def dns_lookup(name: str) -> Dict[str, List[str]]:
    out = {'A': [], 'AAAA': [], 'CNAME': [], 'MX': [], 'TXT': []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    for rtype in ('A', 'AAAA', 'CNAME', 'MX', 'TXT'):
        try:
            answers = resolver.resolve(name, rtype)
            for r in answers:
                out[rtype].append(r.to_text())
        except Exception:
            continue
    # fallback to socket.gethostbyname
    if not out['A']:
        try:
            a = socket.gethostbyname(name)
            out['A'].append(a)
        except Exception:
            pass
    return out


def whois_lookup(domain: str) -> Dict[str, Any]:
    try:
        w = whoislib.whois(domain)
        if isinstance(w, dict):
            return w
        # whoislib sometimes returns objects with attributes; convert minimally
        try:
            return dict(w)
        except Exception:
            return {'raw': str(w)}
    except Exception as e:
        return {'error': str(e)}

# ----------------- IP Geolocation -----------------

def ip_geolocate(ip: str) -> Dict[str, Any]:
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query'
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
        return {'error': f'status {r.status_code}'}
    except Exception as e:
        return {'error': str(e)}

# ----------------- SSL Certificate -----------------

def get_ssl_info(host: str, port: int = 443) -> Dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        return {'error': str(e)}

# ----------------- HTTP Recon -----------------

def fetch_http(url: str, timeout: int = 8) -> Dict[str, Any]:
    try:
        headers = {'User-Agent': 'DarkRecon/1.0 (sch.py)'}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        title = None
        content_type = r.headers.get('Content-Type', '')
        if 'text/html' in content_type:
            soup = BeautifulSoup(r.text, 'html.parser')
            t = soup.title
            if t:
                title = (t.string or '').strip()
        security_headers = {k: v for k, v in r.headers.items() if k.lower() in ['strict-transport-security', 'content-security-policy', 'x-frame-options']}
        return {
            'url': r.url,
            'status_code': r.status_code,
            'title': title,
            'server': r.headers.get('Server'),
            'headers': dict(r.headers),
            'security_headers': security_headers,
            'length': len(r.content)
        }
    except Exception as e:
        return {'error': str(e)}

# ----------------- Port Scanner (async) -----------------
async def tcp_connect(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(b"\r\n")
            await writer.drain()
        except Exception:
            pass
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            banner = data.decode('utf-8', errors='replace').strip()
        except Exception:
            banner = ''
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return banner
    except Exception:
        return None


async def port_scan(host: str, ports: List[int], concurrency: int = 100) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict[str, Any]] = []

    async def worker(p: int):
        async with sem:
            banner = await tcp_connect(host, p)
            if banner is not None:
                results.append({'port': p, 'open': True, 'banner': banner})

    tasks = [asyncio.create_task(worker(p)) for p in ports]
    await asyncio.gather(*tasks)
    return sorted(results, key=lambda x: x['port'])

# ----------------- Subdomain Discovery -----------------

def crtsh_subdomains(domain: str) -> List[str]:
    try:
        q = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(q, timeout=10)
        if r.status_code != 200:
            return []
        js = r.json()
        names = set()
        for item in js:
            name = item.get('name_value') or item.get('common_name')
            if not name:
                continue
            for line in str(name).split('\n'):
                line = line.strip()
                if '*' in line:
                    line = line.replace('*.', '')
                if line.endswith(domain):
                    names.add(line.lower())
        return sorted(names)
    except Exception:
        return []


def wordlist_bruteforce(domain: str, wordlist: str, resolver_timeout: float = 1.5, max_workers: int = 50) -> List[str]:
    names = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = resolver_timeout

    def try_name(prefix: str):
        name = f"{prefix}.{domain}"
        try:
            ans = resolver.resolve(name, 'A')
            if ans:
                return name
        except Exception:
            return None

    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    w = line.strip()
                    if not w:
                        continue
                    futures.append(ex.submit(try_name, w))
        except FileNotFoundError:
            printc(f"Wordlist not found: {wordlist}", Fore.YELLOW)
            return []
        for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc='bruteforce'):
            try:
                res = f.result()
            except Exception:
                res = None
            if res:
                names.append(res)
    return sorted(set(names))


def passive_find_in_js(domain: str, url: str) -> List[str]:
    found = set()
    try:
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            for m in re.findall(r"[\w\-\.]+\.%s" % re.escape(domain), r.text):
                found.add(m.lower())
    except Exception:
        pass
    return sorted(found)

# ----------------- Directory brute force -----------------

def dir_bruteforce(base_url: str, wordlist: str, timeout: int = 6) -> List[Dict[str, Any]]:
    results = []
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as fh:
            words = [w.strip() for w in fh if w.strip()]
    except FileNotFoundError:
        printc(f"Wordlist not found: {wordlist}", Fore.YELLOW)
        return []

    for w in tqdm(words, desc='dir-brute'):
        url = base_url.rstrip('/') + '/' + w
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=False)
            if r.status_code and r.status_code < 400:
                results.append({'path': w, 'status': r.status_code, 'url': url})
        except Exception:
            continue
    return results

# ----------------- Link crawl -----------------

def crawl_links(base_url: str, max_pages: int = 20) -> List[str]:
    seen = set()
    to_visit = [base_url]
    headers = {'User-Agent': 'DarkRecon/1.0 (sch.py)'}
    while to_visit and len(seen) < max_pages:
        u = to_visit.pop(0)
        try:
            r = requests.get(u, headers=headers, timeout=6)
            if r.status_code != 200:
                continue
            soup = BeautifulSoup(r.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href.startswith('/'):
                    parsed = requests.compat.urljoin(u, href)
                elif href.startswith('http'):
                    parsed = href
                else:
                    continue
                if parsed not in seen:
                    seen.add(parsed)
                    to_visit.append(parsed)
        except Exception:
            continue
    return sorted(seen)

# ----------------- Tech fingerprint -----------------
TECH_REGEXES = {
    'php': [re.compile(r'X-Powered-By:.*PHP', re.I), re.compile(r'\\.php', re.I)],
    'nginx': [re.compile(r'Server:.*nginx', re.I)],
    'apache': [re.compile(r'Server:.*Apache', re.I)],
    'cloudflare': [re.compile(r'cloudflare', re.I)],
    'wordpress': [re.compile(r'wp-content|wp-includes|wordpress', re.I)],
}


def fingerprint(headers: Dict[str, Any], body: Optional[str] = None) -> List[str]:
    found = []
    text = ''
    if headers:
        text = ' '.join(f"{k}: {v}" for k, v in headers.items())
    if body:
        text += ' ' + (body[:2000] if len(body) > 0 else '')
    for tech, regexes in TECH_REGEXES.items():
        for rx in regexes:
            if rx.search(text):
                found.append(tech)
                break
    return list(sorted(set(found)))

# ----------------- Orchestration: single-run recon -----------------

def parse_ports(ports_str: str) -> List[int]:
    out = set()
    for part in ports_str.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            a = int(a); b = int(b)
            for p in range(a, b+1):
                out.add(p)
        else:
            out.add(int(part))
    return sorted([p for p in out if 0 < p < 65536])


def build_report_template(target: str) -> Dict[str, Any]:
    return {
        'target': target,
        'timestamp': now_iso(),
        'subdomains': [],
        'hosts': {},
        'notes': []
    }


async def run_full_recon(args) -> Dict[str, Any]:
    report = build_report_template(args.target)
    target = args.target

    # 1) subdomains
    subnames = set()
    if args.subdomains:
        printc('[*] Searching crt.sh ...', Fore.CYAN)
        names = crtsh_subdomains(target)
        for n in names:
            subnames.add(n)
        printc(f"  found {len(names)} from crt.sh", Fore.GREEN)

        # passive parse root and common JS
        try:
            r = requests.get(f'https://{target}', timeout=6)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    full = requests.compat.urljoin(r.url, src)
                    found = passive_find_in_js(target, full)
                    for fnd in found:
                        subnames.add(fnd)
        except Exception:
            pass

        if args.wordlist:
            printc('[*] Running wordlist brute (DNS) ...', Fore.CYAN)
            brut = wordlist_bruteforce(target, args.wordlist, max_workers=args.threads)
            for b in brut:
                subnames.add(b)
            printc(f"  bruteforce found {len(brut)} names", Fore.GREEN)

    if not subnames:
        subnames.add(target)

    report['subdomains'] = sorted(subnames)

    # iterate hosts
    hosts = report['hosts']
    for host in report['subdomains']:
        printc(f"\n[+] Recon for {host}", Fore.MAGENTA, bold=True)
        hosts[host] = {}
        # DNS
        dnsr = dns_lookup(host)
        hosts[host]['dns'] = dnsr
        printc(f"  DNS A: {dnsr.get('A')}")

        # whois only for root domain
        if host == target:
            printc('  WHOIS lookup...', Fore.CYAN)
            who = whois_lookup(host)
            hosts[host]['whois'] = who

        # resolve first A for geo and IP
        ips = dnsr.get('A') or []
        hosts[host]['ips'] = ips
        if ips:
            geo = ip_geolocate(ips[0])
            hosts[host]['geo'] = geo
            country = geo.get('country') if isinstance(geo, dict) else None
            printc(f"  IP geo: {country or ''} {geo.get('regionName') if isinstance(geo, dict) and geo.get('regionName') else ''}")

        # SSL cert
        if args.ssl:
            cert = get_ssl_info(host)
            hosts[host]['ssl'] = cert
            if isinstance(cert, dict) and 'subject' in cert:
                printc('  SSL cert subject: ' + str(cert.get('subject')))

        # HTTP
        httpinfo = {}
        for scheme in ['https://', 'http://']:
            url = scheme + host
            info = fetch_http(url, timeout=args.timeout)
            if 'error' not in info:
                httpinfo = info
                break
        hosts[host]['http'] = httpinfo
        if httpinfo:
            printc(f"  HTTP {httpinfo.get('status_code')} title: {httpinfo.get('title')}")
            techs = fingerprint(httpinfo.get('headers', {}), None)
            hosts[host]['tech'] = techs
            if techs:
                printc('  Techs: ' + ', '.join(techs), Fore.YELLOW)

        # Port scan
        if args.ports:
            ports = parse_ports(args.ports)
            printc(f"  Scanning ports: {len(ports)} ports (concurrency {args.concurrency})...", Fore.CYAN)
            scanned = await port_scan(host, ports, concurrency=args.concurrency)
            hosts[host]['ports'] = scanned
            for s in scanned:
                banner_preview = (s['banner'] or '')[:120]
                printc(f"    Open {s['port']}  banner: {banner_preview}")

        # Dir brute
        if args.dir_wordlist and httpinfo:
            base = httpinfo.get('url')
            printc('  Directory brute force...', Fore.CYAN)
            db = dir_bruteforce(base, args.dir_wordlist)
            hosts[host]['dir_brute'] = db
            if db:
                printc(f"    Found {len(db)} interesting paths", Fore.GREEN)

        # Crawl links
        if args.crawl and httpinfo:
            printc('  Crawling links...', Fore.CYAN)
            links = crawl_links(httpinfo.get('url'), max_pages=args.crawl_pages)
            hosts[host]['links'] = links
            printc(f"    Found {len(links)} links")

    report['notes'].append(f"completed {now_iso()}")
    return report

# ----------------- Interactive Dashboard -----------------

def menu_banner():
    print(ASCII_BANNER)
    printc('Legal: Only scan targets you own or have permission to test.', Fore.YELLOW)


def dashboard_loop():
    menu_banner()
    while True:
        print('\n==== SCH Recon Dashboard ====')
        printc('1. Quick: DNS + HTTP headers', Fore.CYAN)
        printc('2. Port scan (quick)', Fore.CYAN)
        printc('3. Subdomain discovery (crt.sh)', Fore.CYAN)
        printc('4. Full recon (quick mode)', Fore.CYAN)
        printc('5. Directory brute force (requires wordlist)', Fore.CYAN)
        printc('6. Crawl links (simple)', Fore.CYAN)
        printc('7. WHOIS lookup', Fore.CYAN)
        printc('8. SSL certificate', Fore.CYAN)
        printc('9. Save last report to JSON', Fore.CYAN)
        printc('0. Exit', Fore.RED)

        choice = input('\nSelect option > ').strip()
        if choice == '0':
            printc('Goodbye.', Fore.GREEN)
            break

        if choice in {'1','2','3','4','5','6','7','8'}:
            target = input('Target (domain or host) > ').strip()
            if not target:
                printc('Invalid target', Fore.YELLOW)
                continue
        # variables for operations
        global _last_report
        if choice == '1':
            printc('[*] DNS lookup', Fore.CYAN)
            d = dns_lookup(target)
            printc(json.dumps(d, indent=2)[:2000])
            printc('[*] HTTP fetch', Fore.CYAN)
            h = fetch_http('http://' + target, timeout=6)
            printc(json.dumps(h, indent=2)[:2000])
            _last_report = build_report_template(target)
            _last_report['subdomains'] = [target]
            _last_report['hosts'][target] = {'dns': d, 'http': h}

        elif choice == '2':
            pr = input('Ports (e.g. 22,80 or 1-1024) [default 1-1024] > ').strip() or '1-1024'
            ports = parse_ports(pr)
            printc(f'Running async port scan for {len(ports)} ports...', Fore.CYAN)
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                res = loop.run_until_complete(port_scan(target, ports[:200], concurrency=200))
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
            printc('Open ports:', Fore.GREEN)
            for r in res:
                printc(f"  {r['port']} - { (r['banner'] or '')[:120] }")
            _last_report = build_report_template(target)
            _last_report['subdomains'] = [target]
            _last_report['hosts'][target] = {'ports': res}

        elif choice == '3':
            printc('[*] crt.sh enumeration', Fore.CYAN)
            names = crtsh_subdomains(target)
            printc(f'Found {len(names)} names', Fore.GREEN)
            for n in names[:200]:
                print(n)
            _last_report = build_report_template(target)
            _last_report['subdomains'] = names

        elif choice == '4':
            printc('[*] Running quick full recon', Fore.CYAN)
            class Args: pass
            a = Args()
            a.target = target
            a.subdomains = True
            a.wordlist = None
            a.ports = '1-1024'
            a.full = False
            a.ssl = True
            a.dir_wordlist = None
            a.crawl = False
            a.crawl_pages = 20
            a.json = None
            a.timeout = 6
            a.concurrency = 200
            a.threads = 40
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                report = loop.run_until_complete(run_full_recon(a))
            finally:
                try:
                    loop.close()
                except Exception:
                    pass
            _last_report = report
            printc('\n[+] Quick recon complete. Summary:', Fore.GREEN)
            printc(json.dumps(report, indent=2)[:4000])

        elif choice == '5':
            wl = input('Path to directory wordlist file > ').strip()
            base = input('Base URL (e.g. https://example.com) > ').strip()
            if not wl or not base:
                printc('Missing input', Fore.YELLOW)
                continue
            res = dir_bruteforce(base, wl)
            printc(f'Found {len(res)} paths', Fore.GREEN)
            for r in res:
                printc(f"  {r['status']} {r['url']}")

        elif choice == '6':
            pages = input('Max pages to crawl [20] > ').strip() or '20'
            try:
                pages_i = int(pages)
            except Exception:
                pages_i = 20
            res = crawl_links('http://' + target, max_pages=pages_i)
            printc(f'Found {len(res)} links', Fore.GREEN)
            for u in res[:500]:
                print(u)

        elif choice == '7':
            printc('[*] WHOIS', Fore.CYAN)
            w = whois_lookup(target)
            printc(json.dumps(w, indent=2)[:4000])
            _last_report = build_report_template(target)
            _last_report['hosts'][target] = {'whois': w}

        elif choice == '8':
            printc('[*] SSL', Fore.CYAN)
            s = get_ssl_info(target)
            printc(json.dumps(s, indent=2)[:2000])
            _last_report = build_report_template(target)
            _last_report['hosts'][target] = {'ssl': s}

        elif choice == '9':
            path = input('Filename to save JSON (e.g. report.json) > ').strip() or 'report.json'
            try:
                save_json(path, _last_report)
            except Exception as e:
                printc(f'No report to save or failed: {e}', Fore.YELLOW)

        else:
            printc('Invalid choice', Fore.YELLOW)

# ----------------- CLI Parsing -----------------

def build_argparser():
    p = argparse.ArgumentParser(description='sch.py — DarkRecon single-file recon toolkit')
    p.add_argument('--target', help='Target domain or hostname')
    p.add_argument('--subdomains', action='store_true', help='Run subdomain discovery (crt.sh + passive + bruteforce)')
    p.add_argument('--wordlist', help='Wordlist for subdomain brute and dir brute')
    p.add_argument('--ports', default='1-1024', help='Ports to scan (comma or ranges, default 1-1024)')
    p.add_argument('--full', action='store_true', help='Run full recon (subdomains, ports, http, whois, dns)')
    p.add_argument('--ssl', action='store_true', help='Grab SSL certificate info')
    p.add_argument('--dir-wordlist', help='Wordlist for directory brute force')
    p.add_argument('--crawl', action='store_true', help='Crawl links on HTTP site')
    p.add_argument('--crawl-pages', type=int, default=20, help='Max pages to crawl')
    p.add_argument('--json', help='Write JSON report to file')
    p.add_argument('--timeout', type=int, default=8, help='HTTP/network timeout')
    p.add_argument('--concurrency', type=int, default=100, help='Concurrency for port scanning')
    p.add_argument('--threads', type=int, default=30, help='Thread count for blocking tasks (bruteforce)')
    p.add_argument('--interactive', action='store_true', help='Start interactive dashboard')
    return p


def main():
    parser = build_argparser()
    args = parser.parse_args()

    if len(sys.argv) == 1 or args.interactive:
        try:
            dashboard_loop()
        except KeyboardInterrupt:
            printc('\nInterrupted, exiting.', Fore.YELLOW)
        return

    if not args.target:
        printc('Please provide --target or run with --interactive', Fore.YELLOW)
        sys.exit(1)

    # adjust flags if full
    if args.full:
        args.subdomains = True
        args.ssl = True
        args.crawl = True

    loop = asyncio.get_event_loop()
    try:
        report = loop.run_until_complete(run_full_recon(args))
    finally:
        try:
            loop.close()
        except Exception:
            pass

    if args.json:
        save_json(args.json, report)
    else:
        printc('\n[+] Recon complete — summary below:', Fore.GREEN)
        printc(json.dumps(report, indent=2)[:4000])


if __name__ == '__main__':
    # keep last report in memory for interactive save
    _last_report = None
    main()
