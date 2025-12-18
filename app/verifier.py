# app/verifier.py
# Bounso Email Verifier — FastAPI backend core
# Railway-safe | IPv4-only DNS | Thread-safe SMTP

from __future__ import annotations
import os
import re
import time
import random
import string
import smtplib
import socket
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import dns.resolver

# =========================
# RUNTIME CONFIG (ENV)
# =========================
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "3"))
DNS_LIFETIME = float(os.getenv("DNS_LIFETIME", "5"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "6"))
PAUSE_BETWEEN_PROBES = float(os.getenv("PROBE_PAUSE", "0.08"))
MAX_WORKERS_DEFAULT = int(os.getenv("MAX_WORKERS", "8"))
MX_CACHE_TTL = int(os.getenv("MX_CACHE_TTL", "3600"))

HELO_DOMAIN = os.getenv("HELO_DOMAIN", "example.com")
MAIL_FROM = os.getenv("MAIL_FROM", "verify@example.com")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# =========================
# FORCE IPV4 (GLOBAL)
# =========================
socket.setdefaulttimeout(SMTP_TIMEOUT)

# =========================
# IPV4-ONLY DNS RESOLVER (CRITICAL FIX)
# =========================
_resolver = dns.resolver.Resolver(configure=False)
_resolver.nameservers = [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "9.9.9.9",
]
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

# =========================
# MX CACHE
# =========================
class MXCache:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._store: Dict[str, Tuple[float, List[str]]] = {}

    def get(self, domain: str):
        item = self._store.get(domain)
        if not item:
            return None
        ts, records = item
        if time.time() - ts > self.ttl:
            self._store.pop(domain, None)
            return None
        return records

    def set(self, domain: str, records: List[str]):
        self._store[domain] = (time.time(), records)

mx_cache = MXCache(ttl=MX_CACHE_TTL)

# =========================
# HELPERS
# =========================
def random_local(k: int = 8) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def normalize_email(email: str) -> str:
    return email.strip()

def detect_mx_provider(mx_host: str) -> str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:
        return "microsoft365"
    if "google.com" in h or "aspmx" in h:
        return "google"
    if "pphosted" in h or "proofpoint" in h:
        return "proofpoint"
    if "mimecast" in h:
        return "mimecast"
    if "barracuda" in h:
        return "barracuda"
    return "unknown"

# =========================
# MX LOOKUP (SAFE)
# =========================
def resolve_mx(domain: str) -> List[str]:
    cached = mx_cache.get(domain)
    if cached:
        return cached

    answers = _resolver.resolve(domain, "MX")
    mx_hosts = sorted(
        [str(r.exchange).rstrip('.') for r in answers],
        key=lambda _: _
    )
    mx_cache.set(domain, mx_hosts)
    return mx_hosts

# =========================
# SMTP MULTI-PROBE
# =========================
def smtp_multi_probe(mx: str, target_email: str):
    domain = target_email.split("@")[1]
    seq_addrs = [
        f"{random_local()}@{domain}",
        target_email,
        f"{random_local()}@{domain}"
    ]
    out = []

    try:
        s = smtplib.SMTP(mx, 25, timeout=SMTP_TIMEOUT)
        try: s.helo(HELO_DOMAIN)
        except: pass
        try: s.mail(MAIL_FROM)
        except: pass

        for addr in seq_addrs:
            start = time.perf_counter()
            try:
                code, _ = s.rcpt(addr)
            except:
                code = None
            latency = round((time.perf_counter() - start) * 1000, 2)
            out.append((addr, code, latency))
            time.sleep(PAUSE_BETWEEN_PROBES)

        try: s.quit()
        except: pass

    except:
        out.append(("__connect__", None, None))

    return out

# =========================
# TIMING ANALYSIS
# =========================
def analyze_timing(seq):
    times = [t for _, _, t in seq if isinstance(t, (int, float))]
    codes = [str(c) for _, c, _ in seq if c is not None]

    if not times:
        return 0.0, 0, 1, None

    delta = int(max(times) - min(times))
    avg_latency = int(mean(times))
    entropy = len(set(codes)) if codes else 1

    conf = 0.0
    if delta > 120: conf += 0.25
    elif delta > 80: conf += 0.18
    elif delta > 40: conf += 0.12
    elif delta > 10: conf += 0.06
    if entropy > 1: conf += 0.05

    return round(min(conf, 0.35), 2), delta, entropy, avg_latency

# =========================
# BEHAVIOR SCORE
# =========================
def behavioral_score(confidence, entropy, provider, real_code):
    if provider in ["microsoft365", "proofpoint", "mimecast", "barracuda"]:
        if real_code in (250, 450, 451, 452):
            return {"Status": "valid", "Deliverable": True, "Score": 99}
        if real_code == 550:
            return {"Status": "invalid", "Deliverable": False, "Score": 10}

    if confidence >= 0.25:
        return {"Status": "valid", "Deliverable": True, "Score": 85}
    if confidence >= 0.12:
        return {"Status": "risky", "Deliverable": False, "Score": 60}
    return {"Status": "invalid", "Deliverable": False, "Score": 15}

# =========================
# VERIFY SINGLE EMAIL
# =========================
def verify_email(email: str):
    email = normalize_email(email)

    result = {
        "email": email,
        "Status": "invalid",
        "Deliverable": False,
        "Score": 0,
        "Provider": None,
        "Reason": None,
        "MX": []
    }

    if not EMAIL_REGEX.match(email):
        result["Reason"] = "bad_syntax"
        return result

    try:
        domain = email.split("@")[1]
        mx_records = resolve_mx(domain)
        if not mx_records:
            result["Reason"] = "no_mx"
            return result

        mx = mx_records[0]
        provider = detect_mx_provider(mx)
        result["MX"] = mx_records
        result["Provider"] = provider

    except Exception as e:
        result["Reason"] = f"mx_error:{e}"
        return result

    seq = smtp_multi_probe(mx, email)
    conf, delta, entropy, avg = analyze_timing(seq)

    scored = behavioral_score(
        confidence=conf,
        entropy=entropy,
        provider=provider,
        real_code=seq[1][1] if len(seq) > 1 else None
    )

    result.update(scored)
    result["Reason"] = "pattern_analysis"
    return result

# =========================
# BULK VERIFY
# =========================
def verify_bulk_emails(emails, max_workers=MAX_WORKERS_DEFAULT):
    emails = [normalize_email(e) for e in emails if EMAIL_REGEX.match(e or "")]
    if not emails:
        return []

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(verify_email, e): e for e in emails}
        for f in as_completed(futures):
            try:
                results.append(f.result())
            except Exception as e:
                results.append({
                    "email": futures[f],
                    "Status": "error",
                    "Deliverable": False,
                    "Score": 0,
                    "Reason": f"exception:{e}",
                })

    lookup = {r["email"]: r for r in results}
    return [lookup[e] for e in emails if e in lookup]
