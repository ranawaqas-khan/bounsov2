# app/verifier.py
# Bounso Email Verifier — Advanced SMTP Verifier (Railway-safe)

from __future__ import annotations
import os, re, time, random, string, smtplib, socket
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
import dns.resolver

# =========================
# ENV CONFIG
# =========================
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "3"))
DNS_LIFETIME = float(os.getenv("DNS_LIFETIME", "5"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "6"))
PAUSE_BETWEEN_PROBES = float(os.getenv("PROBE_PAUSE", "0.08"))
MAX_WORKERS_DEFAULT = int(os.getenv("MAX_WORKERS", "10"))
MX_CACHE_TTL = int(os.getenv("MX_CACHE_TTL", "3600"))

HELO_DOMAIN = os.getenv("HELO_DOMAIN", "verifier.bounso.com")
MAIL_FROM = os.getenv("MAIL_FROM", "verify@bounso.com")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# =========================
# DNS (IPv4 ONLY)
# =========================
_resolver = dns.resolver.Resolver(configure=False)
_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

# =========================
# MX CACHE
# =========================
class MXCache:
    def __init__(self, ttl):
        self.ttl = ttl
        self.store = {}

    def get(self, d):
        if d in self.store and time.time() - self.store[d][0] < self.ttl:
            return self.store[d][1]
        self.store.pop(d, None)
        return None

    def set(self, d, v):
        self.store[d] = (time.time(), v)

mx_cache = MXCache(MX_CACHE_TTL)

# =========================
# HELPERS
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx):
    mx = mx.lower()
    if "google" in mx or "aspmx" in mx: return "google"
    if "outlook" in mx or "protection" in mx: return "microsoft365"
    if "proofpoint" in mx: return "proofpoint"
    if "mimecast" in mx: return "mimecast"
    if "barracuda" in mx: return "barracuda"
    return "unknown"

def resolve_ipv4(host):
    try:
        a = _resolver.resolve(host, "A")
        return str(a[0])
    except:
        try:
            return socket.getaddrinfo(host, 25, socket.AF_INET)[0][4][0]
        except:
            return None

# =========================
# MX LOOKUP
# =========================
def resolve_mx(domain):
    cached = mx_cache.get(domain)
    if cached: return cached

    ans = _resolver.resolve(domain, "MX")
    mxs = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in ans])
    hosts = [h for _, h in mxs]
    mx_cache.set(domain, hosts)
    return hosts

# =========================
# SMTP MULTI PROBE (FIXED FLOW)
# =========================
def smtp_multi_probe(mx, email):
    domain = email.split("@")[1]
    probes = [
        f"{random_local()}@{domain}",
        email,
        f"{random_local()}@{domain}",
    ]
    out = []

    ip = resolve_ipv4(mx)
    if not ip:
        return [("__connect__", None, None)]

    try:
        s = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        s.connect(ip, 25)

        # EHLO / HELO
        try:
            s.ehlo(HELO_DOMAIN)
        except:
            try: s.helo(HELO_DOMAIN)
            except: pass

        # STARTTLS if available
        try:
            if s.has_extn("starttls"):
                s.starttls()
                s.ehlo(HELO_DOMAIN)
        except:
            pass

        # MAIL FROM (MUST succeed)
        try:
            mail_code, _ = s.mail(MAIL_FROM)
            if mail_code != 250:
                s.quit()
                return [("__mailfrom__", mail_code, None)]
        except:
            s.quit()
            return [("__mailfrom__", None, None)]

        # RCPT PROBES
        for addr in probes:
            start = time.perf_counter()
            try:
                code, _ = s.rcpt(addr)
            except:
                code = None
            t = round((time.perf_counter() - start) * 1000, 2)
            out.append((addr, code, t))
            time.sleep(PAUSE_BETWEEN_PROBES)

        try: s.quit()
        except: pass

    except:
        return [("__connect__", None, None)]

    return out

# =========================
# TIMING ANALYSIS
# =========================
def analyze_timing(seq):
    times = [t for _,_,t in seq if isinstance(t,(int,float))]
    codes = [str(c) for _,c,_ in seq if c]

    if not times:
        return 0, 0, 1, None

    delta = int(max(times) - min(times))
    avg = int(mean(times))
    entropy = len(set(codes))

    conf = 0
    if delta > 120: conf += .25
    elif delta > 80: conf += .18
    elif delta > 40: conf += .12
    elif delta > 10: conf += .06
    if entropy > 1: conf += .05

    return round(min(conf,.35),2), delta, entropy, avg

# =========================
# BEHAVIOR SCORE (503 FIX)
# =========================
def behavioral_score(f1, f2, real, conf, entropy, provider, real_code):

    if real_code in (503, 530, 454, 421):
        return {
            "Pattern": "smtp_blocked",
            "Score": 50,
            "Status": "risky",
            "Deliverable": False
        }

    if provider in ["microsoft365","proofpoint","mimecast","barracuda"]:
        if real_code in (250,450,451,452):
            return {"Pattern":"smtp_valid","Score":99,"Status":"valid","Deliverable":True}
        if real_code == 550:
            return {"Pattern":"smtp_550","Score":10,"Status":"invalid","Deliverable":False}

    avg_fake = ((f1 or 0)+(f2 or f1 or 0))/2
    gap_real = abs((real or 0)-avg_fake)

    score = min(99, round(
        min(gap_real/80,1)*40 +
        min(conf/.35,1)*40 +
        min(entropy/3,1)*19
    ,2))

    if provider=="google":
        score = max(score,75)

    if score>=80:
        return {"Pattern":"timing_valid","Score":score,"Status":"valid","Deliverable":True}
    if score>=55:
        return {"Pattern":"timing_risky","Score":score,"Status":"risky","Deliverable":False}

    return {"Pattern":"timing_invalid","Score":score,"Status":"invalid","Deliverable":False}

# =========================
# VERIFY SINGLE
# =========================
def verify_email(email):
    result = {
        "email": email,
        "Status":"invalid",
        "Deliverable":False,
        "Score":0,
        "Provider":None,
        "Pattern":None,
        "Reason":None,
        "MX":[]
    }

    if not EMAIL_REGEX.match(email):
        result["Reason"]="bad_syntax"
        return result

    domain = email.split("@")[1]
    try:
        mxs = resolve_mx(domain)
        if not mxs:
            result["Reason"]="no_mx"
            return result
    except Exception as e:
        result["Reason"]=f"mx_error:{e}"
        return result

    mx = mxs[0]
    provider = detect_mx_provider(mx)
    result["MX"]=mxs
    result["Provider"]=provider

    seq = smtp_multi_probe(mx,email)

    if seq and seq[0][0].startswith("__"):
        result["Pattern"]="smtp_blocked"
        result["Status"]="risky"
        result["Score"]=50
        result["Reason"]="smtp_policy"
        return result

    f1, f2, real = seq[0][2], seq[2][2] if len(seq)>2 else None, seq[1][2]
    conf, delta, entropy, avg = analyze_timing(seq)

    scored = behavioral_score(
        f1, f2, real, conf, entropy,
        provider,
        seq[1][1] if len(seq)>1 else None
    )

    result.update(scored)
    result["Reason"]="pattern_analysis"
    return result

# =========================
# BULK
# =========================
def verify_bulk_emails(emails, max_workers=MAX_WORKERS_DEFAULT):
    emails = [e for e in emails if EMAIL_REGEX.match(e or "")]
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return list(ex.map(verify_email, emails))
