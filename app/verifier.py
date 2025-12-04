# app/verifier.py
# Bounso Email Verifier — FastAPI backend core
# Optimized for Railway: MX caching, adaptive probing, ESP-aware scoring, bulk concurrency

from __future__ import annotations
import os
import re
import time
import random
import string
import smtplib
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional

import dns.resolver

# =========================
# RUNTIME CONFIG (ENV-TUNABLE)
# =========================
DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "3"))         # seconds
DNS_LIFETIME = float(os.getenv("DNS_LIFETIME", "3"))       # seconds
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "6"))       # seconds
PAUSE_BETWEEN_PROBES = float(os.getenv("PROBE_PAUSE", "0.08"))
MAX_WORKERS_DEFAULT = int(os.getenv("MAX_WORKERS", "20"))
MX_CACHE_TTL = int(os.getenv("MX_CACHE_TTL", "3600"))      # seconds, in-memory cache TTL

HELO_DOMAIN = os.getenv("HELO_DOMAIN", "example.com")
MAIL_FROM = os.getenv("MAIL_FROM", "probe@example.com")

# =========================
# CONSTANTS & REGEX
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# =========================
# DNS RESOLVER (tuned for API)
# =========================
_resolver = dns.resolver.Resolver()
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

# =========================
# MX CACHE WITH TTL
# =========================
class MXCache:
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self._store: Dict[str, Tuple[float, List[str]]] = {}

    def get(self, domain: str) -> Optional[List[str]]:
        item = self._store.get(domain)
        if not item:
            return None
        ts, records = item
        if time.time() - ts > self.ttl:
            self._store.pop(domain, None)
            return None
        return records

    def set(self, domain: str, records: List[str]) -> None:
        self._store[domain] = (time.time(), records)

mx_cache = MXCache(ttl=MX_CACHE_TTL)

# =========================
# HELPERS
# =========================
def random_local(k: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(random.choices(alphabet, k=k))

def detect_mx_provider(mx_host: str) -> str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "pphosted" in h or "proofpoint" in h: return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    return "unknown"

def normalize_email(email: str) -> str:
    return email.strip()

# =========================
# MX LOOKUP
# =========================
def resolve_mx(domain: str) -> List[str]:
    cached = mx_cache.get(domain)
    if cached:
        return cached
    answers = _resolver.resolve(domain, "MX")
    mx_hosts = [str(r.exchange).rstrip('.') for r in answers]
    mx_cache.set(domain, mx_hosts)
    return mx_hosts

# =========================
# ORIGINAL MULTI-PROBE (unchanged)
# =========================
def smtp_multi_probe(mx: str, target_email: str, adaptive: bool = True) -> List[Tuple[str, Optional[int], Optional[float]]]:
    domain = target_email.split("@")[1]
    seq_addrs = [f"{random_local()}@{domain}", target_email, f"{random_local()}@{domain}"]
    out: List[Tuple[str, Optional[int], Optional[float]]] = []

    try:
        s = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        s.connect(mx)
        try:
            s.helo(HELO_DOMAIN)
        except Exception:
            pass
        try:
            s.mail(MAIL_FROM)
        except Exception:
            pass

        # Fake 1
        start = time.perf_counter()
        code1 = None
        try:
            code1, _ = s.rcpt(seq_addrs[0])
        except Exception:
            code1 = None
        t1 = round((time.perf_counter() - start) * 1000.0, 2)
        out.append((seq_addrs[0], code1, t1))
        time.sleep(PAUSE_BETWEEN_PROBES)

        # Real
        start = time.perf_counter()
        code2 = None
        try:
            code2, _ = s.rcpt(seq_addrs[1])
        except Exception:
            code2 = None
        t2 = round((time.perf_counter() - start) * 1000.0, 2)
        out.append((seq_addrs[1], code2, t2))

        # Adaptive optional fake2
        do_fake2 = True
        if adaptive:
            if code2 in (250, 450, 451, 452) and abs(t2 - t1) > 60:
                do_fake2 = False

        if do_fake2:
            time.sleep(PAUSE_BETWEEN_PROBES)
            start = time.perf_counter()
            code3 = None
            try:
                code3, _ = s.rcpt(seq_addrs[2])
            except Exception:
                code3 = None
            t3 = round((time.perf_counter() - start) * 1000.0, 2)
            out.append((seq_addrs[2], code3, t3))

        try:
            s.quit()
        except Exception:
            pass

    except Exception:
        out.append(("__connect__", None, None))

    return out

# =========================
# TIMING ANALYSIS (unchanged)
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

    conf = round(min(conf, 0.35), 2)
    return conf, delta, entropy, avg_latency

# =========================
# BEHAVIORAL + ESP-AWARE SCORING (unchanged)
# =========================
def behavioral_score(fake1_t, fake2_t, real_t, confidence, entropy, provider, real_code):
    if not all(isinstance(x, (int, float)) for x in [fake1_t or 0, real_t or 0]):
        return {"Pattern": "no_data", "Score": 0, "Status": "invalid", "Deliverable": False}

    if fake2_t is None:
        fake2_t = fake1_t

    avg_fake = ((fake1_t or 0) + (fake2_t or 0)) / 2
    gap_fakes = abs((fake1_t or 0) - (fake2_t or 0))
    gap_real_vs_avg_fake = abs((real_t or 0) - avg_fake)

    if gap_fakes < 20 and gap_real_vs_avg_fake < 20:
        pattern = "flat_pattern"
    elif gap_real_vs_avg_fake > 60 and (real_t or 0) > avg_fake:
        pattern = "strong_delay"
    elif gap_fakes < 25 and 20 <= gap_real_vs_avg_fake <= 50:
        pattern = "semi_flat"
    else:
        pattern = "unclear"

    base = (
        min(gap_real_vs_avg_fake / 80, 1.0) * 40 +
        (1 - min(gap_fakes / 100, 1.0)) * 20 +
        min(confidence / 0.35, 1.0) * 20 +
        min(entropy / 3, 1.0) * 10
    )
    score = min(99, round(base, 2))

    if provider in ["microsoft365", "proofpoint", "mimecast", "barracuda"]:
        if real_code in (250, 450, 451, 452):
            score, pattern = 99, f"smtp_{real_code}_valid"
        elif real_code == 550:
            score, pattern = 10, "smtp_550_invalid"
    elif provider == "google":
        if pattern == "strong_delay":
            score = max(score, 90)
        elif pattern == "flat_pattern":
            score = min(score, 40)

    if score >= 80:
        status, deliverable = "valid", True
    elif score >= 55:
        status, deliverable = "risky", False
    else:
        status, deliverable = "invalid", False

    return {
        "Pattern": pattern,
        "Score": score,
        "Status": status,
        "Deliverable": deliverable
    }

# =========================
# SMTP SINGLE-PROBE (OUTLOOK FIX)
# =========================
def outlook_single_probe(mx, addr):
    try:
        s = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        s.connect(mx)

        try:
            s.ehlo()
            s.starttls()
            s.ehlo()
        except:
            pass

        start = time.perf_counter()
        code = None
        try:
            code, _ = s.rcpt(addr)
        except:
            code = None
        latency = round((time.perf_counter() - start) * 1000.0, 2)

        try:
            s.quit()
        except:
            pass

        return code, latency

    except:
        return None, None

# =========================
# CORE: VERIFY SINGLE EMAIL
# =========================
def verify_email(email: str) -> Dict[str, object]:
    email = normalize_email(email)
    result = {
        "email": email,
        "Fake1_Code": None, "Fake1_Time": None,
        "Real_Code": None,  "Real_Time": None,
        "Fake2_Code": None, "Fake2_Time": None,
        "Timing_Delta": None, "Entropy": None,
        "Avg_Latency": None, "Confidence": None,
        "Provider": None, "Pattern": None,
        "Status": "invalid", "Deliverable": False,
        "Score": 0, "Reason": None,
        "MX": []
    }

    if not EMAIL_REGEX.match(email or ""):
        result["Reason"] = "bad_syntax"
        return result

    # MX lookup
    try:
        domain = email.split("@", 1)[1]
        mx_records = resolve_mx(domain)
        result["MX"] = mx_records
        if not mx_records:
            result["Reason"] = "no_mx"
            return result
        provider = detect_mx_provider(mx_records[0])
        result["Provider"] = provider
    except Exception as e:
        result["Reason"] = f"mx_error:{e}"
        return result

    mx_host = mx_records[0]

    # --- OUTLOOK OVERRIDE ---
    if provider == "microsoft365":
        fake1 = f"{random_local()}@{domain}"
        fake2 = f"{random_local()}@{domain}"

        code1, t1 = outlook_single_probe(mx_host, fake1)
        code2, t2 = outlook_single_probe(mx_host, email)
        code3, t3 = outlook_single_probe(mx_host, fake2)

        seq = [
            (fake1, code1, t1),
            (email, code2, t2),
            (fake2, code3, t3)
        ]

    else:
        # original path
        seq = smtp_multi_probe(mx_host, email, adaptive=True)

    # Extract results
    if len(seq) >= 1:
        result["Fake1_Code"] = seq[0][1]
        result["Fake1_Time"] = seq[0][2]
    if len(seq) >= 2:
        result["Real_Code"] = seq[1][1]
        result["Real_Time"] = seq[1][2]
    if len(seq) >= 3:
        result["Fake2_Code"] = seq[2][1]
        result["Fake2_Time"] = seq[2][2]

    conf, delta, entropy, avg = analyze_timing(seq)
    result["Timing_Delta"] = delta
    result["Entropy"] = entropy
    result["Avg_Latency"] = avg
    result["Confidence"] = conf

    scored = behavioral_score(
        fake1_t=result["Fake1_Time"],
        fake2_t=result["Fake2_Time"],
        real_t=result["Real_Time"],
        confidence=conf,
        entropy=entropy,
        provider=result["Provider"],
        real_code=result["Real_Code"],
    )
    result.update(scored)
    result["Reason"] = "pattern_analysis"

    return result

# =========================
# BULK: VERIFY MULTIPLE EMAILS (unchanged)
# =========================
def verify_bulk_emails(emails: List[str], max_workers: int = MAX_WORKERS_DEFAULT) -> List[Dict[str, object]]:
    emails = [normalize_email(e) for e in emails if e and EMAIL_REGEX.match(e)]
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

    email_to_result = {r.get("email"): r for r in results}
    return [email_to_result.get(e) for e in emails if e in email_to_result]
