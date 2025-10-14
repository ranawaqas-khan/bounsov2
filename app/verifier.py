import re, dns.resolver, smtplib, time, random, string
from statistics import mean
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 6
PAUSE_BETWEEN_PROBES = 0.08
MAX_THREADS = 20
CORPORATE_TLDS = {"com", "org", "net", "co", "biz", "ai", "io", "tech"}

# =========================
# HELPERS
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host: str) -> str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "proofpoint" in h or "pphosted" in h: return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    return "unknown"

def get_domain_info(domain: str):
    info = {"spf": False, "dmarc": False, "corporate": False}
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            if "v=spf1" in str(r).lower():
                info["spf"] = True
                break
    except: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in str(r).lower():
                info["dmarc"] = True
                break
    except: pass
    tld = domain.split(".")[-1].lower()
    info["corporate"] = (tld in CORPORATE_TLDS)
    return info

# =========================
# SMTP PROBING (3 probes)
# =========================
def smtp_multi_probe(mx: str, target_email: str):
    domain = target_email.split("@")[1]
    seq = [f"{random_local()}@{domain}", target_email, f"{random_local()}@{domain}"]
    out = []
    try:
        s = smtplib.SMTP(timeout=TIMEOUT)
        s.connect(mx)
        s.helo("example.com")
        s.mail("probe@example.com")

        for a in seq:
            start = time.perf_counter()
            try:
                code, msg = s.rcpt(a)
            except Exception as e:
                code, msg = None, str(e)
            latency = (time.perf_counter() - start) * 1000.0
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            out.append((a, code, msg.strip(), round(latency, 2)))
            time.sleep(PAUSE_BETWEEN_PROBES)
        s.quit()
    except Exception as e:
        out.append(("__connect__", None, f"connect_error:{e}", None))
    return out

# =========================
# TIMING + ENTROPY ANALYSIS
# =========================
def analyze_timing_entropy(seq):
    times = [t for *_ , t in seq if isinstance(t, (int,float))]
    msgs  = [m[-80:] for *_, m, _ in seq if isinstance(m,str)]
    if not times:
        return 0.0, 0, 1, "no_timing"
    delta = int(max(times) - min(times))
    entropy = len(set(msgs))
    avg_latency = int(mean(times))
    conf = 0.0
    if delta > 120: conf += 0.25
    elif delta > 80: conf += 0.18
    elif delta > 40: conf += 0.12
    elif delta > 10: conf += 0.06
    if entropy > 1: conf += 0.05
    conf = min(conf, 0.3)
    return conf, delta, entropy, avg_latency

# =========================
# SCORING SYSTEM
# =========================
def score_advanced(info, mx, timing_conf, provider):
    score = 0.0
    if info["spf"]: score += 0.12
    if info["dmarc"]: score += 0.18
    if info["corporate"]: score += 0.12
    if provider == "proofpoint": score += 0.18
    elif provider == "microsoft365": score += 0.18
    elif provider == "google": score += 0.15
    elif provider == "mimecast": score += 0.12
    score += min(timing_conf, 0.25)
    return max(0.0, min(score, 1.0))

# =========================
# SINGLE VERIFY FUNCTION
# =========================
def verify_email(email: str):
    result = {
        "email": email, "esp": None, "status": "invalid", "deliverable": False,
        "score": 0.0, "mx": None, "spf": None, "dmarc": None, "corporate": None,
        "delta_ms": None, "entropy": None, "avg_latency": None, "confidence": None,
        "detail": None
    }

    if not EMAIL_REGEX.match(email or ""):
        result["detail"] = "bad_syntax"
        return result

    domain = email.split("@")[1]
    info = get_domain_info(domain)
    result.update(info)

    try:
        mx = str(dns.resolver.resolve(domain, "MX")[0].exchange)
        result["mx"] = mx
    except Exception as e:
        result["detail"] = f"no_mx | {e}"
        return result

    seq = smtp_multi_probe(mx, email)
    conf, delta, entropy, avg = analyze_timing_entropy(seq)
    provider = detect_mx_provider(mx)
    result.update({
        "esp": provider, "delta_ms": delta, "entropy": entropy,
        "avg_latency": avg, "confidence": round(conf, 2)
    })

    real_code = seq[1][1]
    if provider in ("microsoft365", "google"):
        label = "likely_valid" if delta > 70 else "risky"
    elif real_code == 250:
        label = "valid"
    elif real_code == 550:
        label = "invalid"
    else:
        label = "risky"

    score = score_advanced(info, mx, conf, provider)
    result["score"] = round(score, 2)
    result["status"] = label
    result["deliverable"] = (label in ("valid", "likely_valid"))
    result["detail"] = f"MX={mx}({provider}) Δ={delta}ms entropy={entropy} avg={avg} conf={conf:.2f}"

    return result

# =========================
# MULTI-THREAD SUPPORT
# =========================
def verify_bulk_emails(emails):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(verify_email, e): e for e in emails}
        for future in as_completed(futures):
            results.append(future.result())
    return results
