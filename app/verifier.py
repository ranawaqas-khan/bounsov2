import re, dns.resolver, smtplib, time, random, string
from statistics import mean

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 6
PAUSE_BETWEEN_PROBES = 0.08

FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "aol.com", "zoho.com", "yandex.com"
}
ROLE_PREFIXES = {
    "info","admin","sales","support","contact","help","office",
    "hello","team","hr","career","jobs","service","billing","marketing"
}
DISPOSABLE_PROVIDERS = {
    "tempmail.com","mailinator.com","guerrillamail.com",
    "10minutemail.com","dispostable.com","trashmail.com"
}

# =========================
# UTILITIES
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host:str)->str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "pphosted" in h or "proofpoint" in h: return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    return "unknown"

def classify_email(local:str, domain:str):
    d = domain.lower()
    if d in FREE_PROVIDERS: return "free"
    if any(d.endswith(dp) for dp in DISPOSABLE_PROVIDERS): return "disposable"
    if any(local.lower().startswith(p) for p in ROLE_PREFIXES): return "role"
    return "business"

# =========================
# SMTP PROBING (3 probes)
# =========================
def smtp_multi_probe(mx:str, target_email:str):
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
# ANALYSIS
# =========================
def analyze_timing_entropy(seq):
    times = [t for *_, t in seq if isinstance(t, (int,float))]
    msgs  = [m[-80:] for *_, m, _ in seq if isinstance(m,str)]
    if not times:
        return 0, 0, 1, 0, "no_timing"

    delta = int(max(times) - min(times))
    entropy = len(set(msgs))
    avg_latency = int(mean(times))

    conf = 0.0
    if delta > 120: conf += 0.25
    elif delta > 80: conf += 0.18
    elif delta > 40: conf += 0.12
    elif delta > 10: conf += 0.06
    if entropy > 1: conf += 0.05
    conf = min(conf, 0.35)

    return conf, delta, entropy, avg_latency, "ok"

# =========================
# VERIFY FUNCTION
# =========================
def verify_email(email:str):
    result = {
        "email": email,
        "status": "invalid",
        "email_type": None,
        "provider": None,
        "mx_record": None,
        "deliverable": False,
        "score": 0.0,
        "reason": None,
        "timing_ms": None,
        "entropy": None,
        "avg_latency": None
    }

    if not EMAIL_REGEX.match(email or ""):
        result["reason"] = "bad_syntax"
        return result

    local, domain = email.split("@", 1)
    result["email_type"] = classify_email(local, domain)

    # MX lookup
    try:
        mx = str(dns.resolver.resolve(domain, "MX")[0].exchange)
        result["mx_record"] = mx
        provider = detect_mx_provider(mx)
        result["provider"] = provider
    except Exception as e:
        result["reason"] = f"no_mx | {e}"
        return result

    seq = smtp_multi_probe(mx, email)
    conf, delta, entropy, avg, _ = analyze_timing_entropy(seq)
    real_code = seq[1][1] if len(seq) >= 2 else None

    # --- Logic handling by ESP ---
    if provider == "microsoft365":
        if real_code == 550:
            label, deliverable = "invalid", False
        elif delta > 120 and entropy > 2:
            label, deliverable = "likely_valid", True
        else:
            label, deliverable = "risky", False
    elif provider == "google":
        if real_code == 550:
            label, deliverable = "invalid", False
        elif delta > 100 and entropy > 2:
            label, deliverable = "likely_valid", True
        else:
            label, deliverable = "risky", False
    elif real_code == 250:
        label, deliverable = "valid", True
    elif real_code == 550:
        label, deliverable = "invalid", False
    else:
        label, deliverable = "risky", False

    # --- Score ---
    score = min(1.0, round((conf + (entropy / 10) + (delta / 400)) / 1.2, 2))

    result.update({
        "status": label,
        "deliverable": deliverable,
        "score": score,
        "reason": "smtp_verified",
        "timing_ms": delta,
        "entropy": entropy,
        "avg_latency": avg
    })

    return result
