import re, dns.resolver, smtplib, time, random, string
from statistics import mean

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 6
PAUSE_BETWEEN_PROBES = 0.08   # faster but stable

# =========================
# UTILITIES
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host: str) -> str:
    h = mx_host.lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "pphosted" in h or "proofpoint" in h: return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    return "unknown"

# =========================
# SMTP MULTI PROBE
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
    times = [t for *_, t in seq if isinstance(t, (int, float))]
    msgs = [m[-80:] for *_, m, _ in seq if isinstance(m, str)]
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
# MAIN VERIFIER
# =========================
def verify_email(email: str):
    result = {
        "email": email, "status": "invalid", "reason": None,
        "provider": None, "mx": None,
        "delta_ms": None, "entropy": None, "avg_latency": None,
        "confidence": 0.0, "smtp_code": None
    }

    if not EMAIL_REGEX.match(email or ""):
        result["reason"] = "bad_syntax"
        return result

    # MX lookup
    try:
        domain = email.split("@")[1]
        mx = str(dns.resolver.resolve(domain, "MX")[0].exchange)
        result["mx"] = mx
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
            label = "invalid"
        elif delta > 120 and entropy > 2:
            label = "likely_valid"
        else:
            label = "risky"
    elif provider == "google":
        if real_code == 550:
            label = "invalid"
        elif delta > 100 and entropy > 2:
            label = "likely_valid"
        else:
            label = "risky"
    elif real_code == 250:
        label = "valid"
    elif real_code == 550:
        label = "invalid"
    else:
        label = "risky"

    # --- Confidence ---
    confidence = round(min(1.0, (conf + (entropy / 10) + (delta / 400)) / 1.5), 2)

    result.update({
        "status": label,
        "delta_ms": delta,
        "entropy": entropy,
        "avg_latency": avg,
        "confidence": confidence,
        "smtp_code": real_code,
        "reason": "smtp_verified"
    })
    return result
