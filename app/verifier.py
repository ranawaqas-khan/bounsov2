import re, dns.resolver, smtplib, time, random, string

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
CORPORATE_TLDS = {"com","org","net","co","biz","ai","io","tech"}
TIMEOUT = 6
PAUSE_BETWEEN_PROBES = 0.15

FREE_PROVIDERS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com","zoho.com","yandex.com"}
DISPOSABLE_DOMAINS = {"mailinator.com","tempmail.com","10minutemail.com","guerrillamail.com","trashmail.com","getnada.com"}

# =========================
# UTILITIES
# =========================
def random_local(k=8): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host:str)->str:
    h = mx_host.lower()
    if "pphosted" in h or "proofpoint" in h: return "proofpoint"
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "mimecast" in h:                      return "mimecast"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "barracuda" in h:                     return "barracuda"
    if "secureserver" in h:                  return "godaddy"
    if "yahoo" in h:                         return "yahoo"
    return "unknown"

def classify_email_type(domain:str):
    d = domain.lower()
    if d in FREE_PROVIDERS: return "free"
    if d in DISPOSABLE_DOMAINS: return "disposable"
    if d.endswith(".gov") or d.endswith(".gov.pk"): return "government"
    return "business"

def get_domain_info(domain:str):
    info = {"spf": False, "dmarc": False, "corporate": False}
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            if "v=spf1" in str(r).lower(): info["spf"] = True; break
    except: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in str(r).lower(): info["dmarc"] = True; break
    except: pass
    tld = domain.split(".")[-1].lower()
    info["corporate"] = (tld in CORPORATE_TLDS)
    return info

NEGATIVE_LOCALS = {"wrong","fake","test","testing","random","spam","junk","noone","nobody",
    "sample","unsubscribe","bounce","mailer-daemon","do-not-reply","donotreply",
    "bouncebox","null","abcd"}

COMMON_NAME_TOKENS = {"muhammad","ahmed","ahmad","ali","abid","waqas","faiez","usman","imran","rana",
    "john","michael","david","daniel","james","robert","william","sarah","fatima","ayesha",
    "ahanger","khan","malik","hussain","hassan","asif","atif","bilal","saad","zubair","abdallah","salem"}

def local_plausibility(local:str):
    l = local.lower()
    if l in NEGATIVE_LOCALS: return 0.0
    score = 0.0
    if re.match(r"^[a-z]+(\.[a-z]+){1,2}$", l): score += 0.30
    if any(v in l for v in "aeiou") and 3 <= len(l) <= 30: score += 0.10
    tokens = re.split(r"[._\-]+", l)
    if any(t in COMMON_NAME_TOKENS for t in tokens if 2 <= len(t) <= 20): score += 0.20
    return min(score, 0.35)

def smtp_single_rcpt(mx:str, address:str):
    try:
        s = smtplib.SMTP(timeout=TIMEOUT)
        s.connect(mx); s.helo("example.com"); s.mail("probe@example.com")
        start = time.time(); code, msg = s.rcpt(address)
        elapsed = (time.time() - start) * 1000.0; s.quit()
        msg = msg.decode() if isinstance(msg, bytes) else str(msg)
        return code, msg.strip(), elapsed
    except Exception as e:
        return None, f"error:{e}", None

def smtp_multi_probe(mx:str, target_email:str, extra_fake=True):
    domain = target_email.split("@")[1]
    seq = [f"{random_local()}@{domain}", f"{random_local()}@{domain}", target_email]
    if extra_fake: seq.append(f"{random_local()}@{domain}")
    out = []
    try:
        srv = smtplib.SMTP(timeout=TIMEOUT)
        srv.connect(mx); srv.helo("example.com"); srv.mail("probe@example.com")
        for a in seq:
            start = time.time()
            try: code, msg = srv.rcpt(a)
            except Exception as e: code, msg = None, str(e)
            elapsed = (time.time() - start) * 1000.0
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            out.append((a, code, msg.strip(), elapsed))
            time.sleep(PAUSE_BETWEEN_PROBES)
        srv.quit()
    except Exception as e:
        out.append(("__connect__", None, f"connect_error:{e}", None))
    return out

def analyze_catchall(seq:list):
    f1c, f2c, rc = seq[0][1], seq[1][1], seq[2][1]
    fake_250 = sum(1 for c in (f1c, f2c) if c == 250)
    return (fake_250 >= 1)

def verify_email(email:str):
    result = {
        "email": email,
        "status": "invalid",
        "score": 0.0,
        "deliverable": False,
        "catch_all": False,
        "mx_provider": None,
        "email_type": None,
        "response_time_ms": None
    }

    if not EMAIL_REGEX.match(email or ""):
        return result

    local, domain = email.split("@", 1)
    info = get_domain_info(domain)
    result["email_type"] = classify_email_type(domain)

    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx = str(mx_records[0].exchange)
    except Exception:
        return result

    result["mx_provider"] = detect_mx_provider(mx)
    fake_addr = f"{random_local()}@{domain}"
    ca_code, _, _ = smtp_single_rcpt(mx, fake_addr)
    seq = smtp_multi_probe(mx, email, extra_fake=True)
    real_code = seq[2][1] if len(seq) >= 3 else None
    avg_response = round(sum(t for *_, t in seq if t) / len(seq), 2) if seq else None
    result["response_time_ms"] = avg_response

    # Simple validity logic
    if real_code == 250:
        result.update({"status": "valid", "score": 1.0, "deliverable": True})
    elif real_code == 550:
        result.update({"status": "invalid", "score": 0.0})
    else:
        # fallback based on heuristics
        local_score = local_plausibility(local)
        if local_score > 0.2 and (info["spf"] or info["dmarc"]):
            result.update({"status": "valid", "score": 0.85, "deliverable": True})
        else:
            result.update({"status": "invalid", "score": 0.4})

    result["catch_all"] = analyze_catchall(seq)
    return result
