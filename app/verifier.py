import re, dns.resolver, smtplib, time, random, string

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
CORPORATE_TLDS = {"com","org","net","co","biz","ai","io","tech"}
TIMEOUT = 6
PAUSE_BETWEEN_PROBES = 0.15

FREE_PROVIDERS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com","zoho.com","yandex.com"}
ROLE_PREFIXES = {"info","admin","sales","support","contact","help","office","hello","team","hr","career","jobs","service","billing","marketing"}

# =========================
# UTILITIES
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host:str)->str:
    h = mx_host.lower()
    if "pphosted" in h or "proofpoint" in h: return "proofpoint"
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "mimecast" in h:                      return "mimecast"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "barracuda" in h:                     return "barracuda"
    if "secureserver" in h:                  return "godaddy"
    if "yahoodns" in h:                      return "yahoo"
    return "unknown"

def classify_email_type(local:str, domain:str):
    d = domain.lower()
    if d in FREE_PROVIDERS:
        return "free"
    if d.endswith(".gov") or d.endswith(".gov.pk"):
        return "government"
    local_lower = local.lower()
    if any(local_lower.startswith(p) for p in ROLE_PREFIXES):
        return "role"
    return "business"

def get_domain_info(domain:str):
    info = {"spf": False, "dmarc": False, "corporate": False}
    try:
        for r in dns.resolver.resolve(domain, "TXT"):
            if "v=spf1" in str(r).lower():
                info["spf"] = True; break
    except: pass
    try:
        for r in dns.resolver.resolve(f"_dmarc.{domain}", "TXT"):
            if "v=dmarc1" in str(r).lower():
                info["dmarc"] = True; break
    except: pass
    tld = domain.split(".")[-1].lower()
    info["corporate"] = (tld in CORPORATE_TLDS)
    return info

NEGATIVE_LOCALS = {"wrong","fake","test","testing","random","spam","junk","noone","nobody",
    "sample","unsubscribe","bounce","mailer-daemon","do-not-reply","donotreply","bouncebox","null","abcd"}
COMMON_NAME_TOKENS = {"muhammad","ahmed","ahmad","ali","abid","waqas","faiez","usman","imran","rana",
    "john","michael","david","daniel","james","robert","william","sarah","fatima","ayesha",
    "ahanger","khan","malik","hussain","hassan","asif","atif","bilal","saad","zubair","abdallah","salem"}

def local_plausibility(local:str):
    l = local.lower()
    if l in NEGATIVE_LOCALS:
        return 0.0, "neg_local"
    score = 0.0
    notes = []
    if re.match(r"^[a-z]+(\.[a-z]+){1,2}$", l):
        score += 0.30; notes.append("first.last")
    if any(v in l for v in "aeiou") and 3 <= len(l) <= 30:
        score += 0.10; notes.append("humanish")
    tokens = re.split(r"[._\-]+", l)
    if any(t in COMMON_NAME_TOKENS for t in tokens if 2 <= len(t) <= 20):
        score += 0.20; notes.append("name_hit")
    score = max(0.0, min(score, 0.35))
    return score, ("+".join(notes) if notes else "plain")

def smtp_single_rcpt(mx:str, address:str):
    try:
        s = smtplib.SMTP(timeout=TIMEOUT)
        s.connect(mx)
        s.helo("example.com")
        s.mail("probe@example.com")
        start = time.time()
        code, msg = s.rcpt(address)
        elapsed = (time.time() - start) * 1000.0
        s.quit()
        msg = msg.decode() if isinstance(msg, bytes) else str(msg)
        return code, msg.strip(), elapsed
    except Exception as e:
        return None, f"error:{e}", None

def smtp_multi_probe(mx:str, target_email:str, extra_fake:bool=True):
    domain = target_email.split("@")[1]
    seq = [f"{random_local()}@{domain}", f"{random_local()}@{domain}", target_email]
    if extra_fake:
        seq.append(f"{random_local()}@{domain}")
    out = []
    try:
        srv = smtplib.SMTP(timeout=TIMEOUT)
        srv.connect(mx)
        srv.helo("example.com")
        srv.mail("probe@example.com")
        for a in seq:
            start = time.time()
            try:
                code, msg = srv.rcpt(a)
            except Exception as e:
                code, msg = None, str(e)
            elapsed = (time.time() - start) * 1000.0
            msg = msg.decode() if isinstance(msg, bytes) else str(msg)
            out.append((a, code, msg.strip(), elapsed))
            time.sleep(PAUSE_BETWEEN_PROBES)
        srv.quit()
    except Exception as e:
        out.append(("__connect__", None, f"connect_error:{e}", None))
    return out

def analyze_catchall(seq:list, target_email:str):
    f1c, f2c, rc = seq[0][1], seq[1][1], seq[2][1]
    fake_250_count = sum(1 for c in (f1c, f2c) if c == 250)
    is_catchall = (fake_250_count >= 1)
    true_catchall = (fake_250_count == 2 and rc == 250)
    return is_catchall, true_catchall

def analyze_timing(seq:list):
    times = [t for *_ , t in seq if isinstance(t, (int,float))]
    msgs  = [m[-80:] for *_, m, _ in seq if isinstance(m,str)]
    if not times:
        return 0.0, 0, 1, "no_timing"
    delta = int(max(times) - min(times))
    entropy = len(set(msgs)) if msgs else 1
    conf = 0.0
    if delta > 120: conf += 0.25
    elif delta > 80: conf += 0.18
    elif delta > 40: conf += 0.12
    elif delta > 10: conf += 0.06
    if entropy > 1: conf += 0.05
    return min(conf, 0.25), delta, entropy, "ok"

def score_advanced(domain_info, mx_host, timing_conf, local_conf):
    score = 0.0
    if domain_info["spf"]:   score += 0.12
    if domain_info["dmarc"]: score += 0.18
    if domain_info["corporate"]: score += 0.12
    mxp = detect_mx_provider(mx_host)
    if   mxp == "proofpoint":     score += 0.18
    elif mxp == "microsoft365":   score += 0.18
    elif mxp == "google":         score += 0.15
    elif mxp == "mimecast":       score += 0.12
    score += min(timing_conf, 0.25)
    score += local_conf
    score = max(0.0, min(score, 1.0))
    if score >= 0.80: label = "valid"
    elif score >= 0.55: label = "likely_valid"
    else: label = "risky"
    return label, score

# =========================
# MASTER VERIFY
# =========================
def verify_email(email:str):
    if not EMAIL_REGEX.match(email or ""):
        return {"email": email, "status": "invalid", "deliverable": False, "esp": None, "email_type": None}

    local, domain = email.split("@", 1)
    email_type = classify_email_type(local, domain)
    info = get_domain_info(domain)

    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx = str(mx_records[0].exchange)
    except Exception:
        return {"email": email, "status": "invalid", "deliverable": False, "esp": None, "email_type": email_type}

    fake_addr = f"{random_local()}@{domain}"
    ca_code, _, _ = smtp_single_rcpt(mx, fake_addr)
    catchall_first = (ca_code == 250)
    seq = smtp_multi_probe(mx, email, extra_fake=True)
    real_code = seq[2][1] if len(seq) >= 3 else None
    is_catchall, true_catchall = analyze_catchall(seq, email)
    timing_conf, delta_ms, entropy, _ = analyze_timing(seq)
    local_conf, _ = local_plausibility(local)
    label, score = score_advanced(info, mx, timing_conf, local_conf)

    # ✅ Corrected decision logic
    if label == "valid":
        deliverable = True
        status = "valid"
    elif label == "likely_valid":
        deliverable = False
        status = "invalid"
    else:
        deliverable = False
        status = "invalid"

    return {
        "email": email,
        "esp": detect_mx_provider(mx),
        "email_type": email_type,
        "status": status,
        "deliverable": deliverable,
        "catch_all": is_catchall,
        "score": round(score, 2)
    }
