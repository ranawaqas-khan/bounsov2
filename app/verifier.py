import re, dns.resolver, smtplib, time, random, string

# =========================
# CONFIG
# =========================
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
TIMEOUT = 6
PAUSE_BETWEEN_PROBES = 0.15

FREE_PROVIDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","icloud.com","aol.com","zoho.com","yandex.com"
}
DISPOSABLE_DOMAINS = {
    "mailinator.com","tempmail.com","10minutemail.com","guerrillamail.com","trashmail.com","getnada.com"
}

ROLE_PREFIXES = {
    "info","admin","sales","support","contact","help","office","hello","enquiry",
    "team","hr","career","jobs","service","billing","marketing","ceo","founder"
}

# =========================
# UTILITIES
# =========================
def random_local(k=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def detect_mx_provider(mx_host: str) -> str:
    h = mx_host.lower()
    if "pphosted" in h or "proofpoint" in h: return "Proofpoint"
    if "outlook" in h or "protection" in h:  return "Microsoft 365"
    if "mimecast" in h:                      return "Mimecast"
    if "google.com" in h or "aspmx" in h:    return "Google Workspace"
    if "barracuda" in h:                     return "Barracuda"
    if "secureserver" in h:                  return "GoDaddy"
    if "yahoodns" in h:                      return "Yahoo Mail"
    return "Unknown"

def classify_email_type(local: str, domain: str) -> str:
    d = domain.lower()
    if d in FREE_PROVIDERS: return "free"
    if d in DISPOSABLE_DOMAINS: return "disposable"
    if d.endswith(".gov") or d.endswith(".gov.pk"): return "government"
    local_part = local.lower().split("@")[0]
    if any(local_part.startswith(p) for p in ROLE_PREFIXES):
        return "role"
    return "business"

# =========================
# SMTP & VALIDATION
# =========================
def smtp_single_rcpt(mx: str, address: str):
    """Quick RCPT to test catch-all."""
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

def smtp_multi_probe(mx: str, target_email: str):
    """Multiple probes: 2 fake → real → fake."""
    domain = target_email.split("@")[1]
    seq = [
        f"{random_local()}@{domain}",
        f"{random_local()}@{domain}",
        target_email,
        f"{random_local()}@{domain}"
    ]
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

def analyze_catchall(seq: list):
    """Detect catch-all behavior."""
    if len(seq) < 3: return False
    fake_codes = [seq[0][1], seq[1][1]]
    real_code = seq[2][1]
    fake_250 = sum(1 for c in fake_codes if c == 250)
    return fake_250 >= 1

# =========================
# VERIFY FUNCTION
# =========================
def verify_email(email: str):
    result = {
        "email": email,
        "mx_record": None,
        "esp": None,
        "email_type": None,
        "deliverable": False,
        "catch_all": False,
        "valid": False
    }

    if not EMAIL_REGEX.match(email or ""):
        return result

    local, domain = email.split("@", 1)
    result["email_type"] = classify_email_type(local, domain)

    # MX lookup
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        mx = str(mx_records[0].exchange)
        result["mx_record"] = mx
        result["esp"] = detect_mx_provider(mx)
    except Exception:
        return result

    # Catch-all quick probe
    fake_addr = f"{random_local()}@{domain}"
    ca_code, _, _ = smtp_single_rcpt(mx, fake_addr)
    catch_all_first = (ca_code == 250)

    # Multi-probe for deeper check
    seq = smtp_multi_probe(mx, email)
    real_code = seq[2][1] if len(seq) >= 3 else None
    result["catch_all"] = analyze_catchall(seq)

    # SMTP logic
    if not catch_all_first:
        if real_code == 250:
            result["deliverable"] = True
            result["valid"] = True
        elif real_code == 550:
            result["deliverable"] = False
            result["valid"] = False
        elif real_code is None:
            result["deliverable"] = False
            result["valid"] = False
    else:
        # Catch-all domain → validity depends on address plausibility
        if any(x in local.lower() for x in ["test", "fake", "spam", "random"]):
            result["valid"] = False
        else:
            result["valid"] = True  # still deliverable but catch-all
        result["deliverable"] = True

    return result
