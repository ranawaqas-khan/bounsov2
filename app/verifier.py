import re, time, socket, smtplib, ssl
from statistics import mean
from typing import Dict, List, Tuple, Optional
from functools import lru_cache

import dns.resolver

# =========
# CONFIG
# =========
EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]
DNS_TIMEOUT = 3.0
SMTP_TIMEOUT = 4.0                         # lower = faster failover
SMTP_PORTS = [25, 587]                     # try 25 first (no TLS), then 587 (STARTTLS)

# You can tune this to your traffic shape
TEMP_FAIL_CODES = {421, 450, 451, 452, 454}
HARD_FAIL_CODES = {550, 551, 552, 553, 554}
SOFT_OK_CODES  = {250, 251}                # 250 = Recipient OK, 251 = User not local but will forward

FREE_PROVIDERS = {
    "gmail.com","yahoo.com","outlook.com","hotmail.com","live.com",
    "icloud.com","aol.com","zoho.com","yandex.com","proton.me","protonmail.com"
}
ROLE_PREFIXES = {
    "info","admin","sales","support","contact","help","office","hello",
    "team","hr","career","jobs","service","billing","marketing"
}
DISPOSABLE_ZONES = {
    "mailinator.com","10minutemail.com","guerrillamail.com","tempmail.email",
    "trashmail.com","dispostable.com","tempmail.com"
}

# =========
# HELPERS
# =========
def classify_email(local: str, domain: str) -> Dict[str, bool | str]:
    d = domain.lower()
    local_l = local.lower()
    is_free        = d in FREE_PROVIDERS
    is_disposable  = any(d == z or d.endswith(f".{z}") for z in DISPOSABLE_ZONES)
    is_role        = any(local_l.startswith(p) for p in ROLE_PREFIXES)
    is_government  = d.endswith(".gov") or d.endswith(".gov.pk") or d.endswith(".gouv.fr") or d.endswith(".gov.uk")

    if is_disposable:
        email_type = "disposable"
    elif is_free:
        email_type = "free"
    elif is_government:
        email_type = "government"
    elif is_role:
        email_type = "role"
    else:
        email_type = "business"

    return {
        "email_type": email_type,
        "is_free_provider": is_free,
        "is_disposable": is_disposable,
        "is_role_based": is_role,
        "is_government": is_government,
    }

def detect_mx_provider(mx_host: str) -> str:
    h = (mx_host or "").lower()
    if "outlook" in h or "protection" in h:  return "microsoft365"
    if "google.com" in h or "aspmx" in h:    return "google"
    if "pphosted" in h or "proofpoint" in h: return "proofpoint"
    if "mimecast" in h:                      return "mimecast"
    if "barracuda" in h:                     return "barracuda"
    if "secureserver" in h:                  return "godaddy"
    if "yahoodns" in h or "yahoodns" in h:   return "yahoo"
    return "unknown"

def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver(configure=True)
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_TIMEOUT
    r.nameservers = DNS_SERVERS
    return r

@lru_cache(maxsize=2048)
def resolve_mx(domain: str) -> List[str]:
    try:
        answers = _resolver().resolve(domain, "MX")
        # keep MX order as returned (priority is in preference value, but first is fine for probing)
        hosts = [str(r.exchange).rstrip(".") for r in answers]
        return hosts
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []
    except Exception:
        return []

def _smtp_one_probe(mx: str, email: str) -> Tuple[Optional[int], str, Optional[float], Optional[int], str]:
    """
    Returns: (code, msg, latency_ms, port_used, session_note)
    Tries port 25 without TLS, then 587 with STARTTLS.
    """
    for port in SMTP_PORTS:
        try:
            start = time.perf_counter()
            with smtplib.SMTP(mx, port, timeout=SMTP_TIMEOUT) as s:
                s.ehlo()
                if port == 587:
                    try:
                        ctx = ssl.create_default_context()
                        s.starttls(context=ctx)
                        s.ehlo()
                        session = "587-starttls"
                    except Exception:
                        session = "587-no-tls"
                else:
                    session = "25-plain"

                s.mail("probe@example.com")
                code, msg = s.rcpt(email)
                latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
                text = msg.decode() if isinstance(msg, bytes) else str(msg)
                return code, text, latency_ms, port, session
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPHeloError):
            # try next port
            continue
        except (socket.timeout, TimeoutError):
            continue
        except Exception as e:
            return None, f"error:{e}", None, port, "exception"

    return None, "connection_failed", None, None, "no_session"

def _score_from_code(code: Optional[int]) -> float:
    if code in SOFT_OK_CODES:
        return 0.98
    if code in HARD_FAIL_CODES:
        return 0.0
    if code in TEMP_FAIL_CODES:
        return 0.5
    return 0.25   # unknown / no response

# =========
# PUBLIC API
# =========
def verify_email(email: str) -> Dict:
    """
    Single-email verification using one RCPT probe.
    Returns a rich dictionary safe for your React UI and Clay.
    """
    base = {
        "email": email,
        "status": "undeliverable",  # final map below
        "deliverable": False,
        "verification_score": 0.0,
        "mx_provider": "unknown",
        "mx_records": {"mx": []},
        "smtp": {
            "code": None,
            "message": None,
            "latency_ms": None,
            "port": None,
            "session": None
        },
        "details": {
            "reasoning": None,
            "email_type": None,
            "is_free_provider": None,
            "is_disposable": None,
            "is_role_based": None,
            "is_government": None,
        }
    }

    # Syntax
    if not EMAIL_REGEX.match(email or ""):
        base["details"]["reasoning"] = "bad_syntax"
        return base

    local, domain = email.split("@", 1)
    # classify (free/role/business/..)
    base["details"].update(classify_email(local, domain))

    # MX
    mx_hosts = resolve_mx(domain)
    base["mx_records"]["mx"] = mx_hosts
    if not mx_hosts:
        base["details"]["reasoning"] = "no_mx"
        base["verification_score"] = 0.0
        return base

    # probe first responsive MX (keep result of first code we get)
    for mx in mx_hosts:
        code, msg, latency, port, session = _smtp_one_probe(mx, email)
        base["mx_provider"] = detect_mx_provider(mx)

        base["smtp"].update({
            "code": code,
            "message": msg,
            "latency_ms": latency,
            "port": port,
            "session": session
        })

        if code is None:
            # try next MX; if none respond, we'll fall through as unknown
            continue

        # decide
        score = _score_from_code(code)
        base["verification_score"] = round(score, 2)

        if code in SOFT_OK_CODES:
            base["status"] = "deliverable"
            base["deliverable"] = True
            base["details"]["reasoning"] = f"{code}_ok"
        elif code in HARD_FAIL_CODES:
            base["status"] = "undeliverable"
            base["deliverable"] = False
            base["details"]["reasoning"] = f"{code}_hard_fail"
        elif code in TEMP_FAIL_CODES:
            base["status"] = "undeliverable"   # you asked: only deliverable/undeliverable
            base["deliverable"] = False
            base["details"]["reasoning"] = f"{code}_temporary_fail"
        else:
            base["status"] = "undeliverable"
            base["deliverable"] = False
            base["details"]["reasoning"] = "unknown_response"

        return base

    # no MX responded
    base["verification_score"] = 0.25
    base["details"]["reasoning"] = "no_mx_response"
    return base


# -------- Bulk helper (thread-friendly) --------
def verify_bulk_emails(emails: List[str]) -> List[Dict]:
    return [verify_email(e) for e in emails]
