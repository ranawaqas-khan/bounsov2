"""
Email Verification Logic for Bounso.com
Contains all verification, classification, and scoring logic
"""

import dns.resolver
import smtplib
import time
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================
# CONFIGURATION
# =========================
class Config:
    SMTP_TIMEOUT = 4
    MAX_THREADS = 50
    DNS_TIMEOUT = 3
    
    # Email classification patterns
    FREE_PROVIDERS = {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", 
        "icloud.com", "aol.com", "protonmail.com", "mail.com",
        "zoho.com", "yandex.com", "gmx.com", "live.com"
    }
    
    ROLE_PATTERNS = {
        "admin", "info", "support", "sales", "contact", "help",
        "service", "billing", "office", "team", "hr", "noreply",
        "hello", "postmaster", "webmaster", "abuse", "security"
    }
    
    GOVT_DOMAINS = {".gov", ".mil", ".edu"}
    
    # MX Provider detection
    MX_PROVIDERS = {
        "google": ["google.com", "aspmx", "googlemail"],
        "microsoft365": ["outlook.com", "protection.outlook", "mx.microsoft"],
        "proofpoint": ["pphosted", "proofpoint"],
        "mimecast": ["mimecast"],
        "barracuda": ["barracuda"],
        "zoho": ["zoho.com", "mx.zoho"],
        "sendgrid": ["sendgrid"],
        "mailgun": ["mailgun"],
        "amazon_ses": ["amazonses"]
    }

config = Config()

# =========================
# EMAIL CLASSIFICATION
# =========================
class EmailClassifier:
    
    @staticmethod
    def classify_email(email: str, domain: str) -> Dict:
        """Classify email into categories"""
        local_part = email.split("@")[0].lower()
        
        # Check if free provider
        is_free = domain.lower() in config.FREE_PROVIDERS
        
        # Check if role-based
        is_role = any(pattern in local_part for pattern in config.ROLE_PATTERNS)
        
        # Check if government
        is_govt = any(domain.endswith(suffix) for suffix in config.GOVT_DOMAINS)
        
        # Check if disposable (basic check)
        is_disposable = domain.lower() in {
            "tempmail.com", "guerrillamail.com", "10minutemail.com",
            "throwaway.email", "mailinator.com"
        }
        
        # Determine primary type
        if is_govt:
            email_type = "government"
        elif is_role:
            email_type = "role"
        elif is_free:
            email_type = "free"
        else:
            email_type = "business"
        
        return {
            "email_type": email_type,
            "is_free": is_free,
            "is_role": is_role,
            "is_disposable": is_disposable
        }

# =========================
# MX PROVIDER DETECTION
# =========================
class MXProvider:
    
    @staticmethod
    def detect_provider(mx_host: str) -> str:
        """Detect email service provider from MX record"""
        mx_lower = mx_host.lower()
        
        for provider, patterns in config.MX_PROVIDERS.items():
            if any(pattern in mx_lower for pattern in patterns):
                return provider
        
        return "other"

# =========================
# DNS RESOLVER
# =========================
class DNSValidator:
    
    @staticmethod
    def get_mx_records(domain: str) -> Tuple[List[str], Optional[str]]:
        """Get MX records for domain"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = config.DNS_TIMEOUT
            resolver.lifetime = config.DNS_TIMEOUT
            
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_list = [str(r.exchange).rstrip('.') for r in sorted(mx_records, key=lambda x: x.preference)]
            
            if not mx_list:
                return [], "no_mx_records"
            
            return mx_list, None
            
        except dns.resolver.NXDOMAIN:
            return [], "domain_not_exist"
        except dns.resolver.NoAnswer:
            return [], "no_mx_records"
        except dns.resolver.Timeout:
            return [], "dns_timeout"
        except Exception:
            return [], "dns_error"

# =========================
# SMTP VALIDATOR
# =========================
class SMTPValidator:
    
    @staticmethod
    def verify_smtp(mx_host: str, email: str) -> Tuple[Optional[int], Optional[str]]:
        """Perform SMTP verification"""
        try:
            smtp = smtplib.SMTP(timeout=config.SMTP_TIMEOUT)
            smtp.connect(mx_host)
            smtp.helo("mail.bounso.com")
            smtp.mail("verify@bounso.com")
            
            code, message = smtp.rcpt(email)
            smtp.quit()
            
            return code, None
            
        except smtplib.SMTPServerDisconnected:
            return None, "server_disconnected"
        except smtplib.SMTPConnectError:
            return None, "connection_refused"
        except TimeoutError:
            return None, "timeout"
        except Exception:
            return None, "smtp_error"

# =========================
# SCORING ENGINE
# =========================
class ScoringEngine:
    
    @staticmethod
    def calculate_score(smtp_code: Optional[int], reason: Optional[str], 
                       mx_provider: str, is_disposable: bool) -> Tuple[int, str]:
        """
        Calculate deliverability score (0-100)
        Returns: (score, status)
        """
        
        # Disposable email = immediate fail
        if is_disposable:
            return 0, "undeliverable"
        
        # DNS/MX errors = low score
        if reason in ["domain_not_exist", "no_mx_records"]:
            return 0, "undeliverable"
        
        if reason in ["dns_timeout", "dns_error"]:
            return 30, "undeliverable"
        
        # SMTP code analysis
        if smtp_code == 250:
            # Deliverable - adjust by provider reliability
            base_score = 95
            
            # Google/Microsoft are most reliable
            if mx_provider in ["google", "microsoft365"]:
                return 100, "deliverable"
            
            return base_score, "deliverable"
        
        elif smtp_code == 550:
            # Mailbox doesn't exist
            return 0, "undeliverable"
        
        elif smtp_code in [451, 452, 421]:
            # Temporary issues - medium score
            return 50, "undeliverable"
        
        elif smtp_code in [553, 554]:
            # Rejected/blocked
            return 5, "undeliverable"
        
        # Connection issues
        if reason in ["server_disconnected", "connection_refused", "timeout"]:
            # Can't verify but domain exists
            return 45, "undeliverable"
        
        # Unknown error
        return 35, "undeliverable"

# =========================
# MAIN VERIFIER CLASS
# =========================
class EmailVerifier:
    
    @staticmethod
    def verify_single(email: str) -> Dict:
        """Verify a single email address"""
        start_time = time.perf_counter()
        
        # Extract domain
        domain = email.split("@")[1].lower()
        
        # Classify email
        classification = EmailClassifier.classify_email(email, domain)
        
        # Get MX records
        mx_records, dns_error = DNSValidator.get_mx_records(domain)
        
        if dns_error:
            score, status = ScoringEngine.calculate_score(
                None, dns_error, "none", classification["is_disposable"]
            )
            
            processing_time = int((time.perf_counter() - start_time) * 1000)
            
            return {
                "email": email,
                "status": status,
                "score": score,
                "reason": dns_error,
                "mx_provider": "none",
                "mx_records": [],
                "smtp_code": None,
                "domain": domain,
                "verified_at": datetime.utcnow().isoformat(),
                "processing_time_ms": processing_time,
                **classification
            }
        
        # Detect MX provider
        mx_provider = MXProvider.detect_provider(mx_records[0])
        
        # SMTP verification
        smtp_code, smtp_error = SMTPValidator.verify_smtp(mx_records[0], email)
        
        # Calculate score
        score, status = ScoringEngine.calculate_score(
            smtp_code, smtp_error, mx_provider, classification["is_disposable"]
        )
        
        processing_time = int((time.perf_counter() - start_time) * 1000)
        
        return {
            "email": email,
            "status": status,
            "score": score,
            "reason": smtp_error if smtp_error else "verified",
            "mx_provider": mx_provider,
            "mx_records": mx_records[:3],  # Top 3 MX records
            "smtp_code": smtp_code,
            "domain": domain,
            "verified_at": datetime.utcnow().isoformat(),
            "processing_time_ms": processing_time,
            **classification
        }
    
    @staticmethod
    def verify_bulk(emails: List[str]) -> Dict:
        """Verify multiple emails in parallel"""
        start_time = time.perf_counter()
        results = []
        
        with ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
            future_to_email = {
                executor.submit(EmailVerifier.verify_single, email): email 
                for email in emails
            }
            
            for future in as_completed(future_to_email):
                try:
                    result = future.result()
                    results.append(result)
                except Exception:
                    email = future_to_email[future]
                    # Fallback error response
                    results.append({
                        "email": email,
                        "status": "undeliverable",
                        "score": 0,
                        "reason": "processing_error",
                        "email_type": "unknown",
                        "is_free": False,
                        "is_role": False,
                        "is_disposable": False,
                        "mx_provider": "error",
                        "mx_records": [],
                        "smtp_code": None,
                        "domain": email.split("@")[1],
                        "verified_at": datetime.utcnow().isoformat(),
                        "processing_time_ms": 0
                    })
        
        # Calculate stats
        deliverable_count = sum(1 for r in results if r["status"] == "deliverable")
        undeliverable_count = len(results) - deliverable_count
        
        total_time = int((time.perf_counter() - start_time) * 1000)
        
        return {
            "total": len(results),
            "deliverable": deliverable_count,
            "undeliverable": undeliverable_count,
            "results": results,
            "processing_time_ms": total_time
        }
