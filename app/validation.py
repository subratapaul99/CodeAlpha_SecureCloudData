"""Task 1: classify incoming data and normalise it so duplicates are detectable."""
import re
from typing import Tuple

NAME_RE = re.compile(r"^[A-Za-z][A-Za-z .'\-]{1,98}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
SQLI_RE = re.compile(
    r"(--|;|/\*|\*/|\b(union|select|insert|update|delete|drop|alter|exec)\b|'\s*or\s*'?\d)",
    re.IGNORECASE)
PLACEHOLDER_EMAILS = {"test@test.com", "a@a.com", "example@example.com", "abc@abc.com"}


def normalise(name: str, email: str, phone: str) -> Tuple[str, str, str]:
    name = " ".join(name.split()).title()
    email = email.strip().lower()
    phone = re.sub(r"\D", "", phone)          # keep digits only
    return name, email, phone


def classify(name: str, email: str, phone: str):
    """Returns (is_valid, classification, reason). Expects normalised input."""
    for field in (name, email, phone):
        if SQLI_RE.search(field):
            return False, "false_positive", "suspicious SQL pattern in input"
    if not NAME_RE.match(name):
        return False, "false_positive", "invalid name"
    if not EMAIL_RE.match(email) or email in PLACEHOLDER_EMAILS:
        return False, "false_positive", "invalid or placeholder email"
    if not 7 <= len(phone) <= 15:
        return False, "false_positive", "invalid phone number"
    return True, "unique", "ok"


def canonical_key(name: str, email: str, phone: str) -> str:
    # Email + phone identify a person; name spelling differences shouldn't bypass dedup.
    return f"{email}|{phone}"
