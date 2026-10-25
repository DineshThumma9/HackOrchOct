"""Subject resolution across current and historical identifiers."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import DATASET
from .model import Obs, extract_emails, norm_email, norm_phone, read_csv

class Identities:
    def __init__(self, dataset: Path = DATASET) -> None:
        self.dataset = Path(dataset)
        self.users: dict[str, dict[str, Any]] = {}
        self.by_email: dict[str, str] = {}
        self.by_phone: dict[str, str] = {}
        self.by_hash: dict[str, str] = {}
        self._load()

    def _add(self, user_id: str, email: str = "", phone: str = "", email_hash: str = "") -> None:
        user = self.users.setdefault(
            user_id, {"emails": set(), "phones": set(), "hashes": set()}
        )
        if email:
            normalized = norm_email(email)
            user["emails"].add(normalized)
            self.by_email.setdefault(normalized, user_id)
        if phone:
            normalized = norm_phone(phone)
            if normalized:
                user["phones"].add(normalized)
                self.by_phone.setdefault(normalized, user_id)
        if email_hash:
            normalized = str(email_hash).strip().lower()
            user["hashes"].add(normalized)
            self.by_hash.setdefault(normalized, user_id)

    def _load(self) -> None:
        for row in read_csv(self.dataset / "user_identities.csv"):
            self._add(row["user_id"], row.get("email", ""), row.get("phone", ""), row.get("email_hash", ""))
        for row in read_csv(self.dataset / "user_audit_log.csv"):
            self._add(
                row["user_id"],
                row.get("old_value", "") if row.get("field_name") == "email" else "",
                row.get("old_value", "") if row.get("field_name") == "phone" else "",
                row.get("old_value", "") if row.get("field_name") == "email_hash" else "",
            )
            self._add(
                row["user_id"],
                row.get("new_value", "") if row.get("field_name") == "email" else "",
                row.get("new_value", "") if row.get("field_name") == "phone" else "",
                row.get("new_value", "") if row.get("field_name") == "email_hash" else "",
            )

    def resolve(self, email: str) -> str:
        normalized = norm_email(email)
        if normalized in self.by_email:
            return self.by_email[normalized]
        # Tolerate display-name wrapped addresses and case differences.
        for candidate in extract_emails(email):
            if candidate in self.by_email:
                return self.by_email[candidate]
        return ""

    def identifiers(self, user_id: str) -> dict[str, set[str]]:
        user = self.users.get(user_id, {"emails": set(), "phones": set(), "hashes": set()})
        return user


def obs_matches_user(obs: Obs, user_id: str, identities: Identities) -> bool:
    if not user_id:
        return False
    if obs.user_ref and obs.user_ref == user_id:
        return True
    known = identities.identifiers(user_id)
    if obs.emails & known["emails"]:
        return True
    if obs.phones & known["phones"]:
        return True
    if obs.hashes & known["hashes"]:
        return True
    return False
