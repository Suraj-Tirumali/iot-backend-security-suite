"""
Brute Force Runner
==================
Generates realistic password lists for brute force simulation tests.
Used by ISVS 2.1.2 tests to verify lockout mechanisms.
"""

from typing import Iterator


def common_passwords(limit: int = 50) -> list[str]:
    """
    Returns a list of commonly used weak passwords.
    Used to test whether an endpoint rejects them without lockout.
    """
    passwords = [
        "password", "password1", "Password1", "123456", "12345678",
        "qwerty", "abc123", "monkey", "1234567", "letmein",
        "trustno1", "dragon", "baseball", "iloveyou", "master",
        "sunshine", "ashley", "bailey", "passw0rd", "shadow",
        "123123", "654321", "superman", "qazwsx", "michael",
        "football", "password2", "login", "welcome", "admin",
        "admin123", "root", "toor", "pass", "test",
        "guest", "user", "1234", "12345", "123456789",
        "0987654321", "qwerty123", "iloveyou1", "princess", "rockyou",
        "charlie", "donald", "password!", "P@ssword1", "Summer2023",
    ]
    return passwords[:limit]


def sequential_passwords(prefix: str = "test", count: int = 20) -> list[str]:
    """Generate sequential passwords for testing lockout thresholds."""
    return [f"{prefix}{i:04d}" for i in range(count)]


def generate_wordlist(base: str, count: int = 30) -> Iterator[str]:
    """
    Generate password variations from a base word.
    Simulates a targeted dictionary attack.
    """
    yield base
    yield base.capitalize()
    yield base.upper()
    yield f"{base}1"
    yield f"{base}123"
    yield f"{base}!"
    yield f"{base}@"
    yield f"{base}2023"
    yield f"{base}2024"
    yield f"{base}2025"

    for i in range(min(count - 10, 20)):
        yield f"{base}{i}"