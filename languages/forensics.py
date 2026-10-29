"""ITzMeow80 — snippet di esempio in Python
Analisi forense base: hash, entropia e ricerca di stringhe sospette.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter

SUSPICIOUS_STRINGS = [
    rb"http://",
    rb"https://",
    rb"cmd\.exe",
    rb"powershell",
    rb"CreateRemoteThread",
    rb"VirtualAllocEx",
    rb"WriteProcessMemory",
    rb"HKEY_",
]


def sha256_of(data: bytes) -> str:
    """Restituisce l'hash SHA-256 di un buffer."""
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Entropia di Shannon (alto valore = packing/criptazione probabile)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def find_suspicious_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Estrae stringhe ASCII e segnala quelle che contengono pattern noti."""
    strings = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    hits: list[str] = []
    for s in strings:
        for pat in SUSPICIOUS_STRINGS:
            if re.search(pat, s, flags=re.IGNORECASE):
                hits.append(s.decode("ascii", errors="replace"))
                break
    return hits


def entropy_label(value: float) -> str:
    if value < 4.0:
        return "LOW (dati non compressi)"
    if value < 6.5:
        return "MEDIUM (testo/compressi leggeri)"
    return "HIGH (possibile packing o cifratura)"


def analyze(path: str) -> None:
    with open(path, "rb") as fh:
        data = fh.read()
    entropy = shannon_entropy(data)
    print(f"File     : {path}")
    print(f"Size     : {len(data)} bytes")
    print(f"SHA-256  : {sha256_of(data)}")
    print(f"Entropy  : {entropy:.4f} -> {entropy_label(entropy)}")
    print("Strings  :")
    for s in find_suspicious_strings(data)[:20]:
        print(f"  - {s}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <file>")
        raise SystemExit(1)
    analyze(sys.argv[1])
