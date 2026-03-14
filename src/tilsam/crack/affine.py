from __future__ import annotations

from tilsam.alphabets.base import Alphabet
from tilsam.analysis import scoring
from tilsam.ciphers import affine
from tilsam.crack.candidate import Candidate


def _gcd(a: int, b: int) -> int:
    while b != 0:
        a, b = b, a % b
    return abs(a)


def _relative_letters_only(text: str, alphabet: Alphabet) -> dict[str, float]:
    counts: dict[str, int] = {alphabet.index_to_char(i): 0 for i in range(alphabet.size())}
    total = 0

    for ch in text:
        if alphabet.contains(ch):
            counts[ch] += 1
            total += 1

    if total == 0:
        # No scorable characters; return uniform to avoid division by zero
        return {k: 1.0 / alphabet.size() for k in counts}

    return {k: v / total for k, v in counts.items()}


def crack(ciphertext: str, alphabet: Alphabet, expected_freq: dict[str, float]) -> list[Candidate]:
    n = alphabet.size()
    candidates: list[Candidate] = []

    for a in range(1, n):
        if _gcd(a, n) != 1:
            continue
        for b in range(n):
            try:
                plaintext = affine.decrypt(ciphertext, a, b, alphabet)
            except ValueError:
                continue

            observed = _relative_letters_only(plaintext, alphabet)
            score = scoring.chi_squared(observed, expected_freq, alphabet)
            candidates.append(
                Candidate(
                    plaintext=plaintext,
                    score=score,
                    key_description=f"a={a}, b={b}",
                )
            )

    candidates.sort(key=lambda c: c.score)
    return candidates
