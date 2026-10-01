#!/usr/bin/env python3
"""
Bird Prepare Wordlist (bird-wl)
Smart Password Wordlist Generator

Generates intelligent password combinations from user-provided seed strings.
Two modes: --py (native Python engine) and --ai (Ollama LLM).

Usage:
    python3 bird-wl.py --py --strings empresa,2026,1234,nome,teste -o wl.txt --top-1000
    python3 bird-wl.py --ai --strings empresa,2026,1234,nome,teste -o wl.txt --top-500
"""

import argparse
import itertools
import os
import sys
import time


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ANSI Terminal Colors
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    @staticmethod
    def disable():
        """Disable colors (e.g. when piping to file)."""
        for attr in ['RESET', 'BOLD', 'DIM', 'RED', 'GREEN', 'YELLOW',
                      'BLUE', 'MAGENTA', 'CYAN', 'WHITE', 'GRAY']:
            setattr(C, attr, '')


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Banner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BANNER = f"""{C.CYAN}{C.BOLD}
    ██████╗ ██╗██████╗ ██████╗     ██╗    ██╗██╗
    ██╔══██╗██║██╔══██╗██╔══██╗    ██║    ██║██║
    ██████╔╝██║██████╔╝██║  ██║    ██║ █╗ ██║██║
    ██╔══██╗██║██╔══██╗██║  ██║    ██║███╗██║██║
    ██████╔╝██║██║  ██║██████╔╝    ╚███╔███╔╝███████╗
    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝     ╚══╝╚══╝ ╚══════╝{C.RESET}
{C.DIM}    ─── Smart Password Wordlist Generator ───────────{C.RESET}
"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Utility Functions
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def log_info(msg):
    sys.stderr.write(f"  {C.CYAN}[*]{C.RESET} {msg}\n")

def log_success(msg):
    sys.stderr.write(f"  {C.GREEN}[✓]{C.RESET} {msg}\n")

def log_warn(msg):
    sys.stderr.write(f"  {C.YELLOW}[!]{C.RESET} {msg}\n")

def log_error(msg):
    sys.stderr.write(f"  {C.RED}[✗]{C.RESET} {msg}\n")

def log_tier(tier_num, tier_name, count):
    sys.stderr.write(f"  {C.MAGENTA}[T{tier_num}]{C.RESET} {tier_name} {C.DIM}→ {count} passwords{C.RESET}\n")

def progress_bar(current, total, label=""):
    """Render an inline progress bar to stderr."""
    bar_width = 35
    if total == 0:
        pct = 100.0
    else:
        pct = min(current / total * 100, 100.0)
    filled = int(bar_width * pct / 100)
    bar = "█" * filled + "░" * (bar_width - filled)
    sys.stderr.write(
        f"\r  {C.CYAN}[{bar}]{C.RESET} {pct:5.1f}%"
        f" {C.DIM}({current}/{total}){C.RESET} {label}  "
    )
    sys.stderr.flush()

def progress_done():
    """Clear progress bar line."""
    sys.stderr.write("\r" + " " * 80 + "\r")
    sys.stderr.flush()

def _dedup_ordered(iterable):
    """Deduplicate an iterable preserving insertion order."""
    seen = set()
    for item in iterable:
        if item not in seen:
            seen.add(item)
            yield item


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Password Engine  (mode: --py)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PasswordEngine:
    """
    Native Python password generation engine.

    Generates passwords in 6 tiers of ascending complexity / descending
    probability, yielding them lazily so we can stop as soon as the
    target count is reached.
    """

    # Leet-speak substitution map  (lowercase key → list of replacements)
    LEET = {
        'a': ['4', '@'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7', '+'],
        'l': ['1'],
        'b': ['8'],
        'g': ['9'],
    }

    # Common numeric suffixes ordered by real-world frequency
    COMMON_NUMS = [
        '123', '1234', '1', '12', '12345', '0', '01', '2', '3',
        '10', '11', '13', '21', '69', '77', '99', '00', '007',
        '100', '111', '321', '666', '777', '888', '999', '000',
        '1000', '123456', '54321', '1111', '7777',
    ]

    YEARS = [str(y) for y in range(2020, 2030)]

    # Common special-char suffixes
    CHAR_SUFFIXES = [
        '!', '@', '#', '$', '*', '!!', '!@', '@!', '!@#',
        '#!', '!1', '@1', '#1', '$!',
    ]

    # Separators used between word and number
    SEPARATORS = ['.', '_', '-', '@', '#', '!', '$', '+', '&']

    # ── constructor ──────────────────────────────────────────────────────────

    def __init__(self, seeds: list[str], target: int):
        self.target = target
        self.seeds = [s.strip() for s in seeds if s.strip()]

        # Classify seeds into words (alpha) and numbers (digit)
        self.words = []
        self.numbers = []
        for s in self.seeds:
            if s.isdigit():
                self.numbers.append(s)
            else:
                self.words.append(s)

        # Build priority-ordered number list (user nums first)
        self._nums = list(_dedup_ordered(
            self.numbers + self.COMMON_NUMS + self.YEARS
        ))

    # ── public API ───────────────────────────────────────────────────────────

    def generate(self) -> list[str]:
        """Generate up to *target* unique passwords, ordered by probability."""

        passwords: dict[str, None] = {}   # ordered set
        tier_counts = []

        tiers = [
            (1, "Basic (case variants)",          self._tier1_basic),
            (2, "Simple combinations",             self._tier2_combos),
            (3, "Capitalized + suffixes",          self._tier3_caps),
            (4, "Separator patterns",              self._tier4_seps),
            (5, "Leet speak",                      self._tier5_leet),
            (6, "Advanced leet + complex",         self._tier6_advanced),
        ]

        try:
            for tier_num, tier_name, gen_func in tiers:
                before = len(passwords)
                for pwd in gen_func():
                    if pwd and pwd not in passwords:
                        passwords[pwd] = None
                        if len(passwords) % 200 == 0:
                            progress_bar(len(passwords), self.target, tier_name)
                        if len(passwords) >= self.target:
                            break
                added = len(passwords) - before
                log_tier(tier_num, tier_name, added)
                if len(passwords) >= self.target:
                    break
    
            # If we still need more, generate padding
            if len(passwords) < self.target:
                before = len(passwords)
                for pwd in self._padding():
                    if pwd and pwd not in passwords:
                        passwords[pwd] = None
                        if len(passwords) >= self.target:
                            break
                added = len(passwords) - before
                if added:
                    log_tier("+", "Padding (extended numbers)", added)
        except KeyboardInterrupt:
            log_warn("\nProcesso interrompido pelo usuário. Salvando wordlist parcial...")
        finally:
            progress_done()
            return list(passwords.keys())[:self.target]

    # ── helpers ──────────────────────────────────────────────────────────────

    def _case_variants(self, word: str):
        """Yield case variants: lower, UPPER, Capitalize."""
        lo = word.lower()
        yield lo
        cap = word.capitalize()
        if cap != lo:
            yield cap
        up = word.upper()
        if up != lo and up != cap:
            yield up

    def _leet_full(self, word: str) -> str:
        """Replace every substitutable char with its primary leet symbol."""
        out = []
        for ch in word:
            key = ch.lower()
            if key in self.LEET:
                out.append(self.LEET[key][0])
            else:
                out.append(ch)
        return ''.join(out)

    def _leet_variants(self, word: str):
        """Yield multiple leet variants of a word (single + pair subs)."""
        # Identify substitutable positions
        positions = []
        for i, ch in enumerate(word):
            key = ch.lower()
            if key in self.LEET:
                positions.append((i, self.LEET[key]))

        if not positions:
            return

        # Full leet (primary only)
        full = list(word)
        for pos, subs in positions:
            full[pos] = subs[0]
        yield ''.join(full)

        # Full leet with alt substitutions where available
        alt = list(word)
        for pos, subs in positions:
            alt[pos] = subs[-1]     # last = secondary if exists, else same as primary
        alt_str = ''.join(alt)
        if alt_str != ''.join(full):
            yield alt_str

        # Single substitutions
        for pos, subs in positions:
            for sub in subs:
                v = list(word)
                v[pos] = sub
                yield ''.join(v)

        # Pair substitutions (primary only, to keep count manageable)
        if len(positions) >= 2:
            for (p1, s1), (p2, s2) in itertools.combinations(positions, 2):
                v = list(word)
                v[p1] = s1[0]
                v[p2] = s2[0]
                yield ''.join(v)

    # ── Tier 1: Basic ────────────────────────────────────────────────────────

    def _tier1_basic(self):
        """Pure case variants of each seed string."""
        for word in self.words:
            yield from self._case_variants(word)
        for num in self.numbers:
            yield num

    # ── Tier 2: Simple combos ────────────────────────────────────────────────

    def _tier2_combos(self):
        """word+number, number+word, word+word."""
        # word + user numbers (highest priority)
        for word in self.words:
            for num in self.numbers:
                yield word.lower() + num
                yield word.capitalize() + num

        # word + common numbers
        for word in self.words:
            for num in self.COMMON_NUMS:
                if num not in self.numbers:
                    yield word.lower() + num
                    yield word.capitalize() + num

        # word + years
        for word in self.words:
            for yr in self.YEARS:
                if yr not in self.numbers:
                    yield word.lower() + yr
                    yield word.capitalize() + yr

        # number + word
        for word in self.words:
            for num in self._nums[:15]:  # top 15 numbers only
                yield num + word.lower()
                yield num + word.capitalize()

        # word + word (all ordered pairs)
        for w1, w2 in itertools.permutations(self.words, 2):
            yield w1.lower() + w2.lower()
            yield w1.capitalize() + w2.lower()
            yield w1.lower() + w2.capitalize()

    # ── Tier 3: Caps + special suffixes ──────────────────────────────────────

    def _tier3_caps(self):
        """Capitalized/upper words + number + special suffix."""
        # UPPER + numbers
        for word in self.words:
            for num in self._nums[:20]:
                yield word.upper() + num

        # Cap + number + special
        for word in self.words:
            for num in self._nums[:15]:
                for suf in self.CHAR_SUFFIXES[:6]:
                    yield word.capitalize() + num + suf

        # word + special (no number)
        for word in self.words:
            for suf in self.CHAR_SUFFIXES:
                yield word.lower() + suf
                yield word.capitalize() + suf
                yield word.upper() + suf

        # CamelCase word pairs
        for w1, w2 in itertools.permutations(self.words, 2):
            yield w1.capitalize() + w2.capitalize()
            for num in self.numbers:
                yield w1.capitalize() + w2.capitalize() + num
                yield w1.capitalize() + num + w2.capitalize()

        # number + word + special
        for word in self.words:
            for num in self.numbers:
                for suf in self.CHAR_SUFFIXES[:4]:
                    yield num + word.capitalize() + suf

        # word + special + number
        for word in self.words:
            for suf in self.CHAR_SUFFIXES[:4]:
                for num in self.numbers:
                    yield word.capitalize() + suf + num

    # ── Tier 4: Separator patterns ───────────────────────────────────────────

    def _tier4_seps(self):
        """word{sep}number, word{sep}word."""
        # word + sep + number
        for word in self.words:
            for sep in self.SEPARATORS:
                for num in self._nums[:20]:
                    yield word.lower() + sep + num
                    yield word.capitalize() + sep + num

        # word + sep + word
        for w1, w2 in itertools.permutations(self.words, 2):
            for sep in self.SEPARATORS:
                yield w1.lower() + sep + w2.lower()
                yield w1.capitalize() + sep + w2.capitalize()

        # number + sep + word
        for word in self.words:
            for sep in self.SEPARATORS[:5]:
                for num in self._nums[:10]:
                    yield num + sep + word.lower()

        # word + sep + number + special
        for word in self.words:
            for sep in self.SEPARATORS[:4]:
                for num in self.numbers:
                    for suf in self.CHAR_SUFFIXES[:3]:
                        yield word.capitalize() + sep + num + suf

        # UPPER + sep + number
        for word in self.words:
            for sep in self.SEPARATORS[:4]:
                for num in self._nums[:10]:
                    yield word.upper() + sep + num

    # ── Tier 5: Leet speak ───────────────────────────────────────────────────

    def _tier5_leet(self):
        """Apply leet-speak substitutions to words and common combos."""
        for word in self.words:
            # Leet of case variants
            for cv in self._case_variants(word):
                yield from self._leet_variants(cv)

            # Leet word + number
            leet_full = self._leet_full(word.lower())
            yield leet_full
            leet_cap = self._leet_full(word.capitalize())
            yield leet_cap
            for num in self._nums[:15]:
                yield leet_full + num
                yield leet_cap + num

            # Leet word + special
            for suf in self.CHAR_SUFFIXES[:5]:
                yield leet_full + suf
                yield leet_cap + suf

            # Leet word + number + special
            for num in self.numbers:
                for suf in self.CHAR_SUFFIXES[:4]:
                    yield leet_full + num + suf
                    yield leet_cap + num + suf

        # Leet word pairs
        for w1, w2 in itertools.permutations(self.words, 2):
            l1 = self._leet_full(w1.capitalize())
            yield l1 + w2.capitalize()
            yield l1 + self._leet_full(w2.lower())
            for num in self.numbers:
                yield l1 + w2.capitalize() + num

    # ── Tier 6: Advanced / complex ───────────────────────────────────────────

    def _tier6_advanced(self):
        """Complex multi-leet, separators + leet, reversed, mixed."""
        # All leet variants (including partials) with numbers and separators
        for word in self.words:
            for cv in self._case_variants(word):
                for lv in self._leet_variants(cv):
                    for num in self._nums[:10]:
                        yield lv + num
                    for sep in self.SEPARATORS[:4]:
                        for num in self.numbers:
                            yield lv + sep + num
                    for suf in self.CHAR_SUFFIXES[:4]:
                        yield lv + suf
                        for num in self.numbers:
                            yield lv + num + suf
                            yield lv + suf + num

        # Reversed words
        for word in self.words:
            rev = word[::-1]
            yield from self._case_variants(rev)
            yield rev.lower() + self.numbers[0] if self.numbers else None
            for num in self.numbers:
                yield rev.lower() + num
                yield rev.capitalize() + num

        # Leet pairs with separators
        for w1, w2 in itertools.permutations(self.words, 2):
            l1 = self._leet_full(w1.lower())
            l2 = self._leet_full(w2.lower())
            yield l1 + l2
            for sep in self.SEPARATORS[:3]:
                yield l1 + sep + l2
            for num in self.numbers:
                yield l1 + l2 + num
                yield l1 + num + l2

        # Triple combinations (word + word + number)
        if len(self.words) >= 2:
            for w1, w2 in itertools.permutations(self.words, 2):
                for num in self.numbers:
                    yield w1.capitalize() + w2.capitalize() + num + '!'
                    yield self._leet_full(w1.capitalize()) + w2.capitalize() + num
                    yield w1.capitalize() + self._leet_full(w2.capitalize()) + num

        # Mixed case mid-word (e.g., eMpReSa)
        for word in self.words:
            if len(word) >= 4:
                alt = ''.join(
                    ch.upper() if i % 2 else ch.lower()
                    for i, ch in enumerate(word)
                )
                yield alt
                for num in self.numbers:
                    yield alt + num
                # inverse alternation
                alt2 = ''.join(
                    ch.lower() if i % 2 else ch.upper()
                    for i, ch in enumerate(word)
                )
                yield alt2
                for num in self.numbers:
                    yield alt2 + num

    # ── Padding: extended numbers to fill remaining slots ────────────────────

    def _padding(self):
        """Extra combinations to reach the target count if tiers ran short."""
        # word + 2-digit numbers (00–99)
        for word in self.words:
            for n in range(100):
                ns = str(n).zfill(2)
                yield word.lower() + ns
                yield word.capitalize() + ns

        # word + 3-digit numbers (000–999)
        for word in self.words:
            for n in range(1000):
                ns = str(n).zfill(3)
                yield word.lower() + ns
                yield word.capitalize() + ns

        # Leet + 2-digit numbers
        for word in self.words:
            leet = self._leet_full(word.lower())
            for n in range(100):
                yield leet + str(n).zfill(2)

        # word + word + 2-digit numbers
        for w1, w2 in itertools.permutations(self.words, 2):
            for n in range(100):
                yield w1.capitalize() + w2.capitalize() + str(n).zfill(2)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Ollama Engine  (mode: --ai)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class OllamaEngine:
    """
    AI-powered password generation using a local Ollama LLM.

    Sends contextualised prompts to the model and parses the raw
    password output.  Falls back with a clear error when the server
    is unreachable.
    """

    SYSTEM_PROMPT = (
        "You are a cybersecurity expert specialized in password auditing. "
        "Your task is to generate realistic password candidates that humans "
        "would actually choose based on given seed words. "
        "Output ONLY passwords, one per line, no numbering, no explanation, no markdown. "
        "Vary complexity from simple (word123) to advanced (W0rd@2026!). "
        "Use real-world patterns: capitalize first letter, append year/numbers, "
        "leet speak (a→4, e→3, i→1, o→0, s→5, t→7), separators (.@#_!), "
        "common suffixes (!@#$), camelCase pairs, reversed words, mixed case."
    )

    def __init__(self, seeds, target, model="llama3.1", base_url="http://localhost:11434"):
        self.seeds = seeds
        self.target = target
        self.model = model
        self.base_url = base_url

    # ── public API ───────────────────────────────────────────────────────────

    def generate(self) -> list[str]:
        import ollama
        client = ollama.Client(host=self.base_url)

        # Verify connectivity
        try:
            client.list()
        except Exception as e:
            raise Exception(f"Cannot connect to Ollama at {self.base_url}: {e}")

        all_passwords: list[str] = []
        seen: set[str] = set()
        batch_size = 500
        max_retries = 3
        stale_rounds = 0

        log_info(f"Model: {C.BOLD}{self.model}{C.RESET}")
        log_info(f"Generating passwords in batches of {batch_size}…")

        try:
            while len(all_passwords) < self.target:
                remaining = self.target - len(all_passwords)
                current_batch = min(batch_size, remaining)
                prompt = self._build_prompt(current_batch, all_passwords)
    
                progress_bar(len(all_passwords), self.target, "Calling Ollama…")
    
                try:
                    resp = client.chat(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": self.SYSTEM_PROMPT},
                            {"role": "user", "content": prompt},
                        ],
                        options={"temperature": 0.9, "num_predict": current_batch * 20},
                    )
                    raw = resp["message"]["content"]
                except Exception as e:
                    log_error(f"Ollama request failed: {e}")
                    stale_rounds += 1
                    if stale_rounds >= max_retries:
                        raise Exception("Max retries reached. AI model is failing repeatedly.")
                    time.sleep(1)
                    continue
    
                new_pwds = self._parse_response(raw)
                added = 0
                for p in new_pwds:
                    if p not in seen:
                        seen.add(p)
                        all_passwords.append(p)
                        added += 1
    
                log_info(f"Batch returned {len(new_pwds)} passwords, {added} new (total: {len(all_passwords)})")
    
                if added == 0:
                    stale_rounds += 1
                    if stale_rounds >= max_retries:
                        log_warn("Model is repeating. Stopping generation.")
                        break
                else:
                    stale_rounds = 0
        except KeyboardInterrupt:
            log_warn("\nGeração via IA interrompida pelo usuário. Salvando wordlist parcial...")
        finally:
            progress_done()
            return all_passwords[:self.target]

    # ── internals ────────────────────────────────────────────────────────────

    def _build_prompt(self, count, existing):
        seeds_str = ", ".join(self.seeds)
        exclude = ""
        if existing:
            sample = existing[-30:]
            exclude = (
                "\n\nDo NOT repeat any of these already-generated passwords:\n"
                + "\n".join(sample)
            )

        return (
            f"Generate exactly {count} unique password candidates based on "
            f"these seed words: {seeds_str}\n\n"
            "Requirements:\n"
            "- One password per line, nothing else\n"
            "- Range from simple to complex:\n"
            "  Simple:  word123, word2026, wordword\n"
            "  Medium:  Word@2026, Word123!, Word_1234, CamelCase\n"
            "  Complex: W0rd#2026!, l33t+sep, 3mPr3$@Year!\n"
            "- Use leet speak: a→4/@, e→3, i→1/!, o→0, s→5/$, t→7/+\n"
            "- Use separators: . _ - @ # ! $ &\n"
            "- Mix the seed words with each other and with numbers\n"
            "- Include reversed words and alternating case\n"
            "- Order from most probable to least probable\n"
            f"{exclude}\n\n"
            "Output ONLY the passwords, one per line:"
        )

    def _parse_response(self, raw: str) -> list[str]:
        passwords = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # Strip numbering ("1. ", "1) ", "- ")
            if len(line) > 2 and line[0].isdigit():
                for delim in ['. ', ') ', ': ', '- ']:
                    idx = line.find(delim)
                    if 0 < idx < 6:
                        line = line[idx + len(delim):]
                        break
            if line.startswith('- '):
                line = line[2:]
            if line.startswith('* '):
                line = line[2:]
            line = line.strip('`').strip()
            # Reject lines with spaces or too short
            if line and ' ' not in line and len(line) >= 2 and len(line) <= 128:
                passwords.append(line)
        return passwords


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI Argument Parsing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TOP_PRESETS = {
    '--top-100':   100,
    '--top-500':   500,
    '--top-1000':  1000,
    '--top-3000':  3000,
    '--top-5000':  5000,
    '--top-8000':  8000,
    '--top-10000': 10000,
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="bird-wl",
        description="Bird Prepare Wordlist — Smart Password Wordlist Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 bird-wl.py --py  --strings empresa,2026,nome -o wl.txt --top-1000\n"
            "  python3 bird-wl.py --ai  --strings empresa,2026,nome -o wl.txt --top-500\n"
            "  python3 bird-wl.py --py  --strings admin,secret     -o wl.txt --n-lines 15000\n"
        ),
    )

    # Mode (mutually exclusive)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ai", action="store_true", help="Use Ollama AI to generate passwords")
    mode.add_argument("--py", action="store_true", help="Use native Python engine to generate passwords")

    # Required args
    parser.add_argument(
        "--strings", required=False,
        help="Comma-separated seed strings (e.g. empresa,2026,1234,nome)"
    )
    parser.add_argument(
        "--wordlist", "-w", required=False,
        help="Input wordlist file containing seed strings (one per line)"
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Output file path"
    )

    # Count: presets or custom
    count_group = parser.add_mutually_exclusive_group(required=True)
    for flag, val in TOP_PRESETS.items():
        count_group.add_argument(flag, dest="count", action="store_const", const=val,
                                 help=f"Generate top {val} passwords")
    count_group.add_argument("--n-lines", type=int, metavar="N",
                             help="Generate exactly N passwords")

    # Ollama options
    parser.add_argument("--ollama-model", default="llama3.1",
                        help="Ollama model to use (default: llama3.1)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Ollama server URL (default: http://localhost:11434)")

    args = parser.parse_args()

    # Resolve count
    if args.n_lines is not None:
        if args.n_lines < 1:
            parser.error("--n-lines must be >= 1")
        args.count = args.n_lines

    return args


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    # Disable colors if not a terminal
    if not sys.stderr.isatty():
        C.disable()

    sys.stderr.write(BANNER)

    args = parse_args()
    
    seeds = []
    if args.strings:
        seeds.extend([s.strip() for s in args.strings.split(",") if s.strip()])
        
    if args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                seeds.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            log_error(f"Erro ao ler wordlist '{args.wordlist}': {e}")
            sys.exit(1)
            
    seeds = list(_dedup_ordered(seeds))

    if not seeds:
        log_error("No seed strings provided. Use --strings or --wordlist.")
        sys.exit(1)

    use_ai = args.ai
    if use_ai:
        try:
            import ollama
        except ImportError:
            log_warn("Pacote Python 'ollama' não encontrado.")
            ans = input(f"  {C.YELLOW}[?]{C.RESET} Deseja instalar o pacote ollama agora ou usar modo nativo (--py)? [I]nstalar / [P]y mode: ").strip().lower()
            if ans.startswith('p'):
                use_ai = False
            else:
                log_info("Instalando pacote ollama...")
                import subprocess
                subprocess.run([sys.executable, "-m", "pip", "install", "ollama", "--break-system-packages"], check=True)
                
        if use_ai:
            import ollama
            client = ollama.Client(host=args.ollama_url)
            try:
                models = client.list()
                
                # Handle different versions of the ollama python library (dict vs object)
                models_list = []
                if isinstance(models, dict):
                    models_list = models.get('models', [])
                elif hasattr(models, 'models'):
                    models_list = models.models

                model_exists = False
                for m in models_list:
                    m_name = ""
                    if isinstance(m, dict):
                        m_name = m.get('name') or m.get('model', '')
                    else:
                        m_name = getattr(m, 'name', getattr(m, 'model', ''))
                    
                    if m_name == args.ollama_model or m_name.startswith(args.ollama_model + ':'):
                        model_exists = True
                        break
                
                if not model_exists:
                    log_warn(f"Modelo '{args.ollama_model}' não encontrado localmente.")
                    ans = input(f"  {C.YELLOW}[?]{C.RESET} Deseja baixar o modelo '{args.ollama_model}' ou usar modo nativo (--py)? [B]aixar / [P]y mode: ").strip().lower()
                    if ans.startswith('p'):
                        use_ai = False
                    else:
                        log_info(f"Baixando modelo '{args.ollama_model}'...")
                        import subprocess
                        subprocess.run(["ollama", "pull", args.ollama_model], check=True)
            except Exception as e:
                log_warn(f"Não foi possível conectar ao servidor Ollama em {args.ollama_url}. Erro: {e}")
                ans = input(f"  {C.YELLOW}[?]{C.RESET} Servidor Ollama offline. Deseja usar o modo nativo (--py) como fallback? [S]im / [N]ão: ").strip().lower()
                if ans.startswith('s'):
                    use_ai = False
                else:
                    log_error("Servidor Ollama indisponível. Encerrando.")
                    sys.exit(1)

    mode_name = "AI (Ollama)" if use_ai else "Python Engine (Fallback)" if args.ai else "Python Engine"

    # ── Print config ─────────────────────────────────────────────────────────
    sys.stderr.write(f"\n  {C.BOLD}Configuration{C.RESET}\n")
    sys.stderr.write(f"  {C.DIM}{'─' * 45}{C.RESET}\n")
    log_info(f"Mode:    {C.BOLD}{mode_name}{C.RESET}")
    if len(seeds) <= 10:
        log_info(f"Strings: {C.BOLD}{', '.join(seeds)}{C.RESET}")
    else:
        log_info(f"Strings: {C.BOLD}{len(seeds)} sementes carregadas{C.RESET}")
    log_info(f"Count:   {C.BOLD}{args.count:,}{C.RESET}")
    log_info(f"Output:  {C.BOLD}{args.output}{C.RESET}")
    sys.stderr.write(f"  {C.DIM}{'─' * 45}{C.RESET}\n\n")

    # ── Generate ─────────────────────────────────────────────────────────────
    t_start = time.time()
    passwords = []

    if use_ai:
        engine = OllamaEngine(seeds, args.count, args.ollama_model, args.ollama_url)
        try:
            passwords = engine.generate()
        except Exception as e:
            log_error(f"Falha na IA: {e}")
            log_warn("Fazendo fallback automático para o modo Python nativo (--py)...")
            use_ai = False

    if not use_ai:
        if args.ai:
            log_info("Iniciando geração nativa via Python Engine...")
        engine = PasswordEngine(seeds, args.count)
        passwords = engine.generate()

    t_elapsed = time.time() - t_start

    # ── Write output ─────────────────────────────────────────────────────────
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        for pwd in passwords:
            f.write(pwd + "\n")

    file_size = os.path.getsize(args.output)

    # ── Summary ──────────────────────────────────────────────────────────────
    def human_size(nbytes):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if nbytes < 1024:
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024
        return f"{nbytes:.1f} TB"

    sys.stderr.write(f"\n  {C.BOLD}Results{C.RESET}\n")
    sys.stderr.write(f"  {C.DIM}{'─' * 45}{C.RESET}\n")
    log_success(f"Passwords generated: {C.BOLD}{len(passwords):,}{C.RESET}")

    if len(passwords) < args.count:
        log_warn(
            f"Requested {args.count:,} but only {len(passwords):,} unique "
            "passwords were possible with the given seeds."
        )
        log_info("Tip: provide more seed strings for larger wordlists.")

    log_success(f"Output file:  {C.BOLD}{args.output}{C.RESET}")
    log_success(f"File size:    {C.BOLD}{human_size(file_size)}{C.RESET}")
    log_success(f"Time elapsed: {C.BOLD}{t_elapsed:.2f}s{C.RESET}")
    sys.stderr.write(f"  {C.DIM}{'─' * 45}{C.RESET}\n\n")

    # Show sample
    sample_n = min(10, len(passwords))
    sys.stderr.write(f"  {C.BOLD}Sample (first {sample_n}):{C.RESET}\n")
    for pwd in passwords[:sample_n]:
        sys.stderr.write(f"    {C.GREEN}→{C.RESET} {pwd}\n")

    if len(passwords) > sample_n:
        sys.stderr.write(f"    {C.DIM}… and {len(passwords) - sample_n:,} more{C.RESET}\n")
    sys.stderr.write("\n")


if __name__ == "__main__":
    main()
