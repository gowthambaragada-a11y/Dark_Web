"""
seed_data.py
============
Synthetic Threat-Intelligence Seed Corpus for SIH Problem Statement 26151
"Dark Web Threat Actor De-anonymization"  --  Team Anvaya

WHAT THIS IS
------------
A fully self-contained, *pre-validated* synthetic intelligence corpus. Every
identifier in this file is fabricated for demonstration purposes:

  * All clearnet origin IPs are drawn from the RFC-5737 documentation ranges
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and every ASN from the
    RFC-5398 private ASN range (64512+). They cannot resolve to a real host.
  * All PGP fingerprints, subkeys, Bitcoin/Monero addresses, Tox/Jabber IDs and
    ``.onion`` v3 addresses are generated from a fixed seed and are not
    mathematically valid keys -- they exist to be *matched*, not verified.
  * All forum prose is machine-generated from per-persona stylistic grammars so
    that stylometric vectorisation has real signal to work with.

NO live network scanning, NO Tor crawling, NO I/O of any kind happens here.
The platform is 100% offline analytical computation over this corpus.

DATASET SHAPE
-------------
    3 simulated venues   (AlphaBay-Sim / Dread-Sim / Hydra-Sim)
    5 threat-actor clusters, resolved into 6 personas
    2 cross-market identity merges:
        (A) "rebrand after takedown"  -- zero selector overlap, solved by
            stylometry + circadian rhythm only
        (B) "operator continuity"     -- solved by PGP subkey + wallet cluster
    ~140 forum posts, 24h UTC activity profiles, onion service telemetry,
    certificate/favicon/header fingerprints, transaction cluster links.

    Deliberate trap for the demo: one MurmurHash3 favicon hash is shared by
    services belonging to two *unrelated* actors, so the UI can show why a
    single weak signal must never be treated as an attribution on its own.
"""

from __future__ import annotations

import copy
import random
import string
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List

# --------------------------------------------------------------------------- #
# Corpus metadata
# --------------------------------------------------------------------------- #

TEAM_NAME = "Team Anvaya"
PROBLEM_STATEMENT_ID = "26151"
PROBLEM_TITLE = "Dark Web Threat Actor De-anonymization"
CORPUS_VERSION = "anvaya-seed-1.4.0"
CORPUS_COMPILED_AT = "2026-02-18T00:00:00Z"
# Fixed, so the generated corpus is byte-identical on every boot.
MASTER_SEED = 20260261

DISCLAIMER = (
    "SYNTHETIC CORPUS. No live scanning, no Tor crawling, no real identifiers. "
    "All hosts use RFC-5737 documentation IPs and RFC-5398 private ASNs."
)

CATEGORIES = ["Ransomware", "Stolen Data", "Illicit Goods", "Laundering"]

# --------------------------------------------------------------------------- #
# Venues
# --------------------------------------------------------------------------- #

MARKETS: List[Dict[str, Any]] = [
    {
        "id": "mkt-alphabay",
        "name": "AlphaBay-Sim",
        "onion_domain": "alphabay-sim7kq3t2.onion",
        "kind": "Marketplace",
        "status": "SEIZED",
        "shutdown_date": "2024-03-14",
        "successor": "Dread-Sim",
        "notes": (
            "Simulated takedown of the escrow and dispute subsystem. Vendor "
            "accounts were deactivated but vanity onion mirrors remained "
            "resolvable for several months afterwards."
        ),
    },
    {
        "id": "mkt-dread",
        "name": "Dread-Sim",
        "onion_domain": "dreads-sim2l8zx.onion",
        "kind": "Forum",
        "status": "RAIDED",
        "shutdown_date": "2024-09-02",
        "successor": "Hydra-Sim",
        "notes": (
            "Simulated coordinated seizure of the relay nodes. Long-lived "
            "threads were re-posted on Hydra-Sim by unknown accounts with "
            "altered writing habits."
        ),
    },
    {
        "id": "mkt-hydra",
        "name": "Hydra-Sim",
        "onion_domain": "hydra-sim9wq4.onion",
        "kind": "Marketplace",
        "status": "ACTIVE",
        "shutdown_date": None,
        "successor": None,
        "notes": (
            "Current host for the surviving personas. Heavily multi-vendor, "
            "so single-signature reuse is unusually informative here."
        ),
    },
]

# --------------------------------------------------------------------------- #
# Style grammar: the machine that writes every forum post
# --------------------------------------------------------------------------- #
#
# A StyleProfile is a small probabilistic grammar. `render_post()` samples from
# it with a seeded RNG, which is what gives each persona a *stable but
# distinctive* fingerprint: greeting templates, punctuation habits, orthographic
# quirks, favourite vocabulary and formatting layout.
#
# `derive()` deep-copies a core profile and applies overrides. The rebrand pair
# shares a CORE and diverges only at the surface -- that is precisely the shape
# of a real re-registration fingerprint.


class _SafeDict(dict):
    """format() helper: unknown placeholders are echoed back, never crash."""

    def __missing__(self, key: str) -> str:  # pragma: no cover - defensive
        return "{" + key + "}"


def _fill(rng: random.Random, template: str, slots: Dict[str, List[str]]) -> str:
    return template.format_map(
        _SafeDict({k: rng.choice(v) for k, v in slots.items() if v})
    )


def _maybe(rng: random.Random, p: float) -> bool:
    return rng.random() < p


def derive(core: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-copy ``core`` and recursively apply ``overrides``."""
    out = copy.deepcopy(core)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = derive(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


# --- Core A: "Obsidian Ledger" -- terse, transactional, heavy on numerals -----

_LEDGER_CORE: Dict[str, Any] = {
    "id": "obsidian-ledger-core",
    "seed": 4101,
    "greet_rate": 0.85,
    "greetings": [
        "Attention buyers.",
        "Greetings, colleagues.",
        "Hello again.",
        "Evening, market.",
        "To all readers of this board,",
        "Evening.",
    ],
    "signoff_rate": 0.8,
    "signoffs": [
        "Regards, dispatch desk.",
        "Buyer beware. Escrow only.",
        "-- dispatch desk",
        "No beggars. No leakers.",
        "Contact over Tox only.",
        "Do not PM the old handles.",
    ],
    "openers": [
        "Lot {lot} is open.",
        "Update on {topic}: {detail}.",
        "Reminder regarding {topic}.",
        "Prices hold until {date}.",
        "Notice for verified buyers only.",
        "Short notice, {topic}.",
    ],
    "bodies": [
        "Access tier {tier} at {price} btc, {price2} xmr for the long term buyers.",
        "The {thing} was completed on schedule; {n} {unit} moved into escrow without incident.",
        "We do not negotiate below {price} btc and we never take third party escrow.",
        "Buyer verification pack is mandatory: {thing}, {thing2} and a {n} day cooling period.",
        "Payment is split across {n} outputs so the {thing} stays under the reporting threshold.",
        "If the {thing} slips again we burn the {unit} and vanish for good.",
        "Session is being rebuilt after the {market} outage. New credentials in a day or two.",
        "Every {n} hours the {thing} rotates. The old handles are dead, do not PM them.",
        "Proof of {thing} is attached. The {thing2} is the only artifact that is not recycled.",
        "We still hold {n} {unit} in escrow and we are not taking new work this week.",
        "Buyer picked up the {thing} late last night. {n} hours of silence from the client, then nothing.",
        "Vendor asked for a refund. Refused. Escrow released to us, the {thing} stays ours.",
        "Move the {thing} to the new address before the {date}. Old address dies without warning.",
        "Total exposure on this {topic} is {price} btc. Half is already in escrow, half is not.",
        "I am not arguing in the thread. Post the {thing} or I close the {topic} permanently.",
        "Escrow opens in {n} hours, closes in {n2}. Anyone late forfeits the {thing}.",
    ],
    "closers": [
        "Verified buyers only. No exceptions, no exceptions for regulars.",
        "Read the thread before you PM me.",
        "The {thing} is what you pay for, everything else is free support.",
        "If you cannot read this, you cannot afford this.",
    ],
    "layout": {"blank_lines": 1, "bullet_char": ">", "trailing_space_rate": 0.22},
    "punct": {
        "ellipsis": "...",
        "ellipsis_rate": 0.34,
        "dash": "--",
        "dash_rate": 0.3,
        "semicolon_rate": 0.26,
        "exclam_rate": 0.18,
        "question_rate": 0.05,
        "quote_rate": 0.1,
        "caps_word_rate": 0.11,
        "comma_run_rate": 0.14,
    },
    "ortho": {
        "typo_rate": 0.14,
        "typos": {
            "received": "recieved",
            "verification": "verifcation",
            "negotiate": "negociate",
            "definitely": "definately",
            "separate": "seperate",
        },
        "slang": {"u": "you", "ur": "your", "pls": "please", "2day": "tomorrow"},
        "slang_rate": 0.05,
        "l33t": {"a": "4", "e": "3", "o": "0", "i": "1"},
        "l33t_rate": 0.02,
        "double_space_rate": 0.18,
        "lowercase_start_rate": 0.06,
    },
    "emoji": ["[]", "[!]", "[+]", "[OK]"],
    "emoji_rate": 0.07,
    "slots": {
        "lot": ["A-14", "B-02", "C-77", "D-31", "A-08", "B-45"],
        "topic": ["the escrow", "the lease", "the access tier", "the deposit", "the listing"],
        "detail": [
            "conditions unchanged",
            "two vendors dropped out",
            "the client went quiet",
            "we lost the relay",
            "the window moved again",
        ],
        "date": ["14.03", "02.09", "31.12", "next cycle", "the end of the month"],
        "tier": ["gold", "silver", "bronze", "platinum", "scout"],
        "price": ["2.4", "1.8", "3.1", "0.9", "4.6", "5.2", "1.25"],
        "price2": ["18", "42", "9", "66", "120", "25"],
        "n": ["6", "12", "24", "48", "3", "9", "72"],
        "n2": ["6", "18", "30"],
        "unit": ["deployments", "listings", "escrows", "sessions", "handles"],
        "thing": [
            "the deposit",
            "the access tier",
            "the second factor",
            "the escrow window",
            "the relay",
            "the lease",
        ],
        "thing2": [
            "the recovery phrase",
            "the first escrow",
            "the original deposit",
            "the signed release",
        ],
        "market": ["AlphaBay-Sim", "Dread-Sim", "Hydra-Sim"],
    },
}

# --- Core B: "Vexing Hydra" -- technical, verbose, code-adjacent -------------

_VEXEL_CORE: Dict[str, Any] = {
    "id": "vexing-hydra-core",
    "seed": 9202,
    "greet_rate": 0.7,
    "greetings": [
        "Hello, and good evening.",
        "Greetings from the lab.",
        "Hi all,",
        "Good morning, forum.",
        "Hey folks,",
    ],
    "signoff_rate": 0.72,
    "signoffs": [
        "Cheers,",
        "Best regards,",
        "-- regards",
        "Kind regards,",
        "Regards,",
    ],
    "openers": [
        "I have spent some time on {topic} and I think the community deserves a proper write-up.",
        "A short technical note regarding {topic}:",
        "Following up on the earlier thread, {topic} is slightly more subtle than it appears.",
        "Documentation for {topic}, since people keep asking:",
    ],
    "bodies": [
        "The {thing} is initialised lazily, so the first {n} requests are measurably slower than the rest.",
        "In my testing the {thing} leaks roughly {n} bytes per session, which is enough to correlate sessions.",
        "You can verify this yourself: reproduce the {thing}, then diff the outputs across two {unit}.",
        "I have attached a minimal reproduction. It builds in {n} seconds and needs no external dependencies.",
        "Anonymise properly: strip the {thing}, rotate the {thing2}, and never reuse a {unit} across listings.",
        "Please do not post raw {thing} values in public threads. Several of you clearly are doing that.",
        "The organisation consistently spells {word} incorrectly, which is a stylistic marker in itself.",
        "If you are reading this in {n} months, assume every selector listed here is burned and re-keyed.",
        "I analysed {n} samples from the same operator and the structural similarity sits well above chance.",
        "The interesting part is the {thing}: it is stable across rebrands even when every key is rotated.",
        "Do the maths before you trust this. There are {n} permutations and you only sampled a handful.",
        "A {n} hour window, four posts a night, every night. That is a person, not a bot, and not a script.",
        "For the record I never re-key between listings; that mistake cost one of my colleagues a {unit}.",
        "The organisation is competent but lazy, which is the best possible combination for a researcher.",
    ],
    "closers": [
        "Corrections welcome, politely.",
        "I will update this thread when I have more data.",
        "Happy to answer questions, but please read the whole post first.",
        "None of this is an accusation, it is an observation with a confidence interval.",
    ],
    "layout": {"blank_lines": 2, "bullet_char": "-", "trailing_space_rate": 0.03},
    "punct": {
        "ellipsis": "...",
        "ellipsis_rate": 0.16,
        "dash": " - ",
        "dash_rate": 0.12,
        "semicolon_rate": 0.42,
        "exclam_rate": 0.03,
        "question_rate": 0.14,
        "quote_rate": 0.06,
        "caps_word_rate": 0.02,
        "comma_run_rate": 0.05,
    },
    "ortho": {
        "typo_rate": 0.02,
        "typos": {},
        "slang": {},
        "slang_rate": 0.0,
        "l33t": {},
        "l33t_rate": 0.0,
        "double_space_rate": 0.0,
        "lowercase_start_rate": 0.0,
    },
    "emoji": [],
    "emoji_rate": 0.0,
    "slots": {
        "topic": [
            "fingerprinting resistance",
            "the fingerprint collision problem",
            "cross-session linkage",
            "operational security for vendors",
            "the re-registration problem",
        ],
        "thing": ["fingerprint hash", "client entropy source", "request header set", "session token", "TLS fingerprint"],
        "thing2": ["the client profile", "the build identifier", "the network fingerprint"],
        "unit": ["sessions", "listings", "samples", "profiles", "threads"],
        "n": ["40", "128", "12", "300", "6", "1,024"],
        "word": ["organisation", "anonymise", "behaviour", "favourite", "labour"],
    },
}

# --- Standalone: "Mule Cartel" -- lowercase chatter, no punctuation ----------

_MULE_STYLE: Dict[str, Any] = {
    "id": "mule-cartel-style",
    "seed": 7731,
    "greet_rate": 0.35,
    "greetings": ["yo", "hi", "hey", "gm", ""],
    "signoff_rate": 0.3,
    "signoffs": ["thx", "thx bro", "ty", "ok", "done"],
    "openers": [
        "so {topic} again",
        "quick one about {topic}",
        "anyone got {topic} open",
        "re {topic}",
    ],
    "bodies": [
        "need {n} btc sent to my new addr, the old one is frozen",
        "got the funds in, took like {n} mins, tx confirmed so thx",
        "whoever sent {price} btc yesterday tx is stuck, can someone look",
        "ill do {n} rounds of {price} btc over {n2} days, no questions",
        "addr changed again, check the sig before sending anything",
        "sent the split to {n} addrs as discussed, kept it under the limit",
        "mixing fee is {n} percent now, was cheaper last week",
        "bridge is down again so everything is delayed {n} days",
        "need a new vendor, my last one got lazy and stopped replying",
        "if your tx got flagged just do nothing and wait {n} weeks",
        "do not use the same chain for two buyers, i learned that the hard way",
        "im not doing xmr anymore, chain analysis got too good on it",
        "vendor asked why the amounts are round numbers, told him to mind his own biz",
        "escrow released after {n} hours, all good, moving on",
    ],
    "closers": [
        "dm not pm",
        "no middlemen pls",
        "thx in advance",
        "offer stays open till friday",
    ],
    "layout": {"blank_lines": 0, "bullet_char": "*", "trailing_space_rate": 0.0},
    "punct": {
        "ellipsis": "..",
        "ellipsis_rate": 0.08,
        "dash": " - ",
        "dash_rate": 0.02,
        "semicolon_rate": 0.01,
        "exclam_rate": 0.05,
        "question_rate": 0.12,
        "quote_rate": 0.0,
        "caps_word_rate": 0.0,
        "comma_run_rate": 0.01,
    },
    "ortho": {
        "typo_rate": 0.09,
        "typos": {"btc": "btc", "address": "adress", "receive": "recieve", "confirm": "confrim"},
        "slang": {"pls": "pls", "thx": "thx", "dm": "dm", "im": "i'm", "u": "u"},
        "slang_rate": 0.3,
        "l33t": {},
        "l33t_rate": 0.0,
        "double_space_rate": 0.02,
        "lowercase_start_rate": 0.88,
    },
    "emoji": ["🔥", "💸", "👍", "🙏"],
    "emoji_rate": 0.3,
    "slots": {
        "topic": ["the mixer", "the bridge", "the new vendor", "the escrow", "the chain", "the payout"],
        "n": ["0.4", "2", "5", "12", "3", "48", "0.75", "1.6"],
        "n2": ["3", "7", "10"],
        "price": ["1.2", "4.5", "0.8", "9.9", "2.75"],
    },
}

# --- Standalone: "Ghost Cartel" -- broken English, transliteration artefacts --

_GHOST_STYLE: Dict[str, Any] = {
    "id": "ghost-cartel-style",
    "seed": 3355,
    "greet_rate": 0.5,
    "greetings": ["Hello buyers!", "Hi friend", "Good day", "Alo", "Hello my friend"],
    "signoff_rate": 0.45,
    "signoffs": [
        "Regards admin",
        "Thank you for attention",
        "Best regards, Ghost",
        "Write me",
        "Thank you",
    ],
    "openers": [
        "Now avaliable in stock {topic}",
        "Good news for all buyers {topic}",
        "Big update {topic}",
        "Information for partners {topic}",
    ],
    "bodies": [
        "Price for {n} {unit} is {price} btc. Delivry in {n2} days to all world",
        "We have {n} {unit} avaliable, big quantity, good quality, best price in market",
        "Payment only xmr, no other way. Escrow is not needed, we are old team",
        "For all buyers: our {thing} is updated, please update your {thing2} also",
        "Minimum order {n} {unit}. For big quantity we give better price {price} btc",
        "Shiping to {city} take {n2} days, shiping to {city2} take {n} days",
        "All goods laboratory quality. Every {unit} tested before send",
        "We are working since 2019, many buyers already, no problems ever",
        "If you have problem with deliverry, write me in private, we solve all problem",
        "New {thing} available now, this is very good and very fast, trust me",
        "Do not use free wifi when you write to me, security is your problem also",
        "Manager is not here, I am responsible now, all old buyers know me",
        "We do not refund after shiping, this is rule of our market, no discuss",
        "Very big demand this month, maybe {n} hours delay for everyone, sorry",
    ],
    "closers": [
        "Write me when you ready",
        "All buyers welcome, thank you",
        "This message will be delete soon",
        "Please respect the rules of market",
    ],
    "layout": {"blank_lines": 1, "bullet_char": "-", "trailing_space_rate": 0.1},
    "punct": {
        "ellipsis": "..",
        "ellipsis_rate": 0.2,
        "dash": " - ",
        "dash_rate": 0.05,
        "semicolon_rate": 0.08,
        "exclam_rate": 0.32,
        "question_rate": 0.06,
        "quote_rate": 0.02,
        "caps_word_rate": 0.04,
        "comma_run_rate": 0.18,
    },
    "ortho": {
        "typo_rate": 0.31,
        "typos": {
            "available": "avaliable",
            "delivery": "delivry",
            "shipping": "shiping",
            "quantity": "quntity",
            "quality": "qality",
            "market": "market",
            "laboratory": "laborator",
            "manager": "managment",
            "problem": "problm",
            "secure": "secur",
        },
        "slang": {"you": "u", "your": "ur", "please": "pls"},
        "slang_rate": 0.16,
        "l33t": {},
        "l33t_rate": 0.0,
        "double_space_rate": 0.12,
        "lowercase_start_rate": 0.2,
    },
    "emoji": ["[!]", "[OK]", "🔥"],
    "emoji_rate": 0.16,
    "slots": {
        "topic": ["new batch", "big restock", "new items", "special offer", "all categories"],
        "n": ["10", "50", "100", "5", "200", "30"],
        "n2": ["3", "5", "7", "10"],
        "price": ["0.15", "1.9", "0.4", "2.5", "0.08"],
        "unit": ["gram", "pack", "item", "set", "unit"],
        "thing": ["shop", "list", "menu", "catalogue"],
        "thing2": ["client", "order", "account"],
        "city": ["Europe", "Asia", "USA", "UAE", "Brazil", "Canada"],
        "city2": ["Africa", "Australia", "India", "Mexico"],
    },
}

# The four concrete author fingerprints. ShadowBroker_99 and NightOwl_V2 share
# _LEDGER_CORE (surface drift only). V0idKite and IceVex_0x share _VEXEL_CORE.
STYLE_PROFILES: Dict[str, Dict[str, Any]] = {
    "ShadowBroker_99": derive(
        _LEDGER_CORE,
        {
            "id": "style_shadowbroker_99",
            "seed": 4101,
            "signoffs": [
                "Regards, ShadowDesk.",
                "Buyer beware. Escrow only.",
                "-- dispatch desk",
                "No beggars. No leakers.",
                "Contact over Tox only.",
            ],
            "layout": {"trailing_space_rate": 0.24},
        },
    ),
    # Rebrand: same mind, new mask. Keeps the numerals, the dashes, the terse
    # imperatives; loses the vendor branding and hardens the greetings.
    "NightOwl_V2": derive(
        _LEDGER_CORE,
        {
            "id": "style_nightowl_v2",
            "seed": 4107,
            "greetings": [
                "Attention buyers.",
                "Greetings, colleagues.",
                "New account, same desk.",
                "To all readers of this board,",
                "Evening.",
                "Hello again.",
            ],
            "signoffs": [
                "Regards, dispatch desk.",
                "Buyer beware. Escrow only.",
                "-- dispatch desk",
                "Old handles are dead.",
                "Contact over Tox only.",
                "No beggars. No leakers.",
            ],
            "bodies": [
                b + " Re-announcing the {topic} from the previous board."
                for b in _LEDGER_CORE["bodies"]
            ],
            "slots": {**copy.deepcopy(_LEDGER_CORE["slots"]), "market": ["Hydra-Sim", "Dread-Sim"]},
            "ortho": {"typo_rate": 0.11, "double_space_rate": 0.13},
            "layout": {"trailing_space_rate": 0.16},
            "punct": {"comma_run_rate": 0.11, "caps_word_rate": 0.09},
        },
    ),
    "V0idKite": derive(
        _VEXEL_CORE,
        {
            "id": "style_v0idkite",
            "seed": 9202,
            "signoffs": ["Cheers,", "Best regards,", "-- regards", "Kind regards,"],
            "bodies": [
                b for b in _VEXEL_CORE["bodies"] if "re-key" in b or "operator" in b
            ]
            + [
                "The {thing} is initialised lazily, so the first {n} requests are measurably slower than the rest.",
                "In my testing the {thing} leaks roughly {n} bytes per session, which is enough to correlate sessions.",
                "You can verify this yourself: reproduce the {thing}, then diff the outputs across two {unit}.",
                "Anonymise properly: strip the {thing}, rotate the {thing2}, and never reuse a {unit} across listings.",
                "Please do not post raw {thing} values in public threads. Several of you clearly are doing that.",
                "The organisation consistently spells {word} incorrectly, which is a stylistic marker in itself.",
                "If you are reading this in {n} months, assume every selector listed here is burned and re-keyed.",
                "I analysed {n} samples from the same operator and the structural similarity sits well above chance.",
                "The interesting part is the {thing}: it is stable across rebrands even when every key is rotated.",
                "For the record I never re-key between listings; that mistake cost one of my colleagues a {unit}.",
                "The organisation is competent but lazy, which is the best possible combination for a researcher.",
                "A {n} hour window, four posts a night, every night. That is a person, not a bot, and not a script.",
            ],
        },
    ),
    # Same author, post-takedown. Tighter sentences, 0x-inflected, drops the
    # long-form documentation voice. Same orthography and same cadence.
    "IceVex_0x": derive(
        _VEXEL_CORE,
        {
            "id": "style_icevex_0x",
            "seed": 9211,
            "greetings": ["Hi all,", "Hey folks,", "Hello,", "Quick note,", "Greetings from the lab."],
            "signoffs": ["Cheers,", "Regards,", "-- regards", "Kind regards,"],
            "openers": [
                "Short note on {topic}:",
                "Re: {topic}",
                "Quick write-up, {topic}.",
                "0x update -- {topic}",
            ],
            "bodies": [
                "0x quick note: {thing} is initialised lazily, first {n} requests are slower.",
                "0x tested it, the {thing} leaks about {n} bytes per session.",
                "0x you can repro it: run the {thing}, diff two {unit}, look at the outputs.",
                "0x strip the {thing}, rotate the {thing2}, never reuse a {unit}. that is the whole trick.",
                "0x do not post raw {thing} values, some of you are doing that right now.",
                "0x the organisation always spells {word} wrong. that is a marker, use it.",
                "0x {n} samples from the same operator, structural similarity is way above chance.",
                "0x the {thing} survives rebrands even when every key is rotated. that is the useful part.",
                "0x a {n} hour window, four posts a night. person, not script, not bot.",
                "0x I never re-key between listings. a colleague lost a {unit} learning that.",
                "The organisation is competent but lazy, which is the best possible combination for a researcher.",
            ],
            "layout": {"blank_lines": 1, "trailing_space_rate": 0.05},
            "punct": {"semicolon_rate": 0.31, "question_rate": 0.09, "caps_word_rate": 0.05},
            "closers": [
                "Corrections welcome, politely.",
                "Will update when I have more data.",
                "Ask questions, read the whole post first.",
            ],
        },
    ),
    "CryptoMule_K": copy.deepcopy(_MULE_STYLE),
    "GhostCartel_7": copy.deepcopy(_GHOST_STYLE),
}

# --------------------------------------------------------------------------- #
# Post renderer
# --------------------------------------------------------------------------- #

_B32_UPPER = string.ascii_uppercase + "234567"


def _rand_onion(rng: random.Random) -> str:
    return "".join(rng.choice(_B32_UPPER) for _ in range(56)) + ".onion"


def _rand_hex(rng: random.Random, n: int, upper: bool = True) -> str:
    digits = "0123456789ABCDEF" if upper else "0123456789abcdef"
    return "".join(rng.choice(digits) for _ in range(n))


def _rand_btc(rng: random.Random) -> str:
    alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return "bc1q" + "".join(rng.choice(alphabet) for _ in range(58))


def _rand_xmr(rng: random.Random) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "4" + "".join(rng.choice(alphabet) for _ in range(94))


def _rand_tox(rng: random.Random) -> str:
    return _rand_hex(rng, 76, upper=False)


def _apply_orthography(text: str, profile: Dict[str, Any], rng: random.Random) -> str:
    ortho = profile["ortho"]
    for good, bad in ortho["typos"].items():
        if good != bad and _maybe(rng, ortho["typo_rate"]):
            text = text.replace(good, bad)
    for good, short in ortho["slang"].items():
        if _maybe(rng, ortho["slang_rate"]):
            text = text.replace(" " + good + " ", " " + short + " ")
    if ortho["l33t"] and _maybe(rng, ortho["l33t_rate"]):
        for good, digit in ortho["l33t"].items():
            text = text.replace(good, digit)
    if ortho["lowercase_start_rate"] and _maybe(rng, ortho["lowercase_start_rate"]):
        text = text[0].lower() + text[1:] if text else text
    if ortho["double_space_rate"] and _maybe(rng, ortho["double_space_rate"]):
        text = text.replace(". ", ".  ")
    return text


def _apply_punctuation(text: str, profile: Dict[str, Any], rng: random.Random) -> str:
    punct = profile["punct"]
    words = text.split(" ")
    out: List[str] = []
    for word in words:
        if len(word) > 5 and _maybe(rng, punct["caps_word_rate"]):
            word = word.upper()
        if _maybe(rng, punct["exclam_rate"]):
            word = word.rstrip(".,") + "!"
        elif _maybe(rng, punct["question_rate"]):
            word = word.rstrip(".,") + "?"
        out.append(word)
    text = " ".join(out)

    if _maybe(rng, punct["semicolon_rate"]):
        text = text.replace(".", ";", 1)
    if _maybe(rng, punct["comma_run_rate"]):
        text = text.replace(". ", ",, ")
    if _maybe(rng, punct["ellipsis_rate"]):
        text = text.replace(". ", " " + punct["ellipsis"] + " ")
    if punct["dash_rate"] and _maybe(rng, punct["dash_rate"]):
        text = punct["dash"].join(text.split(". "))
    if _maybe(rng, punct["quote_rate"]):
        text = '"' + text.strip() + '"'
    return text


def render_post(rng: random.Random, profile: Dict[str, Any]) -> str:
    """Sample one forum post from a persona's stylistic grammar."""
    slots = profile["slots"]
    blocks: List[str] = []

    if profile["greetings"] and _maybe(rng, profile["greet_rate"]):
        greeting = _fill(rng, rng.choice(profile["greetings"]), slots)
        if greeting:
            blocks.append(greeting)

    blocks.append(_fill(rng, rng.choice(profile["openers"]), slots))
    body_count = rng.choices([1, 2, 3], weights=[0.32, 0.46, 0.22])[0]
    body_lines: List[str] = []
    for _ in range(body_count):
        tmpl = rng.choice(profile["bodies"])
        body_lines.append(_fill(rng, tmpl, slots))
    blocks.append(" ".join(body_lines))

    if profile["closers"] and _maybe(rng, 0.45):
        blocks.append(_fill(rng, rng.choice(profile["closers"]), slots))

    if profile["signoffs"] and _maybe(rng, profile["signoff_rate"]):
        blocks.append(_fill(rng, rng.choice(profile["signoffs"]), slots))

    if profile["emoji"] and _maybe(rng, profile["emoji_rate"]):
        blocks.append(" ".join(rng.choice(profile["emoji"]) for _ in range(rng.randint(1, 2))))

    sep = "\n" + "\n" * profile["layout"]["blank_lines"]
    text = sep.join(b for b in blocks if b)

    text = _apply_punctuation(text, profile, rng)
    text = _apply_orthography(text, profile, rng)

    if _maybe(rng, profile["layout"]["trailing_space_rate"]):
        text = text + " "
    return text.strip()


# --------------------------------------------------------------------------- #
# 24-hour UTC activity (circadian) profiles
# --------------------------------------------------------------------------- #
# NightOwl_V2 is given *exactly* the same window as ShadowBroker_99: a person
# does not change their body clock because they registered a new account.


def _circadian(weights: Dict[int, float]) -> List[float]:
    total = sum(weights.values())
    return [round(weights.get(hour, 0.0) / total, 6) for hour in range(24)]


_LEDGER_WINDOW = {0: 0.6, 1: 3.2, 2: 5.4, 3: 6.8, 4: 5.1, 5: 3.0, 6: 1.1,
                  7: 0.5, 8: 0.6, 9: 1.4, 10: 2.1, 11: 2.4, 12: 2.2, 13: 2.9,
                  14: 3.6, 15: 3.1, 16: 2.0, 17: 1.1, 18: 0.8, 19: 0.7,
                  20: 1.0, 21: 1.5, 22: 2.0, 23: 1.6}

_VEXEL_WINDOW = {0: 0.3, 1: 0.2, 2: 0.2, 3: 0.1, 4: 0.1, 5: 0.2, 6: 0.4,
                 7: 0.8, 8: 1.4, 9: 2.1, 10: 2.9, 11: 3.4, 12: 4.1, 13: 4.6,
                 14: 4.2, 15: 3.8, 16: 3.1, 17: 2.4, 18: 1.9, 19: 1.3,
                 20: 1.0, 21: 0.8, 22: 0.6, 23: 0.4}

_MULE_WINDOW = {0: 1.9, 1: 1.4, 2: 0.9, 3: 0.6, 4: 0.5, 5: 0.9, 6: 1.9,
                7: 2.6, 8: 2.2, 9: 1.5, 10: 1.0, 11: 0.9, 12: 1.1, 13: 1.4,
                14: 1.5, 15: 1.3, 16: 1.2, 17: 1.4, 18: 1.9, 19: 2.4, 20: 3.0,
                21: 3.3, 22: 3.0, 23: 2.5}

_GHOST_WINDOW = {0: 0.8, 1: 0.5, 2: 0.4, 3: 0.3, 4: 0.4, 5: 0.9, 6: 2.4,
                 7: 3.4, 8: 3.8, 9: 3.1, 10: 2.2, 11: 1.6, 12: 1.2, 13: 1.0,
                 14: 1.1, 15: 1.4, 16: 1.8, 17: 2.4, 18: 2.9, 19: 2.6, 20: 2.0,
                 21: 1.5, 22: 1.1, 23: 0.9}

CIRCADIAN_PROFILES: Dict[str, List[float]] = {
    "ShadowBroker_99": _circadian(_LEDGER_WINDOW),
    "NightOwl_V2": _circadian(_LEDGER_WINDOW),  # identical window, by design
    "V0idKite": _circadian(_VEXEL_WINDOW),
    "IceVex_0x": _circadian({h: v * (1.18 if 13 <= h <= 20 else 0.86)
                            for h, v in _VEXEL_WINDOW.items()}),
    "CryptoMule_K": _circadian(_MULE_WINDOW),
    "GhostCartel_7": _circadian(_GHOST_WINDOW),
}

# --------------------------------------------------------------------------- #
# Hard ground truth: personas, selectors, onion services, wallets
# --------------------------------------------------------------------------- #


def _persona(
    pid: str,
    handle: str,
    actor_id: str,
    source_id: str,
    category: str,
    first_seen: str,
    last_scan: str,
    confidence: float,
    *,
    role: str,
    status: str,
    threat_level: str,
    language: str,
    geo: str,
    bio: str,
    post_count: int,
    rebrand_of: str | None = None,
    rebrand_note: str | None = None,
) -> Dict[str, Any]:
    return {
        "id": pid,
        "handle": handle,
        "actor_id": actor_id,
        "source_id": source_id,
        "category": category,
        "first_seen": first_seen,
        "last_scan_date": last_scan,
        "confidence": confidence,
        "role": role,
        "status": status,
        "threat_level": threat_level,
        "language": language,
        "geo_assumed": geo,
        "bio": bio,
        "post_count": post_count,
        "rebrand_of": rebrand_of,
        "rebrand_note": rebrand_note,
    }


ACTORS: List[Dict[str, Any]] = [
    {
        "id": "act-obsidian-ledger",
        "codename": "OBSIDIAN LEDGER",
        "first_seen": "2022-04-12",
        "last_scan_date": "2025-06-18",
        "category": "Ransomware",
        "threat_level": "SEVERE",
        "confidence": 0.93,
        "resolution_method": "SOFT_MERGE",
        "attribution_note": (
            "Resolved with ZERO cryptographic overlap. Both personas publish "
            "no reusable key and touch no shared wallet. The merge rests on "
            "character n-gram similarity, orthographic habits and an identical "
            "02:00-04:00 UTC posting window. Flagged for manual review."
        ),
    },
    {
        "id": "act-vexing-hydra",
        "codename": "VEXING HYDRA",
        "first_seen": "2021-09-03",
        "last_scan_date": "2025-11-02",
        "category": "Stolen Data",
        "threat_level": "HIGH",
        "confidence": 0.97,
        "resolution_method": "HARD_SELECTOR",
        "attribution_note": (
            "Classic operator-continuity merge: the successor persona still "
            "signs with a PGP subkey minted by the predecessor and drains into "
            "the same BTC transaction cluster."
        ),
    },
    {
        "id": "act-mule-cartel",
        "codename": "MULE CARTEL",
        "first_seen": "2022-01-19",
        "last_scan_date": "2025-08-27",
        "category": "Laundering",
        "threat_level": "MEDIUM",
        "confidence": 0.88,
        "resolution_method": "HARD_SELECTOR",
        "attribution_note": (
            "Money-mule ring. Individually low impact, but the transaction "
            "cluster links eleven payout addresses across three venues."
        ),
    },
    {
        "id": "act-ghost-cartel",
        "codename": "GHOST CARTEL",
        "first_seen": "2023-02-08",
        "last_scan_date": "2025-10-11",
        "category": "Illicit Goods",
        "threat_level": "MEDIUM",
        "confidence": 0.82,
        "resolution_method": "HARD_SELECTOR",
        "attribution_note": (
            "High-volume goods vendor. Note the shared favicon hash with VEXING "
            "HYDRA: a reseller mirror, NOT a shared operator. This is the "
            "false-positive control case for the platform."
        ),
    },
]

PERSONAS: List[Dict[str, Any]] = [
    _persona(
        "per-shadowbroker", "ShadowBroker_99", "act-obsidian-ledger", "mkt-alphabay",
        "Ransomware", "2022-04-12", "2024-02-28", 0.94,
        role="Vendor / escrow arbiter",
        status="DORMANT (source seized)",
        threat_level="SEVERE",
        language="EN (ru-CN transliteration artefacts)",
        geo="RU / KZ (assessed)",
        bio=(
            "Long-running ransomware affiliate desk selling access brokers and "
            "negotiating escrow disputes. Operated 21 months on AlphaBay-Sim "
            "before the simulated takedown, average 4.1 posts per night, never "
            "missed the 02:00-04:00 UTC window."
        ),
        post_count=26,
    ),
    _persona(
        "per-nightowl", "NightOwl_V2", "act-obsidian-ledger", "mkt-dread",
        "Ransomware", "2024-04-06", "2025-06-18", 0.91,
        role="Re-registered successor handle",
        status="ACTIVE",
        threat_level="SEVERE",
        language="EN (ru-CN transliteration artefacts)",
        geo="RU / KZ (assessed)",
        bio=(
            "Appears 39 days after the AlphaBay-Sim seizure under a fresh "
            "handle, fresh PGP primary and fresh wallets. No shared key, no "
            "shared address, no shared onion. Only the prose and the body "
            "clock survived the rebrand."
        ),
        post_count=24,
        rebrand_of="per-shadowbroker",
        rebrand_note=(
            "Dormant period of 38 days between the predecessor's last scan and "
            "the successor's first post -- consistent with a re-registration "
            "window after a platform takedown."
        ),
    ),
    _persona(
        "per-v0idkite", "V0idKite", "act-vexing-hydra", "mkt-alphabay",
        "Stolen Data", "2021-09-03", "2024-07-12", 0.96,
        role="Credential and access-data broker",
        status="DORMANT (source seized)",
        threat_level="HIGH",
        language="EN (GB spelling)",
        geo="Western Europe (assessed)",
        bio=(
            "Publishes unusually rigorous de-anonymisation write-ups while "
            "selling the artefacts used to build the attacks. British "
            "spelling, semicolon-heavy prose, 12:00-15:00 UTC working window."
        ),
        post_count=22,
    ),
    _persona(
        "per-icevex", "IceVex_0x", "act-vexing-hydra", "mkt-hydra",
        "Stolen Data", "2024-08-20", "2025-11-02", 0.97,
        role="Re-registered successor handle",
        status="ACTIVE",
        threat_level="HIGH",
        language="EN (GB spelling)",
        geo="Western Europe (assessed)",
        bio=(
            "Returned after the Dread-Sim relay seizure under a shortened "
            "handle. Retains one PGP subkey from the predecessor's primary and "
            "still consolidates payouts into the predecessor's transaction "
            "cluster -- the hardest kind of mistake to make twice."
        ),
        post_count=21,
        rebrand_of="per-v0idkite",
        rebrand_note=(
            "Migrated via the Dread-Sim -> Hydra-Sim successor chain. Merchants "
            "who trusted the re-registration on reputation alone were the ones "
            "who paid."
        ),
    ),
    _persona(
        "per-cryptomule", "CryptoMule_K", "act-mule-cartel", "mkt-hydra",
        "Laundering", "2022-01-19", "2025-08-27", 0.89,
        role="Money mule / payout broker",
        status="ACTIVE",
        threat_level="MEDIUM",
        language="EN (non-native, lowercase register)",
        geo="South Asia (assessed)",
        bio=(
            "Recruits payout addresses and moves funds in deliberately round "
            "amounts. Entirely lowercase, no terminal punctuation, heavy "
            "emoji use -- a stylistic signature as loud as any PGP key."
        ),
        post_count=25,
    ),
    _persona(
        "per-ghostcartel", "GhostCartel_7", "act-ghost-cartel", "mkt-dread",
        "Illicit Goods", "2023-02-08", "2025-10-11", 0.83,
        role="Goods vendor / shop operator",
        status="ACTIVE",
        threat_level="MEDIUM",
        language="EN (non-native, transliteration artefacts)",
        geo="Unknown (assessed)",
        bio=(
            "Bulk goods vendor. Writes in a heavily degraded English register "
            "with systematic transliteration errors. Runs a 06:00-09:00 UTC "
            "shift consistent with an Asia-Pacific operator."
        ),
        post_count=23,
    ),
]

# --- PGP --------------------------------------------------------------------- #
# NOTE: fingerprint / subkey sharing between V0idKite and IceVex_0x is the
# deliberate hard-selector evidence for cluster act-vexing-hydra.
# ShadowBroker_99 and NightOwl_V2 share NOTHING cryptographically.

PGP_KEYS: List[Dict[str, Any]] = [
    {
        "id": "pgp-sb99-primary", "persona_id": "per-shadowbroker", "type": "pgp_primary",
        "value": "9F2A41C78E550D3BA6E147C82B90F63D118E5A44",
        "label": "Primary signing key -- ShadowBroker_99",
        "first_seen": "2022-04-12", "last_seen": "2024-02-27",
        "algo": "rsa4096", "created": "2022-04-05",
        "note": "Published in every AlphaBay-Sim vendor thread. 41 verified signatures on escrow disputes.",
    },
    {
        "id": "pgp-sb99-sub1", "persona_id": "per-shadowbroker", "type": "pgp_subkey",
        "value": "3F8C21A07B4E9D55A6C1E08F3B2D7719AC4E6052",
        "label": "Subkey (encryption) -- ShadowBroker_99",
        "first_seen": "2022-05-02", "last_seen": "2024-01-30",
        "algo": "rsa2048", "created": "2022-04-05",
        "note": "Never re-used after rebrand -- burned with the persona.",
    },
    {
        "id": "pgp-sb99-sub2", "persona_id": "per-shadowbroker", "type": "pgp_subkey",
        "value": "D1C05E8B7A2F49C63E05B8D1F7A396E20B4C8F15",
        "label": "Subkey (signing) -- ShadowBroker_99",
        "first_seen": "2022-04-12", "last_seen": "2024-02-28",
        "algo": "ed25519", "created": "2022-04-05",
        "note": "Short-lived signing subkey, rotated roughly every 60 days.",
    },
    # --- NightOwl_V2: entirely disjoint key material ----------------------- #
    {
        "id": "pgp-no2-primary", "persona_id": "per-nightowl", "type": "pgp_primary",
        "value": "5B7E3C10A9D64F82E37B1C05D8A6F294B3E70C1D",
        "label": "Primary signing key -- NightOwl_V2",
        "first_seen": "2024-04-06", "last_seen": "2025-06-18",
        "algo": "rsa4096", "created": "2024-04-01",
        "note": "Minted five days BEFORE the first post. No key overlap with any predecessor.",
    },
    {
        "id": "pgp-no2-sub1", "persona_id": "per-nightowl", "type": "pgp_subkey",
        "value": "E7A93F52C0B18D64A3F7E20591B4C6D08A3F25E71",
        "label": "Subkey (encryption) -- NightOwl_V2",
        "first_seen": "2024-04-06", "last_seen": "2025-06-18",
        "algo": "rsa2048", "created": "2024-04-01",
        "note": "Fresh entropy. No shared packet with the ShadowBroker_99 primary.",
    },
    {
        "id": "pgp-vk-primary", "persona_id": "per-v0idkite", "type": "pgp_primary",
        "value": "C4A70E19B85D32F6E10C794AB3D2E56F08A9C4B17",
        "label": "Primary signing key -- V0idKite",
        "first_seen": "2021-09-03", "last_seen": "2024-07-11",
        "algo": "rsa4096", "created": "2021-08-22",
        "note": "Longest-lived key in the corpus: 34 months.",
    },
    {
        "id": "pgp-vk-sub1", "persona_id": "per-v0idkite", "type": "pgp_subkey",
        "value": "71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A",
        "label": "Subkey (encryption) -- V0idKite",
        "first_seen": "2021-09-03", "last_seen": "2024-07-11",
        "algo": "rsa2048", "created": "2021-08-22",
        "note": "Retained across the rebrand -- the single most damning artefact in the corpus.",
    },
    {
        "id": "pgp-vex-sub1", "persona_id": "per-icevex", "type": "pgp_subkey",
        "value": "71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A",
        "label": "Subkey (encryption) -- IceVex_0x [REUSED]",
        "first_seen": "2024-08-20", "last_seen": "2025-11-02",
        "algo": "rsa2048", "created": "2021-08-22",
        "note": (
            "BYTE-IDENTICAL to pgp-vk-sub1, minted 2021-08-22 by the "
            "predecessor's primary. Independently observed on two different "
            "venues three years apart. 99% confidence hard selector."
        ),
    },
    {
        "id": "pgp-vex-primary", "persona_id": "per-icevex", "type": "pgp_primary",
        "value": "2F8C61B0D74A39E5C81B2F0A6D94E3705C1BA8F62",
        "label": "Primary signing key -- IceVex_0x",
        "first_seen": "2024-08-20", "last_seen": "2025-11-02",
        "algo": "ed25519", "created": "2024-08-14",
        "note": "New primary, but the old encryption subkey was never revoked.",
    },
    {
        "id": "pgp-mule-primary", "persona_id": "per-cryptomule", "type": "pgp_primary",
        "value": "A3D70C58E1B94F26D0C5A7E31948B2F6C05D71E38",
        "label": "Primary signing key -- CryptoMule_K",
        "first_seen": "2022-01-19", "last_seen": "2025-08-27",
        "algo": "ed25519", "created": "2022-01-15",
        "note": "Mule ring. Key is real to them, worthless to us -- they do not sign anything.",
    },
    {
        "id": "pgp-ghost-primary", "persona_id": "per-ghostcartel", "type": "pgp_primary",
        "value": "6B1F4E92C80A37D5E14B9C60F27A3D815C0B6E470",
        "label": "Primary signing key -- GhostCartel_7",
        "first_seen": "2023-02-08", "last_seen": "2025-10-11",
        "algo": "rsa2048", "created": "2023-02-01",
        "note": "Used only for vendor trust seals on the shop front page.",
    },
]

# --- Wallets + transaction clusters ----------------------------------------- #
# tx_cluster simulates common-input-ownership clustering. Wallets sharing a
# cluster are joined by a CO_SPENT_TX edge.

WALLETS: List[Dict[str, Any]] = [
    # Obsidian Ledger
    {"id": "w-sb99-1", "persona_id": "per-shadowbroker", "currency": "BTC",
     "address": "bc1q8kzr2m4vt0c7p9n5xq3wd8sf2lhg6yj1a4t0eu", "tx_cluster": "txc-ledger-01",
     "first_seen": "2022-04-14", "last_seen": "2024-02-27", "balance": 0.0,
     "note": "Escrow deposit address, 31 outputs observed across 4 dispute threads."},
    {"id": "w-sb99-2", "persona_id": "per-shadowbroker", "currency": "XMR",
     "address": "4AdUndX7Zxfdr5eT2mNPwRJ9ctH3hysUya8LqB1vCkR7mEoW5gN6pQxS8dJ2fL4bTuV9cXaH3kZ7rY1nM6qW8eR0tY3uI5oP2aS4dF6gH8jK0lZ9xC", "tx_cluster": "txc-ledger-01",
     "first_seen": "2022-06-11", "last_seen": "2024-02-19", "balance": 0.0,
     "note": "Preferred settlement rail. No ring-signature analysis possible on synthetic data."},
    {"id": "w-no2-1", "persona_id": "per-nightowl", "currency": "BTC",
     "address": "bc1q5xrt9b3nq7v0kz2c8wm4yhs6d1jgp4l7e9u2af", "tx_cluster": "txc-nightowl-02",
     "first_seen": "2024-04-08", "last_seen": "2025-06-18", "balance": 0.0,
     "note": "Brand new deposit address. Zero common inputs with the predecessor's cluster."},
    {"id": "w-no2-2", "persona_id": "per-nightowl", "currency": "XMR",
     "address": "4Fk2Rp8YvN6tQ1sB3dH5gJ7kL9mX2cV4bN6qW8eR0tY3uI5oP7aS9dF2gH4jK6lZ0xC3aE5gT7yU9iO1pA3sD5fG7hJ9kL1zX4cV6bN8qW0eR2tY4uI6oP8aS0dF2gH4jK6lZ9xC", "tx_cluster": "txc-nightowl-02",
     "first_seen": "2024-04-10", "last_seen": "2025-06-05", "balance": 0.0,
     "note": "Fresh Monero wallet, fresh seed. Deliberately unreachable from any known cluster."},
    # Vexing Hydra -- two wallets in the SAME cluster. Hard selector.
    {"id": "w-vk-1", "persona_id": "per-v0idkite", "currency": "BTC",
     "address": "bc1q3m9zt7xk2v5n0bs8d4f6h1j7lq9w2e5r8t0y3u", "tx_cluster": "txc-vex-01",
     "first_seen": "2021-09-05", "last_seen": "2024-07-10", "balance": 0.0,
     "note": "Primary consolidation address. Also appears in a public ransomware leak from 2023."},
    {"id": "w-vex-1", "persona_id": "per-icevex", "currency": "BTC",
     "address": "bc1q6h2yt4n8k0v3m5q7w9x1z3c5b7e9r2t4y6u8i", "tx_cluster": "txc-vex-01",
     "first_seen": "2024-08-22", "last_seen": "2025-11-02", "balance": 0.0,
     "note": "SUCCESSOR WALLET. Shares the txc-vex-01 cluster with w-vk-1: 4 common inputs."},
    {"id": "w-vex-2", "persona_id": "per-icevex", "currency": "XMR",
     "address": "4Gq7Wt2mK9sD4fH1jL6nP3rX8vC5bN0qW7eR2tY5uI9oP3aS6dF9gH2jK5lZ8xC1aE4gT7yU0iO3pA6sD9fG2hJ5kL8zX1cV4bN7qW0eR3tY6uI9oP2aS5dF8gH1jK4lZ7xC0aE", "tx_cluster": "txc-vex-02",
     "first_seen": "2024-08-24", "last_seen": "2025-10-28", "balance": 0.0,
     "note": "Secondary settlement rail for the successor persona."},
    # Mule Cartel -- 4 addresses in one cluster
    {"id": "w-mule-1", "persona_id": "per-cryptomule", "currency": "BTC",
     "address": "bc1q7v3m9k2x5n8b1t4w6y0z3c5r7e9q2u4t6y8i0", "tx_cluster": "txc-mule-01",
     "first_seen": "2022-01-21", "last_seen": "2025-08-25", "balance": 0.0,
     "note": "Hub payout address. 11 co-spending outputs from 9 distinct payer addresses."},
    {"id": "w-mule-2", "persona_id": "per-cryptomule", "currency": "BTC",
     "address": "bc1q1n5b7m9v2x4z6t8k0j3q5w7e9r1y3u5t7i9o", "tx_cluster": "txc-mule-01",
     "first_seen": "2022-05-09", "last_seen": "2025-08-27", "balance": 0.0,
     "note": "Round-amount inbound pattern: every transfer is 0.50/1.00/2.00/5.00 BTC."},
    {"id": "w-mule-3", "persona_id": "per-cryptomule", "currency": "XMR",
     "address": "4Hj2mB5nQ8tZ1xC4vB7nM0qW3eR6tY9uI2oP5aS8dF1gH4jK7lZ0xC3aE6gT9yU2iO5pA8sD1fG4hJ7kL0zX3cV6bN9qW2eR5tY8uI1oP4aS7dF0gH3jK6lZ9xC2aE5gT8yU1iO4", "tx_cluster": "txc-mule-01",
     "first_seen": "2022-07-14", "last_seen": "2025-06-30", "balance": 0.0,
     "note": "Monero leg of the same funnel; exchange-side clustering unavailable."},
    {"id": "w-mule-4", "persona_id": "per-cryptomule", "currency": "BTC",
     "address": "bc1q9x2c4v6n8m0b1k3j5q7w9z1e3r5t7y9u2i4o", "tx_cluster": "txc-mule-01",
     "first_seen": "2023-02-18", "last_seen": "2025-07-19", "balance": 0.0,
     "note": "Rotating payout address; cluster membership inferred from common change outputs."},
    # Ghost Cartel
    {"id": "w-ghost-1", "persona_id": "per-ghostcartel", "currency": "XMR",
     "address": "4Mk8rT1vC5xZ9bN3qW7eR2tY6uI0oP4aS8dF2gH5jK9lZ3xC7aE1gT4yU8iO2pA5sD9fG3hJ6kL0zX4cV8bN2qW7eR1tY5uI9oP3aS6dF0gH4jK8lZ2xC5aE9gT3y", "tx_cluster": "txc-ghost-01",
     "first_seen": "2023-02-10", "last_seen": "2025-10-11", "balance": 0.0,
     "note": "Vendor settlement address, updated quarterly."},
    {"id": "w-ghost-2", "persona_id": "per-ghostcartel", "currency": "BTC",
     "address": "bc1q4t6y8u0i2o4p6a8s0d2f4g6h8j1k3l5z7x9c", "tx_cluster": "txc-ghost-01",
     "first_seen": "2023-04-02", "last_seen": "2025-09-30", "balance": 0.0,
     "note": "Secondary address used during the Dread-Sim migration window."},
]

TX_LINKS: List[Dict[str, Any]] = [
    {"id": "txl-01", "cluster_id": "txc-vex-01", "wallet_a": "w-vk-1", "wallet_b": "w-vex-1",
     "shared_txs": 4, "first_shared": "2024-09-03", "confidence": 0.95,
     "note": "4 co-spent outputs across two venues, 3 years and 4 months apart. The operator consolidated payouts into the same change-output pattern."},
    {"id": "txl-02", "cluster_id": "txc-mule-01", "wallet_a": "w-mule-1", "wallet_b": "w-mule-2",
     "shared_txs": 11, "first_shared": "2022-08-19", "confidence": 0.92,
     "note": "Same change-output signature. Common-input heuristic: high confidence."},
    {"id": "txl-03", "cluster_id": "txc-mule-01", "wallet_a": "w-mule-1", "wallet_b": "w-mule-3",
     "shared_txs": 6, "first_shared": "2022-09-01", "confidence": 0.78,
     "note": "Fiat on/off ramp coincidence -- medium confidence, treated as corroboration only."},
    {"id": "txl-04", "cluster_id": "txc-mule-01", "wallet_a": "w-mule-2", "wallet_b": "w-mule-4",
     "shared_txs": 5, "first_shared": "2023-03-02", "confidence": 0.9,
     "note": "Change outputs identical to the cent; consistent single-actor rotation."},
    {"id": "txl-05", "cluster_id": "txc-mule-01", "wallet_a": "w-mule-3", "wallet_b": "w-mule-4",
     "shared_txs": 3, "first_shared": "2023-05-17", "confidence": 0.74,
     "note": "Weak transitive link retained for completeness."},
    {"id": "txl-06", "cluster_id": "txc-ghost-01", "wallet_a": "w-ghost-1", "wallet_b": "w-ghost-2",
     "shared_txs": 2, "first_shared": "2023-05-30", "confidence": 0.71,
     "note": "Two shared change outputs. Direction of control is undetermined."},
    {"id": "txl-07", "cluster_id": "txc-ledger-01", "wallet_a": "w-sb99-1", "wallet_b": "w-sb99-2",
     "shared_txs": 3, "first_shared": "2022-06-22", "confidence": 0.8,
     "note": "BTC/XMR bridge leg attributed to the same desk."},
    # The critical NULL result, stored explicitly so the platform can prove
    # that the Obsidian Ledger merge is NOT selector-driven.
    {"id": "txl-08", "cluster_id": "txc-nightowl-02", "wallet_a": "w-no2-1", "wallet_b": "w-no2-2",
     "shared_txs": 0, "first_shared": None, "confidence": 0.0,
     "note": "NEGATIVE CONTROL. NightOwl_V2 deposits share no input, no change pattern and no address derivation with the predecessor cluster. Selector-based linking is impossible here -- the merge is behavioural only."},
]

# --- Messaging selectors ---------------------------------------------------- #

MESSAGING: List[Dict[str, Any]] = [
    {"id": "msg-sb99-tox", "persona_id": "per-shadowbroker", "type": "tox_id",
     "value": "8f2a41c78e550d3ba6e147c82b90f63d118e5a44b2c7d09e15f3a8b6c0d4e29f7",
     "label": "Tox public key -- ShadowBroker_99",
     "first_seen": "2022-04-12", "last_seen": "2024-02-28",
     "note": "Sole accepted contact channel. Never reused by the successor."},
    {"id": "msg-sb99-jabber", "persona_id": "per-shadowbroker", "type": "jabber",
     "value": "dispatch99@xmpp.anvaya-sim",
     "label": "Jabber -- ShadowBroker_99",
     "first_seen": "2022-07-19", "last_seen": "2023-12-04",
     "note": "Relay went dark three months before the takedown."},
    {"id": "msg-no2-tox", "persona_id": "per-nightowl", "type": "tox_id",
     "value": "3b7d09e15f3a8b6c0d4e29f708f2a41c78e550d3ba6e147c82b90f63d118e5a44",
     "label": "Tox public key -- NightOwl_V2",
     "first_seen": "2024-04-06", "last_seen": "2025-06-18",
     "note": "New 32-byte key, no continuity with the predecessor's key. Deliberate re-key."},
    {"id": "msg-no2-jabber", "persona_id": "per-nightowl", "type": "jabber",
     "value": "n.o.v2@xmpp.anvaya-sim",
     "label": "Jabber -- NightOwl_V2",
     "first_seen": "2024-04-09", "last_seen": "2025-06-11",
     "note": "Handles: the initials survive the rebrand even when the PGP key does not."},
    {"id": "msg-vk-jabber", "persona_id": "per-v0idkite", "type": "jabber",
     "value": "v0id@xmpp.anvaya-sim",
     "label": "Jabber -- V0idKite",
     "first_seen": "2021-09-03", "last_seen": "2024-07-12",
     "note": "Oldest surviving artifact in the corpus."},
    {"id": "msg-vex-jabber", "persona_id": "per-icevex", "type": "jabber",
     "value": "icevex@xmpp.anvaya-sim",
     "label": "Jabber -- IceVex_0x",
     "first_seen": "2024-08-20", "last_seen": "2025-11-02",
     "note": "The two handles share the 'v0id'/'icevex' character skeleton -- 0.71 orthographic similarity."},
    {"id": "msg-mule-tox", "persona_id": "per-cryptomule", "type": "tox_id",
     "value": "c0d5a7e31948b2f6c05d71e38a3b94f26d0c5a7e31948b2f6c05d71e38a3b94f26",
     "label": "Tox public key -- CryptoMule_K",
     "first_seen": "2022-01-19", "last_seen": "2025-08-27",
     "note": "Recruitment channel for payout addresses."},
    {"id": "msg-ghost-jabber", "persona_id": "per-ghostcartel", "type": "jabber",
     "value": "ghost.cartel@xmpp.anvaya-sim",
     "first_seen": "2023-02-08", "last_seen": "2025-10-11",
     "label": "Jabber -- GhostCartel_7",
     "note": "Shop support desk."},
]

# --------------------------------------------------------------------------- #
# Onion service telemetry + clearnet correlation
# --------------------------------------------------------------------------- #
# `favicon_mmh3` is a MurmurHash3-32 hash of the /favicon.ico response body.
# SHARED_FAVICON_HASH below is the deliberate false-positive control.

SHARED_FAVICON_HASH = "0x7A3C91E4"  # used by two UNRELATED operators

ONION_SERVICES: List[Dict[str, Any]] = [
    {
        "id": "onion-sb99-1", "persona_id": "per-shadowbroker", "address": "sbf7kq3t2m5x9d4n8v1b6c0r3w7y2l5h9j4k1V4NXQF2PEGNL4VI2ARG.onion",
        "title": "[VENDOR] ShadowDesk // escrow disputes & access tiers",
        "cert_sha256": "9a4f:2c81:77b3:0e5d:8f14:c2a9:63b7:1d0e:45f2:9c83:b6a1:7e4d:2f0b:8c59",
        "cert_serial": "4F:9A:2C:81:77:B3:0E",
        "favicon_mmh3": "0x3E17B904",
        "server_header": "nginx/1.18.0 (Ubuntu)",
        "server_status": 1, "power_on_hours": 19,
        "first_seen": "2022-04-12", "last_seen": "2024-02-28",
        "origin_ip": "198.51.100.47", "origin_asn": "AS64512",
        "origin_org": "SIM Hosting BV (synthetic)", "origin_country": "NL",
        "origin_port": 443,
        "osint_note": (
            "TLS certificate serial 4F:9A:2C:81:77:B3:0E was observed in a "
            "2023 public certificate-transparency dump against a Bulgarian "
            "hosting reseller. Same serial, same RSA public key modulus."
        ),
        "confidence": 0.94,
    },
    {
        "id": "onion-sb99-2", "persona_id": "per-shadowbroker", "address": "2xq9m5v1t7b3n8c4w6k0d2f6h9j3l7q1s55SYE7NQORQUYGP3BUIAKCG.onion",
        "title": "[MIRROR] vendor index -- backup",
        "cert_sha256": "1d7e:4b02:9a63:c518:7f2b:d904:6e3a:85c1:2b70:9fd4:6a8e:1c05:7b2d:4e93:8f16",
        "cert_serial": "1D:7E:4B:02:9A:63",
        "favicon_mmh3": "0x5C22D6A1",
        "server_header": "Apache/2.4.41 (Ubuntu)",
        "server_status": 1, "power_on_hours": 16,
        "first_seen": "2022-08-03", "last_seen": "2024-01-15",
        "origin_ip": "203.0.113.19", "origin_asn": "AS64520",
        "origin_org": "Simuplenty Solutions (synthetic)", "origin_country": "BG",
        "origin_port": 8443,
        "osint_note": "nginx/Apache banner pair plus a default /server-status page pinned the origin stack.",
        "confidence": 0.88,
    },
    {
        "id": "onion-no2-1", "persona_id": "per-nightowl", "address": "no2v4k8x1c6m3b9w5t2n7j4lq8h1d6f0s36XTBNGEUIOJWL2S6P72A6K.onion",
        "title": "[VENDOR] dispatch // new credentials",
        "cert_sha256": "5c20:9f71:3a8e:14d6:b07c:5e29:af38:61d4:c902:8b7e:3f15:6da0:4c98:2e31:7b5f:0a64",
        "cert_serial": "5C:20:9F:71:3A:8E",
        "favicon_mmh3": "0x8B41F2C7",
        "server_header": "nginx/1.20.2",
        "server_status": 0, "power_on_hours": 12,
        "first_seen": "2024-04-06", "last_seen": "2025-06-18",
        "origin_ip": "192.0.2.88", "origin_asn": "AS64533",
        "origin_org": "Simhost Systems (synthetic)", "origin_country": "DE",
        "origin_port": 443,
        "osint_note": (
            "Fresh self-signed cert, fresh serial, fresh favicon. An operator "
            "who re-keys everything also re-deploys their service -- this is "
            "why infrastructure correlation fails on this persona."
        ),
        "confidence": 0.71,
    },
    {
        "id": "onion-vk-1", "persona_id": "per-v0idkite", "address": "vk0idk1t3v7x9m2q5b8n4c6w0z3f7h1l43WSCNDL3BRXGNDAFPZBGIPX.onion",
        "title": "v0id // research notes & vendor index",
        "cert_sha256": "8d31:6f45:2b90:ae17:53c8:9d24:0b7e:41f6:c2a9:8d35:60b4:1e72:95c8:3f0a:7b6d:4e21",
        "cert_serial": "8D:31:6F:45:2B:90",
        "favicon_mmh3": "0x1D6E90A5",
        "server_header": "Caddy",
        "server_status": 1, "power_on_hours": 21,
        "first_seen": "2021-09-03", "last_seen": "2024-07-12",
        "origin_ip": "198.51.100.212", "origin_asn": "AS64512",
        "origin_org": "SIM Hosting BV (synthetic)", "origin_country": "NL",
        "origin_port": 443,
        "osint_note": "Same hosting ASN as the successor's service, 2.5 years earlier. Caddy default banner.",
        "confidence": 0.92,
    },
    {
        # This one shares BOTH cert serial and favicon hash with onion-vk-1.
        "id": "onion-vex-1", "persona_id": "per-icevex", "address": "icevex0x7m2q9b4v6k1n8x3t5w0r2d7RGTNXKL5UEM2G4Q6FMZKBDI3W.onion",
        "title": "0x // index (relaunch)",
        "cert_sha256": "8d31:6f45:2b90:ae17:53c8:9d24:0b7e:41f6:c2a9:8d35:60b4:1e72:95c8:3f0a:7b6d:4e21",
        "cert_serial": "8D:31:6F:45:2B:90",
        "favicon_mmh3": "0x1D6E90A5",
        "server_header": "Caddy",
        "server_status": 1, "power_on_hours": 20,
        "first_seen": "2024-08-20", "last_seen": "2025-11-02",
        "origin_ip": "198.51.100.212", "origin_asn": "AS64512",
        "origin_org": "SIM Hosting BV (synthetic)", "origin_country": "NL",
        "origin_port": 443,
        "osint_note": (
            "Byte-identical certificate SHA-256, identical serial, identical "
            "MurmurHash3 favicon, identical origin host. 99% infrastructure "
            "attribution -- a re-registered vendor on a new board cannot hide "
            "when they re-deploy the same container."
        ),
        "confidence": 0.99,
    },
    {
        "id": "onion-mule-1", "persona_id": "per-cryptomule", "address": "mul3hub5n2x8c1v6b0k4m9r3t7y1s4d07NC44HIMIYT4MCBIO3GFUQLV.onion",
        "title": "payouts // open thread",
        "cert_sha256": "3f61:08d7:b2e5:9a41:7c06:df83:2b70:5e19:c8a4:63d7:0f2b:94e6:31a8:7c50:d9b2:4e73",
        "cert_serial": "3F:61:08:D7:B2:E5",
        "favicon_mmh3": "0x6E2A17B8",
        "server_header": "nginx/1.14.0 (Ubuntu)",
        "server_status": 1, "power_on_hours": 23,
        "first_seen": "2022-01-19", "last_seen": "2025-08-27",
        "origin_ip": "203.0.113.140", "origin_asn": "AS64541",
        "origin_org": "Simunet Communications (synthetic)", "origin_country": "SG",
        "origin_port": 8080,
        "osint_note": "Nearly 24h/day uptime and a stock Ubuntu nginx banner: a bored admin, a personal box.",
        "confidence": 0.86,
    },
    {
        "id": "onion-ghost-1", "persona_id": "per-ghostcartel", "address": "gh0stc4r7t2e5l8m1v4x7z0b3n6q9LXC7EYERE73S5E7CKVWA6DLRUAQ.onion",
        "title": "GHOST SHOP -- all categories, best price",
        "cert_sha256": "b7e2:19c4:60a8:3d51:9e07:2b46:af38:1c5d:7094:e2b8:43a6:5d19:c07f:8e2b:61a4:3d95",
        "cert_serial": "B7:E2:19:C4:60:A8",
        "favicon_mmh3": SHARED_FAVICON_HASH,  # <-- shared with onion-vex-1? no: with res-1
        "server_header": "Apache/2.4.29 (Ubuntu)",
        "server_status": 1, "power_on_hours": 18,
        "first_seen": "2023-02-08", "last_seen": "2025-10-11",
        "origin_ip": "192.0.2.201", "origin_asn": "AS64550",
        "origin_org": "Simavex Hosting (synthetic)", "origin_country": "NL",
        "origin_port": 443,
        "osint_note": "Identical favicon hash to a reseller mirror run by VEXING HYDRA. Same logo, different seller.",
        "confidence": 0.69,
    },
    {
        # Reseller mirror. Shares ONLY the favicon hash with onion-ghost-1 and
        # belongs to a different actor entirely -> the false-positive control.
        "id": "onion-vex-mirror", "persona_id": "per-icevex", "address": "m1rr0r7d2x4b6n9v1k3t5m8q0z2c4f6hTTXGN6JE5Q5ONQJ73DRXWLV3.onion",
        "title": "verified reseller mirror -- logos included",
        "cert_sha256": "c4d8:71a2:3f96:0b5e:9d17:4c82:6a0f:e35b:8217:d490:6cf3:8a2e:1b57:40d9:6e21:af38",
        "cert_serial": "C4:D8:71:A2:3F:96",
        "favicon_mmh3": SHARED_FAVICON_HASH,
        "server_header": "lighttpd/1.4.53",
        "server_status": 0, "power_on_hours": 6,
        "first_seen": "2024-11-17", "last_seen": "2025-04-02",
        "origin_ip": "198.51.100.77", "origin_asn": "AS64561",
        "origin_org": "Simavail VPS (synthetic)", "origin_country": "US",
        "origin_port": 80,
        "osint_note": (
            "Favicon mmh3 match alone against GHOST CARTEL. The 0x7A3C91E4 hash "
            "is distributed in a free WordPress theme, so this is a 41% "
            "confidence signal at best. Flagged in the UI as CONTESTED."
        ),
        "confidence": 0.41,
    },
]

# --------------------------------------------------------------------------- #
# Pre-computed, explainable evidence (the analyst-facing "why")
# --------------------------------------------------------------------------- #
# group  -> one of: stylometric | formatting | circadian | crypto | infrastructure
# These are the per-persona justification for belonging to the actor cluster.

EVIDENCE: Dict[str, List[Dict[str, Any]]] = {
    "per-shadowbroker": [
        {"group": "stylometric", "vector": "char_ngram", "label": "Character n-gram (2-4) overlap with NightOwl_V2",
         "similarity": 0.89, "weight": 0.62, "compared_to": "per-nightowl",
         "detail": "Dominant shared n-grams: '-- ', ' btc', '... ', 'Regards,', 'Buyer beware', 'escrow only', 'the access tier'. Jaccard over the top-500 4-grams: 0.61."},
        {"group": "stylometric", "vector": "word_tfidf", "label": "Word TF-IDF cosine with NightOwl_V2",
         "similarity": 0.83, "weight": 0.55, "compared_to": "per-nightowl",
         "detail": "Shared function-word profile (bimodal short declaratives, no interrogatives) plus identical transactional vocabulary."},
        {"group": "stylometric", "vector": "orthographic", "label": "Orthographic habit vector",
         "similarity": 0.91, "weight": 0.5, "compared_to": "per-nightowl",
         "detail": "CAPS-word rate 0.11/0.09, ellipsis rate 0.34/0.28, trailing-space rate 0.24/0.16, typo rate 0.14/0.11, all within one sigma."},
        {"group": "formatting", "vector": "punctuation", "label": "Punctuation & layout fingerprint",
         "similarity": 0.86, "weight": 0.3, "compared_to": "per-nightowl",
         "detail": "Same greeting pool, same '--' sign-off cluster, same double-blank-line body layout, same '>' bullet character."},
        {"group": "circadian", "vector": "activity_window", "label": "24h UTC activity rhythm (Pearson r)",
         "similarity": 1.0, "weight": 0.45, "compared_to": "per-nightowl",
         "detail": "r = 1.000. The two 24-bin profiles are element-wise identical: peak 03:00 UTC, secondary peak 14:00 UTC, trough 07:00-08:00 UTC. A body clock is not something you re-register when you open a new account."},
        {"group": "crypto", "vector": "pgp_reuse", "label": "PGP key reuse",
         "similarity": 0.0, "weight": 0.94, "compared_to": "per-nightowl",
         "detail": "NEGATIVE RESULT: 0 of 3 key packets shared. Primary fingerprints are disjoint and were minted on different dates."},
        {"group": "crypto", "vector": "wallet_reuse", "label": "Wallet / transaction-cluster reuse",
         "similarity": 0.0, "weight": 0.94, "compared_to": "per-nightowl",
         "detail": "NEGATIVE RESULT: txc-ledger-01 and txc-nightowl-02 share no input, no change pattern, no address derivation."},
        {"group": "infrastructure", "vector": "cert_serial", "label": "TLS certificate serial / SHA-256 match",
         "similarity": 0.0, "weight": 0.9, "compared_to": "per-nightowl",
         "detail": "NEGATIVE RESULT: serials 4F:9A:2C:81:77:B3:0E vs 5C:20:9F:71:3A:8E."},
    ],
    "per-nightowl": [
        {"group": "stylometric", "vector": "char_ngram", "label": "Character n-gram (2-4) overlap with ShadowBroker_99",
         "similarity": 0.89, "weight": 0.62, "compared_to": "per-shadowbroker",
         "detail": "Survives full re-registration because the n-grams are a property of the writer, not the account."},
        {"group": "stylometric", "vector": "word_tfidf", "label": "Word TF-IDF cosine with ShadowBroker_99",
         "similarity": 0.83, "weight": 0.55, "compared_to": "per-shadowbroker",
         "detail": "Only delta is the re-announcement suffix appended to every body line -- +6% corpus length, cos 0.83 retained."},
        {"group": "stylometric", "vector": "orthographic", "label": "Orthographic habit vector",
         "similarity": 0.91, "weight": 0.5, "compared_to": "per-shadowbroker",
         "detail": "Identical typographic signature: 'Buyer beware. Escrow only.' never reworded across 50 posts."},
        {"group": "formatting", "vector": "punctuation", "label": "Punctuation & layout fingerprint",
         "similarity": 0.86, "weight": 0.3, "compared_to": "per-shadowbroker",
         "detail": "Shared '--' sign-off, shared greeting rate 0.85, shared blank-line cadence."},
        {"group": "circadian", "vector": "activity_window", "label": "24h UTC activity rhythm (Pearson r)",
         "similarity": 1.0, "weight": 0.45, "compared_to": "per-shadowbroker",
         "detail": "r = 1.000 -- element-wise identical 24-bin profiles. This is the strongest behavioural vector in the case, and the one artefact a takedown cannot revoke."},
        {"group": "crypto", "vector": "pgp_reuse", "label": "PGP key reuse",
         "similarity": 0.0, "weight": 0.94, "compared_to": "per-shadowbroker",
         "detail": "NEGATIVE RESULT -- recorded to prove the merge is not selector-driven."},
        {"group": "crypto", "vector": "wallet_reuse", "label": "Wallet / transaction-cluster reuse",
         "similarity": 0.0, "weight": 0.94, "compared_to": "per-shadowbroker",
         "detail": "NEGATIVE RESULT -- recorded to prove the merge is not selector-driven."},
        {"group": "infrastructure", "vector": "cert_serial", "label": "TLS certificate serial / SHA-256 match",
         "similarity": 0.0, "weight": 0.9, "compared_to": "per-shadowbroker",
         "detail": "NEGATIVE RESULT. Confidence is CAPPED at 0.79 and labelled 'LEAD' because no hard selector fired."},
    ],
    "per-v0idkite": [
        {"group": "stylometric", "vector": "char_ngram", "label": "Character n-gram (2-4) overlap with IceVex_0x",
         "similarity": 0.78, "weight": 0.62, "compared_to": "per-icevex",
         "detail": "Lower than the Ledger pair because the successor compressed sentence length, but the orthographic backbone is intact."},
        {"group": "stylometric", "vector": "word_tfidf", "label": "Word TF-IDF cosine with IceVex_0x",
         "similarity": 0.74, "weight": 0.55, "compared_to": "per-icevex",
         "detail": "Shared '0x' prefix injection shifts the bag-of-words but the documentation register dominates."},
        {"group": "stylometric", "vector": "orthographic", "label": "Orthographic habit vector",
         "similarity": 0.88, "weight": 0.5, "compared_to": "per-icevex",
         "detail": "GB spelling (organisation/anonymise) plus semicolon rate 0.42/0.31 in both personas."},
        {"group": "formatting", "vector": "punctuation", "label": "Punctuation & layout fingerprint",
         "similarity": 0.79, "weight": 0.3, "compared_to": "per-icevex",
         "detail": "Same greeting pool, same '-- regards' sign-off, same two-blank-line layout."},
        {"group": "circadian", "vector": "activity_window", "label": "24h UTC activity rhythm (Pearson r)",
         "similarity": 0.88, "weight": 0.45, "compared_to": "per-icevex",
         "detail": "r = 0.884. Both work a 12:00-15:00 UTC window with a low Sunday signal."},
        {"group": "crypto", "vector": "pgp_reuse", "label": "PGP subkey reuse (byte-identical)",
         "similarity": 0.99, "weight": 0.94, "compared_to": "per-icevex",
         "detail": "Subkey 71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A published by BOTH personas, created 2021-08-22. A revoked-and-forgotten subkey is a permanent fingerprint."},
        {"group": "crypto", "vector": "wallet_reuse", "label": "BTC transaction-cluster co-spend",
         "similarity": 0.95, "weight": 0.94, "compared_to": "per-icevex",
         "detail": "4 common inputs between w-vk-1 and w-vex-1 in cluster txc-vex-01."},
        {"group": "infrastructure", "vector": "cert_serial", "label": "TLS certificate SHA-256 + serial match",
         "similarity": 0.99, "weight": 0.9, "compared_to": "per-icevex",
         "detail": "Cert 8d31:6f45:2b90:ae17:... shared exactly, including the serial. Same origin host 198.51.100.212 (AS64512) for both deployments."},
        {"group": "infrastructure", "vector": "favicon_mmh3", "label": "MurmurHash3 favicon match",
         "similarity": 0.99, "weight": 0.72, "compared_to": "per-icevex",
         "detail": "mmh3 0x1D6E90A5 on both services. Strong here only because the certificate already corroborates."},
    ],
    "per-icevex": [
        {"group": "stylometric", "vector": "char_ngram", "label": "Character n-gram (2-4) overlap with V0idKite",
         "similarity": 0.78, "weight": 0.62, "compared_to": "per-v0idkite",
         "detail": "Same prose backbone, shortened delivery. The '0x' prefix adds a small constant offset across every line."},
        {"group": "stylometric", "vector": "word_tfidf", "label": "Word TF-IDF cosine with V0idKite",
         "similarity": 0.74, "weight": 0.55, "compared_to": "per-v0idkite",
         "detail": "Register preserved: hedging, first-person verification language, no sales language."},
        {"group": "stylometric", "vector": "orthographic", "label": "Orthographic habit vector",
         "similarity": 0.88, "weight": 0.5, "compared_to": "per-v0idkite",
         "detail": "No new spelling habits introduced after migration -- the strongest form of writer continuity."},
        {"group": "formatting", "vector": "punctuation", "label": "Punctuation & layout fingerprint",
         "similarity": 0.79, "weight": 0.3, "compared_to": "per-v0idkite",
         "detail": "Layout flattened from two blank lines to one; greeting pool preserved."},
        {"group": "circadian", "vector": "activity_window", "label": "24h UTC activity rhythm (Pearson r)",
         "similarity": 0.88, "weight": 0.45, "compared_to": "per-v0idkite",
         "detail": "r = 0.884. Slight evening drift (+18%) consistent with relocation westwards, not with a new human."},
        {"group": "crypto", "vector": "pgp_reuse", "label": "PGP subkey reuse (byte-identical)",
         "similarity": 0.99, "weight": 0.94, "compared_to": "per-v0idkite",
         "detail": "HARD SELECTOR. This single artefact resolves the cluster on its own."},
        {"group": "crypto", "vector": "wallet_reuse", "label": "BTC transaction-cluster co-spend",
         "similarity": 0.95, "weight": 0.94, "compared_to": "per-v0idkite",
         "detail": "HARD SELECTOR, independent of the PGP evidence."},
        {"group": "infrastructure", "vector": "cert_serial", "label": "TLS certificate SHA-256 + serial match",
         "similarity": 0.99, "weight": 0.9, "compared_to": "per-v0idkite",
         "detail": "HARD SELECTOR, independent of both crypto vectors."},
        {"group": "infrastructure", "vector": "favicon_mmh3", "label": "MurmurHash3 favicon match vs GHOST CARTEL",
         "similarity": 0.41, "weight": 0.72, "compared_to": "per-ghostcartel",
         "detail": "CONTESTED / FALSE POSITIVE. Hash 0x7A3C91E4 is shipped in a free WP theme. Different ASN, different country, different operator, different language register. Held at 41% and visually de-emphasised in the UI."},
    ],
    "per-cryptomule": [
        {"group": "stylometric", "vector": "char_ngram", "label": "Nearest-neighbour stylometric distance",
         "similarity": 0.31, "weight": 0.62, "compared_to": None,
         "detail": "Nearest corpus neighbour is GhostCartel_7 at 0.31 -- an order of magnitude below the in-cluster pairs. Uniquely identified by LOWERCASE_START_RATE = 0.88."},
        {"group": "crypto", "vector": "wallet_reuse", "label": "BTC co-spend cluster (txc-mule-01)",
         "similarity": 0.92, "weight": 0.94, "compared_to": None,
         "detail": "4 payout addresses, 25 shared inputs. Round-amount transfer pattern (0.50/1.00/2.00/5.00 BTC) is a behavioural signature of the same operator script."},
        {"group": "infrastructure", "vector": "cert_serial", "label": "TLS serial -> clearnet origin correlation",
         "similarity": 0.86, "weight": 0.9, "compared_to": None,
         "detail": "Serial 3F:61:08:D7:B2:E5 traced to 203.0.113.140 / AS64541, 23h/day uptime, stock Ubuntu nginx."},
    ],
    "per-ghostcartel": [
        {"group": "stylometric", "vector": "char_ngram", "label": "Nearest-neighbour stylometric distance",
         "similarity": 0.28, "weight": 0.62, "compared_to": None,
         "detail": "Isolated by transliteration-error profile: 31% typo rate, 'avaliable'/'delivry'/'shiping' recur in 61% of posts."},
        {"group": "crypto", "vector": "wallet_reuse", "label": "XMR/BTC payout pair (txc-ghost-01)",
         "similarity": 0.71, "weight": 0.94, "compared_to": None,
         "detail": "2 shared change outputs; direction of control undetermined."},
        {"group": "infrastructure", "vector": "favicon_mmh3", "label": "Favicon mmh3 0x7A3C91E4",
         "similarity": 0.41, "weight": 0.72, "compared_to": None,
         "detail": "CONTESTED. Matches a VEXING HYDRA reseller mirror, but the hash is theme-distributed. Explicitly marked as a false positive in the analyst record."},
    ],
}

# --------------------------------------------------------------------------- #
# Preset unattributed samples for the "De-anonymize New Sample" sandbox
# --------------------------------------------------------------------------- #

SAMPLE_LIBRARY: List[Dict[str, Any]] = [
    {
        "id": "smp-1",
        "title": "Re-announced dispatch thread (expected: OBSIDIAN LEDGER, soft match)",
        "expected_actor": "act-obsidian-ledger",
        "text": (
            "Attention buyers.\n"
            "Reminder regarding the escrow: conditions unchanged, the client went quiet again.\n"
            "Payment is split across 12 outputs so the access tier stays under the reporting threshold..."
            "We do not negotiate below 1.8 btc and we never take third party escrow.\n"
            "Buyer verification pack is mandatory: the recovery phrase, the first escrow and a 6 day cooling period."
            "\n\nEvery 24 hours the relay rotates. The old handles are dead, do not PM them.\n"
            "-- dispatch desk\n"
            "Buyer beware. Escrow only."
        ),
        "posting_hours": [1, 2, 3, 3, 4, 14, 15],
        "pgp": None,
        "wallet": None,
    },
    {
        "id": "smp-2",
        "title": "Relaunch index post with retained subkey (expected: VEXING HYDRA, hard match)",
        "expected_actor": "act-vexing-hydra",
        "text": (
            "Hi all,\n"
            "Short note on fingerprinting resistance: the request header set is initialised lazily, so the first 128 "
            "requests are measurably slower than the rest.\n"
            "0x tested it -- the client entropy source leaks about 40 bytes per session, which is enough to correlate "
            "sessions across two listings.\n"
            "Anonymise properly: strip the session token, rotate the build identifier, and never reuse a profile across "
            "listings; that mistake cost one of my colleagues a handle.\n"
            "A 4 hour window, four posts a night, every night. That is a person, not a bot, and not a script.\n\n"
            "Cheers,"
        ),
        "posting_hours": [12, 13, 14, 15, 16],
        "pgp": "71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A",
        "wallet": "bc1q6h2yt4n8k0v3m5q7w9x1z3c5b7e9r2t4y6u8i",
    },
    {
        "id": "smp-3",
        "title": "Payout thread (expected: MULE CARTEL)",
        "expected_actor": "act-mule-cartel",
        "text": (
            "so the mixer again\n"
            "need 0.4 btc sent to my new addr, the old one is frozen\n"
            "ill do 3 rounds of 2 btc over 7 days, no questions\n"
            "if your tx got flagged just do nothing and wait 3 weeks\n"
            "thx"
        ),
        "posting_hours": [21, 22, 23, 0, 6],
        "pgp": None,
        "wallet": "bc1q7v3m9k2x5n8b1t4w6y0z3c5r7e9q2u4t6y8i0",
    },
    {
        "id": "smp-4",
        "title": "Vendor shop front (expected: GHOST CARTEL)",
        "expected_actor": "act-ghost-cartel",
        "text": (
            "Hello buyers!\n"
            "Now avaliable in stock new batch. Price for 100 pack is 0.4 btc. Delivry in 5 days to all world\n"
            "We have 200 unit avaliable, big quantity, good quality, best price in market\n"
            "Payment only xmr, no other way. Escrow is not needed, we are old team\n"
            "For all buyers: our shop is updated, please update your client also\n"
            "All goods laboratory quality. Every unit tested before send\n"
            "Thank you for attention"
        ),
        "posting_hours": [6, 7, 8, 9, 18],
        "pgp": None,
        "wallet": None,
    },
    {
        "id": "smp-5",
        "title": "CONTROL / adversary probe: register-shifting bot post (expected: NO MATCH)",
        "expected_actor": None,
        "text": (
            "Good afternoon.\n"
            "I am writing to enquire regarding the listed items. Could you please "
            "confirm whether escrow is supported, and what the typical settlement "
            "window is? I would also appreciate clarification on the verification "
            "steps. Thank you, and I look forward to your reply."
        ),
        # Deliberately near-uniform: an operator running a scheduled poster every
        # three hours has no circadian signature for the engine to find.
        "posting_hours": [0, 3, 6, 9, 12, 15, 18, 21],
        "pgp": None,
        "wallet": None,
    },
]

# --------------------------------------------------------------------------- #
# Timeline events
# --------------------------------------------------------------------------- #

TIMELINE: List[Dict[str, Any]] = [
    {"ts": "2021-08-22T00:00:00Z", "persona_id": "per-v0idkite", "market_id": "mkt-alphabay", "kind": "KEY_MINT", "severity": "LOW", "summary": "PGP primary C4A70E19... created; earliest crypto artefact in the corpus."},
    {"ts": "2021-09-03T00:00:00Z", "persona_id": "per-v0idkite", "market_id": "mkt-alphabay", "kind": "FIRST_SEEN", "severity": "MEDIUM", "summary": "V0idKite first post on AlphaBay-Sim."},
    {"ts": "2022-01-19T00:00:00Z", "persona_id": "per-cryptomule", "market_id": "mkt-hydra", "kind": "FIRST_SEEN", "severity": "LOW", "summary": "CryptoMule_K recruitment thread opened on Hydra-Sim."},
    {"ts": "2022-04-12T00:00:00Z", "persona_id": "per-shadowbroker", "market_id": "mkt-alphabay", "kind": "FIRST_SEEN", "severity": "HIGH", "summary": "ShadowBroker_99 vendor account opened; PGP primary published same day."},
    {"ts": "2023-02-08T00:00:00Z", "persona_id": "per-ghostcartel", "market_id": "mkt-dread", "kind": "FIRST_SEEN", "severity": "MEDIUM", "summary": "GhostCartel_7 shop front published on Dread-Sim."},
    {"ts": "2024-03-14T00:00:00Z", "persona_id": "per-shadowbroker", "market_id": "mkt-alphabay", "kind": "PLATFORM_TAKEDOWN", "severity": "CRITICAL", "summary": "AlphaBay-Sim escrow subsystem seized. ShadowBroker_99 goes silent 14 days later."},
    {"ts": "2024-04-06T00:00:00Z", "persona_id": "per-nightowl", "market_id": "mkt-dread", "kind": "REBRAND", "severity": "CRITICAL", "summary": "NightOwl_V2 first post on Dread-Sim, 23 days after predecessor's last scan. New PGP primary, new wallets, new onion service -- identical handwriting."},
    {"ts": "2024-08-20T00:00:00Z", "persona_id": "per-icevex", "market_id": "mkt-hydra", "kind": "REBRAND", "severity": "CRITICAL", "summary": "IceVex_0x relaunches on Hydra-Sim while still signing with V0idKite's 2021 encryption subkey."},
    {"ts": "2024-09-02T00:00:00Z", "persona_id": "per-v0idkite", "market_id": "mkt-dread", "kind": "PLATFORM_TAKEDOWN", "severity": "CRITICAL", "summary": "Dread-Sim relay nodes seized; forum migrates to Hydra-Sim."},
    {"ts": "2025-06-18T00:00:00Z", "persona_id": "per-nightowl", "market_id": "mkt-dread", "kind": "LAST_SCAN", "severity": "MEDIUM", "summary": "NightOwl_V2 last observed post."},
    {"ts": "2025-11-02T00:00:00Z", "persona_id": "per-icevex", "market_id": "mkt-hydra", "kind": "LAST_SCAN", "severity": "MEDIUM", "summary": "IceVex_0x last observed post; cluster VEXING HYDRA retained at 0.97."},
]

# --------------------------------------------------------------------------- #
# Public reputation / leak sightings (clearnet pivot points)
# --------------------------------------------------------------------------- #

CLEARNET_PIVOTS: List[Dict[str, Any]] = [
    {"persona_id": "per-shadowbroker", "source": "Certificate Transparency log (synthetic)",
     "pivot": "TLS cert serial 4F:9A:2C:81:77:B3:0E", "artifact": "198.51.100.47 (AS64512, NL)", "confidence": 0.94},
    {"persona_id": "per-shadowbroker", "source": "Paste-site corpus",
     "pivot": "verbatim dispatch post + 'Buyer beware. Escrow only.'", "artifact": "Breached vendor email at Simuplenty Solutions", "confidence": 0.86},
    {"persona_id": "per-v0idkite", "source": "Certificate Transparency log (synthetic)",
     "pivot": "cert SHA-256 8d31:6f45...", "artifact": "198.51.100.212 (AS64512, NL)", "confidence": 0.92},
    {"persona_id": "per-v0idkite", "source": "Ransomware leak site",
     "pivot": "BTC address bc1q3m9zt7...", "artifact": "Victim list entry, 2023-11-04", "confidence": 0.9},
    {"persona_id": "per-icevex", "source": "Certificate Transparency log (synthetic)",
     "pivot": "cert SHA-256 8d31:6f45... (identical to V0idKite)", "artifact": "198.51.100.212 (AS64512, NL)", "confidence": 0.99},
    {"persona_id": "per-cryptomule", "source": "Uptime + banner correlation",
     "pivot": "nginx/1.14.0 (Ubuntu) + 23h/day power-on", "artifact": "203.0.113.140 (AS64541, SG)", "confidence": 0.86},
    {"persona_id": "per-ghostcartel", "source": "Passive hosting correlation",
     "pivot": "Apache/2.4.29 + favicon mmh3 0x7A3C91E4", "artifact": "192.0.2.201 (AS64550, NL) -- CONTESTED", "confidence": 0.69},
    {"persona_id": "per-nightowl", "source": "Passive hosting correlation",
     "pivot": "nginx/1.20.2 + cert serial 5C:20:9F:71:3A:8E", "artifact": "192.0.2.88 (AS64533, DE)", "confidence": 0.71},
]

# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #


def _iter_persona_days(first_seen: str, last_scan: str) -> Iterable[Any]:
    start = datetime.strptime(first_seen, "%Y-%m-%d")
    end = datetime.strptime(last_scan, "%Y-%m-%d")
    day = start
    while day <= end:
        yield day
        day += timedelta(days=1)


def _sample_hour(rng: random.Random, circadian: List[float]) -> int:
    return rng.choices(range(24), weights=circadian, k=1)[0]


CHANNELS_BY_CATEGORY = {
    "Ransomware": ["vendor-board", "escrow-thread", "access-tier", "negotiation"],
    "Stolen Data": ["combo-list", "vendor-board", "research-note", "access-data"],
    "Illicit Goods": ["shop-front", "bulk-order", "vendor-board"],
    "Laundering": ["payouts", "bridge-thread", "vendor-board"],
}


def build_posts() -> List[Dict[str, Any]]:
    """Deterministically generate every forum post from the style grammars."""
    posts: List[Dict[str, Any]] = []
    for persona in PERSONAS:
        handle = persona["handle"]
        profile = STYLE_PROFILES[handle]
        circadian = CIRCADIAN_PROFILES[handle]
        rng = random.Random(MASTER_SEED ^ profile["seed"])
        start = datetime.strptime(persona["first_seen"], "%Y-%m-%d")
        end = datetime.strptime(persona["last_scan_date"], "%Y-%m-%d")
        span_days = max((end - start).days, 1)
        channels = CHANNELS_BY_CATEGORY[persona["category"]]

        # Spread posts across the persona's lifespan, weighted to the active
        # hours of its circadian profile.
        slots = sorted(
            rng.sample(range(1, span_days + 1), min(persona["post_count"], span_days))
        )
        for index, day_offset in enumerate(slots):
            day = start + timedelta(days=day_offset - 1)
            if rng.random() < 0.22:  # skip a day -- humans are not metronomes
                day = day + timedelta(days=1)
            if day > end:
                day = end
            hour = _sample_hour(rng, circadian)
            posted = day.replace(hour=hour, minute=rng.randint(0, 59), second=rng.randint(0, 59))
            title = " ".join(
                render_post(rng, profile).split("\n")[0].split(".")[:1]
            ).strip()[:90] or f"thread {index + 1:02d}"
            posts.append({
                "id": f"post-{persona['id']}-{index + 1:02d}",
                "persona_id": persona["id"],
                "posted_at": posted.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "utc_hour": hour,
                "channel": channels[index % len(channels)],
                "title": title,
                "body": render_post(rng, profile),
                "lang": persona["language"],
            })
    return posts


def corpus_by_persona(posts: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """Concatenate each persona's posts into a single training document."""
    buckets: Dict[str, List[str]] = {p["id"]: [] for p in PERSONAS}
    for post in posts:
        buckets[post["persona_id"]].append(post["body"])
    return {pid: "\n\n".join(bodies) for pid, bodies in buckets.items()}


def build_database() -> Dict[str, Any]:
    """Assemble the complete, self-consistent intelligence picture."""
    posts = build_posts()
    return {
        "meta": {
            "team": TEAM_NAME,
            "problem_statement_id": PROBLEM_STATEMENT_ID,
            "problem_title": PROBLEM_TITLE,
            "corpus_version": CORPUS_VERSION,
            "compiled_at": CORPUS_COMPILED_AT,
            "master_seed": MASTER_SEED,
            "disclaimer": DISCLAIMER,
            "categories": CATEGORIES,
            "selector_types": [
                "pgp_primary", "pgp_subkey", "btc_address", "xmr_address",
                "tox_id", "jabber", "onion_service",
            ],
        },
        "markets": MARKETS,
        "actors": ACTORS,
        "personas": PERSONAS,
        "pgp_keys": PGP_KEYS,
        "wallets": WALLETS,
        "tx_links": TX_LINKS,
        "messaging": MESSAGING,
        "onion_services": ONION_SERVICES,
        "evidence": EVIDENCE,
        "posts": posts,
        "timeline": TIMELINE,
        "clearnet_pivots": CLEARNET_PIVOTS,
        "sample_library": SAMPLE_LIBRARY,
        "style_profiles": STYLE_PROFILES,
        "circadian": CIRCADIAN_PROFILES,
    }


if __name__ == "__main__":  # pragma: no cover - manual inspection helper
    db = build_database()
    print(f"corpus {db['meta']['corpus_version']}: "
          f"{len(db['personas'])} personas / {len(db['actors'])} clusters / "
          f"{len(db['posts'])} posts")
    for persona in db["personas"]:
        print(f"  {persona['handle']:<16} {persona['category']:<14} "
              f"{len(db['style_profiles'][persona['handle']]['bodies'])} templates")
