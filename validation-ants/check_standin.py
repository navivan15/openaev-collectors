"""
Compare the ants' stand-in for the OpenAEV client with the real client (pyoaev).

Run it on a machine that has pyoaev installed:

  splunk-es/.venv/Scripts/python validation-ants/check_standin.py

It checks, piece by piece, that the stand-in in ants/oaev_standin.py behaves like the real thing
for what the ants use:

  1. signature type names and values
  2. the similarity score behind fuzzy matching, on thousands of string pairs
  3. the match helper, on generated signatures and alert data
  4. the expectation objects: what they accept, what they refuse, what they hand back

Exit code 0: no difference. 1: a difference was found. 2: pyoaev is not installed, nothing compared.
"""

import importlib.util
import logging
import random
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

if importlib.util.find_spec("pyoaev") is None:
    print("pyoaev is not installed here: nothing to compare with.")
    sys.exit(2)

from pyoaev.apis.inject_expectation.model import DetectionExpectation, PreventionExpectation  # noqa: E402
from pyoaev.helpers import OpenAEVDetectionHelper  # noqa: E402
from pyoaev.signatures.types import SignatureTypes  # noqa: E402
from thefuzz import fuzz  # noqa: E402  (pyoaev's own dependency)

from ants import oaev_standin  # noqa: E402

MINE = oaev_standin.build()
RNG = random.Random(20261118)
QUIET = logging.getLogger("check_standin")
QUIET.setLevel(logging.CRITICAL)
DIFFERENCES = []


def differ(part, detail):
    DIFFERENCES.append(f"{part}: {detail}")


def outcome(fn):
    """What a call did: its value, or the kind of error it raised."""
    try:
        return ("value", fn())
    except Exception as e:      # noqa: BLE001  (the kind of error is what is compared)
        return ("error", type(e).__name__)


# 1. signature types ---------------------------------------------------------------------------
def check_types():
    mine = MINE["pyoaev.signatures.types"]["SignatureTypes"]
    for member in mine:
        real = getattr(SignatureTypes, member.name, None)
        if real is None or real.value != member.value:
            differ("types", f"{member.name}={member.value!r} is {real!r} in the client")
    return len(list(mine))


# 2. similarity --------------------------------------------------------------------------------
ALPHABET = "abcdef0123456789-_. "


def word(low, high):
    return "".join(RNG.choice(ALPHABET) for _ in range(RNG.randint(low, high)))


def near(text):
    """The same text with a few characters changed, dropped or added."""
    chars = list(text)
    for _ in range(RNG.randint(0, 4)):
        if not chars:
            break
        at = RNG.randrange(len(chars))
        kind = RNG.choice("cda")
        if kind == "c":
            chars[at] = RNG.choice(ALPHABET)
        elif kind == "d":
            del chars[at]
        else:
            chars.insert(at, RNG.choice(ALPHABET))
    return "".join(chars)


def implant():
    return f"oaev-implant-{uuid.UUID(int=RNG.getrandbits(128))}-agent-{uuid.UUID(int=RNG.getrandbits(128))}"


def check_similarity(pairs=20000):
    cases = [("", ""), ("a", ""), ("", "a"), ("abc", "abc"), ("abc", "abd")]
    for _ in range(pairs):
        pick = RNG.random()
        if pick < 0.4:
            base = implant()
            cases.append((base, near(base)))
        elif pick < 0.7:
            base = word(1, 40)
            cases.append((base, near(base)))
        else:
            cases.append((word(0, 30), word(0, 30)))
    for a, b in cases:
        mine, real = oaev_standin.similarity(a, b), fuzz.ratio(a, b)
        if mine != real:
            differ("similarity", f"{a!r} / {b!r}: stand-in {mine}, client {real}")
    return len(cases)


# 3. the match helper --------------------------------------------------------------------------
TYPES = ["parent_process_name", "source_ipv4_address", "target_ipv4_address",
         "source_ipv6_address", "target_ipv6_address", "target_hostname_address"]


def ip():
    return ".".join(str(RNG.randint(1, 254)) for _ in range(4))


def helper_case():
    relevant = RNG.sample(TYPES, RNG.randint(1, len(TYPES)))
    signatures, alert = [], {}
    for kind in RNG.sample(TYPES, RNG.randint(0, 4)):
        value = implant() if kind == "parent_process_name" else ip()
        signatures.append({"type": kind, "value": value})
        if RNG.random() < 0.12:
            continue                                   # the alert has no data for this type
        if kind == "parent_process_name":
            seen = [near(value) if RNG.random() < 0.7 else implant() for _ in range(RNG.randint(0, 3))]
            alert[kind] = {"type": "fuzzy", "data": seen, "score": RNG.choice([80, 90, 95, 99])}
        else:
            seen = [value if RNG.random() < 0.6 else ip() for _ in range(RNG.randint(0, 3))]
            alert[kind] = {"type": RNG.choice(["simple", "simple", "other"]), "data": seen}
    return relevant, signatures, alert


def check_helper(cases=5000):
    mine_cls = MINE["pyoaev.helpers"]["OpenAEVDetectionHelper"]
    for _ in range(cases):
        relevant, signatures, alert = helper_case()
        real = outcome(lambda: OpenAEVDetectionHelper(QUIET, relevant).match_alert_elements(signatures, alert))
        mine = outcome(lambda: mine_cls(QUIET, relevant).match_alert_elements(signatures, alert))
        if real != mine:
            differ("helper", f"client {real}, stand-in {mine} for {signatures} on {alert} (relevant {relevant})")
    return cases


# 4. expectation objects -----------------------------------------------------------------------
def check_models():
    models = MINE["pyoaev.apis.inject_expectation.model"]
    good = [{"type": "source_ipv4_address", "value": "10.0.0.5"},
            {"type": "parent_process_name", "value": implant()},
            {"type": "target_hostname_address", "value": "WS-TEST-01"},
            {"type": "start_date", "value": "2026-11-18T10:00:00"},
            {"type": "end_date", "value": "2026-11-18T10:05:00"}]
    step = str(uuid.UUID(int=RNG.getrandbits(128)))
    inputs = [
        ("good", {"inject_expectation_id": step, "inject_expectation_signatures": good}),
        ("no signatures", {"inject_expectation_id": step, "inject_expectation_signatures": []}),
        ("id is not a UUID", {"inject_expectation_id": "step-1", "inject_expectation_signatures": good}),
        ("value is not text", {"inject_expectation_id": step,
                               "inject_expectation_signatures": [{"type": "end_date", "value": None}]}),
        ("signature without a type", {"inject_expectation_id": step,
                                      "inject_expectation_signatures": [{"value": "x"}]}),
        ("no id", {"inject_expectation_signatures": good}),
    ]

    def shape(cls, fields):
        made = cls(**fields, api_client=None)
        return (str(made.inject_expectation_id),
                [(s.type.value, s.value) for s in made.inject_expectation_signatures],
                made.success_label, made.failure_label)

    pairs = [(DetectionExpectation, models["DetectionExpectation"]),
             (PreventionExpectation, models["PreventionExpectation"])]
    for real_cls, mine_cls in pairs:
        for name, fields in inputs:
            real, mine = outcome(lambda: shape(real_cls, fields)), outcome(lambda: shape(mine_cls, fields))
            if real != mine:
                differ("models", f"{real_cls.__name__}, {name}: client {real}, stand-in {mine}")
        if issubclass(models["DetectionExpectation"], models["PreventionExpectation"]):
            differ("models", "a detection expectation counts as a prevention expectation")
    return len(pairs) * len(inputs)


def main():
    print(f"Comparing ants/oaev_standin.py with pyoaev {getattr(__import__('pyoaev'), '__version__', '?')}")
    print(f"  signature types : {check_types()} compared")
    print(f"  similarity      : {check_similarity()} string pairs compared")
    print(f"  match helper    : {check_helper()} cases compared")
    print(f"  expectations    : {check_models()} cases compared")
    if DIFFERENCES:
        print(f"{len(DIFFERENCES)} difference(s):")
        for line in DIFFERENCES[:20]:
            print("  " + line)
        sys.exit(1)
    print("no differences")


if __name__ == "__main__":
    main()
