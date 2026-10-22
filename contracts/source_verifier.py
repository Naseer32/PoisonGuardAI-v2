# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import json
import re

# SourceVerifier: fetches a public dataset page and checks that the registered name and SHA-256
# appear on it. Deterministic checks only; validators must agree on reachable/name_found/hash_found.
HOSTS = ("huggingface.co", "github.com", "zenodo.org")
URLP = re.compile(r"https://([a-z0-9.\-]+)/[^\s]{1,300}")
HASHP = re.compile(r"[0-9a-f]{64}")
IDP = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}")


def _fail(msg: str):
    raise gl.vm.UserError(msg)


class SourceVerifier(gl.Contract):
    results: TreeMap[str, str]
    owners: TreeMap[str, str]
    count: u256

    def __init__(self):
        self.count = u256(0)

    @gl.public.write
    def verify_source(self, assessment_id: str, source_url: str, claimed_name: str, claimed_hash: str) -> None:
        aid = assessment_id.strip()
        if IDP.fullmatch(aid) is None:
            _fail("invalid assessment_id")
        url = source_url.strip()
        m = URLP.fullmatch(url)
        if m is None or m.group(1) not in HOSTS:
            _fail("source_url must be https on huggingface.co, github.com or zenodo.org")
        name = claimed_name.strip().lower()
        if len(name) < 2 or len(name) > 128:
            _fail("claimed_name must be 2-128 chars")
        h = claimed_hash.strip().lower()
        if HASHP.fullmatch(h) is None:
            _fail("claimed_hash must be 64 hex chars")
        sender = gl.message.sender_address.as_hex
        if aid in self.owners and self.owners[aid] != sender:
            _fail("only the original verifier can update this id")

        def fetch() -> str:
            try:
                text = gl.nondet.web.render(url, mode="text")
                text = text.lower() if isinstance(text, str) else ""
            except Exception:
                text = ""
            return json.dumps({"reachable": len(text) > 0, "name_found": name in text,
                               "hash_found": h in text}, sort_keys=True)

        raw = json.loads(gl.eq_principle.strict_eq(fetch))
        if not raw["reachable"]:
            verdict = "UNREACHABLE"
        elif raw["name_found"] and raw["hash_found"]:
            verdict = "MATCH"
        elif raw["name_found"] or raw["hash_found"]:
            verdict = "PARTIAL"
        else:
            verdict = "MISMATCH"
        if aid not in self.owners:
            self.owners[aid] = sender
            self.count = u256(int(self.count) + 1)
        self.results[aid] = json.dumps({
            "assessment_id": aid, "source_url": url, "verdict": verdict,
            "reachable": raw["reachable"], "name_found": raw["name_found"],
            "hash_found": raw["hash_found"], "claimed_hash": h}, sort_keys=True)

    @gl.public.view
    def get_verification(self, assessment_id: str) -> dict:
        aid = assessment_id.strip()
        if aid not in self.results:
            return {"assessment_id": aid, "verdict": "NOT_VERIFIED"}
        return json.loads(self.results[aid])

    @gl.public.view
    def get_verification_count(self) -> int:
        return int(self.count)
