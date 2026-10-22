"""Direct Mode tests for SourceVerifier (web access is mocked; no real network)."""
CONTRACT = "contracts/source_verifier.py"
H = "a" * 64
URL = "https://huggingface.co/datasets/acme/demo"
ANY = r".*huggingface\.co.*"


def deploy(direct_deploy):
    return direct_deploy(CONTRACT)


def page(vm, body):
    vm.clear_mocks()
    vm.mock_web(ANY, {"body": body})


def test_match(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    page(direct_vm, "Dataset Demo Set ... sha256: " + H)
    c.verify_source("ds-1", URL, "demo set", H)
    r = c.get_verification("ds-1")
    assert r["verdict"] == "MATCH" and r["name_found"] and r["hash_found"]
    assert c.get_verification_count() == 1


def test_partial_name_only(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    page(direct_vm, "Demo Set dataset card, no checksum listed")
    c.verify_source("ds-2", URL, "demo set", H)
    assert c.get_verification("ds-2")["verdict"] == "PARTIAL"


def test_mismatch(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    page(direct_vm, "Completely unrelated page")
    c.verify_source("ds-3", URL, "demo set", H)
    assert c.get_verification("ds-3")["verdict"] == "MISMATCH"


def test_unknown_id_is_not_verified(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    assert c.get_verification("nope")["verdict"] == "NOT_VERIFIED"


def test_rejects_other_hosts(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    with direct_vm.expect_revert("source_url must be https"):
        c.verify_source("ds-4", "https://evil.example.com/x", "demo set", H)


def test_rejects_bad_hash(direct_vm, direct_deploy):
    c = deploy(direct_deploy)
    with direct_vm.expect_revert("claimed_hash must be 64 hex chars"):
        c.verify_source("ds-5", URL, "demo set", "xyz")
