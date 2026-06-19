import copy

import pytest

from compliancedrift.baseline import (
    build_baseline,
    extract_config,
    is_baseline,
    verify_baseline,
)
from compliancedrift.digest import compute_digest, normalize


def test_build_baseline_envelope_shape():
    cfg = {"a": 1, "b": [1, 2, 3]}
    env = build_baseline(cfg)
    assert env["compliancedrift_baseline"] == "1"
    assert env["algorithm"] == "sha256"
    assert len(env["digest"]) == 64
    assert env["config"] == cfg


def test_digest_stable_across_key_order():
    a = {"x": 1, "y": {"p": 1, "q": 2}}
    b = {"y": {"q": 2, "p": 1}, "x": 1}
    assert compute_digest(a) == compute_digest(b)


def test_digest_changes_on_value_change():
    assert compute_digest({"a": 1}) != compute_digest({"a": 2})


def test_normalize_sorts_dict_keys_recursively():
    out = normalize({"b": {"d": 1, "c": 2}, "a": 3})
    assert list(out.keys()) == ["a", "b"]
    assert list(out["b"].keys()) == ["c", "d"]


def test_normalize_preserves_list_order():
    assert normalize([3, 1, 2]) == [3, 1, 2]


def test_verify_passes_on_clean_baseline():
    env = build_baseline({"secure": True, "level": 5})
    ok, expected, actual = verify_baseline(env)
    assert ok
    assert expected == actual


def test_verify_fails_on_tampered_config():
    env = build_baseline({"mfa_required": True})
    tampered = copy.deepcopy(env)
    # Attacker flips the captured config but leaves the stored digest.
    tampered["config"]["mfa_required"] = False
    ok, expected, actual = verify_baseline(tampered)
    assert not ok
    assert expected != actual


def test_verify_fails_on_tampered_digest():
    env = build_baseline({"a": 1})
    env["digest"] = "0" * 64
    ok, _, _ = verify_baseline(env)
    assert not ok


def test_verify_rejects_non_baseline():
    with pytest.raises(ValueError):
        verify_baseline({"just": "config"})


def test_verify_rejects_unknown_algorithm():
    env = build_baseline({"a": 1})
    env["algorithm"] = "md5"
    with pytest.raises(ValueError):
        verify_baseline(env)


def test_extract_config_from_envelope_and_plain():
    env = build_baseline({"a": 1})
    assert extract_config(env) == {"a": 1}
    assert extract_config({"a": 1}) == {"a": 1}


def test_is_baseline():
    assert is_baseline(build_baseline({"a": 1}))
    assert not is_baseline({"a": 1})
    assert not is_baseline("string")
