"""Unit tests for hcaptcha.live helpers (no network / Node needed)."""
import pytest

from hcaptcha.live import _hex_to_bytes, _dispatch_json, _to_js_bytes


def test_hex_to_bytes():
    assert _hex_to_bytes("deadbeef") == b"\xde\xad\xbe\xef"
    assert _hex_to_bytes("0xDEAD") == b"\xde\xad"
    assert _hex_to_bytes(" de ad ") == b"\xde\xad"


def test_hex_to_bytes_bad():
    with pytest.raises(ValueError):
        _hex_to_bytes("nothex")


def test_to_js_bytes():
    assert _to_js_bytes(b"\x00\x01\xff") == "0,1,255"
    assert _to_js_bytes(b"") == ""


class _FakeDecryptor:
    def hsj_decrypt(self, b): return b[::-1]
    def hsw_decrypt(self, b): return bytes((x ^ 0xFF) for x in b)
    def hsj_encrypt(self, b): return b
    def hsw_encrypt(self, b): return b
    def hsj_n_token(self, s): return "tok:" + s
    def hsw_solve(self, s): return "pow:" + s


def test_dispatch_json_ops():
    d = _FakeDecryptor()
    assert _dispatch_json(d, {"op": "decrypt-hsj", "data_hex": "0102"}) == {
        "ok": True, "out_hex": "0201"}
    assert _dispatch_json(d, {"op": "decrypt-hsw", "data_hex": "00ff"}) == {
        "ok": True, "out_hex": "ff00"}
    assert _dispatch_json(d, {"op": "encrypt-hsj", "data_hex": "abcd"}) == {
        "ok": True, "out_hex": "abcd"}
    assert _dispatch_json(d, {"op": "n-token", "data": "abc"}) == {
        "ok": True, "out": "tok:abc"}
    assert _dispatch_json(d, {"op": "solve", "data": "jwt"}) == {
        "ok": True, "out": "pow:jwt"}


def test_dispatch_json_unknown():
    out = _dispatch_json(_FakeDecryptor(), {"op": "nope"})
    assert out["ok"] is False
    assert "nope" in out["error"]
