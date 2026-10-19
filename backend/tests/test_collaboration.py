"""Tests for multi-node encrypted media transfer, integrity verification, and security goals."""
import os
import pytest

from app.collaboration.node_transfer import (
    derive_node_key, encrypt_payload, decrypt_and_verify_payload,
    get_transfer_audit_log, MediaType
)
from app.collaboration.security_evaluation import (
    evaluate_confidentiality, evaluate_integrity, run_full_security_goals_evaluation
)


def test_text_and_media_encryption_roundtrip():
    key = derive_node_key("secure-node-shared-key-123456789")

    # 1. Text payload
    text_data = b"Autonomous Security Engineer: Inter-node communication payload"
    pkt_text = encrypt_payload(text_data, MediaType.TEXT, "Node-Scanner", "Node-Controller", key)
    res_text = decrypt_and_verify_payload(pkt_text, key)
    assert res_text["raw_bytes"] == text_data
    assert res_text["integrity_verified"] is True

    # 2. Simulated Image / Binary payload (PNG magic bytes header)
    png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(100)
    pkt_img = encrypt_payload(png_data, MediaType.IMAGE, "Node-Scanner", "Node-Controller", key)
    res_img = decrypt_and_verify_payload(pkt_img, key)
    assert res_img["raw_bytes"] == png_data
    assert res_img["verified_sha256"] == pkt_img["original_sha256"]

    # 3. Simulated Audio payload
    audio_data = b"ID3\x03\x00\x00\x00" + os.urandom(200)
    pkt_audio = encrypt_payload(audio_data, MediaType.AUDIO, "Node-Scanner", "Node-Controller", key)
    res_audio = decrypt_and_verify_payload(pkt_audio, key)
    assert res_audio["raw_bytes"] == audio_data

    # 4. Simulated Video payload
    video_data = b"\x00\x00\x00\x18ftypmp42" + os.urandom(300)
    pkt_video = encrypt_payload(video_data, MediaType.VIDEO, "Node-Scanner", "Node-Controller", key)
    res_video = decrypt_and_verify_payload(pkt_video, key)
    assert res_video["raw_bytes"] == video_data


def test_tampering_fails_authentication_tag():
    key = derive_node_key("secure-key-123")
    payload = b"Original uncorrupted message"
    pkt = encrypt_payload(payload, MediaType.TEXT, "Node-1", "Node-2", key)

    # Tamper with ciphertext by corrupting last byte of base64
    tampered_pkt = dict(pkt)
    chars = list(tampered_pkt["ciphertext_b64"])
    chars[5] = "Z" if chars[5] != "Z" else "A"
    tampered_pkt["ciphertext_b64"] = "".join(chars)

    # Must raise PermissionError on authentication tag mismatch
    with pytest.raises(PermissionError, match="authentication tag verification failed"):
        decrypt_and_verify_payload(tampered_pkt, key)


def test_wrong_key_fails_decryption():
    key1 = derive_node_key("key-one")
    key2 = derive_node_key("key-two")
    payload = b"Secret payload"
    pkt = encrypt_payload(payload, MediaType.TEXT, "Node-1", "Node-2", key1)

    with pytest.raises(PermissionError):
        decrypt_and_verify_payload(pkt, key2)


def test_security_goals_evaluation():
    eval_res = run_full_security_goals_evaluation()
    assert eval_res["confidentiality"]["status"] == "PASS"
    assert eval_res["integrity"]["status"] == "PASS"
    assert eval_res["authentication_and_accountability"]["authentication_status"] == "NOT_MEASURED"
    assert "cpu_usage_percent" in eval_res["performance"]
    assert "ram_resident_set_mb" in eval_res["performance"]
    assert eval_res["performance"]["encryption_throughput_mb_per_sec"] > 0
