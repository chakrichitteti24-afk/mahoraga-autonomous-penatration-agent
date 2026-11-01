import pytest
import tempfile
from pathlib import Path

from cipherflux.storage.target_store import TargetStore, TargetItem, TargetType

@pytest.fixture
def temp_target_store():
    with tempfile.TemporaryDirectory() as tmpdir:
        store = TargetStore(storage_dir=tmpdir)
        yield store

def test_target_validation_url(temp_target_store):
    # Valid URL
    valid, msg, meta = temp_target_store.validate_target("https://secure.lab:8443", TargetType.URL)
    assert valid is True
    assert meta["hostname"] == "secure.lab"
    assert meta["port"] == 8443

    # Invalid URL scheme
    valid, msg, _ = temp_target_store.validate_target("ftp://invalid.lab", TargetType.URL)
    assert valid is False

def test_target_validation_blocks_cloud_metadata(temp_target_store):
    # Direct IP metadata block
    valid, msg, _ = temp_target_store.validate_target("http://169.254.169.254/latest/meta-data/", TargetType.URL)
    assert valid is False
    assert "cloud metadata" in msg.lower() or "blocked" in msg.lower()

    # Domain metadata block
    valid, msg, _ = temp_target_store.validate_target("metadata.google.internal", TargetType.DOMAIN)
    assert valid is False
    assert "prohibited" in msg.lower()

def test_target_validation_ip_and_cidr(temp_target_store):
    # Valid IP
    valid, msg, meta = temp_target_store.validate_target("192.168.1.10", TargetType.IP)
    assert valid is True
    assert meta["is_private"] is True

    # Invalid IP
    valid, msg, _ = temp_target_store.validate_target("999.999.999.999", TargetType.IP)
    assert valid is False

    # Valid CIDR
    valid, msg, meta = temp_target_store.validate_target("10.0.0.0/24", TargetType.CIDR)
    assert valid is True
    assert meta["num_addresses"] == 256

    # Overly large CIDR (> 65536)
    valid, msg, _ = temp_target_store.validate_target("10.0.0.0/8", TargetType.CIDR)
    assert valid is False

def test_target_crud_operations(temp_target_store):
    t = TargetItem(
        id="tgt-test-1",
        name="Staging Ingress",
        target_type=TargetType.URL,
        value="https://staging.lab",
        authorized=True,
        authorized_by="Lead Security Auditor",
    )
    temp_target_store.add_target(t)

    retrieved = temp_target_store.get_target("tgt-test-1")
    assert retrieved is not None
    assert retrieved.name == "Staging Ingress"
    assert retrieved.authorized is True

    # Scope check
    in_scope, scope_msg, item = temp_target_store.check_scope("https://staging.lab")
    assert in_scope is True
    assert item.id == "tgt-test-1"

    # Out of scope check
    out_scope, out_msg, _ = temp_target_store.check_scope("https://unauthorized.org")
    assert out_scope is False

    # Remove
    assert temp_target_store.remove_target("tgt-test-1") is True
    assert temp_target_store.get_target("tgt-test-1") is None

def test_target_import_export_json_csv(temp_target_store, tmp_path):
    t1 = TargetItem(id="t1", name="Target One", target_type=TargetType.URL, value="https://app1.lab", authorized=True)
    t2 = TargetItem(id="t2", name="Target Two", target_type=TargetType.IP, value="192.168.1.1", authorized=False)
    temp_target_store.add_target(t1)
    temp_target_store.add_target(t2)

    # JSON Export & Import
    json_path = tmp_path / "targets.json"
    temp_target_store.export_json(str(json_path))
    assert json_path.exists()

    expected_count = len(temp_target_store.list_targets())
    new_store = TargetStore(storage_dir=str(tmp_path / "new_store"))
    imported_count = new_store.import_json(str(json_path))
    assert imported_count == expected_count
    assert new_store.get_target("t1") is not None

    # CSV Export & Import
    csv_path = tmp_path / "targets.csv"
    temp_target_store.export_csv(str(csv_path))
    assert csv_path.exists()

    csv_store = TargetStore(storage_dir=str(tmp_path / "csv_store"))
    imported_csv = csv_store.import_csv(str(csv_path))
    assert imported_csv == expected_count
    assert csv_store.get_target("t1").value == "https://app1.lab"
