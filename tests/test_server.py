import os
import platform
import pytest
from mcp_forensic_toolkit.server import file_metadata, scan_syslog, hash_directory, generate_forensic_report

SAFE_BASE = os.getenv("SAFE_BASE", None)

def get_test_path():
    # Try to use SAFE_BASE if set; fallback to relative path
    if SAFE_BASE:
        test_path = os.path.join(SAFE_BASE, "mcp_forensic_toolkit", "server.py")
    else:
        test_path = os.path.join(os.path.dirname(__file__), "..", "mcp_forensic_toolkit", "server.py")
    return os.path.abspath(test_path)

def test_file_metadata_returns_sha256():
    """Check that file_metadata returns a SHA-256 hash for a valid file."""
    test_path = get_test_path()
    if SAFE_BASE and not test_path.startswith(os.path.abspath(SAFE_BASE)):
        pytest.skip(f"Test file path {test_path} is outside SAFE_BASE {SAFE_BASE}")

    assert os.path.exists(test_path), f"Test file not found: {test_path}"

    result = file_metadata(test_path)
    assert isinstance(result, dict), "Expected dict result"
    assert "sha256" in result, f"Missing sha256 hash, got {result}"
    assert len(result["sha256"]) == 64, "Invalid SHA-256 length"
    assert result["sha256"].isalnum(), "Hash should be alphanumeric"

def test_scan_syslog_returns_list():
    """Check that scan_syslog returns a list of strings."""
    result = scan_syslog("error")
    assert isinstance(result, list), "Expected list result"
    assert all(isinstance(line, str) for line in result), "All entries should be strings"

def test_hash_directory_returns_hashes():
    """Check that hash_directory returns file hashes or errors."""
    result = hash_directory(".")
    assert isinstance(result, dict), "Expected dict result"
    assert result, "No files found"
    for path, value in result.items():
        assert isinstance(value, str), f"Expected string hash or error message, got: {value}"

def test_generate_forensic_report_valid_file():
    """Test that the forensic report runs on a known valid file within SAFE_BASE."""
    test_file = get_test_path()
    if SAFE_BASE and not test_file.startswith(os.path.abspath(SAFE_BASE)):
        pytest.skip(f"Test file path {test_file} is outside SAFE_BASE {SAFE_BASE}")

    keyword = "import"
    if platform.system() in ("Darwin", "Linux"):
        report = generate_forensic_report(test_file, keyword)
        assert isinstance(report, dict), "Expected dict output"
        if "error" in report:
            assert isinstance(report["error"], str), "Error message should be a string"
        else:
            assert "filename" in report, "Missing filename in report"
            assert "file_modified_time" in report, "Missing file_modified_time"
            assert "log_hits" in report, "Missing log_hits"
            assert "correlation_found" in report, "Missing correlation_found"