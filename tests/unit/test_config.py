"""
Unit tests for the config loader.

Tests cover valid configs, validation errors, and edge cases
including the new bearer/cookie validation added in the review pass.
"""

from pathlib import Path

import pytest
import yaml

from bac_detector.config.loader import load_config

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_config_dict() -> dict:
    """A minimal valid config with two bearer-auth identities and an OpenAPI source."""
    return {
        "target": {
            "base_url": "https://api.example.com",
            "openapi_url": "https://api.example.com/openapi.json",
        },
        "identities": [
            {
                "name": "alice",
                "role": "user",
                "auth_mechanism": "bearer",
                "token": "tok_alice",
                "owned_object_ids": ["1", "2"],
            },
            {
                "name": "bob",
                "role": "admin",
                "auth_mechanism": "bearer",
                "token": "tok_bob",
            },
        ],
    }


@pytest.fixture
def config_file(tmp_path: Path, minimal_config_dict: dict) -> Path:
    """Write minimal config to a temp YAML file and return its path."""
    path = tmp_path / "config.yaml"
    path.write_text(yaml.dump(minimal_config_dict))
    return path


# ---------------------------------------------------------------------------
# Valid config loading
# ---------------------------------------------------------------------------


class TestLoadConfig:
    def test_loads_minimal_config(self, config_file: Path):
        config = load_config(config_file)
        assert config.target.base_url == "https://api.example.com"
        assert len(config.identities) == 2

    def test_identity_profiles_conversion(self, config_file: Path):
        config = load_config(config_file)
        profiles = config.identity_profiles
        assert len(profiles) == 2
        names = [p.name for p in profiles]
        assert "alice" in names
        assert "bob" in names

    def test_effective_api_base_url_fallback(self, config_file: Path):
        config = load_config(config_file)
        assert config.effective_api_base_url == "https://api.example.com"

    def test_effective_api_base_url_override(self, tmp_path: Path, minimal_config_dict: dict):
        minimal_config_dict["target"]["api_base_url"] = "https://api.example.com/v2"
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        config = load_config(path)
        assert config.effective_api_base_url == "https://api.example.com/v2"

    def test_default_throttle_values(self, config_file: Path):
        config = load_config(config_file)
        assert config.throttle.requests_per_second == 2.0
        assert config.throttle.request_budget == 500

    def test_default_safety_read_only(self, config_file: Path):
        config = load_config(config_file)
        assert config.safety.read_only is True
        assert config.safety.dry_run is False

    def test_default_log_config(self, config_file: Path):
        config = load_config(config_file)
        assert config.log_config.level == "INFO"
        assert config.log_config.json_logs is False

    def test_log_config_key_in_yaml(self, tmp_path: Path, minimal_config_dict: dict):
        # Confirm the YAML key is log_config, not logging
        minimal_config_dict["log_config"] = {"level": "DEBUG", "json_logs": True}
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        config = load_config(path)
        assert config.log_config.level == "DEBUG"
        assert config.log_config.json_logs is True

    def test_endpoint_list_path_source(self, tmp_path: Path, minimal_config_dict: dict):
        del minimal_config_dict["target"]["openapi_url"]
        minimal_config_dict["target"]["endpoint_list_path"] = "/tmp/endpoints.txt"
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        config = load_config(path)
        assert config.target.endpoint_list_path == "/tmp/endpoints.txt"

    def test_none_auth_mechanism_accepted(self, tmp_path: Path, minimal_config_dict: dict):
        # Guest identity with no token should be accepted
        minimal_config_dict["identities"].append({
            "name": "guest",
            "role": "guest",
            "auth_mechanism": "none",
        })
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        config = load_config(path)
        assert any(i.name == "guest" for i in config.identities)

    def test_cookie_auth_with_cookies_accepted(self, tmp_path: Path, minimal_config_dict: dict):
        minimal_config_dict["identities"].append({
            "name": "carol",
            "role": "manager",
            "auth_mechanism": "cookie",
            "cookies": {"session": "abc123"},
        })
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        config = load_config(path)
        assert any(i.name == "carol" for i in config.identities)


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


class TestConfigValidationErrors:
    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "does_not_exist.yaml")

    def test_not_a_mapping_raises(self, tmp_path: Path):
        path = tmp_path / "bad.yaml"
        path.write_text("- item1\n- item2\n")
        with pytest.raises(ValueError, match="mapping"):
            load_config(path)

    def test_only_one_identity_rejected(self, tmp_path: Path, minimal_config_dict: dict):
        minimal_config_dict["identities"] = [minimal_config_dict["identities"][0]]
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        with pytest.raises(Exception):
            load_config(path)

    def test_no_discovery_source_rejected(self, tmp_path: Path, minimal_config_dict: dict):
        del minimal_config_dict["target"]["openapi_url"]
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        with pytest.raises(Exception):
            load_config(path)

    def test_write_methods_without_lab_mode_rejected(
        self, tmp_path: Path, minimal_config_dict: dict
    ):
        minimal_config_dict["safety"] = {
            "lab_mode": False,
            "enabled_methods": ["GET", "POST"],
        }
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        with pytest.raises(Exception):
            load_config(path)

    def test_write_methods_with_lab_mode_accepted(
        self, tmp_path: Path, minimal_config_dict: dict
    ):
        minimal_config_dict["safety"] = {
            "lab_mode": True,
            "read_only": False,
            "enabled_methods": ["GET", "POST"],
        }
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        config = load_config(path)
        assert "POST" in config.safety.enabled_methods

    def test_invalid_base_url_rejected(self, tmp_path: Path, minimal_config_dict: dict):
        minimal_config_dict["target"]["base_url"] = "not-a-url"
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        with pytest.raises(Exception):
            load_config(path)

    def test_bearer_without_token_rejected(self, tmp_path: Path, minimal_config_dict: dict):
        # New validation added in review pass
        minimal_config_dict["identities"].append({
            "name": "broken",
            "role": "user",
            "auth_mechanism": "bearer",
            # no token field
        })
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        with pytest.raises(Exception, match="token"):
            load_config(path)

    def test_cookie_without_cookies_rejected(self, tmp_path: Path, minimal_config_dict: dict):
        # New validation added in review pass
        minimal_config_dict["identities"].append({
            "name": "broken",
            "role": "user",
            "auth_mechanism": "cookie",
            # no cookies field
        })
        path = tmp_path / "config.yaml"
        path.write_text(yaml.dump(minimal_config_dict))
        with pytest.raises(Exception, match="cookie"):
            load_config(path)
