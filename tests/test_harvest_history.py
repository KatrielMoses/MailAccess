from backend.core.harvest_history import load_latest, save_latest
from pathlib import Path


def _root() -> Path:
    root = Path.cwd() / ".tmp" / "harvest_history_test"
    root.mkdir(parents=True, exist_ok=True)
    return root


def test_harvest_history_round_trip():
    payload = {"domain": "acme.org", "emails": [{"email": "alice@acme.org"}]}
    root = _root()
    assert save_latest("acme.org", payload, root=root)
    assert load_latest("acme.org", root=root) == payload


def test_harvest_history_is_fail_soft():
    assert load_latest("missing.org", root=_root()) is None
