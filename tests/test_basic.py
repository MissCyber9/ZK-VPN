"""Basic smoke tests: imports must succeed (no ImportError swallowing)."""


def test_import_package():
    import zkvpn
    assert zkvpn.__version__ == "0.1.0"


def test_circuit_source_is_packaged():
    from pathlib import Path
    import zkvpn.circuits
    assert (Path(zkvpn.circuits.__file__).parent / "session_auth.circom").is_file()


def test_cli_structure():
    from zkvpn.cli import main
    assert hasattr(main, "cli")
    assert callable(main.main)
