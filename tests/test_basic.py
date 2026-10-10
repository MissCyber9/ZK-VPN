"""Basic smoke tests: imports must succeed (no ImportError swallowing)."""


def test_import_package():
    import zkvpn
    assert zkvpn.__version__ == "0.1.0"


def test_circuits_module():
    from zkvpn.circuits import no_logging
    assert no_logging.NoLoggingCircuit().circuit_id == "no_logging_v1"


def test_cli_structure():
    from zkvpn.cli import main
    assert hasattr(main, "cli")
    assert callable(main.main)
