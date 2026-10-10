"""CLI smoke tests (the CLI used to crash on --help)."""

from click.testing import CliRunner

from zkvpn.cli.main import cli


def test_help_lists_commands():
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for name in ("connect", "serve", "identity", "config", "peer", "test", "status"):
        assert name in result.output


def test_subcommands_are_actually_awaited(tmp_path):
    path = str(tmp_path / "id")
    runner = CliRunner()
    result = runner.invoke(cli, ["identity", "new", path])
    assert "never awaited" not in (result.output or "")
    assert (tmp_path / "id").exists()            # coroutine really ran
    again = runner.invoke(cli, ["identity", "new", path])
    assert again.exit_code != 0 and "refusing to overwrite" in again.output


def test_config_set_rejects_unknown_key():
    result = CliRunner().invoke(cli, ["config", "set", "nope", "1"])
    assert result.exit_code == 1
