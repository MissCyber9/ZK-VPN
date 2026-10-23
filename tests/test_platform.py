"""Platform layer: paths for every OS, private files, shutdown handling.

The path logic of Linux, macOS and Windows is tested on whichever OS runs the suite;
the file-permission tests act on the real operating system of the runner.
"""

import asyncio
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from zkvpn.platform import LINUX, MACOS, WINDOWS, UnsupportedPlatform, fsperm, paths, system
from zkvpn.platform.process import wait_for_shutdown

ON_WINDOWS = sys.platform == "win32"


def acl_report(path):
    """Diagnostics for a failed ownership assertion (Windows ACL dump; empty elsewhere)."""
    if not ON_WINDOWS:
        return ""
    who = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
    acl = subprocess.run(["icacls", str(path)], capture_output=True, text=True).stdout
    return f"whoami={who!r}\n{acl}"


def make_world_readable(path):
    """Give everybody access, the way a careless user would."""
    if ON_WINDOWS:
        subprocess.run(["icacls", str(path), "/grant", "Everyone:(R)"], capture_output=True, check=True)
    else:
        os.chmod(path, 0o644)


class TestSystemDetection:
    @pytest.mark.parametrize("name,expected", [
        ("linux", LINUX), ("linux2", LINUX), ("darwin", MACOS), ("win32", WINDOWS), ("cygwin", WINDOWS)])
    def test_known_systems(self, name, expected):
        assert system(name) == expected

    def test_unknown_system_is_a_clear_error(self):
        with pytest.raises(UnsupportedPlatform, match="freebsd"):
            system("freebsd14")


class TestPaths:
    ENV = {"PROGRAMDATA": r"C:\ProgramData", "LOCALAPPDATA": r"C:\Users\me\AppData\Local"}

    def test_linux(self):
        assert paths.config_dir("linux", {}) == Path("/etc/zkvpn")
        assert paths.env_file("linux", {}) == Path("/etc/zkvpn/.env")
        assert paths.state_dir("linux", {}) == Path("/run/zkvpn")
        assert paths.wireguard_config_dir("linux", {}) == Path("/etc/wireguard")
        assert paths.data_dir("linux", {"XDG_DATA_HOME": "/xdg"}, home=Path("/h")) == Path("/xdg/zkvpn")
        assert paths.data_dir("linux", {}, home=Path("/h")) == Path("/h/.local/share/zkvpn")

    def test_macos(self):
        assert paths.config_dir("darwin", {}) == Path("/usr/local/etc/zkvpn")
        assert paths.state_dir("darwin", {}) == Path("/var/run/zkvpn")
        assert paths.data_dir("darwin", {}, home=Path("/Users/me")) == \
            Path("/Users/me/Library/Application Support/zkvpn")

    def test_windows(self):
        assert paths.config_dir("win32", self.ENV).name == "zkvpn"
        assert "ProgramData" in str(paths.config_dir("win32", self.ENV))
        assert paths.state_dir("win32", self.ENV).name == "run"
        assert paths.data_dir("win32", self.ENV, home=Path("C:/Users/me")).name == "zkvpn"
        assert "AppData" in str(paths.data_dir("win32", self.ENV))

    def test_windows_without_programdata_has_a_default(self):
        assert "ProgramData" in str(paths.config_dir("win32", {}))

    @pytest.mark.parametrize("fn,var", [(paths.config_dir, "ZKVPN_CONFIG_DIR"), (paths.state_dir, "ZKVPN_STATE_DIR"),
                                        (paths.data_dir, "ZKVPN_DATA_DIR"), (paths.zk_dir, "ZKVPN_ZK_DIR")])
    @pytest.mark.parametrize("name", ["linux", "darwin", "win32"])
    def test_environment_overrides_everywhere(self, fn, var, name):
        assert fn(name, {var: "/custom"}) == Path("/custom")

    def test_zk_dir_default_is_under_the_user_data_dir(self):
        assert paths.zk_dir("linux", {}) == paths.data_dir("linux", {}) / "zk"

    def test_no_posix_only_default_leaks_into_windows(self):
        for fn in (paths.config_dir, paths.state_dir, paths.data_dir, paths.wireguard_config_dir):
            assert not str(fn("win32", self.ENV)).startswith(("/etc", "/run", "/var", "/usr"))


class TestPrivateFiles:
    def test_written_file_is_private(self, tmp_path):
        f = tmp_path / "secret"
        fsperm.write_private_file(f, "s3cret\n")
        assert f.read_text() == "s3cret\n"
        assert fsperm.is_private(f), acl_report(f)

    def test_world_readable_file_is_detected(self, tmp_path):
        f = tmp_path / "secret"
        fsperm.write_private_file(f, "x")
        make_world_readable(f)
        assert not fsperm.is_private(f)
        fsperm.restrict_to_owner(f)
        assert fsperm.is_private(f), acl_report(f)

    def test_exclusive_never_overwrites(self, tmp_path):
        f = tmp_path / "id"
        fsperm.write_private_file(f, "one", exclusive=True)
        with pytest.raises(FileExistsError):
            fsperm.write_private_file(f, "two", exclusive=True)
        assert f.read_text() == "one"

    def test_binary_data_is_written_unchanged(self, tmp_path):
        f = tmp_path / "bin"
        fsperm.write_private_file(f, b"a\r\nb\x00\xff")
        assert f.read_bytes() == b"a\r\nb\x00\xff"

    def test_atomic_replace_keeps_it_private(self, tmp_path):
        f = tmp_path / ".env"
        fsperm.replace_private_file(f, "A=1\n")
        fsperm.replace_private_file(f, "A=2\n")
        assert f.read_text() == "A=2\n"
        assert fsperm.is_private(f), acl_report(f)
        assert not (tmp_path / ".env.tmp").exists()

    def test_private_directory(self, tmp_path):
        d = fsperm.ensure_private_dir(tmp_path / "state" / "sub")
        assert d.is_dir()
        if not ON_WINDOWS:
            assert (d.stat().st_mode & 0o077) == 0

    def test_windows_acl_parsing_is_pure(self):
        out = ("C:\\x\\secret ME\\alice:(F)\n"
               "              NT AUTHORITY\\SYSTEM:(F)\n"
               "              Everyone:(R)\n\nSuccessfully processed 1 files\n")
        assert fsperm._icacls_principals(out, "C:\\x\\secret") == \
            {"ME\\ALICE", "NT AUTHORITY\\SYSTEM", "EVERYONE"}

    def test_identity_files_follow_the_same_rules(self, tmp_path):
        from zkvpn.zk import load_identity, save_identity
        path = str(tmp_path / "id")
        sk = save_identity(path)
        assert load_identity(path) == sk
        with pytest.raises(FileExistsError):
            save_identity(path)
        make_world_readable(path)
        with pytest.raises(PermissionError):
            load_identity(path)


class TestShutdown:
    async def test_interrupt_ends_the_wait(self):
        saved = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        try:
            asyncio.get_running_loop().call_later(0.2, signal.raise_signal, signal.SIGINT)
            await asyncio.wait_for(wait_for_shutdown(), 5)
        finally:
            for s, handler in saved.items():
                signal.signal(s, handler)
