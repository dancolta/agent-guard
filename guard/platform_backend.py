"""Per-OS primitives: modal dialog, time-boxed grant store, file locking.

Selected at import by `backend()`. Each back-end degrades safely: no GUI
(ssh / headless) -> ask() returns "deny" so guarded actions fail closed.
The grant store keeps prompt-injected *tool calls* from re-granting; it is
not a barrier against a shell running as the same user (documented).
"""
import os
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
GRANT_SECONDS = 30 * 60


class _Base:
    name = "base"

    def ask(self, title, body, deny_label, allow_label, timeout):
        """Return 'allow' | 'deny' | 'timeout'."""
        return "deny"

    def alarm(self, title, body, keep_label, unfreeze_label, on_unfreeze_path):
        """Show a non-blocking alarm; if the user picks unfreeze, delete on_unfreeze_path."""

    def grant_get(self, sid):
        return False

    def grant_set(self, sid):
        pass

    def grant_clear_all(self):
        pass

    def lock(self, paths):
        pass

    def unlock(self, paths):
        pass


# ---------------------------------------------------------------- macOS
class _MacOS(_Base):
    name = "macos"
    KC = "agent-guard-unlock"

    def _osa(self, script, detach=False, timeout=None):
        try:
            if detach:
                p = subprocess.Popen(["/usr/bin/osascript", "-"], stdin=subprocess.PIPE,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
                p.stdin.write(script.encode("utf-8"))
                p.stdin.close()
                return ""
            r = subprocess.run(["/usr/bin/osascript", "-"], input=script,
                               capture_output=True, text=True, timeout=timeout)
            return r.stdout
        except Exception:
            return ""

    @staticmethod
    def _q(s):
        return s.replace("\\", "/").replace('"', "'")

    def ask(self, title, body, deny_label, allow_label, timeout):
        script = (
            f'display dialog "{self._q(body)}" with title "{self._q(title)}" '
            f'buttons {{"{deny_label}", "{allow_label}"}} default button "{deny_label}" '
            f'with icon caution giving up after {timeout}\n')
        out = self._osa(script, timeout=timeout + 10)
        if "gave up:true" in out:
            return "timeout"
        return "allow" if f"button returned:{allow_label}" in out else "deny"

    def alarm(self, title, body, keep_label, unfreeze_label, on_unfreeze_path):
        script = (
            f'set r to display dialog "{self._q(body)}" with title "{self._q(title)}" '
            f'buttons {{"{keep_label}", "{unfreeze_label}"}} default button "{keep_label}" '
            'with icon stop\n'
            f'if button returned of r is "{unfreeze_label}" then do shell script '
            f'"rm -f " & quoted form of "{on_unfreeze_path}"\n')
        self._osa(script, detach=True)

    def _sec(self, args):
        return subprocess.run(["/usr/bin/security"] + args, capture_output=True,
                              text=True, timeout=10, stdin=subprocess.DEVNULL)

    def grant_get(self, sid):
        try:
            r = self._sec(["find-generic-password", "-s", self.KC, "-a", sid, "-w"])
            return r.returncode == 0 and 0 <= time.time() - float(r.stdout.strip()) < GRANT_SECONDS
        except Exception:
            return False

    def grant_set(self, sid):
        try:
            self._sec(["add-generic-password", "-U", "-s", self.KC, "-a", sid, "-w", str(time.time())])
        except Exception:
            pass

    def grant_clear_all(self):
        try:
            self._sec(["delete-generic-password", "-s", self.KC])
        except Exception:
            pass

    def lock(self, paths):
        self._chflags("uchg", paths)

    def unlock(self, paths):
        self._chflags("nouchg", paths)

    @staticmethod
    def _chflags(flag, paths):
        paths = [p for p in paths if os.path.exists(p)]
        if paths:
            subprocess.run(["/usr/bin/chflags", flag] + paths, capture_output=True, check=False)


# --------------------------------------------------------------- Windows
class _Windows(_Base):
    name = "windows"

    def _ps(self, script, detach=False, timeout=None):
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
        try:
            if detach:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=0x00000008)  # DETACHED_PROCESS
                return ""
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip()
        except Exception:
            return ""

    @staticmethod
    def _q(s):
        return s.replace("`", "``").replace('"', '`"').replace("$", "`$")

    def ask(self, title, body, deny_label, allow_label, timeout):
        # MessageBox YesNo: Yes = allow. No timeout arg on MessageBox; rely on the
        # hook's own timeout wrapper via subprocess timeout below.
        script = (
            'Add-Type -AssemblyName PresentationFramework;'
            f'$r=[System.Windows.MessageBox]::Show("{self._q(body)}","{self._q(title)}",4,48);'
            'if($r -eq "Yes"){"allow"}else{"deny"}')
        out = self._ps(script, timeout=timeout + 10)
        if out == "allow":
            return "allow"
        return "deny"

    def alarm(self, title, body, keep_label, unfreeze_label, on_unfreeze_path):
        p = on_unfreeze_path.replace("'", "''")
        script = (
            'Add-Type -AssemblyName PresentationFramework;'
            f'$r=[System.Windows.MessageBox]::Show("{self._q(body)}`n`nYes = Unfreeze, '
            f'No = Keep frozen","{self._q(title)}",4,16);'
            f"if($r -eq 'Yes'){{Remove-Item -LiteralPath '{p}' -Force -ErrorAction SilentlyContinue}}")
        self._ps(script, detach=True)

    def _grant_file(self, sid):
        return os.path.join(HOME, ".claude", "guard", "grants", sid)

    def grant_get(self, sid):
        try:
            with open(self._grant_file(sid), encoding="utf-8") as f:
                return 0 <= time.time() - float(f.read().strip()) < GRANT_SECONDS
        except Exception:
            return False

    def grant_set(self, sid):
        try:
            d = os.path.dirname(self._grant_file(sid))
            os.makedirs(d, exist_ok=True)
            with open(self._grant_file(sid), "w", encoding="utf-8") as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def grant_clear_all(self):
        import shutil
        shutil.rmtree(os.path.join(HOME, ".claude", "guard", "grants"), ignore_errors=True)

    def lock(self, paths):
        for p in paths:
            if os.path.exists(p):
                subprocess.run(["attrib", "+R", p], capture_output=True, check=False)

    def unlock(self, paths):
        for p in paths:
            if os.path.exists(p):
                subprocess.run(["attrib", "-R", p], capture_output=True, check=False)


# ----------------------------------------------------------------- Linux
class _Linux(_Base):
    name = "linux"

    def _tool(self):
        from shutil import which
        for t in ("zenity", "kdialog"):
            if which(t):
                return t
        return None

    def ask(self, title, body, deny_label, allow_label, timeout):
        t = self._tool()
        try:
            if t == "zenity":
                r = subprocess.run(
                    ["zenity", "--question", "--title", title, "--text", body,
                     "--ok-label", allow_label, "--cancel-label", deny_label,
                     f"--timeout={timeout}"], capture_output=True, timeout=timeout + 10)
                return "allow" if r.returncode == 0 else "deny"
            if t == "kdialog":
                r = subprocess.run(["kdialog", "--title", title, "--yesno", body],
                                   capture_output=True, timeout=timeout + 10)
                return "allow" if r.returncode == 0 else "deny"
        except Exception:
            return "deny"
        return "deny"  # headless -> fail closed

    def alarm(self, title, body, keep_label, unfreeze_label, on_unfreeze_path):
        t = self._tool()
        if not t:
            return
        try:
            if t == "zenity":
                subprocess.Popen(
                    ["sh", "-c",
                     f'zenity --question --title "{title}" --text "{body}" '
                     f'--ok-label "{unfreeze_label}" --cancel-label "{keep_label}" '
                     f'&& rm -f "{on_unfreeze_path}"'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            else:
                subprocess.Popen(
                    ["sh", "-c",
                     f'kdialog --yesno "{body}" --title "{title}" && rm -f "{on_unfreeze_path}"'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except Exception:
            pass

    def _grant_file(self, sid):
        return os.path.join(HOME, ".claude", "guard", "grants", sid)

    def grant_get(self, sid):
        try:
            with open(self._grant_file(sid), encoding="utf-8") as f:
                return 0 <= time.time() - float(f.read().strip()) < GRANT_SECONDS
        except Exception:
            return False

    def grant_set(self, sid):
        try:
            d = os.path.dirname(self._grant_file(sid))
            os.makedirs(d, mode=0o700, exist_ok=True)
            fd = os.open(self._grant_file(sid), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def grant_clear_all(self):
        import shutil
        shutil.rmtree(os.path.join(HOME, ".claude", "guard", "grants"), ignore_errors=True)

    def lock(self, paths):
        subprocess.run(["chmod", "0500"] + [p for p in paths if os.path.exists(p)],
                       capture_output=True, check=False)

    def unlock(self, paths):
        subprocess.run(["chmod", "0700"] + [p for p in paths if os.path.exists(p)],
                       capture_output=True, check=False)


_CACHE = None


def backend():
    global _CACHE
    if _CACHE is None:
        if sys.platform == "darwin":
            _CACHE = _MacOS()
        elif os.name == "nt" or sys.platform.startswith("win"):
            _CACHE = _Windows()
        else:
            _CACHE = _Linux()
    return _CACHE
