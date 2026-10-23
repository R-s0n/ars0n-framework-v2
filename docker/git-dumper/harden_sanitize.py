"""Build-time hardening of git-dumper 1.0.9's sanitize_file(), then a self-test.

git-dumper comments out "unsafe" keys in the downloaded .git/config before it runs `git checkout .`,
but its pattern `^\\s*fsmonitor|sshcommand|...` has no MULTILINE flag, so `^` only matches the start
of the file and an ordinary indented `fsmonitor = ...` line survives (upstream issue #42). It also
leaves out other keys that make git run a program or touch files outside the repository.

The replacement drops the anchor entirely, as upstream already does for its other keywords: every
occurrence of a listed word gets "# " inserted before it, so the rest of that line is a comment. That
also covers a key written on the same line as its section header ("[core] fsmonitor = ..."). Values
that merely contain a word (a URL with "path" in it) are truncated, which is harmless; a config this
turns invalid makes git refuse to run, which fails closed.

Fails the build if the upstream line is not found exactly once, so a changed wheel cannot silently
skip the patch.
"""
import importlib.util
import os
import pathlib
import subprocess
import tempfile

OLD = '    UNSAFE=r"^\\s*fsmonitor|sshcommand|askpass|editor|pager"\n'
NEW = (
    '    UNSAFE=r"(fsmonitor|sshcommand|askpass|editor|pager|hookspath|worktree|gitproxy|smudge|'
    'clean|process|textconv|program|external|helper|command|path)"\n'
)

path = pathlib.Path(importlib.util.find_spec("git_dumper").origin)
source = path.read_text()
assert source.count(OLD) == 1, "git_dumper.sanitize_file no longer matches the reviewed 1.0.9 source"
path.write_text(source.replace(OLD, NEW))

# Self-test against the patched module: every key below must be gone as far as git itself is
# concerned. Values are inert placeholders.
import git_dumper  # noqa: E402  (imported after patching on purpose)

sample = (
    "[core]\n"
    "\tfsmonitor = x\n"
    "  hooksPath = x\n"
    "\tworktree = x\n"
    "\tsshCommand = x\n"
    "\tpager = x\n"
    "[core] fsMonitor = x\n"
    '[filter "f"]\n'
    "\tsmudge = x\n"
    "\tclean = x\n"
    "\tprocess = x\n"
    '[diff "d"]\n'
    "\ttextconv = x\n"
    "[gpg]\n"
    "\tprogram = x\n"
    "[include]\n"
    "\tpath = x\n"
)
with tempfile.TemporaryDirectory() as tmp:
    config = os.path.join(tmp, "config")
    with open(config, "w") as f:
        f.write(sample)
    git_dumper.sanitize_file(config)
    listed = subprocess.run(
        ["git", "config", "--file", config, "--list"],
        capture_output=True, text=True, check=True,
    ).stdout
assert listed.strip() == "", "sanitize_file left keys active:\n" + listed
print("git-dumper sanitize_file hardened and self-tested")
