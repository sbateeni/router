"""Patch RouterSploit wordlists for setuptools 82+ (pkg_resources removed)."""
import os

from core.paths import project_root

PATCHED_CONTENT = """\
from importlib.resources import files


def _wordlist_uri(name):
    return "file://" + str(files(__package__).joinpath(name))


defaults = _wordlist_uri("defaults.txt")
passwords = _wordlist_uri("passwords.txt")
usernames = _wordlist_uri("usernames.txt")
snmp = _wordlist_uri("snmp.txt")
"""


def wordlists_path():
    return os.path.join(
        project_root(),
        "tools",
        "routersploit",
        "routersploit",
        "resources",
        "wordlists",
        "__init__.py",
    )


def patch_routersploit_wordlists():
    path = wordlists_path()
    if not os.path.isfile(path):
        return False
    try:
        with open(path, encoding="utf-8") as fh:
            current = fh.read()
    except OSError:
        return False
    if "importlib.resources" in current and "pkg_resources" not in current:
        return True
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(PATCHED_CONTENT)
    except OSError:
        return False
    return True
