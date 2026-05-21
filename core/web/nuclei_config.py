import glob
import os
import shutil

from core.utils import TOOLS_DIR, valid_env_value

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CUSTOM_TEMPLATES = os.path.join(REPO_ROOT, "templates", "nuclei", "custom")

# Router / camera focused tags (from official templates + auto-pwn useful subset)
ROUTER_NUCLEI_TAGS = "default-logins,cves,misconfiguration,exposed-panel,hikvision,upnp,rce,zte"

LOCAL_NUCLEI_BINS = (
    os.path.join(TOOLS_DIR, "nuclei", "nuclei.exe"),
    os.path.join(TOOLS_DIR, "nuclei", "nuclei"),
)


def resolve_nuclei_cmd():
    env_path = os.environ.get("NUCLEI_PATH", "").strip()
    if valid_env_value(env_path) and os.path.isfile(env_path):
        return os.path.abspath(env_path)
    for path in LOCAL_NUCLEI_BINS:
        if os.path.isfile(path):
            return path
    return shutil.which("nuclei") or "nuclei"


def custom_template_dir():
    if os.path.isdir(CUSTOM_TEMPLATES) and _dir_has_yaml(CUSTOM_TEMPLATES):
        return os.path.abspath(CUSTOM_TEMPLATES)
    return None


def nuclei_tags_for_profile(profile):
    if profile.get("nuclei_all_templates"):
        return None
    override = os.environ.get("NUCLEI_TAGS", "").strip()
    if valid_env_value(override):
        return override
    return ROUTER_NUCLEI_TAGS


def build_nuclei_base_cmd(target_url):
    cmd = [resolve_nuclei_cmd(), "-u", target_url, "-no-color"]
    custom = custom_template_dir()
    if custom:
        cmd.extend(["-t", custom])
    return cmd


def _dir_has_yaml(path):
    return any(glob.glob(os.path.join(path, "**", "*.yaml"), recursive=True))
