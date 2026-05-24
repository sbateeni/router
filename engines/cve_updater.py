import os
import re
import json
from pathlib import Path
from engines.utils import log

def find_nuclei_templates_dir():
    """Locate the nuclei-templates directory on the system."""
    home = str(Path.home())
    possible_paths = [
        os.path.join(home, "nuclei-templates"),
        os.path.join(home, ".local", "nuclei-templates"),
        os.path.join(home, "projectdiscovery", "nuclei-templates"),
        # For Kali
        "/usr/share/nuclei-templates"
    ]
    for p in possible_paths:
        if os.path.exists(p) and os.path.isdir(p):
            return p
    return None

def parse_nuclei_template(filepath):
    """Parse a single nuclei YAML template for CVE intel."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Extract ID
            id_match = re.search(r'^id:\s*([^\s]+)', content, re.MULTILINE)
            if not id_match: return None
            template_id = id_match.group(1).strip()
            
            # Extract Name
            name_match = re.search(r'name:\s*(.+)', content)
            name = name_match.group(1).strip(' "\'') if name_match else template_id
            
            # Extract Severity
            sev_match = re.search(r'severity:\s*([^\s]+)', content)
            severity = sev_match.group(1).strip() if sev_match else "unknown"
            
            # Extract Tags
            tags_match = re.search(r'tags:\s*(.+)', content)
            tags_str = tags_match.group(1).strip(' "\'') if tags_match else ""
            tags = [t.strip() for t in tags_str.split(',') if t.strip()]
            
            return {
                "cve": template_id,
                "title": name,
                "severity": severity,
                "nuclei_templates": [filepath],
                "nuclei_tags": ",".join(tags)
            }
    except Exception:
        return None

def update_cve_database():
    """Scan nuclei-templates and build a JSON database of router/IoT CVEs."""
    templates_dir = find_nuclei_templates_dir()
    if not templates_dir:
        log("Nuclei templates directory not found. Please run 'nuclei -update-templates'.", "ERROR")
        return False
        
    log(f"Scanning Nuclei templates in {templates_dir} for Router/IoT CVEs...", "INFO")
    
    target_tags = {
        # IoT & Routers
        'router', 'iot', 'camera', 'dvr', 'hikvision', 'dahua', 'dlink', 'tplink', 'netis', 'mikrotik', 'zte', 'ubiquiti', 'cisco', 'openwrt',
        # Operating Systems & Services
        'windows', 'linux', 'macos', 'unix', 'ubuntu', 'server', 'smb', 'rdp', 'ssh', 'ftp'
    }
    cves_by_vendor = {}
    
    count = 0
    for root, dirs, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.yaml'):
                filepath = os.path.join(root, file)
                # Quick check before full parse to speed up
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        head = f.read(1024).lower()
                        if not any(tag in head for tag in target_tags):
                            continue
                except:
                    continue
                    
                parsed = parse_nuclei_template(filepath)
                if not parsed: continue
                
                ptags = set(parsed['nuclei_tags'].lower().split(','))
                if ptags.intersection(target_tags):
                    vendor = "GENERIC"
                    
                    # IoT/Routers
                    for v in ['hikvision', 'dahua', 'dlink', 'tplink', 'netis', 'mikrotik', 'zte', 'ubiquiti', 'cisco', 'openwrt']:
                        if v in ptags or v in parsed['title'].lower():
                            vendor = v.upper()
                            break
                            
                    # OS/Systems (If not already matched to IoT)
                    if vendor == "GENERIC":
                        for v in ['windows', 'linux', 'macos', 'unix', 'ubuntu']:
                            if v in ptags or v in parsed['title'].lower():
                                vendor = v.upper()
                                break
                    
                    if vendor not in cves_by_vendor:
                        cves_by_vendor[vendor] = []
                        
                    # Remove absolute path, keep relative for nuclei
                    rel_path = os.path.relpath(filepath, templates_dir)
                    parsed['nuclei_templates'] = [rel_path.replace('\\', '/')]
                    
                    cves_by_vendor[vendor].append(parsed)
                    count += 1

    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(data_dir, exist_ok=True)
    out_file = os.path.join(data_dir, "latest_cves.json")
    
    try:
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(cves_by_vendor, f, indent=4)
        log(f"Successfully extracted {count} CVEs/exploits into {out_file}", "SUCCESS")
        return True
    except Exception as e:
        log(f"Failed to write CVE database: {e}", "ERROR")
        return False

if __name__ == "__main__":
    update_cve_database()
