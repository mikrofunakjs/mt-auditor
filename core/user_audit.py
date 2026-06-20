from .utils import (
    info, ok, warn, error, kritikal, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD
)


def audit_users(ip, credentials, services_found):
    section(f"USER AUDIT: {ip}")

    cred = credentials[0] if credentials else None
    if not cred:
        error("Butuh kredensial valid.")
        return []

    has_api = any(s["port"] in [8728, 8729] for s in services_found)
    if not has_api:
        error("API tidak accessible.")
        return []

    try:
        from librouteros import connect
    except ImportError:
        error("librouteros tidak terinstall.")
        return []

    api_port = 8728
    for s in services_found:
        if s["port"] in [8728, 8729]:
            api_port = s["port"]
            break

    try:
        api = connect(
            host=ip, port=api_port,
            username=cred["username"],
            password=cred["password"],
            timeout=8
        )
    except Exception as e:
        error(f"Gagal konek: {e}")
        return []

    findings = []

    try:
        users = api("/user/print")
        info(f"Total user: {len(users)}")

        weak_passwords = ["", "admin", "1234", "12345", "123456", "password", "pass", "qwerty"]

        for u in users:
            name = u.get("name", "?")
            group = u.get("group", "?")
            disabled = u.get("disabled", "true")
            comment = u.get("comment", "")

            is_active = disabled != "true"
            is_full = group == "full"

            row = {
                "name": name,
                "group": group,
                "active": is_active,
                "issues": [],
            }

            print(f"\n  {CYAN}{BOLD}User: {name}{RST}")
            print(f"    Group: {group} | Active: {is_active} | Comment: {comment}")

            if is_full and is_active:
                row["issues"].append("User dengan group 'full' — akses penuh!")
                warn(f"    [!] Group 'full' — user ini bisa apa saja!")

            if name == "admin" and group == "full":
                pass

            if name in ("support", "user", "test", "guest") and is_full:
                row["issues"].append(f"User '{name}' punya akses full — tidak perlu!")
                warn(f"    [!] User '{name}' tidak seharusnya punya group 'full'")

            if is_full:
                try:
                    passwd = api("/user", "get", name=name, attribute="password")
                    if passwd:
                        pwd = passwd[0].get("ret", "")
                        if pwd == "":
                            row["issues"].append("PASSWORD KOSONG!")
                            kritikal(f"    [!!] PASSWORD KOSONG!")
                        elif pwd.lower() in weak_passwords:
                            row["issues"].append(f"Password lemah: '{pwd}'")
                            warn(f"    [!] Password lemah: '{pwd}'")
                except Exception:
                    pass

            findings.append(row)

    except Exception as e:
        error(f"Gagal audit user: {e}")

    try:
        api.close()
    except Exception:
        pass

    return findings


def check_active_sessions(ip, credentials, services_found):
    section(f"ACTIVE SESSIONS: {ip}")

    cred = credentials[0] if credentials else None
    if not cred:
        return

    try:
        from librouteros import connect
    except ImportError:
        return

    api_port = 8728
    for s in services_found:
        if s["port"] in [8728, 8729]:
            api_port = s["port"]
            break

    try:
        api = connect(
            host=ip, port=api_port,
            username=cred["username"],
            password=cred["password"],
            timeout=8
        )
    except Exception:
        return

    try:
        sessions = api("/user/active/print")
        info(f"Session aktif: {len(sessions)}")
        for s in sessions:
            user = s.get("name", "?")
            via = s.get("via", "?")
            addr = s.get("address", "?")
            uptime = s.get("when", "?")
            print(f"  {YELLOW}User: {user:<15} Via: {via:<10} From: {addr:<18} Uptime: {uptime}{RST}")
    except Exception as e:
        warn(f"Gagal baca session: {e}")

    try:
        api.close()
    except Exception:
        pass
