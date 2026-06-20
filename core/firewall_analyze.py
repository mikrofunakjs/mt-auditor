from .utils import (
    info, ok, warn, error, kritikal, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD
)


def analyze_firewall(ip, credentials, services_found):
    section(f"FIREWALL ANALYZER: {ip}")

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
        filter_rules = api("/ip/firewall/filter/print")
        info(f"Firewall filter rules: {len(filter_rules)}")

        has_input_drop = False
        has_wan_block = False
        has_established = False
        wan_accept_rules = []

        for rule in filter_rules:
            chain = rule.get("chain", "")
            action = rule.get("action", "")
            in_iface = rule.get("in-interface", "")
            dst_port = rule.get("dst-port", "")
            comment = rule.get("comment", "")

            if chain == "input" and action == "drop":
                has_input_drop = True
            if chain == "input" and "ether1" in in_iface and action == "drop":
                has_wan_block = True
            if "established" in str(rule).lower() and action == "accept":
                has_established = True
            if chain == "input" and action == "accept" and "ether1" in in_iface:
                wan_accept_rules.append(rule)

        if not has_input_drop:
            findings.append({
                "severity": "KRITIS",
                "msg": "Tidak ada DROP rule di INPUT chain! Semua traffic dari WAN diterima!",
            })
            kritikal("Tidak ada DROP rule di INPUT chain!")

        if wan_accept_rules:
            findings.append({
                "severity": "WARNING",
                "msg": f"Ada {len(wan_accept_rules)} ACCEPT rule dari WAN di INPUT chain.",
            })
            warn(f"Ada {len(wan_accept_rules)} ACCEPT rule dari WAN di INPUT chain.")

        if not has_established:
            findings.append({
                "severity": "WARNING",
                "msg": "Tidak ada rule 'established/related' — koneksi balik tidak difilter.",
            })
            warn("Rule 'established/related' tidak ditemukan.")

        print()
        info("Ringkasan Firewall Filter:")
        chains = {}
        for rule in filter_rules:
            c = rule.get("chain", "other")
            chains[c] = chains.get(c, 0) + 1
        for chain, count in chains.items():
            print(f"  Chain {CYAN}{chain:<10}{RST} : {count} rules")

    except Exception as e:
        warn(f"Gagal baca filter rules: {e}")

    try:
        nat_rules = api("/ip/firewall/nat/print")
        info(f"NAT rules: {len(nat_rules)}")
        has_masq = any(r.get("action") == "masquerade" for r in nat_rules)
        if not has_masq:
            findings.append({
                "severity": "WARNING",
                "msg": "Tidak ada masquerade — client lokal mungkin tidak bisa internet.",
            })
    except Exception:
        pass

    try:
        api.close()
    except Exception:
        pass

    return findings
