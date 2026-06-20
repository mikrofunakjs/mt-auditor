from .utils import (
    info, ok, warn, error, kritikal, section,
    GREEN, RED, YELLOW, CYAN, RST, BOLD
)


def inspect_infrastructure(ip, credentials, services_found):
    section(f"INFRASTRUKTUR INSPECTOR: {ip}")

    cred = credentials[0] if credentials else None
    if not cred:
        error("Butuh kredensial valid.")
        return

    has_api = any(s["port"] in [8728, 8729] for s in services_found)
    if not has_api:
        error("API tidak accessible.")
        return

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

    api = None
    try:
        api = connect(
            host=ip, port=api_port,
            username=cred["username"],
            password=cred["password"],
            timeout=8
        )
    except Exception as e:
        error(f"Gagal konek: {e}")
        return

    check_dns(api)
    check_dhcp(api)
    check_ppp(api)
    check_hotspot(api)
    check_ntp(api)
    check_proxy(api)
    check_interface(api)

    try:
        api.close()
    except Exception:
        pass


def check_dns(api):
    try:
        dns = api("/ip/dns/print")
        for d in dns:
            servers = d.get("servers", "")
            allow_remote = d.get("allow-remote-requests", "no")
            cache_size = d.get("cache-size", "?")

            print(f"\n  {BOLD}DNS Configuration:{RST}")
            print(f"    Servers: {CYAN}{servers}{RST}")
            print(f"    Cache Size: {cache_size}")
            if allow_remote == "yes":
                kritikal(f"    allow-remote-requests = YES — Resiko DNS Amplification Attack!")
            else:
                ok(f"    allow-remote-requests = no (aman)")

            if "8.8.8.8" in servers or "8.8.4.4" in servers:
                info(f"    Menggunakan Google DNS — oke")
            if "1.1.1.1" in servers:
                info(f"    Menggunakan Cloudflare DNS — oke")
    except Exception as e:
        warn(f"Gagal baca DNS: {e}")


def check_dhcp(api):
    try:
        dhcp_servers = api("/ip/dhcp-server/print")
        dhcp_networks = api("/ip/dhcp-server/network/print")
        dhcp_leases = api("/ip/dhcp-server/lease/print")

        print(f"\n  {BOLD}DHCP Configuration:{RST}")
        print(f"    DHCP Servers: {len(dhcp_servers)}")
        for ds in dhcp_servers:
            name = ds.get("name", "?")
            iface = ds.get("interface", "?")
            disabled = ds.get("disabled", "true")
            status = f"{GREEN}active{RST}" if disabled != "true" else f"{RED}disabled{RST}"
            print(f"      {name} ({iface}) -> {status}")

        print(f"    DHCP Networks: {len(dhcp_networks)}")
        for dn in dhcp_networks:
            addr = dn.get("address", "?")
            gw = dn.get("gateway", "?")
            print(f"      Network: {addr} | Gateway: {gw}")

        print(f"    Active Leases: {len(dhcp_leases)}")
        for dl in dhcp_leases[:5]:
            mac = dl.get("mac-address", "?")
            addr = dl.get("address", "?")
            host = dl.get("host-name", "?")
            print(f"      {YELLOW}{addr:<15}{RST} {mac:<20} {host}")
        if len(dhcp_leases) > 5:
            print(f"      ... dan {len(dhcp_leases) - 5} lease lainnya")

    except Exception as e:
        warn(f"Gagal baca DHCP: {e}")


def check_ppp(api):
    try:
        ppp_secrets = api("/ppp/secret/print")
        if ppp_secrets:
            print(f"\n  {BOLD}PPP Secrets (VPN/PPPoE Users):{RST}")
            for p in ppp_secrets:
                name = p.get("name", "?")
                service = p.get("service", "any")
                profile = p.get("profile", "?")
                print(f"    {CYAN}User: {name:<15}{RST} Service: {service:<10} Profile: {profile}")

        ppp_active = api("/ppp/active/print")
        if ppp_active:
            print(f"\n  {BOLD}PPP Active Connections:{RST}")
            for p in ppp_active:
                name = p.get("name", "?")
                addr = p.get("address", "?")
                uptime = p.get("uptime", "?")
                print(f"    {name} | IP: {addr} | Uptime: {uptime}")
    except Exception:
        pass


def check_hotspot(api):
    try:
        hotspot_users = api("/ip/hotspot/user/print")
        if hotspot_users:
            print(f"\n  {BOLD}Hotspot Users: {len(hotspot_users)}{RST}")
            for h in hotspot_users[:10]:
                name = h.get("name", "?")
                profile = h.get("profile", "?")
                disabled = h.get("disabled", "true")
                status = f"{GREEN}active{RST}" if disabled != "true" else f"{RED}disabled{RST}"
                print(f"    {name:<20} Profile: {profile:<10} -> {status}")
            if len(hotspot_users) > 10:
                print(f"    ... dan {len(hotspot_users) - 10} user lainnya")
    except Exception:
        pass


def check_ntp(api):
    try:
        ntp_client = api("/system/ntp/client/print")
        for n in ntp_client:
            enabled = n.get("enabled", "no")
            mode = n.get("mode", "?")
            servers = n.get("server-dns-names", n.get("primary-ntp", "?"))
            if enabled == "yes":
                info(f"NTP Client aktif: {servers} (mode: {mode})")
    except Exception:
        pass


def check_proxy(api):
    try:
        proxy = api("/ip/proxy/print")
        for p in proxy:
            enabled = p.get("enabled", "no")
            port = p.get("port", "?")
            if enabled == "yes":
                warn(f"Web Proxy aktif di port {port}! Bisa disalahgunakan.")
    except Exception:
        pass


def check_interface(api):
    try:
        interfaces = api("/interface/print")
        print(f"\n  {BOLD}Network Interfaces:{RST}")
        for iface in interfaces:
            name = iface.get("name", "?")
            type_ = iface.get("type", "?")
            mac = iface.get("mac-address", "?")
            running = iface.get("running", "no")
            status = f"{GREEN}up{RST}" if running == "true" else f"{RED}down{RST}"
            print(f"    {name:<15} {type_:<12} {mac:<20} {status}")
    except Exception:
        pass
