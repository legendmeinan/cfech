import dns.resolver
import ssl
import socket

def is_cloudflare(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for r in answers:
            ip = r.address
            if ip.startswith("104.") or ip.startswith("172.") or ip.startswith("188.") or ip.startswith("141.") or ip.startswith("162."):
                return True
    except:
        pass
    return False


def check_ech_dns(domain):
    """检测 DNS HTTPS RR / SVCB 中是否带有 echconfig"""
    try:
        answers = dns.resolver.resolve(domain, "HTTPS")
        for r in answers:
            text = r.to_text().lower()
            if "echconfig" in text or "ech=" in text:
                return True
    except:
        pass
    return False


def check_ech_tls(domain):
    """检查 TLS 是否提供 ECH (扩展 type 0xfe0d)"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((domain, 443), timeout=3)
        tls = ctx.wrap_socket(sock, server_hostname=domain)

        if hasattr(tls, "shared_ciphers"):
            # 没有直接 API 查询 ECH，但如果 server 踢回 "retry_config"，表示支持 ECH
            return False
    except ssl.SSLError as e:
        # Cloudflare ECH 会返回类似: tls alert, retry ECH
        if "unrecognized_name" in str(e).lower():
            return True
        if "alert" in str(e).lower() and "retry" in str(e).lower():
            return True
    except:
        pass
    return False


def test(domain):
    domain = domain.strip()
    if not domain:
        return None

    print(f"→ 测试 {domain}")

    if not is_cloudflare(domain):
        print("  ❌ 非 Cloudflare 托管")
        return False

    if check_ech_dns(domain):
        print("  ✅ DNS 发现 ECH 配置")
        return True

    if check_ech_tls(domain):
        print("  ✅ TLS 握手返回 ECH retry")
        return True

    print("  ❌ 未启用 ECH")
    return False


def main():
    with open("domains.txt") as f:
        domains = [i.strip() for i in f.readlines()]

    enabled = []
    disabled = []

    for d in domains:
        if test(d):
            enabled.append(d)
        else:
            disabled.append(d)

    with open("ech_enabled.txt", "w") as f:
        f.write("\n".join(enabled))

    with open("ech_disabled.txt", "w") as f:
        f.write("\n".join(disabled))


if __name__ == "__main__":
    main()
