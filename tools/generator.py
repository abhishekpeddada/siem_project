#!/usr/bin/env python3
"""
Generate logs that match the YARA rules in rules/*.yar:
- Brute force: many AUTH_FAIL from same IP in short window -> triggers threshold=5
- DoS (SYN_FLOOD): many TRAFFIC_DENY lines from same src_ip quickly -> triggers threshold=10
- Phish: suspicious EMAIL_RECEIVED, EMAIL_CLICK, EMAIL_ALERT entries

Writes files into ./logs/.
"""
import os, time, random, datetime

OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
os.makedirs(OUT_DIR, exist_ok=True)

def now(offset_sec=0):
    return (datetime.datetime.utcnow() + datetime.timedelta(seconds=offset_sec)).strftime('%Y-%m-%d %H:%M:%S')

def write_lines(path, lines):
    with open(path, 'a', encoding='utf-8') as f:
        for l in lines:
            f.write(l + '\n')

def gen_bruteforce_file(path, ip='185.22.56.12', user='admin', attempts=7):
    """
    Produce (attempts-1) AUTH_FAIL lines and one AUTH_SUCCESS at end.
    Threshold in rule = 5 within 60s -> produce 6 fails to trigger.
    """
    base = []
    ts0 = datetime.datetime.utcnow()
    for i in range(attempts):
        ts = (ts0 + datetime.timedelta(seconds=i*5)).strftime('%Y-%m-%d %H:%M:%S')
        if i < attempts - 1:
            base.append(f"{ts} AUTH_FAIL user={user} src_ip={ip} dst_ip=10.0.0.5 reason=invalid_password")
        else:
            base.append(f"{ts} AUTH_SUCCESS user={user} src_ip={ip} dst_ip=10.0.0.5")
    write_lines(path, base)
    print(f"Wrote {len(base)} lines to {path}")

def gen_dos_file(path, ip='202.44.112.9', bursts=15):
    """
    Produce 'bursts' of TRAFFIC_DENY lines in tight interval to exceed threshold=10 in 10s.
    """
    base = []
    ts0 = datetime.datetime.utcnow()
    # put them within a 10 second span (some micro-seconds apart)
    for i in range(bursts):
        ts = (ts0 + datetime.timedelta(seconds=(i//5))).strftime('%Y-%m-%d %H:%M:%S')
        base.append(f"{ts} TRAFFIC_DENY src_ip={ip} dst_ip=10.0.0.8 dst_port=443 protocol=TCP reason=SYN_FLOOD")
    write_lines(path, base)
    print(f"Wrote {len(base)} lines to {path}")

def gen_phish_file(path):
    """
    Produce one EMAIL_RECEIVED from suspicious domain, one EMAIL_CLICK and EMAIL_ALERT.
    rule threshold=1 -> triggers immediately.
    """
    base = []
    ts0 = datetime.datetime.utcnow()
    t1 = ts0.strftime('%Y-%m-%d %H:%M:%S')
    base.append(f'{t1} EMAIL_RECEIVED from="it-support@secure-microsoft-login.com" to="employee1@company.com" subject="Password Reset Required" action=delivered')
    # click 30s later
    t2 = (ts0 + datetime.timedelta(seconds=30)).strftime('%Y-%m-%d %H:%M:%S')
    base.append(f'{t2} EMAIL_CLICK user=employee1@company.com link="http://secure-microsoft-login.com/reset"')
    # email alert 60s later
    t3 = (ts0 + datetime.timedelta(seconds=60)).strftime('%Y-%m-%d %H:%M:%S')
    base.append(f'{t3} EMAIL_ALERT user=employee1@company.com detection=phishing domain="secure-microsoft-login.com"')
    write_lines(path, base)
    print(f"Wrote {len(base)} lines to {path}")

def gen_mixed_file(path):
    """
    Mixed file with other IPs and noise so you have non-triggering events too.
    """
    base = []
    ts0 = datetime.datetime.utcnow()
    # Random normal log lines
    for i in range(10):
        ts = (ts0 + datetime.timedelta(seconds=i*10)).strftime('%Y-%m-%d %H:%M:%S')
        ip = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
        base.append(f"{ts} INFO ServiceHeartbeat host=svc-{i} ip={ip} status=ok")
    # some failed logins from other IPs (below threshold)
    for i in range(3):
        ts = (ts0 + datetime.timedelta(seconds=5 + i*7)).strftime('%Y-%m-%d %H:%M:%S')
        base.append(f"{ts} AUTH_FAIL user=user{i} src_ip=198.51.100.{10+i} dst_ip=10.0.0.5 reason=invalid_password")
    write_lines(path, base)
    print(f"Wrote {len(base)} lines to {path}")

if __name__ == "__main__":
    # file paths
    bf = os.path.join(OUT_DIR, 'bruteforce.log')
    dos = os.path.join(OUT_DIR, 'dos.log')
    ph = os.path.join(OUT_DIR, 'phish_email.log')
    mix = os.path.join(OUT_DIR, 'mixed.log')

    # generate
    gen_bruteforce_file(bf, ip='185.22.56.12', user='admin', attempts=7)
    time.sleep(0.2)
    gen_dos_file(dos, ip='202.44.112.9', bursts=15)
    time.sleep(0.2)
    gen_phish_file(ph)
    time.sleep(0.2)
    gen_mixed_file(mix)

    print("Done. Now POST to /ingest or click Ingest in the UI to process these logs.")
