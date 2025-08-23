#!/usr/bin/env python3
"""
Generate sample logs into ./logs/ for bruteforce, dos, and phish scenarios.
Run: python tools/generate_logs.py
"""
import os, random, time, datetime

OUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'logs')
os.makedirs(OUT_DIR, exist_ok=True)

def now():
    return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

def gen_bruteforce(filepath, ip='185.22.56.12', user='admin', attempts=8):
    with open(filepath, 'a') as f:
        for i in range(attempts):
            t = now()
            if i == attempts-1:
                f.write(f"{t} AUTH_SUCCESS user={user} src_ip={ip} dst_ip=10.0.0.5\\n")
            else:
                f.write(f"{t} AUTH_FAIL user={user} src_ip={ip} dst_ip=10.0.0.5 reason=invalid_password\\n")

def gen_dos(filepath, ip='202.44.112.9', repetitions=20):
    with open(filepath, 'a') as f:
        for _ in range(repetitions):
            t = now()
            f.write(f"{t} TRAFFIC_DENY src_ip={ip} dst_ip=10.0.0.8 dst_port=443 protocol=TCP reason=SYN_FLOOD\\n")

def gen_phish(filepath):
    with open(filepath, 'a') as f:
        t = now()
        f.write(f'{t} EMAIL_RECEIVED from=\"it-support@secure-microsoft-login.com\" to=\"employee1@company.com\" subject=\"Password Reset Required\" action=delivered\\n')
        f.write(f'{now()} EMAIL_CLICK user=employee1@company.com link=\"http://secure-microsoft-login.com/reset\"\\n')
        f.write(f'{now()} EMAIL_ALERT user=employee1@company.com detection=phishing domain=\"secure-microsoft-login.com\"\\n')

if __name__ == "__main__":
    gen_bruteforce(os.path.join(OUT_DIR, 'bruteforce.log'), attempts=8)
    gen_dos(os.path.join(OUT_DIR, 'dos.log'), repetitions=30)
    gen_phish(os.path.join(OUT_DIR, 'phish_email.log'))
    print("Generated logs into", OUT_DIR)
