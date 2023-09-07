import subprocess

# Respond to a detected DoS attack
def respond_to_dos_attack(attacker_ip):
    print(f"Responding to DoS attack from IP: {attacker_ip}")

    # Block the attacker's IP using iptables (Linux command)
    subprocess.run(["iptables", "-A", "INPUT", "-s", attacker_ip, "-j", "DROP"])

    print(f"Blocked IP: {attacker_ip} using iptables.")
