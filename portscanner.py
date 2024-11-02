import nmap
import re
import socket
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
port_min = 0
port_max = 65535

open_ports = []
print("***************************************************************")
print(r"""$$$$$$$\   $$$$$$\  $$$$$$$\ $$$$$$$$\        $$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\ $$\   $$\ $$$$$$$$\ $$$$$$$\  
$$  __$$\ $$  __$$\ $$  __$$\\__$$  __|      $$  __$$\ $$  __$$\ $$  __$$\ $$$\  $$ |$$$\  $$ |$$  _____|$$  __$$\ 
$$ |  $$ |$$ /  $$ |$$ |  $$ |  $$ |         $$ /  \__|$$ /  \__|$$ /  $$ |$$$$\ $$ |$$$$\ $$ |$$ |      $$ |  $$ |
$$$$$$$  |$$ |  $$ |$$$$$$$  |  $$ |         \$$$$$$\  $$ |      $$$$$$$$ |$$ $$\$$ |$$ $$\$$ |$$$$$\    $$$$$$$  |
$$  ____/ $$ |  $$ |$$  __$$<   $$ |          \____$$\ $$ |      $$  __$$ |$$ \$$$$ |$$ \$$$$ |$$  __|   $$  __$$< 
$$ |      $$ |  $$ |$$ |  $$ |  $$ |         $$\   $$ |$$ |  $$\ $$ |  $$ |$$ |\$$$ |$$ |\$$$ |$$ |      $$ |  $$ |
$$ |       $$$$$$  |$$ |  $$ |  $$ |         \$$$$$$  |\$$$$$$  |$$ |  $$ |$$ | \$$ |$$ | \$$ |$$$$$$$$\ $$ |  $$ |
\__|       \______/ \__|  \__|  \__|          \______/  \______/ \__|  \__|\__|  \__|\__|  \__|\________|\__|  \__|
                                                                                                                   """)
print("***************************************************************")
decide = input("Type 's' for scoket scan or 'n' for nmap scan: ")


while True:
    ip_add_entered = input("Enter the address you want to scan: ")
    if ip_add_pattern.search(ip_add_entered):
        print(f"{ip_add_entered} is a valid IP address")
        break

while True:
    print("Enter your range of ports you'd like to scan <int>-<int> (for ex. 69-420)")
    port_range = input("Enter your port range:")

    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

if decide == 's':
    for port in range(port_min, port_max + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((ip_add_entered, port))
                open_ports.append(port)
        except:
            pass

    for port in open_ports:
        print(f"Port {port} is open on {ip_add_entered}")

if decide == 'n':
    nm = nmap.PortScanner()
    for port in range(port_min, port_max + 1):
        try:
            result = nm.scan(ip_add_entered, str(port))
            port_status = result['scan'][ip_add_entered]['tcp'][port]['state']
            print(f"Port {port} is {port_status}")
        except:
            print(f"Cannot scan port {port}.")
