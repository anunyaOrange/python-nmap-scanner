import nmap

scanner = nmap.PortScanner()

print("Nmap version:", scanner.nmap_version())
print("Enter the target IP address or hostname:")
target = input().strip()
print("Target:", target)

type(target)

option = input("""\nOptions:
                  \n1. Syn Ack scan
                  \n2. UDP scan
                  \n3. Comprehensive scan""")
print("Option selected:", option)

if option == "1":
    print("Nmap version:", scanner.nmap_version())
    print("Performing Syn Ack scan...")
    # scanner.scan(target, arguments='-sS')
    scanner.scan(target, '1-1024', '-v -sS')
    print(scaner.scaninfo())
    print("IP status:", scanner[target].state())
    print(scanner[target].all_protocols())
    print("Open ports:", scanner[target]['tcp'].keys())
elif option == "2":
    print("Performing UDP scan...")
    # scanner.scan(target, arguments='-sU')
    scanner.scan(target, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("IP status:", scanner[target].state())
    print(scanner[target].all_protocols())
    print("Open ports:", scanner[target]['udp'].keys())
elif option == "3":
    print("Performing comprehensive scan...")
    scanner.scan(target, arguments='-v -sS -sV -sC -A -O -T4')
    print(scanner.scaninfo())
    print("IP status:", scanner[target].state())
    print(scanner[target].all_protocols())
    print("Open ports:", scanner[target]['tcp'].keys())
    print("Service versions:", scanner[target]['tcp'].values())
    print("Operating system:", scanner[target]['osmatch'])
    print("OS details:", scanner[target]['osmatch'][0]['osclass'])
    print("OS accuracy:", scanner[target]['osmatch'][0]['accuracy'])
else:
    print("Invalid option selected. Exiting...")



