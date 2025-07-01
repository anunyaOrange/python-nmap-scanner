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




