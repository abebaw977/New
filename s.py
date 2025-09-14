from scapy.all import *

# Detect the subnet automatically
CONTAINER_IP = "10.0.0.148"  # your container IP
SUBNET = ".".join(CONTAINER_IP.split(".")[:3]) + ".0/24"  # e.g., 10.0.0.0/24

# ARP request packet
arp_request = ARP(pdst=SUBNET)
broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
arp_request_broadcast = broadcast / arp_request

# Send the request and receive responses
answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

print("IP\t\tMAC Address")
print("-" * 30)

for sent, received in answered_list:
    print(f"{received.psrc}\t{received.hwsrc}")
from scapy.all import conf

def getting_ip_of_access_point():
    # Returns the gateway IP (default route) to reach the Internet
    return conf.route.route("8.8.8.8")[2]

ap_ip = getting_ip_of_access_point()
print(ap_ip)
