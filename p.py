from scapy.all import ARP, Ether, srp
import time

# Container IP and subnet
CONTAINER_IP = "10.0.0.148"  # replace with your container IP
SUBNET = ".".join(CONTAINER_IP.split(".")[:3]) + ".0/24"

# Keep track of devices we've already seen
devices_seen = set()

print("Scanning subnet:", SUBNET)
print("Waiting for devices...\n")
print("IP\t\tMAC Address")
print("-" * 30)

while True:
    arp_request = ARP(pdst=SUBNET)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for sent, received in answered_list:
        device_id = received.hwsrc  # MAC address as unique ID
        if device_id not in devices_seen:
            devices_seen.add(device_id)
            print(f"{received.psrc}\t{received.hwsrc}")

    time.sleep(5)  # wait 5 seconds before next scanx
