# -*- coding: utf-8 -*-
import bluetooth._bluetooth as bluez
import json
import paho.mqtt.publish as publish
import re
import struct
import time

SERVER = "192.168.0.10"
PORT = 1883

TOPIC_PREFIX = "monitor/brew"

# Store list of active brewmometers
brewmometers = {}

isBean = re.compile('^a495....c5b14b44b5121370f02d74de$')

LE_META_EVENT = 0x3e
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_ENABLE=0x000C
EVT_LE_ADVERTISING_REPORT=0x02

def process_ble_advertisements(sock, loop_count=100):
    def packet2string(pkt):
        return ''.join(map(lambda x: "%02x" % struct.unpack("B", x)[0], pkt))

    def packed_bdaddr_to_string(bdaddr_packed):
        return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB", bdaddr_packed[::-1]))
    
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)
    
    # perform a device inquiry on bluetooth device #0
    # The inquiry should last 8 * 1.28 = 10.24 seconds
    # before the inquiry is performed, bluez should flush its cache of
    # previously discovered devices
    flt = bluez.hci_filter_new()
    bluez.hci_filter_all_events(flt)
    bluez.hci_filter_set_ptype(flt, bluez.HCI_EVENT_PKT)
    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, flt )

    reports = {}
    for i in range(0, loop_count):
        pkt = sock.recv(255)
        ptype, event, plen = struct.unpack("BBB", pkt[:3])
        
        if event == LE_META_EVENT:
            subevent, = struct.unpack("B", pkt[3])
            pkt = pkt[4:]

            if subevent == EVT_LE_ADVERTISING_REPORT:
                num_reports = struct.unpack("B", pkt[0])[0]
                report_pkt_offset = 0
                if not isBean.match(packet2string(pkt[report_pkt_offset-22: report_pkt_offset-6])):
                    continue

                def fmt_major_minor(value):
                    return sum(map(lambda c: struct.unpack("B", c)[0], value[1:]),
                               struct.unpack("B", value[0])[0] * 256)
                
                for i in range(0, num_reports):
                    report = {
                        "UDID": packet2string(pkt[report_pkt_offset - 22: report_pkt_offset - 6]).upper(),
                        "MAJOR": fmt_major_minor(pkt[report_pkt_offset - 6: report_pkt_offset - 4]),
                        "MINOR": fmt_major_minor(pkt[report_pkt_offset - 4: report_pkt_offset - 2]),
                        "MACADDR": packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                    }

                    reports[report["UDID"]] = report

    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return reports

def hci_le_set_scan_parameters(sock):
    old_filter = sock.getsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, 14)

    SCAN_RANDOM = 0x01
    OWN_TYPE = SCAN_RANDOM
    SCAN_TYPE = 0x01


def hci_toggle_le_scan(sock, enable):
    cmd_pkt = struct.pack("<BB", enable, 0x00)
    bluez.hci_send_cmd(sock, OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE, cmd_pkt)

    
def hci_enable_le_scan(sock):
    hci_toggle_le_scan(sock, 0x01)


def process_brewmometers(sock):
    timestamp = int(time.time())
    reports = process_ble_advertisements(sock)
    for udid, report in reports.iteritems():
        if udid not in brewmometers:
            brewmometers[udid] = report

        brewmometers[udid]['timestamp'] = timestamp
        brewmometers[udid].update(report)

    return brewmometers

def publish_brewmometers(brewmometers):
    
    while True:
        payload = {}
        publish.single("/".join([TOPIC_PREFIX, TOPIC_SUFFIX]), payload, hostname=SERVER)


def main():
    dev_id = 0
    try:
	sock = bluez.hci_open_dev(dev_id)

    except:
	print("FATAL: Can't access bluetooth device...")
    	sys.exit(1)

    hci_le_set_scan_parameters(sock)
    hci_enable_le_scan(sock)

    while True:
        reports = process_brewmometers(sock)
	for udid, report in reports.iteritems():
            print json.dumps(report, indent=4)



if __name__ == "__main__":
    main()
