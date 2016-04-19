# -*- coding: utf-8 -*-
# Portions of this code were taken from https://github.com/switchdoclabs/iBeacon-Scanner-.git
# SwitchDoc Labs, LLC - June 2014
import bluetooth._bluetooth as bluez
import json
import optparse
import os
import paho.mqtt.publish as publish
import re
import struct
import sys
import time

__version__ = '1.0'
CONFIG_FILE = '.brewmonitor'
SERVER = '127.0.0.1'
PORT = 1883

TOPIC_PREFIX = "monitor/brewometer"

# Store list of active brewmometers
brewmometers = {}

isBean = re.compile('^a495....c5b14b44b5121370f02d74de$')

LE_META_EVENT = 0x3e
OGF_LE_CTL=0x08
OCF_LE_SET_SCAN_ENABLE=0x000C
EVT_LE_ADVERTISING_REPORT=0x02


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
                               struct.unpack("B", value[0])[0] * 256.0)

                for i in range(0, num_reports):
                    report = {
                        "udid": packet2string(pkt[report_pkt_offset - 22: report_pkt_offset - 6]),
                        "temp": fmt_major_minor(pkt[report_pkt_offset - 6: report_pkt_offset - 4]),
                        "sg": fmt_major_minor(pkt[report_pkt_offset - 4: report_pkt_offset - 2]) / 1000.0,
                        "addr": packed_bdaddr_to_string(pkt[report_pkt_offset + 3:report_pkt_offset + 9])
                    }

                    reports[report["udid"]] = report

    sock.setsockopt( bluez.SOL_HCI, bluez.HCI_FILTER, old_filter )
    return reports


def process_brewmometers(sock):
    timestamp = int(time.time())
    reports = process_ble_advertisements(sock)
    for udid, report in reports.iteritems():
        if udid not in brewmometers:
            brewmometers[udid] = report

        brewmometers[udid]['timestamp'] = timestamp
        brewmometers[udid].update(report)

    return brewmometers


def publish_mqtt(mqtt_config, brewmometers):
    topic_prefix = mqtt_config.get('topic_prefix', TOPIC_PREFIX)
    server = mqtt_config.get('server', SERVER)
    port = mqtt_config.get('port', PORT)

    for udid, report in brewmometers.iteritems():
        payload = json.dumps(report)
        publish.single("/".join([topic_prefix, udid]),
                       payload, hostname=server, port=port)


def monitor(opts, dev_id=0):
    mqtt_config = {
        'server': opts.mqttserver,
        'port': opts.mqttport if opts.mqttport else PORT,
    }
    try:
        sock = bluez.hci_open_dev(dev_id)

    except:
        print("FATAL: Can't access bluetooth device...")
        sys.exit(1)

    hci_le_set_scan_parameters(sock)
    hci_enable_le_scan(sock)

    while True:
        reports = process_brewmometers(sock)
        if opts.mqttserver:
            publish_mqtt(mqtt_config, reports)


def main():
    parser = optparse.OptionParser(version=__version__)

    parser.add_option('-c', '--config', help="specify alternate config file (default='%s')" % CONFIG_FILE)

    mqtt = optparse.OptionGroup(parser, "MQTT Options", "Options for using MQTT broadcast")
    mqtt.add_option('-t', '--topic', action="store", help="MQTT topic prefix")
    mqtt.add_option('--mqttserver', action="store", help="MQTT server")
    mqtt.add_option('--mqttport', action="store", help="MQTT port")
    parser.add_option_group(mqtt)

    http = optparse.OptionGroup(parser, "HTTP Options", "Options for using HTTP submission")
    http.add_option('--httpserver', action="store", help="MQTT server and port <host:port>")
    parser.add_option_group(http)

    parser.set_defaults(config=CONFIG_FILE, index=0)
    opts, args = parser.parse_args()
    if os.path.exists(opts.config):
        config = ConfigParser.ConfigParser()
        config.read(opts.config)
    else:
        print("missing config file '%s'" % opts.config)
        parser.print_usage()

    return monitor(opts)

if __name__ == "__main__":
    main()
