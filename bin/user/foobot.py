#!/usr/bin/env python
# Copyright 2016 Matthew Wall, all rights reserved
"""
Collect data from foobot air quality monitor.

# run the driver to capture packets
sudo PYTHONPATH=bin python bin/user/foobot.py

# capture packets and send them to the weewx host
ssh root@192.168.32.1 "tcpdump -U -w - -i vr1 host 192.168.32.94" | nc 192.168.32.52 8083

# receive packets on the weewx host
nc -l -p 8083 > /dev/null

"""

from __future__ import with_statement
import Queue
import fnmatch
import string
import syslog
import threading
import time
import urlparse

import weewx.drivers

DRIVER_NAME = 'Foobot'
DRIVER_VERSION = '0.1'

DEFAULT_IFACE = 'eth0'
DEFAULT_FILTER = 'dst port 8083'


def loader(config_dict, _):
    return FoobotDriver(**config_dict[DRIVER_NAME])

def confeditor_loader():
    return FoobotConfigurationEditor()


def logmsg(level, msg):
    syslog.syslog(level, 'foobot: %s: %s' %
                  (threading.currentThread().getName(), msg))

def logdbg(msg):
    logmsg(syslog.LOG_DEBUG, msg)

def loginf(msg):
    logmsg(syslog.LOG_INFO, msg)

def logerr(msg):
    logmsg(syslog.LOG_ERR, msg)

def _obfuscate_passwords(msg):
    idx = msg.find('PASSWORD')
    if idx >= 0:
        import re
        msg = re.sub(r'PASSWORD=[^&]+', r'PASSWORD=XXXX', msg)
    return msg

def _fmt_bytes(data):
    return ' '.join(['%02x' % ord(x) for x in data])


class Consumer(object):

    queue = Queue.Queue()

    def __init__(self, iface=DEFAULT_IFACE, pcap_filter=DEFAULT_FILTER):
        self._server = Consumer.SniffServer(iface, pcap_filter)

    def run_server(self):
        self._server.run()

    def stop_server(self):
        self._server.stop()
        self._server = None

    def get_queue(self):
        return Consumer.queue

    class SniffServer(object):
        SNAPLEN = 1600
        PROMISCUOUS = 0
        TIMEOUT_MS = 100

        def __init__(self, iface, pcap_filter):
            import pcap
            self.packet_sniffer = pcap.pcapObject()
            loginf("sniff iface %s" % iface)
            self.packet_sniffer.open_live(
                iface, self.SNAPLEN, self.PROMISCUOUS, self.TIMEOUT_MS)
            loginf("sniff filter '%s'" % pcap_filter)
            self.packet_sniffer.setfilter(pcap_filter, 0, 0)
            self.running = False
            self.query_string = ''

        def run(self):
            logdbg("start sniff server");
            self.running = True
            while self.running:
                self.packet_sniffer.dispatch(1, self.decode_ip_packet)

        def stop(self):
            logdbg("stop sniff server");
            self.running = False
            self.packet_sniffer.close()
            self.packet_sniffer = None

        def decode_ip_packet(self, _pktlen, data, _timestamp):
            if not data:
                return
            logdbg("sniff: timestamp=%s pktlen=%s data=%s" %
                   (_timestamp, _pktlen, _fmt_bytes(data)))
            s = [chr(ord(x)) for x in data]
            s = ''.join(s)
            printable = set(string.printable)
            f = filter(lambda x: x in printable, s)
            logdbg("sniff: filtered=%s" % f)
#            Consumer.queue.put(s)

    class Parser(object):

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            # the sensor map is a dictionary of database field names as keys,
            # each with an associated observation identifier.
            if sensor_map is None:
                return pkt
            packet = dict()
            if 'dateTime' in pkt:
                packet['dateTime'] = pkt['dateTime']
            if 'usUnits' in pkt:
                packet['usUnits'] = pkt['usUnits']
            for n in sensor_map:
                label = Consumer.Parser._find_match(sensor_map[n], pkt.keys())
                if label:
                    packet[n] = pkt.get(label)
            return packet

        @staticmethod
        def _find_match(pattern, keylist):
            # pattern can be a simple label, or an identifier pattern.
            # keylist is an array of observations, each of which is either
            # a simple label, or an identifier tuple.
            match = None
            pparts = pattern.split('.')
            if len(pparts) == 3:
                for k in keylist:
                    kparts = k.split('.')
                    if (len(kparts) == 3 and
                        Consumer.Parser._part_match(pparts[0], kparts[0]) and
                        Consumer.Parser._part_match(pparts[1], kparts[1]) and
                        Consumer.Parser._part_match(pparts[2], kparts[2])):
                        match = k
                    elif pparts[0] == k:
                        match = k
            else:
                for k in keylist:
                    if pattern == k:
                        match = k
            return match

        @staticmethod
        def _part_match(pattern, value):
            # use glob matching for parts of the tuple
            matches = fnmatch.filter([value], pattern)
            return True if matches else False


class FoobotConfigurationEditor(weewx.drivers.AbstractConfEditor):
    @property
    def default_stanza(self):
        return """
[Foobot]
    # This section is for the foobot air quality monitor.

    # The driver to use
    driver = user.foobot
"""


class FoobotDriver(weewx.drivers.AbstractDevice):

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        self._obs_map = stn_dict.get('sensor_map', None)
        self._queue = Queue.Queue()
        self._capture_thread = threading.Thread(target=self.capture)
        self._capture_thread.setDaemon(True)
        self._capture_thread.setName('capture-thread')
        self._capture_thread.start()

    def closePort(self):
        loginf('shutting down server thread')
        self._capture_thread.join(20.0)
        if self._capture_thread.isAlive():
            logerr('unable to shut down capture thread')

    def hardware_name(self):
        return 'Foobot'

    def genLoopPackets(self):
        while True:
            try:
                data = self._queue.get(True, 10)
                logdbg('raw data: %s' % data)
                packet = self.parse(data)
                logdbg('raw packet: %s' % packet)
                packet = self.map_to_fields(packet, self._obs_map)
                logdbg('mapped packet: %s' % packet)
                yield packet
            except Queue.Empty:
                logdbg('empty queue')

    def parse(self, data):
        packet = dict()
        return packet

    def map_to_fields(self, pkt, obs_map):
        if obs_map is None:
            return pkt
        packet = dict()
        for k in obs_map:
            if k in pkt:
                packet[obs_map[k]] = pkt[k]
        return packet


# define a main entry point for determining sensor identifiers.
# invoke this as follows from the weewx root dir:
#
# PYTHONPATH=bin python bin/user/foobot.py

if __name__ == '__main__':
    import optparse

    usage = """%prog [options] [--debug] [--help]"""

    syslog.openlog('foobot', syslog.LOG_PID | syslog.LOG_CONS)
    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_INFO))

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--version', dest='version', action='store_true',
                      help='display driver version')
    parser.add_option('--debug', dest='debug', action='store_true',
                      default=False,
                      help='display diagnostic information while running')
    parser.add_option('--iface', dest='iface', metavar='IFACE',
                      default=DEFAULT_IFACE,
                      help='network interface to sniff')
    parser.add_option('--filter', dest='filter', metavar='FILTER',
                      default=DEFAULT_FILTER,
                      help='pcap filter for sniffing')

    (options, args) = parser.parse_args()

    debug = False
    if options.debug:
        syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_DEBUG))
        debug = True

    device = Consumer(iface=options.iface, pcap_filter=options.filter)
    server_thread = threading.Thread(target=device.run_server)
    server_thread.setDaemon(True)
    server_thread.setName('ServerThread')
    server_thread.start()

    while True:
        try:
            _data = device.get_queue().get(True, 10)
            if debug:
                print 'raw data: %s' % _data
                _pkt = Consumer.Parser.parse(_data)
                print 'raw packet: %s' % _pkt
                _pkt = Consumer.Parser.map_to_fields(_pkt, None)
                print 'mapped packet: %s' % _pkt
        except Queue.Empty:
            logdbg("empty queue")
