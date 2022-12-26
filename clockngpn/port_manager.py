import logging
import socket
import sys
import threading

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from .proc_worker import ProcWorker, Event, bypass, ProcWorkerEvent, TocTocPortsEvent, PortManagerEvent

log = logging.getLogger(__name__)


class PortManager():

    def __init__(self, address='0.0.0.0', unmanaged_ports=[]):

        self._active = {}
        self._sockets = []
        self._threads = []
        self._address = address
        self._port_lists = {}
        self._unmanaged_ports = unmanaged_ports

        try:

            evt = threading.Event()
            t = threading.Thread(target=self.wait_and_listen, args=(evt,))
            self._threads.append(evt)
            t.start()

        except socket.error as msg:
            # TODO Send END
            log.error('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

    def wait_and_listen(self, evt):
        log.info("wait_and_listen")

        # TODO Ver por qué no termina el hilo...
        # myfilter = '(tcp[13]&2!=0 and tcp[13]&16==0)'
        myfilter = '(udp[2]&5!=0)'
        sniff(lfilter=lambda pkt: pkt.haslayer(UDP),
              prn=lambda pkt: self.notify_connection(pkt[IP].src, pkt[UDP].dport), stop_filter=lambda x: evt.is_set(), filter=myfilter, store=0)

        log.info("nor_wait_nor_listen")

    def notify_connection(self, addr, port):
        log.debug("connection from %s:%s" % (addr, port))
        # TODO Hacer esto con métodos con bloqueos (@lock)
        if addr in self._active:
            addr_info = self._active[addr]
            if port == addr_info['next']:
                next_n = addr_info['n'] + 1
                if len(self._port_lists[addr_info.secret]) <= next_n:
                    self.last_port(addr)
                    del self._active[addr]
                else:
                    addr_info['n'] = next_n
                    addr_info['next'] = self._port_lists[addr_info.secret][next_n]
                    self._active[addr] = addr_info
            else:
                if port not in self._unmanaged_ports:
                    del self._active[addr]
        else:
            self._active[addr] = self.find_port(port)

    def find_port(self, port):
        for secret in self._port_lists.key():
            if self._port_lists[secret].port_list[0] == port:
                return dict(next=list.port_list[1], n=1, secret=secret)
        return None

    def last_port(self, addr):
        log.info("%s reached last port" % (addr))

    def reset(self, secret, port_list):
        self._active = {}
        self._port_lists.update({secret: port_list})

    def close_thread(self, evt):
        try:
            evt.set()
        except Exception as e:
            pass

    def unlock_threads(self):
        while len(self._threads):
            try:
                evt = self._threads.pop()
                self.close_thread(evt)
            except Exception as e:
                pass

    def close(self):
        self.unlock_threads()


# https://eli.thegreenplace.net/2011/12/27/python-threads-communication-and-stopping
# http://www.bogotobogo.com/python/Multithread/python_multithreading_Event_Objects_between_Threads.php
class PortManagerWorker(ProcWorker):

    def __init__(self, i_q, o_q, pm=None):
        super(PortManagerWorker, self).__init__(i_q, o_q)

        if not pm:
            pm = PortManager()

        self._pm = pm

        self._pm.notify_connection = bypass(self._pm.notify_connection, self.notify_connection)
        self._pm.last_port = bypass(self._pm.last_port, self.last_port)

    def notify_connection(self, addr, port):
        self._o.put(Event(PortManagerEvent.NEW_CONNECTION, {'port': port, 'address': addr}))

    def last_port(self, address):
        self._o.put(Event(PortManagerEvent.LAST_PORT, dict(address=address)))

    def process_evt(self, evt):
        super(PortManagerWorker, self).process_evt(evt)

        if evt.get_id() == ProcWorkerEvent.END:
            self._pm.close()

        if evt.get_id() == TocTocPortsEvent.NEW_SLOT:
            port_list = evt.get_value()['port_list'].get_values()
            secret = evt.get_value()['secret']
            self._pm.reset(secret, port_list)

        if evt.get_id() == PortManagerEvent.PROTECT_PORT:
            pass
