import totp
import time

def bytes2int(b):
    return int.from_bytes(b, byteorder='big', signed=False)

# TODO Threading & sockets!
# import threading, socket

class Last(Exception):
    pass

class PortList():

    def __init__(self, l):
        self._l = l
        self.actual = 0

    def next(self):

        if len(self._l) <= self.actual:
            # raise Last()
            return 0

        n = self._l[self.actual]
        self.actual += 1
        return n

    def prev(self):

        if len(0 <= self.actual):
            raise Last()

        n = self._l[self.actual]
        self.actual -= 1
        return n

    def get_values(self):
        return self._l

    def reset(self):
        self.actual = 0


class TocTocPorts():

    def __init__(self, secret, slot=30, n_ports=4, destination=22, forbidden=[]):

        self._secret = secret
        self._slot = slot
        self._forbidden = forbidden
        self._destination = destination

        if n_ports > 20:
            raise Exception("Error, max ports: %d" % 20)

        self._n_ports = n_ports

        ports = self.get_all()

        self._p = ports['p']
        self._a = ports['a']
        self._n = ports['n']
        # time.sleep(ns)

    # 1 < n < 10
    def gen_ports(self, val):
        values = []
        for i in range(self._n_ports):
            aux = bytes2int(val[2*i:(2*i)+2])
            if aux < 1024:
                aux += 1024
            while aux in self._forbidden or aux in values or aux == self._destination:
                aux += 1
            values.append(aux)
        return values


    def get_slot(self):
        return self._slot

    def get_destination(self):
        return self._destination

    def next(self):
        t = int(time.time())
        remainder = t % self._slot
        return self._slot - remainder


    def last(self):
        t = int(time.time())
        remainder = t % self._slot

        return t - remainder

    def get_all(self):

        tc = self.last()
        tcp = tc - self._slot
        tcn = tc + self._slot

        valp = totp.totp(self._secret, tcp)
        vala = totp.totp(self._secret, tc)
        valn = totp.totp(self._secret, tcn)

        portsp = self.gen_ports(valp)
        portsa = self.gen_ports(vala)
        portsn = self.gen_ports(valn)

        return {'p': PortList(portsp), 'a': PortList(portsa), 'n': PortList(portsn)}

    def get_prev(self):
        return self.get_all()['p']

    def get_actual(self):
        return self.get_all()['a']

    def get_next(self):
        return self.get_all()['n']

    def __str__(self):
        res = ''
        banner = "N\tPrev\t\tActu\t\tNext\n"
        res += (banner)
        res += ("-" * len(banner))
        res += "\n"

        ports = self.get_all()
        p = ports['p'].get_values()
        a = ports['a'].get_values()
        n = ports['n'].get_values()

        for port in range(len(p)):
            res += ("%d\t%d\t\t%d\t\t%d\n" % (port, p[port], a[port], n[port]))
        res += ("-" * len(banner))
        res += "\n"

        return res

def manage_socket(s, next):
    pass

import socket
def open_ports(ttp):

    values = ttp.get_actual()

    n = values.next()
    while n:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.bind(('0.0.0.0', n))
        s.listen(1)
        s.accept()
        s.close()
        n = values.next()
        print("Next %d" % n)

    print("Opening port %d" % ttp.get_destination())

def toc_ports(ttp):

    values = ttp.get_actual()

    retry = 0
    n = values.next()
    while n:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.connect(('localhost', n))
            s.close()
        except:
            if retry > 3:
                print("End")
                return
            retry += 1
            time.sleep(0.1)
            continue
        retry = 0
        n = values.next()
        print("Next %d" % n)

    print("Opening port %d" % ttp.get_destination())

import sys

# TODO https://github.com/ldx/python-iptables
# TODO https://docs.python.org/3/library/argparse.html
def main():

    slot = 30

    secret = sys.argv[1]

    print("Secret: %s" % secret)

    ports = TocTocPorts(secret)

    print(ports)
    toc_ports(ports)

if __name__ == '__main__':
    main()
