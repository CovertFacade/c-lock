import totp
from proc_worker import Event, Broker
from ttp import *
from queue import Queue

import os
import logging

log = logging.getLogger(__name__)



def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    slot = 30

    secret = totp.gen_secret()

    # TODO Delete after debug
    secret = '874895c82728d55c3e8e62c449954e1c2ee8d364f3bc953e230c23be452def7119b3c59d4be21799'

    log.debug("Secret: %s" % secret)

    if not os.geteuid() == 0:
        log.error("This program needs root for managing IPTABLES!")
        return -1

    try:
        import iptc
    except:

        if 'XTABLES_LIBDIR' not in os.environ:
            os.environ['XTABLES_LIBDIR'] = '/usr/lib/x86_64-linux-gnu/xtables'
        else:
            raise "Error, la variable XTABLES_LIBDIR está mal configurada"

    from port_manager import PortManagerWorker, PortManager
    from firewall_manager import FirewallManager, FirewallManagerWorker
    
    oq = Queue()
    bq = Queue()

    b = Broker(bq, oq)

    fwm = FirewallManager()
    fwmq = Queue()
    b.add_client(fwmq)
    fwmw = FirewallManagerWorker(fwmq, bq, fwm=fwm)

    pmq = Queue()
    b.add_client(pmq)
    pm = PortManager()
    pmw = PortManagerWorker(pmq, bq, pm=pm)

    ttp = TocTocPorts(secret, forbidden=[8080])

    ttpq = Queue()
    b.add_client(ttpq)
    ttpw = TocTocPortsWorker(ttpq, bq, ttp)

    # TODO Clase orquestador

if __name__ == '__main__':
    main()
