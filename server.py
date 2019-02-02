import totp
from proc_worker import Event, Broker, ProcWorkerEvent
from ttp import *
from queue import Queue
import time
import os
import logging

import signal

log = logging.getLogger(__name__)

def check_environment():

    if not os.geteuid() == 0:
        raise Exception("This program needs root for managing IPTABLES!")

    try:
        import iptc
    except Exception as e:

        if 'XTABLES_LIBDIR' not in os.environ:
            os.environ['XTABLES_LIBDIR'] = '/usr/lib/x86_64-linux-gnu/xtables'
        else:
            raise Exception("Error, la variable XTABLES_LIBDIR está mal configurada")


# TODO Sacar a una clase y hacer el main con arg_parser
def main_server(secret, slot, address, ports):

    try:
        check_environment()
    except Exception as e:
        log.error(e)
        exit(-1)

    log.debug("Secret: %s" % secret)

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
    pm = PortManager(address)
    pmw = PortManagerWorker(pmq, bq, pm=pm)

    ttp = TocTocPorts(secret, destination=ports)

    ttpq = Queue()
    b.add_client(ttpq)
    ttpw = TocTocPortsWorker(ttpq, bq, ttp)

    fwmw.start()
    pmw.start()
    ttpw.start()
    b.start()

    # TODO Refactor de este método
    def end(signum, *args):
        log.warning('Signal handler called with signal %s' % signum)
        bq.put(Event(ProcWorkerEvent.END, None))
        retry = 0
        while retry <= 3:
            if not fwmw.is_alive() and not pmw.is_alive() and not ttpw.is_alive() and not b.is_alive():
                break
            time.sleep(retry * 1)

        if fwmw.is_alive():
            log.warning("Bad killing thread fwmw")
        if pmw.is_alive():
            log.warning("Bad killing thread pmw")
        if ttpw.is_alive():
            log.warning("Bad killing thread ttpw")
        if b.is_alive():
            log.warning("Bad killing thread broker")

        if fwmw.is_alive() or pmw.is_alive() or ttpw.is_alive() or b.is_alive():
            exit(0)


    signal.signal(signal.SIGINT, end)
    signal.signal(signal.SIGSEGV, end)
    signal.signal(signal.SIGFPE, end)
    signal.signal(signal.SIGABRT, end)
    signal.signal(signal.SIGBUS, end)
    signal.signal(signal.SIGILL, end)
    # TODO Clase orquestador

import argparse

def main():


    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL,
        'QUIET': logging.NOTSET
    }

    parser = argparse.ArgumentParser(description='Launch TOTP based port knocking protection')
    parser.add_argument('-ts', '--time-slot', dest='slot', default=30, type=int, help='Time slot for TOTP')
    parser.add_argument('-a', '--address', default='0.0.0.0', help="Address to protect")
    parser.add_argument('-s', '--secret', help="Secret part of TOTP")
    parser.add_argument('-p', '--protected-ports', type=int, action='append', help="Port which has to be protected")
    parser.add_argument('--gen-secret', help="Generate random secret", action='store_true')
    parser.add_argument('--clean-firewall', help="Clean firewall configuration (e.g., after a bad close)", action='store_true')
    parser.add_argument('--log-level', default="DEBUG", help="Log level")
    # parser.add_argument('--config-file')

    args = parser.parse_args()

    log_level = args.log_level

    level = log_levels.get(log_level, logging.DEBUG)
    logging.basicConfig(
        level= level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print(args)

    if args.gen_secret:
        secret = totp.gen_secret()
        print("TOTP Secret: %s" % secret)

    elif args.clean_firewall:

        try:
            check_environment()
        except Exception as e:
            log.error(e)
            exit(-1)

        from firewall_manager import FirewallManager

        FirewallManager().clean_firewall()
    else:

        if not args.secret:
            log.error("A secret is required to start")
            parser.print_help()
            return

        secret = args.secret
        slot = args.slot

        address = args.address
        ports = args.protected_ports if args.protected_ports else [22]

        main_server(secret, slot, address, ports)


if __name__ == '__main__':
    main()
