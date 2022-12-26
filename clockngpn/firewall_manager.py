from .proc_worker import ProcWorker, ProcWorkerEvent, TocTocPortsEvent
import uuid
import logging
import threading
import time
import iptc


log = logging.getLogger(__name__)

# GUIDE: https://github.com/ldx/python-iptables
class FirewallManager():

    def __init__(self, protocol):

        self.protocol = protocol
        self.backup()

        log.debug("Starting FirewallManager")

        table = iptc.Table(iptc.Table.FILTER)

        # Crear chain
        try:
            table.create_chain("ceelock")
        except Exception:
            log.debug("ceelock exists!")
        log.debug("create_chain")


        # TODO ¿Debería venir desde ACCEPT?
        input_chain = iptc.Chain(table, "INPUT")
        input_chain = input_chain if input_chain else table.create_chain("INPUT")
        log.debug("input_chain")
        # TODO Añadir que mande aquí todos los puertos protegidos, o todas las conexiones si se protege todo
        # create a protocol rule that gates the chain?
        protocol_rule = input_chain.create_rule()
        log.debug("new rule")
        protocol_rule.protocol = protocol
        # Apuntar INPUT a ceelock
        protocol_rule.target = protocol_rule.create_target("ceelock")
        log.debug("protocol configured")
        log.debug(protocol_rule)
        input_chain.insert_rule(protocol_rule, position=len(input_chain.rules))

        log.debug("insert_rule")

        # ceelock config
        # create a ceelock chain used for filtering
        clock_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "ceelock")

        '''
        TODO 1b53c7b5-55d7-4834-9719-1ef86a7bfe12
        if unmanaged_ports:
            OPEN(unmanaged_ports)
            DROP_ALL
        else:
            DROP (PROTECTED_PORTS)
        '''
        # Drop all the rest
        drop_rule = iptc.Rule()
        drop_rule.protocol = protocol
        drop_rule.target = iptc.Target(drop_rule, "DROP")
        clock_chain.insert_rule(drop_rule)

        log.debug("clock_chain drop")
        # # Accept all established
        # rule = iptc.Rule()
        # rule.protocol = protocol
        # rule.target = iptc.Target(rule, "ACCEPT")
        # match = iptc.Match(rule, "state")
        # match.state = "RELATED,ESTABLISHED"
        # rule.add_match(match)
        # chain.insert_rule(rule)

        # TODO Accept all OUTPUT

        # Accept all localhost connections
        rule = iptc.Rule() # *
        rule.protocol = protocol
        rule.src = "127.0.0.1"
        rule.target = iptc.Target(rule, "ACCEPT")
        clock_chain.insert_rule(rule)
        log.debug("clock_chain insert")

        # TODO Not working right
        # Accept all output connections
        # rule = iptc.Rule()
        # rule.protocol = protocol
        # rule.target = iptc.Target(rule, "ACCEPT")
        # rule.src = "127.0.0.1"
        # chain.insert_rule(rule)
    #
    # def unmanage_port(self, port):
    #
    #     table = iptc.Table(iptc.Table.FILTER)
    #
    #     chain = iptc.Chain(table, "ceelock-unmanaged")
    #
    #     rule = iptc.Rule() # *
    #     rule.protocol = protocol
    #     match = iptc.Match(rule, protocol)
    #     match.dport = "%d" % port
    #     rule.add_match(match)
    #
    #     # TODO Debería ir a INPUT, pero puede hacer un bucle infinito
    #     rule.target = iptc.Target(rule, "ACCEPT")
    #
    #     chain.insert_rule(rule)


    # if !open then close
    def gen_rule(self, d_port=None, s_address=None, open=True, protocol="udp"):

        rule = iptc.Rule() # *
        rule.protocol = protocol

        if s_address:
            rule.src = s_address

        if d_port:
            log.info(d_port)
            match = iptc.Match(rule, protocol)
            match.dport = "%d" % d_port
            rule.add_match(match)

        rule.target = iptc.Target(rule, "ACCEPT" if open else "REJECT")

        # TODO Puede servir para evitar repetidos
        # try:
        #     self.delete_rule(rule)
        # except Exception as e:
        #     pass

        return rule

    def open(self, protocol="udp", d_port=None, s_address=None):
        # TODO Evitar insertar reglas repetidas
        table = iptc.Table(iptc.Table.FILTER)

        chain = iptc.Chain(table, "ceelock")

        rule = self.gen_rule(d_port, s_address, open=True, protocol=protocol)

        chain.insert_rule(rule)

        return rule

    def close(self, d_port=None, s_address=None, protocol="udp"):
        table = iptc.Table(iptc.Table.FILTER)

        chain = iptc.Chain(table, "ceelock")

        rule = self.gen_rule(d_port, s_address, open=False, protocol=protocol)

        chain.insert_rule(rule)

        return rule

    def add_rule(self, rule):

        table = iptc.Table(iptc.Table.FILTER)

        chain = iptc.Chain(table, "ceelock")
        chain.insert_rule(rule)

    def delete_rule(self, rule):
        table = iptc.Table(iptc.Table.FILTER)

        chain = iptc.Chain(table, "ceelock")
        chain.delete_rule(rule)

    def clean_firewall(self):
        log.info("Cleaning firewall rules")

        table = iptc.Table(iptc.Table.FILTER)

        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        rule = iptc.Rule()
        rule.protocol = self.protocol
        rule.target = iptc.Target(rule, "ceelock")

        # TODO Ver como usar esto sin borrar otras reglas del firewall
        while rule in chain.rules:
            chain.delete_rule(rule)

        chain = iptc.Chain(table, "ceelock")
        chain.flush()
        chain.delete()

    def finish(self):
        self.clean_firewall()
        self.restore()

    def backup(self):
        # TODO Search how to backup iptables
        pass

    def restore(self):
        # TODO Search how to restore iptables
        pass


class RuleManager(threading.Thread):

    rules = {}

    def __init__(self, fwm):
        super(RuleManager, self).__init__()
        self._lock = threading.Lock()
        self._fwm = fwm
        self._end_evt = threading.Event()
        self.start()

    def run(self):
        while not self._end_evt.is_set():
            self.delete_caduced_rules()
            self._end_evt.wait(1)

    def close(self):
        self._end_evt.set()
        self.delete_all_rules()

    def lock(f):

        def locker(self, *args, **kwargs):

            self._lock.acquire()

            res = f(self, *args, **kwargs)

            self._lock.release()

            return res

        return locker

    @lock
    def add_rule(self, r, caducity=-1, protected=False):

        # TODO rule_id como hash de la regla para evitar repetidos
        # Sin repetidos, sólo actualizaríamos la caducidad
        rule_id = str(uuid.uuid4())
        log.debug("Adding rule %s -> %s" % (rule_id, str(r)))

        # TODO Comprobar si ya existe
        self.rules[rule_id] = {
            'rule': r,
            'timestamp': time.time(),
            'caducity': caducity,
            'protected': protected
        }

        return rule_id

    @lock
    def exist_rule(self, r):

        for rule in self.rules:
            raux = self.rules[rule]
            if raux['rule'] == r:
                return rule

        return None

    @lock
    def renew_rule_timestamp(self, rule_id, caducity=None):

        if caducity:
            self.rules[rule_id]['caducity'] = caducity

        self.rules[rule_id]['timestamp'] = time.time()

    @lock
    def get_rule(self, rule_id):

        rule_data = self.rules.get(rule_id, None)

        return rule_data

    @lock
    def delete_rule(self, rule_id):

        if rule_id in self.rules:
            rule_data = self.rules[rule_id]
            try:
                log.debug("Deleting rule %s -> %s" % (rule_id, str(rule_data.get('rule'))))
                self._fwm.delete_rule(rule_data.get('rule'))
            except Exception as e:
                log.error("Error deleting %s: %s" % (rule_id, str(e)))

            del self.rules[rule_id]

    def delete_caduced_rules(self):
        # Copy of keys
        keys = [key for key in self.rules.keys()]

        for rule_id in keys:
            rule_data = self.get_rule(rule_id)
            if rule_data:
                if rule_data['caducity'] < 0:
                    continue
                elif rule_data['caducity'] < (time.time() - rule_data['timestamp']):
                    self.delete_rule(rule_id)

    # If `hard`, the protected rules are deleted too
    def delete_all_rules(self, hard=False):

        keys = [key for key in self.rules.keys()]

        for rule_id in keys:
            rule_data = self.get_rule(rule_id)
            if rule_data:
                # Delete if its not protected or hard deleting
                if hard or not rule_data['protected']:
                    self.delete_rule(rule_id)


class FirewallManagerWorker(ProcWorker):

    def __init__(self, i_q, o_q, fwm=None):

        super(FirewallManagerWorker, self).__init__(i_q, o_q)

        if not fwm:
            fwm = FirewallManager()

        self._fwm = fwm

        # TODO Abrir puertos marcados como no gestionados (prohibidos)
        self._rule_manager = RuleManager(fwm)

    def open(self, port=None, s_address=None, caducity=-1, protected=False):

        # We protect this rule for allowing the user to connect on step change
        r = self._fwm.gen_rule(port, s_address=s_address)

        exist = self._rule_manager.exist_rule(r)

        if exist:
            self._rule_manager.renew_rule_timestamp(exist)
        else:
            try:
                self._fwm.add_rule(r)
                self._rule_manager.add_rule(r, caducity=caducity, protected=protected)
                log.debug("Opening port %d for %s" % (port, s_address))
            except Exception as e:
                log.critical("Error opening port for %s %s" % (s_address, e))

    def process_evt(self, evt):

        super(FirewallManagerWorker, self).process_evt(evt)

        if evt.get_id() == ProcWorkerEvent.END:
            self._rule_manager.close()
            self._fwm.finish()

        if evt.get_id() == TocTocPortsEvent.LAST_PORT:
            evt_value = evt.get_value()
            ports = evt_value['ports']
            addr = evt_value['address']
            log.info("Opening ports %s for %s" % (ports, addr))

            # Usamos esto porque hemos determinado usar FT/SNIFF/O1
            if len(ports):
                for port in ports:
                    self.open(port, s_address=addr, caducity=30, protected=True)
            else:
                # TODO Implementar esto si determinamos usar FT/SNIFF/O2
                self.open(s_address=addr, caducity=30, protected=True)

        if evt.get_id() == TocTocPortsEvent.NEW_SLOT:
            # TODO ¿Close o borrar las reglas guardadas?
            # self._fwm.close()
            self._rule_manager.delete_all_rules()
