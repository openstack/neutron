# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
import six

from neutron.agent.common import config
from neutron.agent.linux import interface
from neutron.agent.linux import iptables_manager
from neutron.common import constants as constants
from neutron.common import ipv6_utils
from neutron.common import log
from neutron.i18n import _LE, _LI
from neutron.services.metering.drivers import abstract_driver


LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
WRAP_NAME = 'neutron-meter'
EXTERNAL_DEV_PREFIX = 'qg-'
TOP_CHAIN = WRAP_NAME + "-FORWARD"
RULE = '-r-'
LABEL = '-l-'

config.register_interface_driver_opts_helper(cfg.CONF)
config.register_use_namespaces_opts_helper(cfg.CONF)
cfg.CONF.register_opts(interface.OPTS)


class IptablesManagerTransaction(object):
    __transactions = {}

    def __init__(self, im):
        self.im = im

        transaction = self.__transactions.get(im, 0)
        transaction += 1
        self.__transactions[im] = transaction

    def __enter__(self):
        return self.im

    def __exit__(self, type, value, traceback):
        transaction = self.__transactions.get(self.im)
        if transaction == 1:
            self.im.apply()
            del self.__transactions[self.im]
        else:
            transaction -= 1
            self.__transactions[self.im] = transaction


class RouterWithMetering(object):

    def __init__(self, conf, router):
        self.conf = conf
        self.id = router['id']
        self.router = router
        self.ns_name = NS_PREFIX + self.id if conf.use_namespaces else None
        self.iptables_manager = iptables_manager.IptablesManager(
            namespace=self.ns_name,
            binary_name=WRAP_NAME,
            use_ipv6=ipv6_utils.is_enabled())
        self.metering_labels = {}


class IptablesMeteringDriver(abstract_driver.MeteringAbstractDriver):

    def __init__(self, plugin, conf):
        self.plugin = plugin
        self.conf = conf or cfg.CONF
        self.routers = {}

        if not self.conf.interface_driver:
            raise SystemExit(_('An interface driver must be specified'))
        LOG.info(_LI("Loading interface driver %s"),
                 self.conf.interface_driver)
        self.driver = importutils.import_object(self.conf.interface_driver,
                                                self.conf)

    def _update_router(self, router):
        r = self.routers.get(router['id'],
                             RouterWithMetering(self.conf, router))
        r.router = router
        self.routers[r.id] = r

        return r

    @log.log
    def update_routers(self, context, routers):
        # disassociate removed routers
        router_ids = set(router['id'] for router in routers)
        for router_id, rm in six.iteritems(self.routers):
            if router_id not in router_ids:
                self._process_disassociate_metering_label(rm.router)

        for router in routers:
            old_gw_port_id = None
            old_rm = self.routers.get(router['id'])
            if old_rm:
                old_gw_port_id = old_rm.router['gw_port_id']
            gw_port_id = router['gw_port_id']

            if gw_port_id != old_gw_port_id:
                if old_rm:
                    with IptablesManagerTransaction(old_rm.iptables_manager):
                        self._process_disassociate_metering_label(router)
                        if gw_port_id:
                            self._process_associate_metering_label(router)
                elif gw_port_id:
                    self._process_associate_metering_label(router)

    @log.log
    def remove_router(self, context, router_id):
        if router_id in self.routers:
            del self.routers[router_id]

    def get_external_device_name(self, port_id):
        return (EXTERNAL_DEV_PREFIX + port_id)[:self.driver.DEV_NAME_LEN]

    def _process_metering_label_rules(self, rm, rules, label_chain,
                                      rules_chain):
        im = rm.iptables_manager
        ext_dev = self.get_external_device_name(rm.router['gw_port_id'])
        if not ext_dev:
            return

        for rule in rules:
            self._add_rule_to_chain(ext_dev, rule, im,
                                    label_chain, rules_chain)

    def _process_metering_label_rule_add(self, rm, rule, ext_dev,
                                         label_chain, rules_chain):
        im = rm.iptables_manager
        self._add_rule_to_chain(ext_dev, rule, im, label_chain, rules_chain)

    def _process_metering_label_rule_delete(self, rm, rule, ext_dev,
                                            label_chain, rules_chain):
        im = rm.iptables_manager
        self._remove_rule_from_chain(ext_dev, rule, im,
                                     label_chain, rules_chain)

    def _add_rule_to_chain(self, ext_dev, rule, im,
                           label_chain, rules_chain):
        ipt_rule = self._prepare_rule(ext_dev, rule, label_chain)
        if rule['excluded']:
            im.ipv4['filter'].add_rule(rules_chain, ipt_rule,
                                       wrap=False, top=True)
        else:
            im.ipv4['filter'].add_rule(rules_chain, ipt_rule,
                                       wrap=False, top=False)

    def _remove_rule_from_chain(self, ext_dev, rule, im,
                                label_chain, rules_chain):
        ipt_rule = self._prepare_rule(ext_dev, rule, label_chain)
        if rule['excluded']:
            im.ipv4['filter'].remove_rule(rules_chain, ipt_rule,
                                          wrap=False, top=True)
        else:
            im.ipv4['filter'].remove_rule(rules_chain, ipt_rule,
                                          wrap=False, top=False)

    def _prepare_rule(self, ext_dev, rule, label_chain):
        remote_ip = rule['remote_ip_prefix']
        if rule['direction'] == 'egress':
            dir_opt = '-o %s -s %s' % (ext_dev, remote_ip)
        else:
            dir_opt = '-i %s -d %s' % (ext_dev, remote_ip)

        if rule['excluded']:
            ipt_rule = '%s -j RETURN' % dir_opt
        else:
            ipt_rule = '%s -j %s' % (dir_opt, label_chain)
        return ipt_rule

    def _process_associate_metering_label(self, router):
        self._update_router(router)
        rm = self.routers.get(router['id'])

        with IptablesManagerTransaction(rm.iptables_manager):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']

                label_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              LABEL + label_id,
                                                              wrap=False)
                rm.iptables_manager.ipv4['filter'].add_chain(label_chain,
                                                             wrap=False)

                rules_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              RULE + label_id,
                                                              wrap=False)
                rm.iptables_manager.ipv4['filter'].add_chain(rules_chain,
                                                             wrap=False)
                rm.iptables_manager.ipv4['filter'].add_rule(TOP_CHAIN, '-j ' +
                                                            rules_chain,
                                                            wrap=False)

                rm.iptables_manager.ipv4['filter'].add_rule(label_chain,
                                                            '',
                                                            wrap=False)

                rules = label.get('rules')
                if rules:
                    self._process_metering_label_rules(rm, rules,
                                                       label_chain,
                                                       rules_chain)

                rm.metering_labels[label_id] = label

    def _process_disassociate_metering_label(self, router):
        rm = self.routers.get(router['id'])
        if not rm:
            return

        with IptablesManagerTransaction(rm.iptables_manager):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']
                if label_id not in rm.metering_labels:
                    continue

                label_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              LABEL + label_id,
                                                              wrap=False)
                rules_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              RULE + label_id,
                                                              wrap=False)

                rm.iptables_manager.ipv4['filter'].remove_chain(label_chain,
                                                                wrap=False)
                rm.iptables_manager.ipv4['filter'].remove_chain(rules_chain,
                                                                wrap=False)

                del rm.metering_labels[label_id]

    @log.log
    def add_metering_label(self, context, routers):
        for router in routers:
            self._process_associate_metering_label(router)

    @log.log
    def add_metering_label_rule(self, context, routers):
        for router in routers:
            self._add_metering_label_rule(router)

    @log.log
    def remove_metering_label_rule(self, context, routers):
        for router in routers:
            self._remove_metering_label_rule(router)

    @log.log
    def update_metering_label_rules(self, context, routers):
        for router in routers:
            self._update_metering_label_rules(router)

    def _add_metering_label_rule(self, router):
        self._process_metering_rule_action(router, 'create')

    def _remove_metering_label_rule(self, router):
        self._process_metering_rule_action(router, 'delete')

    def _process_metering_rule_action(self, router, action):
        rm = self.routers.get(router['id'])
        if not rm:
            return
        ext_dev = self.get_external_device_name(rm.router['gw_port_id'])
        if not ext_dev:
            return
        with IptablesManagerTransaction(rm.iptables_manager):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']
                label_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              LABEL + label_id,
                                                              wrap=False)

                rules_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              RULE + label_id,
                                                              wrap=False)
                rule = label.get('rule')
                if rule:
                    if action == 'create':
                        self._process_metering_label_rule_add(rm, rule,
                                                              ext_dev,
                                                              label_chain,
                                                              rules_chain)
                    elif action == 'delete':
                        self._process_metering_label_rule_delete(rm, rule,
                                                                 ext_dev,
                                                                 label_chain,
                                                                 rules_chain)

    def _update_metering_label_rules(self, router):
        rm = self.routers.get(router['id'])
        if not rm:
            return

        with IptablesManagerTransaction(rm.iptables_manager):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']

                label_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              LABEL + label_id,
                                                              wrap=False)
                rules_chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                              RULE + label_id,
                                                              wrap=False)
                rm.iptables_manager.ipv4['filter'].empty_chain(rules_chain,
                                                               wrap=False)

                rules = label.get('rules')
                if rules:
                    self._process_metering_label_rules(rm, rules,
                                                       label_chain,
                                                       rules_chain)

    @log.log
    def remove_metering_label(self, context, routers):
        for router in routers:
            self._process_disassociate_metering_label(router)

    @log.log
    def get_traffic_counters(self, context, routers):
        accs = {}
        for router in routers:
            rm = self.routers.get(router['id'])
            if not rm:
                continue

            for label_id, label in rm.metering_labels.items():
                try:
                    chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                            LABEL +
                                                            label_id,
                                                            wrap=False)

                    chain_acc = rm.iptables_manager.get_traffic_counters(
                        chain, wrap=False, zero=True)
                except RuntimeError:
                    LOG.exception(_LE('Failed to get traffic counters, '
                                      'router: %s'), router)
                    continue

                if not chain_acc:
                    continue

                acc = accs.get(label_id, {'pkts': 0, 'bytes': 0})

                acc['pkts'] += chain_acc['pkts']
                acc['bytes'] += chain_acc['bytes']

                accs[label_id] = acc

        return accs
