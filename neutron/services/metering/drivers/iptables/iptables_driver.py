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

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_utils import netutils

from neutron.agent.common import utils as common_utils
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespaces
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.conf.agent import common as config
from neutron.services.metering.drivers import abstract_driver


LOG = logging.getLogger(__name__)
NS_PREFIX = 'qrouter-'
WRAP_NAME = 'neutron-meter'
EXTERNAL_DEV_PREFIX = 'qg-'
ROUTER_2_FIP_DEV_PREFIX = namespaces.ROUTER_2_FIP_DEV_PREFIX
TOP_CHAIN = WRAP_NAME + "-FORWARD"
RULE = '-r-'
LABEL = '-l-'

config.register_interface_driver_opts_helper(cfg.CONF)
config.register_interface_opts()


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
        # TODO(cbrandily): deduplicate ns_name generation in metering/l3
        self.ns_name = NS_PREFIX + self.id
        self.iptables_manager = None
        self.snat_iptables_manager = None
        self.metering_labels = {}

        self.create_iptables_managers()

    def create_iptables_managers(self):
        """Creates iptables managers if the are not already created

        Returns True if any manager is created
        """

        created = False

        if self.router['distributed'] and self.snat_iptables_manager is None:
            # If distributed routers then we need to apply the
            # metering agent label rules in the snat namespace as well.
            snat_ns_name = dvr_snat_ns.SnatNamespace.get_snat_ns_name(
                self.id)
            # Check for namespace existence before we assign the
            # snat_iptables_manager
            if ip_lib.network_namespace_exists(snat_ns_name):
                self.snat_iptables_manager = iptables_manager.IptablesManager(
                    namespace=snat_ns_name,
                    binary_name=WRAP_NAME,
                    state_less=True,
                    use_ipv6=netutils.is_ipv6_enabled())

                created = True

        if self.iptables_manager is None:
            # Check of namespace existence before we assign the
            # iptables_manager
            # NOTE(Swami): If distributed routers, all external traffic on a
            # compute node will flow through the rfp interface in the router
            # namespace.
            if ip_lib.network_namespace_exists(self.ns_name):
                self.iptables_manager = iptables_manager.IptablesManager(
                    namespace=self.ns_name,
                    binary_name=WRAP_NAME,
                    state_less=True,
                    use_ipv6=netutils.is_ipv6_enabled())

                created = True

        return created


class IptablesMeteringDriver(abstract_driver.MeteringAbstractDriver):

    def __init__(self, plugin, conf):
        super(IptablesMeteringDriver, self).__init__(plugin, conf)

        self.routers = {}
        self.driver = common_utils.load_interface_driver(self.conf)

    def _update_router(self, router):
        r = self.routers.get(router['id'])

        if r is None:
            r = RouterWithMetering(self.conf, router)

        r.router = router
        self.routers[r.id] = r

        return r

    @log_helpers.log_method_call
    def update_routers(self, context, routers):
        # disassociate removed routers
        router_ids = set(router['id'] for router in routers)
        for router_id, rm in self.routers.items():
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
                    if router.get('distributed'):
                        old_rm_im = old_rm.snat_iptables_manager
                    else:
                        old_rm_im = old_rm.iptables_manager

                    # In case the selected manager is None pick another one.
                    # This is not ideal sometimes.
                    old_rm_im = (old_rm_im or
                                 old_rm.snat_iptables_manager or
                                 old_rm.iptables_manager)

                    if old_rm_im:
                        with IptablesManagerTransaction(old_rm_im):
                            self._process_disassociate_metering_label(router)
                            if gw_port_id:
                                self._process_associate_metering_label(router)
                elif gw_port_id:
                    self._process_associate_metering_label(router)

    @log_helpers.log_method_call
    def remove_router(self, context, router_id):
        if router_id in self.routers:
            del self.routers[router_id]

    def get_external_device_names(self, rm):
        gw_port_id = rm.router.get('gw_port_id')
        if not gw_port_id:
            return None, None

        # NOTE (Swami): External device 'qg' should be used on the
        # Router namespace if the router is legacy and should be used on
        # SNAT namespace if the router is distributed.
        ext_dev = (EXTERNAL_DEV_PREFIX +
                   gw_port_id)[:self.driver.DEV_NAME_LEN]
        ext_snat_dev = (ROUTER_2_FIP_DEV_PREFIX +
                        rm.id)[:self.driver.DEV_NAME_LEN]
        return ext_dev, ext_snat_dev

    def _process_metering_label_rules(self, rules, label_chain,
                                      rules_chain, ext_dev, im):
        if not ext_dev:
            return
        for rule in rules:
            self._add_rule_to_chain(ext_dev, rule, im,
                                    label_chain, rules_chain)

    def _process_metering_label_rule_add(self, rule, ext_dev,
                                         label_chain, rules_chain, im):
        self._add_rule_to_chain(ext_dev, rule, im, label_chain, rules_chain)

    def _process_metering_label_rule_delete(self, rule, ext_dev,
                                            label_chain, rules_chain, im):
        self._remove_rule_from_chain(ext_dev, rule, im,
                                     label_chain, rules_chain)

    def _add_rule_to_chain(self, ext_dev, rule, im,
                           label_chain, rules_chain):
        ipt_rule = self._prepare_rule(ext_dev, rule, label_chain)

        LOG.debug("Adding IPtables rule [%s] for configurations [%s].",
                  ipt_rule, rule)

        if rule['excluded']:
            im.ipv4['filter'].add_rule(rules_chain, ipt_rule,
                                       wrap=False, top=True)
        else:
            im.ipv4['filter'].add_rule(rules_chain, ipt_rule,
                                       wrap=False, top=False)

    def _remove_rule_from_chain(self, ext_dev, rule, im,
                                label_chain, rules_chain):
        ipt_rule = self._prepare_rule(ext_dev, rule, label_chain)

        LOG.debug("Removing IPtables rule [%s] for configurations [%s].",
                  ipt_rule, rule)

        if rule['excluded']:
            im.ipv4['filter'].remove_rule(rules_chain, ipt_rule,
                                          wrap=False, top=True)
        else:
            im.ipv4['filter'].remove_rule(rules_chain, ipt_rule,
                                          wrap=False, top=False)

    def _prepare_rule(self, ext_dev, rule, label_chain):
        if rule.get('remote_ip_prefix'):
            ipt_rule = IptablesMeteringDriver.\
                prepare_source_and_destination_rule_legacy(ext_dev, rule)
        else:
            ipt_rule = IptablesMeteringDriver.\
                prepare_source_and_destination_rule(ext_dev, rule)

        if rule['excluded']:
            ipt_rule = '%s -j RETURN' % ipt_rule
        else:
            ipt_rule = '%s -j %s' % (ipt_rule, label_chain)
        return ipt_rule

    @staticmethod
    def prepare_source_and_destination_rule(ext_dev, rule):
        if rule['direction'] == 'egress':
            iptables_rule = '-o %s' % ext_dev
        else:
            iptables_rule = '-i %s' % ext_dev

        source_ip_prefix = rule.get('source_ip_prefix')
        if source_ip_prefix:
            iptables_rule = "-s %s %s" % (source_ip_prefix, iptables_rule)

        destination_ip_prefix = rule.get('destination_ip_prefix')
        if destination_ip_prefix:
            iptables_rule = "-d %s %s" % (destination_ip_prefix, iptables_rule)

        return iptables_rule

    @staticmethod
    def prepare_source_and_destination_rule_legacy(ext_dev, rule):
        remote_ip = rule['remote_ip_prefix']
        if rule['direction'] == 'egress':
            ipt_rule = '-s %s -o %s' % (remote_ip, ext_dev)
        else:
            ipt_rule = '-d %s -i %s' % (remote_ip, ext_dev)
        return ipt_rule

    def _process_ns_specific_metering_label(self, router, ext_dev, im):
        '''Process metering label based on the associated namespaces.'''
        rm = self.routers.get(router['id'])
        with IptablesManagerTransaction(im):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']

                label_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + LABEL + label_id, wrap=False)

                rules_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + RULE + label_id, wrap=False)

                exists = rm.metering_labels.get(label_id)
                if not exists:
                    self._create_metering_label_chain(rm,
                                                      label_chain,
                                                      rules_chain)
                    rm.metering_labels[label_id] = label

                rules = label.get('rules')
                if rules:
                    self._process_metering_label_rules(
                        rules, label_chain, rules_chain, ext_dev, im)

    def _process_associate_metering_label(self, router):
        self._update_router(router)
        rm = self.routers.get(router['id'])

        ext_dev, ext_snat_dev = self.get_external_device_names(rm)
        for (im, dev) in [(rm.iptables_manager, ext_dev),
                          (rm.snat_iptables_manager, ext_snat_dev)]:
            if im:
                self._process_ns_specific_metering_label(router, dev, im)

    def _process_ns_specific_disassociate_metering_label(self, router, im):
        '''Disassociate metering label based on specific namespaces.'''
        rm = self.routers.get(router['id'])
        with IptablesManagerTransaction(im):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']
                if label_id not in rm.metering_labels:
                    continue

                label_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + LABEL + label_id, wrap=False)
                rules_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + RULE + label_id, wrap=False)
                im.ipv4['filter'].remove_chain(label_chain, wrap=False)
                im.ipv4['filter'].remove_chain(rules_chain, wrap=False)

    def _process_disassociate_metering_label(self, router):
        rm = self.routers.get(router['id'])
        if not rm:
            return

        for im in [rm.iptables_manager, rm.snat_iptables_manager]:
            if im:
                self._process_ns_specific_disassociate_metering_label(
                    router, im)

        labels = router.get(constants.METERING_LABEL_KEY, [])
        for label in labels:
            label_id = label['id']
            if rm.metering_labels.get(label_id):
                del rm.metering_labels[label_id]

    @log_helpers.log_method_call
    def add_metering_label(self, context, routers):
        for router in routers:
            self._process_associate_metering_label(router)

    @log_helpers.log_method_call
    def add_metering_label_rule(self, context, routers):
        for router in routers:
            self._add_metering_label_rule(router)

    @log_helpers.log_method_call
    def remove_metering_label_rule(self, context, routers):
        for router in routers:
            self._remove_metering_label_rule(router)

    @log_helpers.log_method_call
    def update_metering_label_rules(self, context, routers):
        for router in routers:
            self._update_metering_label_rules(router)

    def _add_metering_label_rule(self, router):
        self._process_metering_rule_action(router, 'create')

    def _remove_metering_label_rule(self, router):
        self._process_metering_rule_action(router, 'delete')

    def _create_metering_label_chain(self, rm, label_chain, rules_chain):
        rm.iptables_manager.ipv4['filter'].add_chain(label_chain, wrap=False)
        rm.iptables_manager.ipv4['filter'].add_chain(rules_chain, wrap=False)
        rm.iptables_manager.ipv4['filter'].add_rule(
            TOP_CHAIN, '-j ' + rules_chain, wrap=False)
        rm.iptables_manager.ipv4['filter'].add_rule(
            label_chain, '', wrap=False)

    def _process_metering_rule_action_based_on_ns(self, router, action,
                                                  ext_dev, im):
        '''Process metering rule actions based specific namespaces.'''
        rm = self.routers.get(router['id'])
        with IptablesManagerTransaction(im):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']
                label_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + LABEL + label_id, wrap=False)

                rules_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + RULE + label_id, wrap=False)

                exists = rm.metering_labels.get(label_id)
                if action == 'create' and not exists:
                    self._create_metering_label_chain(rm,
                                                      label_chain,
                                                      rules_chain)
                    rm.metering_labels[label_id] = label

                rule = label.get('rule')
                if rule:
                    if action == 'create':
                        self._process_metering_label_rule_add(
                            rule, ext_dev, label_chain, rules_chain, im)
                    elif action == 'delete':
                        self._process_metering_label_rule_delete(
                            rule, ext_dev, label_chain, rules_chain, im)

    def _process_metering_rule_action(self, router, action):
        rm = self.routers.get(router['id'])
        if not rm:
            return

        ext_dev, ext_snat_dev = self.get_external_device_names(rm)
        for (im, dev) in [(rm.iptables_manager, ext_dev),
                          (rm.snat_iptables_manager, ext_snat_dev)]:
            if im and dev:
                self._process_metering_rule_action_based_on_ns(
                    router, action, dev, im)

    def _update_metering_label_rules_based_on_ns(self, router, ext_dev, im):
        '''Update metering lable rules based on namespace.'''
        with IptablesManagerTransaction(im):
            labels = router.get(constants.METERING_LABEL_KEY, [])
            for label in labels:
                label_id = label['id']

                label_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + LABEL + label_id, wrap=False)
                rules_chain = iptables_manager.get_chain_name(
                    WRAP_NAME + RULE + label_id, wrap=False)
                im.ipv4['filter'].empty_chain(rules_chain, wrap=False)

                rules = label.get('rules')
                if rules:
                    self._process_metering_label_rules(
                        rules, label_chain, rules_chain, ext_dev, im)

    def _update_metering_label_rules(self, router):
        rm = self.routers.get(router['id'])
        if not rm:
            return

        ext_dev, ext_snat_dev = self.get_external_device_names(rm)
        for (im, dev) in [(rm.iptables_manager, ext_dev),
                          (rm.snat_iptables_manager, ext_snat_dev)]:
            if im and dev:
                self._update_metering_label_rules_based_on_ns(router, dev, im)

    @log_helpers.log_method_call
    def remove_metering_label(self, context, routers):
        for router in routers:
            self._process_disassociate_metering_label(router)

    @log_helpers.log_method_call
    def get_traffic_counters(self, context, routers):
        traffic_counters = {}
        routers_to_reconfigure = set()
        for router in routers:
            if self.granular_traffic_data:
                self.retrieve_and_account_granular_traffic_counters(
                    router, routers_to_reconfigure, traffic_counters)
            else:
                self.retrieve_and_account_traffic_counters_legacy(
                    router, routers_to_reconfigure, traffic_counters)

        for router_id in routers_to_reconfigure:
            del self.routers[router_id]

        return traffic_counters

    def retrieve_and_account_traffic_counters_legacy(self, router,
                                                     routers_to_reconfigure,
                                                     traffic_counters):
        rm = self.routers.get(router['id'])
        if not rm:
            return

        for label_id in rm.metering_labels:
            chain_acc = self.retrieve_traffic_counters(label_id, rm, router,
                                                       routers_to_reconfigure)

            if not chain_acc:
                continue

            acc = traffic_counters.get(label_id, {'pkts': 0, 'bytes': 0})

            acc['pkts'] += chain_acc['pkts']
            acc['bytes'] += chain_acc['bytes']

            traffic_counters[label_id] = acc

    @staticmethod
    def retrieve_traffic_counters(label_id, rm, router,
                                  routers_to_reconfigure):
        try:
            chain = iptables_manager.get_chain_name(WRAP_NAME +
                                                    LABEL +
                                                    label_id,
                                                    wrap=False)

            chain_acc = rm.iptables_manager.get_traffic_counters(
                chain, wrap=False, zero=True)
        except RuntimeError as e:
            LOG.warning('Failed to get traffic counters for router [%s] due '
                        'to [%s]. This error message can happen when routers '
                        'are migrated; therefore, most of the times they can '
                        'be ignored.', router, e)

            routers_to_reconfigure.add(router['id'])
            return {}
        return chain_acc

    def retrieve_and_account_granular_traffic_counters(self, router,
                                                       routers_to_reconfigure,
                                                       traffic_counters):
        """Retrieve and account traffic counters for routers.

        This method will retrieve the traffic counters for all labels that
        are assigned to a router. Then, it will account the traffic counter
        data in the following granularities.
                * label -- all of the traffic counter for a given label.
                One must bear in mind that a label can be assigned to multiple
                routers.
                * router -- all of the traffic counter for all labels that
                are assigned to the router.
                * project -- all of the traffic counters for all labels of
                all routers that a project has.
                * router-label -- all of the traffic counters for a router
                and the given label.
                * project-label -- all of the traffic counters for all
                routers of a project that have a given label.


        All of the keys have the following standard in the
        `traffic_counters` dictionary.
                * labels -- label-<label_id>
                * routers -- router-<router_id>
                * project -- project-<tenant_id>
                * router-label -- router-<router_id>-label-<label_id>
                * project-label -- project-<tenant_id>-label-<label_id>

        And last, but not least, if we are not able to retrieve the traffic
        counters from `iptables` for a given router, we will add it to
        `routers_to_reconfigure` set.

        :param router:
        :param routers_to_reconfigure:
        :param traffic_counters:
        """
        router_id = router['id']
        rm = self.routers.get(router_id)
        if not rm:
            return

        default_traffic_counters = {'pkts': 0, 'bytes': 0}
        project_traffic_counter_key = self.get_project_traffic_counter_key(
            router['tenant_id'])
        router_traffic_counter_key = self.get_router_traffic_counter_key(
            router_id)

        project_counters = traffic_counters.get(
            project_traffic_counter_key, default_traffic_counters.copy())
        project_counters['traffic-counter-granularity'] = "project"

        router_counters = traffic_counters.get(
            router_traffic_counter_key, default_traffic_counters.copy())
        router_counters['traffic-counter-granularity'] = "router"

        for label_id in rm.metering_labels:
            label_traffic_counter_key = self.get_label_traffic_counter_key(
                label_id)

            project_label_traffic_counter_key = "%s-%s" % (
                project_traffic_counter_key, label_traffic_counter_key)
            router_label_traffic_counter_key = "%s-%s" % (
                router_traffic_counter_key, label_traffic_counter_key)

            chain_acc = self.retrieve_traffic_counters(label_id, rm, router,
                                                       routers_to_reconfigure)

            if not chain_acc:
                continue

            label_traffic_counters = traffic_counters.get(
                label_traffic_counter_key, default_traffic_counters.copy())
            label_traffic_counters['traffic-counter-granularity'] = "label"

            project_label_traffic_counters = traffic_counters.get(
                project_label_traffic_counter_key,
                default_traffic_counters.copy())
            project_label_traffic_counters[
                'traffic-counter-granularity'] = "label_project"

            router_label_traffic_counters = traffic_counters.get(
                router_label_traffic_counter_key,
                default_traffic_counters.copy())
            router_label_traffic_counters[
                'traffic-counter-granularity'] = "label_router"

            project_label_traffic_counters['pkts'] += chain_acc['pkts']
            project_label_traffic_counters['bytes'] += chain_acc['bytes']

            router_label_traffic_counters['pkts'] += chain_acc['pkts']
            router_label_traffic_counters['bytes'] += chain_acc['bytes']

            label_traffic_counters['pkts'] += chain_acc['pkts']
            label_traffic_counters['bytes'] += chain_acc['bytes']

            traffic_counters[project_label_traffic_counter_key] = \
                project_label_traffic_counters

            traffic_counters[router_label_traffic_counter_key] = \
                router_label_traffic_counters

            traffic_counters[label_traffic_counter_key] = \
                label_traffic_counters

            router_counters['pkts'] += chain_acc['pkts']
            router_counters['bytes'] += chain_acc['bytes']

            project_counters['pkts'] += chain_acc['pkts']
            project_counters['bytes'] += chain_acc['bytes']

        traffic_counters[router_traffic_counter_key] = router_counters
        traffic_counters[project_traffic_counter_key] = project_counters

    @log_helpers.log_method_call
    def sync_router_namespaces(self, context, routers):
        for router in routers:
            rm = self.routers.get(router['id'])
            if not rm:
                continue

            # NOTE(bno1): Sometimes a router is added before its namespaces are
            # created. The metering agent has to periodically check if the
            # namespaces for the missing iptables managers have appearead and
            # create the managers for them. When a new manager is created, the
            # metering rules have to be added to it.
            if rm.create_iptables_managers():
                self._process_associate_metering_label(router)
