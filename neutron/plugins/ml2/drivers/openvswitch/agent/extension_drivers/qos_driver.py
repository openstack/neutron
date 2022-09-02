# Copyright (c) 2015 OpenStack Foundation
# Copyright (c) 2021-2022 Chinaunicom
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import secrets

from neutron_lib import constants
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.l2.extensions import qos_linux as qos
from neutron.plugins.ml2.common import constants as comm_consts
from neutron.services.qos.drivers.openvswitch import driver


LOG = logging.getLogger(__name__)

MAX_RETIES = 1000


class MeterIDGenerator:
    # This cache will be:
    #  PORT_METER_ID = {"port_id_1_ingress": 1,
    #                   "port_id_1_egress: 2,
    #                   "port_id_2_ingress": 3,
    #                   "port_id_2_egress: 4}

    def __new__(cls, *args, **kwargs):
        # make it a singleton
        if not hasattr(cls, '_instance'):
            cls._instance = super().__new__(cls)
            cls.PORT_METER_ID = {}
        return cls._instance

    def __init__(self, max_meter):
        self.max_meter = max_meter

    def _generate_meter_id(self):
        if self.max_meter <= 0:
            return
        used_meter_ids = self.PORT_METER_ID.values()
        cid = None
        times = 0
        while not cid or cid in used_meter_ids:
            cid = secrets.SystemRandom().randint(1, self.max_meter)
            times += 1
            if times >= MAX_RETIES:
                return
        return cid

    def allocate_meter_id(self, key):
        meter_id = self._generate_meter_id()
        if not meter_id:
            return
        self.set_meter_id(key, meter_id)
        return meter_id

    def remove_port_meter_id(self, key):
        return self.PORT_METER_ID.pop(key, None)

    def set_meter_id(self, key, meter_id):
        self.PORT_METER_ID[key] = meter_id


class MeterRuleManager:

    def __init__(self, br_int, type_=comm_consts.METER_FLAG_PPS):
        self.br_int = br_int
        self.max_meter = 0
        self._init_max_meter_id()
        self.rule_type = type_
        self.generator = MeterIDGenerator(self.max_meter)
        # This will be:
        #  PORT_INFO_INGRESS = {"port_id_1": (mac_1, 1),
        #                       "port_id_2": (mac_2, 2),
        #                       "port_id_3": (mac_3, 3),
        #                       "port_id_4": (mac_4, 4)}
        self.PORT_INFO_INGRESS = {}
        #  PORT_INFO_EGRESS = {"port_id_1": (mac_1, 1),
        #                      "port_id_2": (mac_2, 1),
        #                      "port_id_3": (mac_3, 1),
        #                      "port_id_4": (mac_4, 1)}
        self.PORT_INFO_EGRESS = {}

    def _init_max_meter_id(self):
        features = self.br_int.list_meter_features()
        for f in features:
            if f["max_meter"] > 0:
                self.max_meter = f["max_meter"]
                break

    def get_data_key(self, port_id, direction):
        return "{}_{}_{}".format(self.rule_type, port_id, direction)

    def load_port_meter_id(self, port_name, port_id, direction):
        key = self.get_data_key(port_id, direction)
        try:
            meter_id = self.br_int.get_value_from_other_config(
                port_name, key, value_type=int)
            self.generator.set_meter_id(key, meter_id)
            return meter_id
        except Exception:
            LOG.warning("Failed to load port $(port)s meter id in "
                        "direction %(direction)s",
                        {"direction": direction,
                         "port": port_id})

    def store_port_meter_id_to_ovsdb(self, port_name, port_id,
                                     direction, meter_id):
        key = self.get_data_key(port_id, direction)
        self.br_int.set_value_to_other_config(
            port_name, key, meter_id)

    def clean_port_meter_id_from_ovsdb(self, port_name, port_id, direction):
        key = self.get_data_key(port_id, direction)
        self.br_int.remove_value_from_other_config(
            port_name, key)

    def allocate_meter_id(self, port_id, direction):
        key = self.get_data_key(port_id, direction)
        return self.generator.allocate_meter_id(key)

    def remove_port_meter_id(self, port_id, direction):
        key = self.get_data_key(port_id, direction)
        return self.generator.remove_port_meter_id(key)

    def set_port_info_ingress(self, port_id, port_name, mac, vlan):
        self.PORT_INFO_INGRESS[port_id] = (port_name, mac, vlan)

    def remove_port_info_ingress(self, port_id):
        return self.PORT_INFO_INGRESS.pop(port_id, (None, None, None))

    def set_port_info_egress(self, port_id, port_name, mac, ofport):
        self.PORT_INFO_EGRESS[port_id] = (port_name, mac, ofport)

    def remove_port_info_egress(self, port_id):
        return self.PORT_INFO_EGRESS.pop(port_id, (None, None, None))


class OVSMeterQoSDriver:

    SUPPORT_METER = None

    def check_meter_features(self):
        features = self.br_int.list_meter_features()
        for f in features:
            if (f["max_meter"] != 0 and f["band_types"] != 0 and
                    f["capabilities"] != 0 and f["max_bands"] != 0):
                return True
        return False

    @property
    def support_meter(self):
        if self.SUPPORT_METER is None:
            self.SUPPORT_METER = self.check_meter_features()
        return self.SUPPORT_METER

    def _delete_meter_rate_limit(self, port_id, direction, cache, type_):
        if not self.support_meter:
            LOG.debug("Meter feature was not support by ovs %s bridge",
                      self.br_int.br_name)
            return

        LOG.debug("Delete %(direction)s %(qos_type)s rate limit "
                  "for port %(port)s.",
                  {"qos_type": type_,
                   "direction": direction,
                   "port": port_id})

        pkt_rate = qos_consts.RULE_TYPE_PACKET_RATE_LIMIT
        bw_rate = qos_consts.RULE_TYPE_BANDWIDTH_LIMIT
        qos_type = pkt_rate if type_ == comm_consts.METER_FLAG_PPS else bw_rate
        self.ports[port_id].pop((qos_type, direction), None)

        meter_id = cache.remove_port_meter_id(
            port_id, direction)

        if direction == constants.INGRESS_DIRECTION:
            port_name, mac, local_vlan = (
                cache.remove_port_info_ingress(port_id))
            if mac is not None and local_vlan is not None:
                self.br_int.remove_meter_from_port(
                    direction, mac, local_vlan=local_vlan,
                    type_=type_)
            if port_name is not None:
                cache.clean_port_meter_id_from_ovsdb(
                    port_name, port_id, direction)
        else:
            port_name, mac, ofport = (
                cache.remove_port_info_egress(port_id))
            if mac is not None and ofport is not None:
                self.br_int.remove_meter_from_port(
                    direction, mac, in_port=ofport,
                    type_=type_)
            if port_name is not None:
                cache.clean_port_meter_id_from_ovsdb(
                    port_name, port_id, direction)

        if meter_id:
            self.br_int.delete_meter(meter_id)

    def _update_meter_rate_limit(self, vif_port, direction, rate,
                                 burst, cache, type_):
        if not self.support_meter:
            LOG.debug("Meter feature was not support by ovs %s bridge",
                      self.br_int.br_name)
            return

        port_name = vif_port.port_name
        LOG.debug("Update port %(port)s %(direction)s %(qos_type)s rate limit "
                  "with rate: %(rate)s, burst: %(burst)s",
                  {"qos_type": type_,
                   "port": vif_port.vif_id,
                   "direction": direction,
                   "rate": rate,
                   "burst": burst})

        meter_id = cache.load_port_meter_id(
            port_name, vif_port.vif_id, direction)
        if not meter_id:
            meter_id = cache.allocate_meter_id(
                vif_port.vif_id, direction)
            if not meter_id:
                LOG.warning("Failed to retrieve and re-allocate meter id, "
                            "skipping updating port %(port)s "
                            "%(direction)s %(qos_type)s rate limit",
                            {"qos_type": type_,
                             "port": vif_port.vif_id,
                             "direction": direction})
                return
            cache.store_port_meter_id_to_ovsdb(
                port_name, vif_port.vif_id, direction, meter_id)

        try:
            self.br_int.create_meter(meter_id, rate,
                                     burst=burst, type_=type_)
        except Exception:
            self.br_int.update_meter(meter_id, rate,
                                     burst=burst, type_=type_)

        local_vlan = self.br_int.get_port_tag_by_name(port_name)

        if direction == constants.INGRESS_DIRECTION:
            cache.set_port_info_ingress(
                vif_port.vif_id,
                port_name, vif_port.vif_mac, local_vlan)
            self.br_int.apply_meter_to_port(
                meter_id, direction, vif_port.vif_mac,
                local_vlan=local_vlan, type_=type_)
        else:
            cache.set_port_info_egress(
                vif_port.vif_id,
                port_name, vif_port.vif_mac, vif_port.ofport)
            self.br_int.apply_meter_to_port(
                meter_id, direction, vif_port.vif_mac,
                in_port=vif_port.ofport, type_=type_)

    def _delete_packet_rate_limit(self, port, direction):
        self._delete_meter_rate_limit(port.get('port_id'), direction,
                                      self.meter_cache_pps,
                                      type_=comm_consts.METER_FLAG_PPS)

    def _update_packet_rate_limit(self, vif_port, rule, direction):
        max_kpps = rule.max_kpps * 1000
        max_burst_kpps = rule.max_burst_kpps * 1000 or 0
        LOG.debug("Update port %(port)s %(direction)s packet rate limit "
                  "with rate: %(rate)s, burst: %(burst)s",
                  {"port": vif_port.vif_id,
                   "direction": direction,
                   "rate": rule.max_kpps,
                   "burst": rule.max_burst_kpps})
        self._update_meter_rate_limit(vif_port, direction,
                                      max_kpps, max_burst_kpps,
                                      self.meter_cache_pps,
                                      type_=comm_consts.METER_FLAG_PPS)

    def _delete_meter_bandwidth_rate_limit(self, port_id, direction):
        self._delete_meter_rate_limit(port_id, direction, self.meter_cache_bps,
                                      type_=comm_consts.METER_FLAG_BPS)

    def _update_meter_bandwidth_rate_limit(self, vif_port, rule, direction):
        max_kbps = rule.max_kbps
        max_burst_kbps = rule.max_burst_kbps or 0
        LOG.debug("Update port %(port)s %(direction)s meter bandwidth limit "
                  "with rate: %(rate)s, burst: %(burst)s",
                  {"port": vif_port.vif_id,
                   "direction": direction,
                   "rate": max_kbps,
                   "burst": max_burst_kbps})
        self._update_meter_rate_limit(vif_port, direction,
                                      max_kbps, max_burst_kbps,
                                      self.meter_cache_bps,
                                      type_=comm_consts.METER_FLAG_BPS)


class QosOVSAgentDriver(qos.QosLinuxAgentDriver,
                        OVSMeterQoSDriver):

    SUPPORTED_RULES = driver.SUPPORTED_RULES

    def __init__(self):
        super().__init__()
        self.br_int_name = cfg.CONF.OVS.integration_bridge
        self.br_int = None
        self.agent_api = None
        self.ports = collections.defaultdict(dict)

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def _qos_bandwidth_initialize(self):
        """Clear QoS setting at agent restart.

        This is for clearing stale settings (such as ports and QoS tables
        deleted while the agent is down). The current implementation
        can not find stale settings. The solution is to clear everything and
        rebuild. There is no performance impact however the QoS feature will
        be down until the QoS rules are rebuilt.
        """
        self.br_int.clear_bandwidth_qos()
        self.br_int.set_queue_for_ingress_bandwidth_limit()

    def initialize(self):
        self.br_int = self.agent_api.request_int_br()
        self.cookie = self.br_int.default_cookie
        self._qos_bandwidth_initialize()
        self.meter_cache_pps = MeterRuleManager(self.br_int)
        self.meter_cache_bps = MeterRuleManager(
            self.br_int, type_=comm_consts.METER_FLAG_BPS)

    def create_bandwidth_limit(self, port, rule):
        self.update_bandwidth_limit(port, rule)

    def update_bandwidth_limit(self, port, rule):
        vif_port = port.get('vif_port')
        if not vif_port:
            port_id = port.get('port_id')
            LOG.debug("update_bandwidth_limit was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        self.ports[port['port_id']][(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                     rule.direction)] = port
        if rule.direction == constants.INGRESS_DIRECTION:
            self._update_ingress_bandwidth_limit(vif_port, rule)
        else:
            self._update_egress_bandwidth_limit(vif_port, rule)

    def delete_bandwidth_limit(self, port):
        port_id = port.get('port_id')
        vif_port = port.get('vif_port')
        port = self.ports[port_id].pop((qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                        constants.EGRESS_DIRECTION),
                                       None)

        if not port and not vif_port:
            LOG.debug("delete_bandwidth_limit was received "
                      "for port %s but port was not found. "
                      "It seems that bandwidth_limit is already deleted",
                      port_id)
            return
        vif_port = vif_port or port.get('vif_port')

        if cfg.CONF.OVS.qos_meter_bandwidth:
            self._delete_meter_bandwidth_rate_limit(
                port_id, direction=constants.EGRESS_DIRECTION)
        else:
            self.br_int.delete_egress_bw_limit_for_port(vif_port.port_name)

    def delete_bandwidth_limit_ingress(self, port):
        port_id = port.get('port_id')
        vif_port = port.get('vif_port')
        port = self.ports[port_id].pop((qos_consts.RULE_TYPE_BANDWIDTH_LIMIT,
                                        constants.INGRESS_DIRECTION),
                                       None)
        if not port and not vif_port:
            LOG.debug("delete_bandwidth_limit_ingress was received "
                      "for port %s but port was not found. "
                      "It seems that bandwidth_limit is already deleted",
                      port_id)
            return
        vif_port = vif_port or port.get('vif_port')

        if cfg.CONF.OVS.qos_meter_bandwidth:
            self._delete_meter_bandwidth_rate_limit(
                port_id, direction=constants.INGRESS_DIRECTION)
        else:
            self.br_int.delete_ingress_bw_limit_for_port(vif_port.port_name)

    def create_dscp_marking(self, port, rule):
        self.update_dscp_marking(port, rule)

    def update_dscp_marking(self, port, rule):
        self.ports[port['port_id']][qos_consts.RULE_TYPE_DSCP_MARKING] = port
        vif_port = port.get('vif_port')
        if not vif_port:
            port_id = port.get('port_id')
            LOG.debug("update_dscp_marking was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        port = self.br_int.get_port_ofport(vif_port.port_name)
        self.br_int.install_dscp_marking_rule(port=port,
                                              dscp_mark=rule.dscp_mark)

    def delete_dscp_marking(self, port):
        vif_port = port.get('vif_port')
        dscp_port = self.ports[port['port_id']].pop(qos_consts.
                                                    RULE_TYPE_DSCP_MARKING, 0)

        if not dscp_port and not vif_port:
            LOG.debug("delete_dscp_marking was received for port %s but "
                      "no port information was stored to be deleted",
                      port['port_id'])
            return

        vif_port = vif_port or dscp_port.get('vif_port')
        port_num = vif_port.ofport
        self.br_int.uninstall_flows(in_port=port_num, table_id=0, reg2=0)

    def _update_egress_bandwidth_limit(self, vif_port, rule):
        max_kbps = rule.max_kbps
        # NOTE(slaweq): According to ovs docs:
        # http://openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html
        # ovs accepts only integer values of burst:
        max_burst_kbps = int(self._get_egress_burst_value(rule))

        if cfg.CONF.OVS.qos_meter_bandwidth:
            self._update_meter_bandwidth_rate_limit(
                vif_port, rule, direction=constants.EGRESS_DIRECTION)
        else:
            self.br_int.create_egress_bw_limit_for_port(vif_port.port_name,
                                                        max_kbps,
                                                        max_burst_kbps)

    def _update_ingress_bandwidth_limit(self, vif_port, rule):
        port_name = vif_port.port_name
        max_kbps = rule.max_kbps or 0
        max_burst_kbps = rule.max_burst_kbps or 0

        if cfg.CONF.OVS.qos_meter_bandwidth:
            self._update_meter_bandwidth_rate_limit(
                vif_port, rule, direction=constants.INGRESS_DIRECTION)
        else:
            self.br_int.update_ingress_bw_limit_for_port(
                port_name,
                max_kbps,
                max_burst_kbps
            )

    def create_minimum_bandwidth(self, port, rule):
        self.update_minimum_bandwidth(port, rule)

    def update_minimum_bandwidth(self, port, rule):
        vif_port = port.get('vif_port')
        if not vif_port:
            LOG.debug('update_minimum_bandwidth was received for port %s but '
                      'vif_port was not found. It seems that port is already '
                      'deleted', port.get('port_id'))
            return
        if not port.get('physical_network'):
            LOG.debug('update_minimum_bandwidth was received for port %s but '
                      'has no physical network associated',
                      port.get('port_id'))
            return

        self.ports[port['port_id']][(qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
                                     rule.direction)] = port
        if rule.direction == constants.INGRESS_DIRECTION:
            LOG.debug('Minimum bandwidth ingress rule was updated/created for '
                      'port %s and rule %s.', port['port_id'], rule.id)
            return

        # queue_num is used to identify the port which traffic come from,
        # it needs to be unique across br-int. It is convenient to use ofport
        # as queue_num because it is unique in br-int and start from 1.
        egress_port_names = []
        for phy_br in self.agent_api.request_phy_brs():
            ports = phy_br.get_bridge_ports('')
            if not ports:
                LOG.warning('Bridge %s does not have a physical port '
                            'connected', phy_br.br_name)
            egress_port_names.extend(ports)
        qos_id = self.br_int.update_minimum_bandwidth_queue(
            port['port_id'], egress_port_names, vif_port.ofport, rule.min_kbps)
        for phy_br in self.agent_api.request_phy_brs():
            phy_br.set_queue_for_minimum_bandwidth(vif_port.ofport)
        LOG.debug('Minimum bandwidth egress rule was updated/created for port '
                  '%(port_id)s and rule %(rule_id)s. QoS ID: %(qos_id)s. '
                  'Egress ports with QoS applied: %(ports)s',
                  {'port_id': port['port_id'], 'rule_id': rule.id,
                   'qos_id': qos_id, 'ports': egress_port_names})

    def delete_minimum_bandwidth(self, port):
        rule_port = self.ports[port['port_id']].pop(
            (qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
             constants.EGRESS_DIRECTION), None)
        if not rule_port:
            LOG.debug('delete_minimum_bandwidth was received for port %s but '
                      'no port information was stored to be deleted',
                      port['port_id'])
            return
        self.br_int.delete_minimum_bandwidth_queue(port['port_id'])
        LOG.debug("Minimum bandwidth rule was deleted for port: %s.",
                  port['port_id'])

    def delete_minimum_bandwidth_ingress(self, port):
        rule_port = self.ports[port['port_id']].pop(
            (qos_consts.RULE_TYPE_MINIMUM_BANDWIDTH,
             constants.INGRESS_DIRECTION), None)
        if not rule_port:
            LOG.debug('delete_minimum_bandwidth_ingress was received for port '
                      '%s but no port information was stored to be deleted',
                      port['port_id'])
            return
        LOG.debug("Minimum bandwidth rule for ingress direction was deleted "
                  "for port %s", port['port_id'])

    # NOTE(przszc): Even though dataplane enforcement is not yet implemented
    # for minimum packet rate rule, we need dummy methods to support placement
    # enforcement.
    def create_minimum_packet_rate(self, port, rule):
        LOG.debug("Minimum packet rate rule was created for port %s and "
                  "rule %s.", port['port_id'], rule.id)

    def update_minimum_packet_rate(self, port, rule):
        LOG.debug("Minimum packet rate rule was updated for port %s and "
                  "rule %s.", port['port_id'], rule.id)

    def delete_minimum_packet_rate(self, port):
        LOG.debug("Minimum packet rate rule was deleted for port %s",
                  port['port_id'])

    def delete_minimum_packet_rate_ingress(self, port):
        LOG.debug("Minimum packet rate rule for ingress direction was deleted "
                  "for port %s", port['port_id'])

    def create_packet_rate_limit(self, port, rule):
        self.update_packet_rate_limit(port, rule)

    def update_packet_rate_limit(self, port, rule):
        LOG.debug("Update packet rate limit for port: %s", port)
        vif_port = port.get('vif_port')
        if not vif_port:
            port_id = port.get('port_id')
            LOG.debug("update_packet_rate_limit was received for port %s but "
                      "vif_port was not found. It seems that port is already "
                      "deleted", port_id)
            return
        self.ports[port['port_id']][(qos_consts.RULE_TYPE_PACKET_RATE_LIMIT,
                                     rule.direction)] = port

        self._update_packet_rate_limit(vif_port, rule, rule.direction)

    def delete_packet_rate_limit(self, port):
        self._delete_packet_rate_limit(port, constants.EGRESS_DIRECTION)

    def delete_packet_rate_limit_ingress(self, port):
        self._delete_packet_rate_limit(port, constants.INGRESS_DIRECTION)
