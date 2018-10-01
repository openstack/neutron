# Copyright (c) 2017 Fujitsu Limited
# All Rights Reserved.
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

from neutron_lib import constants as lib_const
from os_ken.base import app_manager
from os_ken.lib.packet import packet
from oslo_config import cfg
from oslo_log import formatters
from oslo_log import handlers
from oslo_log import log as logging

from neutron.agent.linux.openvswitch_firewall import constants as ovsfw_consts
from neutron.agent.linux.openvswitch_firewall import firewall as ovsfw
from neutron.agent.linux.openvswitch_firewall import rules
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants \
        as ovs_consts
from neutron.services.logapi.agent import log_extension as log_ext
from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import exceptions as log_exc
from neutron.services.logapi.drivers.openvswitch import log_oskenapp

LOG = logging.getLogger(__name__)

OVS_FW_TO_LOG_TABLES = {
    ovs_consts.RULES_EGRESS_TABLE: ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
    ovs_consts.RULES_INGRESS_TABLE: ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
}

FIELDS_TO_REMOVE = ['priority', 'actions', 'dl_type',
                    'reg_port', 'reg_remote_group']

REMOTE_RULE_PRIORITY = 70


def setup_logging():
    log_file = cfg.CONF.network_log.local_output_log_base
    if log_file:
        from logging import handlers as watch_handler
        log_file_handler = watch_handler.WatchedFileHandler(log_file)
        log_file_handler.setLevel(
            logging.DEBUG if cfg.CONF.debug else logging.INFO)
        LOG.logger.addHandler(log_file_handler)
        log_file_handler.setFormatter(
            formatters.ContextFormatter(
                fmt=cfg.CONF.logging_default_format_string,
                datefmt=cfg.CONF.log_date_format))
    elif cfg.CONF.use_journal:
        journal_handler = handlers.OSJournalHandler()
        LOG.logger.addHandler(journal_handler)
    else:
        syslog_handler = handlers.OSSysLogHandler()
        LOG.logger.addHandler(syslog_handler)


def find_deleted_sg_rules(old_port, new_ports):
    del_rules = list()
    for port in new_ports:
        if old_port.id == port.id:
            for rule in old_port.secgroup_rules:
                if rule not in port.secgroup_rules:
                    del_rules.append(rule)
            return del_rules
    return del_rules


class Cookie(object):

    def __init__(self, cookie_id, port, action, project):
        self.id = cookie_id
        self.port = port
        self.action = action
        self.project = project
        self.log_object_refs = set()

    def __eq__(self, other):
        return (self.id == other.id and
                self.action == other.action and
                self.port == other.port)

    def __hash__(self):
        return hash(self.id)

    def add_log_obj_ref(self, log_id):
        self.log_object_refs.add(log_id)

    def remove_log_obj_ref(self, log_id):
        self.log_object_refs.discard(log_id)

    @property
    def is_empty(self):
        return not self.log_object_refs


class OFPortLog(object):

    def __init__(self, port, ovs_port, log_event):
        self.id = port['port_id']
        self.ofport = ovs_port.ofport
        self.secgroup_rules = [self._update_rule(rule) for rule in
                               port['security_group_rules']]
        # event can be ALL, DROP and ACCEPT
        self.event = log_event

    def _update_rule(self, rule):
        protocol = rule.get('protocol')
        if protocol is not None:
            if not isinstance(protocol, int) and protocol.isdigit():
                rule['protocol'] = int(protocol)
            elif (rule.get('ethertype') == lib_const.IPv6 and
                  protocol == lib_const.PROTO_NAME_ICMP):
                rule['protocol'] = lib_const.PROTO_NUM_IPV6_ICMP
            else:
                rule['protocol'] = lib_const.IP_PROTOCOL_MAP.get(
                    protocol, protocol)
        return rule


class OVSFirewallLoggingDriver(log_ext.LoggingDriver):

    SUPPORTED_LOGGING_TYPES = ['security_group']
    REQUIRED_PROTOCOLS = [
        ovs_consts.OPENFLOW13,
        ovs_consts.OPENFLOW14,
    ]

    def __init__(self, agent_api):
        integration_bridge = agent_api.request_int_br()
        self.int_br = self.initialize_bridge(integration_bridge)
        self._deferred = False
        self.log_ports = collections.defaultdict(dict)
        self.cookies_table = set()
        self.cookie_ids_to_delete = set()
        self.conj_id_map = ovsfw.ConjIdMap()

    def initialize(self, resource_rpc, **kwargs):
        self.resource_rpc = resource_rpc
        setup_logging()
        self.start_logapp()

    @staticmethod
    def initialize_bridge(bridge):
        bridge.add_protocols(*OVSFirewallLoggingDriver.REQUIRED_PROTOCOLS)
        # set rate limit and burst limit for controller
        bridge.set_controller_rate_limit(cfg.CONF.network_log.rate_limit)
        bridge.set_controller_burst_limit(cfg.CONF.network_log.burst_limit)
        return bridge.deferred(full_ordered=True)

    def start_logapp(self):
        app_mgr = app_manager.AppManager.get_instance()
        self.log_app = app_mgr.instantiate(log_oskenapp.OVSLogOSKenApp)
        self.log_app.start()
        self.log_app.register_packet_in_handler(self.packet_in_handler)

    def packet_in_handler(self, ev):
        msg = ev.msg
        cookie_id = msg.cookie
        pkt = packet.Packet(msg.data)
        try:
            cookie_entry = self._get_cookie_by_id(cookie_id)
            LOG.info("action=%s project_id=%s log_resource_ids=%s vm_port=%s "
                     "pkt=%s", cookie_entry.action, cookie_entry.project,
                     list(cookie_entry.log_object_refs),
                     cookie_entry.port, pkt)
        except log_exc.CookieNotFound:
            LOG.warning("Unknown cookie=%s packet_in pkt=%s", cookie_id, pkt)

    def defer_apply_on(self):
        self._deferred = True

    def defer_apply_off(self):
        if self._deferred:
            self.int_br.apply_flows()
            self._cleanup_cookies()
            self._deferred = False

    def _get_cookie(self, port_id, action):
        for cookie in self.cookies_table:
            if cookie.port == port_id and cookie.action == action:
                return cookie

    def _get_cookies_by_port(self, port_id):
        cookies_list = []
        for cookie in self.cookies_table:
            if cookie.port == port_id:
                cookies_list.append(cookie)
        return cookies_list

    def _get_cookie_by_id(self, cookie_id):
        for cookie in self.cookies_table:
            if str(cookie.id) == str(cookie_id):
                return cookie
        raise log_exc.CookieNotFound(cookie_id=cookie_id)

    def _cleanup_cookies(self):
        cookie_ids = self.cookie_ids_to_delete
        self.cookie_ids_to_delete = set()
        for cookie_id in cookie_ids:
            self.int_br.br.unset_cookie(cookie_id)

    def generate_cookie(self, port_id, action, log_id, project_id):
        cookie = self._get_cookie(port_id, action)
        if not cookie:
            cookie_id = self.int_br.br.request_cookie()
            cookie = Cookie(cookie_id=cookie_id, port=port_id,
                            action=action, project=project_id)
            self.cookies_table.add(cookie)
        cookie.add_log_obj_ref(log_id)
        return cookie.id

    def _schedule_cookie_deletion(self, cookie):
        # discard a cookie object
        self.cookies_table.remove(cookie)
        # schedule to cleanup cookie_ids later
        self.cookie_ids_to_delete.add(cookie.id)

    def start_logging(self, context, **kwargs):
        LOG.debug("start logging: %s", str(kwargs))
        for resource_type in self.SUPPORTED_LOGGING_TYPES:
            # handle port updated, agent restarted
            if 'port_id' in kwargs:
                self._handle_logging('_create', context,
                                     resource_type, **kwargs)
            else:
                self._handle_log_resources_by_type(
                    '_create', context, resource_type, **kwargs)

    def stop_logging(self, context, **kwargs):
        LOG.debug("stop logging: %s", str(kwargs))
        for resource_type in self.SUPPORTED_LOGGING_TYPES:
            # handle port deleted
            if 'port_id' in kwargs:
                self._handle_logging('_delete', context,
                                     resource_type, **kwargs)
            else:
                self._handle_log_resources_by_type(
                    '_delete', context, resource_type, **kwargs)

    def _handle_log_resources_by_type(
            self, action, context, resource_type, **kwargs):

        log_resources = []
        for log_obj in kwargs.get('log_resources', []):
            if log_obj['resource_type'] == resource_type:
                log_resources.append(log_obj)
        if log_resources:
            self._handle_logging(
                action, context, resource_type, log_resources=log_resources)

    def _handle_logging(self, action, context, resource_type, **kwargs):
        handler_name = "%s_%s_log" % (action, resource_type)
        handler = getattr(self, handler_name)
        handler(context, **kwargs)

    def create_ofport_log(self, port, log_id, log_event):
        port_id = port['port_id']
        ovs_port = self.int_br.br.get_vif_port_by_id(port_id)
        if ovs_port:
            of_port_log = OFPortLog(port, ovs_port, log_event)
            self.log_ports[log_id].add(of_port_log)

    def _create_security_group_log(self, context, **kwargs):

        port_id = kwargs.get('port_id')
        log_resources = kwargs.get('log_resources')
        logs_info = []
        if port_id:
            # try to clean port flows log for port updated/create event
            self._cleanup_port_flows_log(port_id)
            logs_info = self.resource_rpc.get_sg_log_info_for_port(
                context,
                resource_type=log_const.SECURITY_GROUP,
                port_id=port_id)
        elif log_resources:
            logs_info = self.resource_rpc.get_sg_log_info_for_log_resources(
                context,
                resource_type=log_const.SECURITY_GROUP,
                log_resources=log_resources)

        for log_info in logs_info:
            log_id = log_info['id']
            old_ofport_logs = self.log_ports.get(log_id, [])
            ports = log_info.get('ports_log')
            self.log_ports[log_id] = set()
            for port in ports:
                self.create_ofport_log(port, log_id, log_info.get('event'))

            # try to clean flows log if sg_rules are deleted
            for port in old_ofport_logs:
                del_rules = find_deleted_sg_rules(
                    port, self.log_ports[log_id])
                if del_rules:
                    self._delete_sg_rules_flow_log(port, del_rules)

            for port_log in self.log_ports[log_id]:
                self.add_flows_from_rules(port_log, log_info)

    def _cleanup_port_flows_log(self, port_id):
        cookies_list = self._get_cookies_by_port(port_id)
        for cookie in cookies_list:
            if cookie.action == log_const.ACCEPT_EVENT:
                self._delete_flows(
                    table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                    cookie=cookie.id)
                self._delete_flows(
                    table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
                    cookie=cookie.id)
            if cookie.action == log_const.DROP_EVENT:
                self._delete_flows(
                    table=ovs_consts.DROPPED_TRAFFIC_TABLE,
                    cookie=cookie.id)
            self._schedule_cookie_deletion(cookie)

    def _delete_security_group_log(self, context, **kwargs):
        # port deleted event
        port_id = kwargs.get('port_id')

        if port_id:
            self._cleanup_port_flows_log(port_id)

        # log resources deleted events
        for log_resource in kwargs.get('log_resources', []):
            log_id = log_resource.get('id')
            of_port_logs = self.log_ports.get(log_id, [])
            for of_port_log in of_port_logs:
                self.delete_port_flows_log(of_port_log, log_id)

    def _log_accept_flow(self, **flow):
        # log first accepted packet
        flow['table'] = OVS_FW_TO_LOG_TABLES[flow['table']]
        flow['actions'] = 'controller'
        # forward egress accepted packet and log
        if flow['table'] == ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE:
            flow['actions'] = 'resubmit(,%d),controller' % (
                ovs_consts.ACCEPTED_EGRESS_TRAFFIC_NORMAL_TABLE)
        self._add_flow(**flow)

    def _add_flow(self, **kwargs):
        dl_type = kwargs.get('dl_type')
        ovsfw.create_reg_numbers(kwargs)
        if isinstance(dl_type, int):
            kwargs['dl_type'] = "0x{:04x}".format(dl_type)
        LOG.debug("Add flow firewall log %s", str(kwargs))
        if self._deferred:
            self.int_br.add_flow(**kwargs)
        else:
            self.int_br.br.add_flow(**kwargs)

    def _delete_flows(self, **kwargs):
        ovsfw.create_reg_numbers(kwargs)
        if self._deferred:
            self.int_br.delete_flows(**kwargs)
        else:
            self.int_br.br.delete_flows(**kwargs)

    def _log_drop_packet(self, port, log_id, project_id):
        cookie = self.generate_cookie(port.id, log_const.DROP_EVENT,
                                      log_id, project_id)
        self._add_flow(
            cookie=cookie,
            table=ovs_consts.DROPPED_TRAFFIC_TABLE,
            priority=53,
            reg_port=port.ofport,
            actions='controller'
        )

    def create_rules_generator_for_port(self, port):
        for rule in port.secgroup_rules:
            yield rule

    def _create_conj_flows_log(self, remote_rule, port):
        ethertype = remote_rule['ethertype']
        direction = remote_rule['direction']
        remote_sg_id = remote_rule['remote_group_id']
        secgroup_id = remote_rule['security_group_id']
        # we only want to log first accept packet, that means a packet with
        # ct_state=+new-est, reg_remote_group=conj_id + 1 will be logged
        flow_template = {
            'priority': REMOTE_RULE_PRIORITY,
            'dl_type': ovsfw_consts.ethertype_to_dl_type_map[ethertype],
            'reg_port': port.ofport,
            'reg_remote_group': self.conj_id_map.get_conj_id(
                secgroup_id, remote_sg_id, direction, ethertype) + 1,
        }
        if direction == lib_const.INGRESS_DIRECTION:
            flow_template['table'] = ovs_consts.RULES_INGRESS_TABLE
        elif direction == lib_const.EGRESS_DIRECTION:
            flow_template['table'] = ovs_consts.RULES_EGRESS_TABLE
        return [flow_template]

    def _log_accept_packet(self, port, log_id, project_id):
        cookie = self.generate_cookie(port.id, log_const.ACCEPT_EVENT,
                                      log_id, project_id)
        for rule in self.create_rules_generator_for_port(port):
            if 'remote_group_id' in rule:
                flows = self._create_conj_flows_log(rule, port)
            else:
                flows = rules.create_flows_from_rule_and_port(rule, port)
            for flow in flows:
                flow['cookie'] = cookie
                self._log_accept_flow(**flow)

    def add_flows_from_rules(self, port, log_info):
        # log event can be ACCEPT or DROP or ALL(both ACCEPT and DROP)
        event = log_info['event']
        project_id = log_info['project_id']
        log_id = log_info['id']
        if event == log_const.ACCEPT_EVENT:
            self._log_accept_packet(port, log_id, project_id)
        elif event == log_const.DROP_EVENT:
            self._log_drop_packet(port, log_id, project_id)
        else:
            self._log_drop_packet(port, log_id, project_id)
            self._log_accept_packet(port, log_id, project_id)

    def _delete_accept_flows_log(self, port, log_id):
        cookie = self._get_cookie(port.id, log_const.ACCEPT_EVENT)
        if cookie:
            cookie.remove_log_obj_ref(log_id)
            if cookie.is_empty:
                self._delete_flows(
                    table=ovs_consts.ACCEPTED_INGRESS_TRAFFIC_TABLE,
                    cookie=cookie.id)
                self._delete_flows(
                    table=ovs_consts.ACCEPTED_EGRESS_TRAFFIC_TABLE,
                    cookie=cookie.id)
                self._schedule_cookie_deletion(cookie)

    def _delete_drop_flows_log(self, port, log_id):
        cookie = self._get_cookie(port.id, log_const.DROP_EVENT)
        if cookie:
            cookie.remove_log_obj_ref(log_id)
            if cookie.is_empty:
                self._delete_flows(table=ovs_consts.DROPPED_TRAFFIC_TABLE,
                                   cookie=cookie.id)
                self._schedule_cookie_deletion(cookie)

    def delete_port_flows_log(self, port, log_id):
        """Delete all flows log for given port and log_id"""
        event = port.event
        if event == log_const.ACCEPT_EVENT:
            self._delete_accept_flows_log(port, log_id)
        elif event == log_const.DROP_EVENT:
            self._delete_drop_flows_log(port, log_id)
        else:
            self._delete_accept_flows_log(port, log_id)
            self._delete_drop_flows_log(port, log_id)

    def _delete_sg_rules_flow_log(self, port, del_rules):
        cookie = self._get_cookie(port.id, log_const.ACCEPT_EVENT)
        if not cookie:
            return
        for rule in del_rules:
            if 'remote_group_id' in rule:
                flows = self._create_conj_flows_log(rule, port)
            else:
                flows = rules.create_flows_from_rule_and_port(rule, port)
            for flow in flows:
                for kw in FIELDS_TO_REMOVE:
                    flow.pop(kw, None)
                flow['table'] = OVS_FW_TO_LOG_TABLES[flow['table']]
                flow['cookie'] = cookie.id
                self._delete_flows(**flow)
