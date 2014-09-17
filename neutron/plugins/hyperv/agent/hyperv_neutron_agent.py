# vim: tabstop=4 shiftwidth=4 softtabstop=4

#Copyright 2013 Cloudbase Solutions SRL
#Copyright 2013 Pedro Navarro Perez
#All Rights Reserved.
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
# @author: Pedro Navarro Perez
# @author: Alessandro Pilotti, Cloudbase Solutions Srl

import eventlet
import platform
import re
import time

from oslo.config import cfg

from neutron.agent.common import config
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as logging_config
from neutron.common import constants as n_const
from neutron.common import topics
from neutron import context
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.openstack.common.rpc import dispatcher
from neutron.plugins.common import constants as p_const
from neutron.plugins.hyperv.agent import utils
from neutron.plugins.hyperv.agent import utilsfactory
from neutron.plugins.hyperv.common import constants

LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.ListOpt(
        'physical_network_vswitch_mappings',
        default=[],
        help=_('List of <physical_network>:<vswitch> '
               'where the physical networks can be expressed with '
               'wildcards, e.g.: ."*:external"')),
    cfg.StrOpt(
        'local_network_vswitch',
        default='private',
        help=_('Private vswitch name used for local networks')),
    cfg.IntOpt('polling_interval', default=2,
               help=_("The number of seconds the agent will wait between "
                      "polling for local device changes.")),
    cfg.BoolOpt('enable_metrics_collection',
                default=False,
                help=_('Enables metrics collections for switch ports by using '
                       'Hyper-V\'s metric APIs. Collected data can by '
                       'retrieved by other apps and services, e.g.: '
                       'Ceilometer. Requires Hyper-V / Windows Server 2012 '
                       'and above')),
    cfg.IntOpt('metrics_max_retries',
               default=100,
               help=_('Specifies the maximum number of retries to enable '
                      'Hyper-V\'s port metrics collection. The agent will try '
                      'to enable the feature once every polling_interval '
                      'period for at most metrics_max_retries or until it '
                      'succeedes.'))
]


CONF = cfg.CONF
CONF.register_opts(agent_opts, "AGENT")
config.register_agent_state_opts_helper(cfg.CONF)


class HyperVSecurityAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    # Set RPC API version to 1.1 by default.
    RPC_API_VERSION = '1.1'

    def __init__(self, context, plugin_rpc):
        self.context = context
        self.plugin_rpc = plugin_rpc

        if sg_rpc.is_firewall_enabled():
            self.init_firewall()
            self._setup_rpc()

    def _setup_rpc(self):
        self.topic = topics.AGENT
        self.dispatcher = self._create_rpc_dispatcher()
        consumers = [[topics.SECURITY_GROUP, topics.UPDATE]]

        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

    def _create_rpc_dispatcher(self):
        rpc_callback = HyperVSecurityCallbackMixin(self)
        return dispatcher.RpcDispatcher([rpc_callback])


class HyperVSecurityCallbackMixin(sg_rpc.SecurityGroupAgentRpcCallbackMixin):
    # Set RPC API version to 1.1 by default.
    RPC_API_VERSION = '1.1'

    def __init__(self, sg_agent):
        self.sg_agent = sg_agent


class HyperVPluginApi(agent_rpc.PluginApi,
                      sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class HyperVNeutronAgent(object):
    # Set RPC API version to 1.1 by default.
    RPC_API_VERSION = '1.1'

    def __init__(self):
        self._utils = utilsfactory.get_hypervutils()
        self._polling_interval = CONF.AGENT.polling_interval
        self._load_physical_network_mappings()
        self._network_vswitch_map = {}
        self._port_metric_retries = {}
        self._set_agent_state()
        self._setup_rpc()

    def _set_agent_state(self):
        self.agent_state = {
            'binary': 'neutron-hyperv-agent',
            'host': cfg.CONF.host,
            'topic': n_const.L2_AGENT_TOPIC,
            'configurations': {'vswitch_mappings':
                               self._physical_network_mappings},
            'agent_type': n_const.AGENT_TYPE_HYPERV,
            'start_flag': True}

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception as ex:
            LOG.exception(_("Failed reporting state! %s"), ex)

    def _setup_rpc(self):
        self.agent_id = 'hyperv_%s' % platform.node()
        self.topic = topics.AGENT
        self.plugin_rpc = HyperVPluginApi(topics.PLUGIN)

        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)

        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.dispatcher = self._create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.PORT, topics.DELETE],
                     [constants.TUNNEL, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

        self.sec_groups_agent = HyperVSecurityAgent(
            self.context, self.plugin_rpc)
        report_interval = CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.LoopingCall(self._report_state)
            heartbeat.start(interval=report_interval)

    def _load_physical_network_mappings(self):
        self._physical_network_mappings = {}
        for mapping in CONF.AGENT.physical_network_vswitch_mappings:
            parts = mapping.split(':')
            if len(parts) != 2:
                LOG.debug(_('Invalid physical network mapping: %s'), mapping)
            else:
                pattern = re.escape(parts[0].strip()).replace('\\*', '.*')
                vswitch = parts[1].strip()
                self._physical_network_mappings[pattern] = vswitch

    def _get_vswitch_for_physical_network(self, phys_network_name):
        for pattern in self._physical_network_mappings:
            if phys_network_name is None:
                phys_network_name = ''
            if re.match(pattern, phys_network_name):
                return self._physical_network_mappings[pattern]
        # Not found in the mappings, the vswitch has the same name
        return phys_network_name

    def _get_network_vswitch_map_by_port_id(self, port_id):
        for network_id, map in self._network_vswitch_map.iteritems():
            if port_id in map['ports']:
                return (network_id, map)

    def network_delete(self, context, network_id=None):
        LOG.debug(_("network_delete received. "
                    "Deleting network %s"), network_id)
        # The network may not be defined on this agent
        if network_id in self._network_vswitch_map:
            self._reclaim_local_network(network_id)
        else:
            LOG.debug(_("Network %s not defined on agent."), network_id)

    def port_delete(self, context, port_id=None):
        LOG.debug(_("port_delete received"))
        self._port_unbound(port_id)

    def port_update(self, context, port=None, network_type=None,
                    segmentation_id=None, physical_network=None):
        LOG.debug(_("port_update received"))
        if CONF.SECURITYGROUP.enable_security_group:
            if 'security_groups' in port:
                self.sec_groups_agent.refresh_firewall()

        self._treat_vif_port(
            port['id'], port['network_id'],
            network_type, physical_network,
            segmentation_id, port['admin_state_up'])

    def _create_rpc_dispatcher(self):
        return dispatcher.RpcDispatcher([self])

    def _get_vswitch_name(self, network_type, physical_network):
        if network_type != p_const.TYPE_LOCAL:
            vswitch_name = self._get_vswitch_for_physical_network(
                physical_network)
        else:
            vswitch_name = CONF.AGENT.local_network_vswitch
        return vswitch_name

    def _provision_network(self, port_id,
                           net_uuid, network_type,
                           physical_network,
                           segmentation_id):
        LOG.info(_("Provisioning network %s"), net_uuid)

        vswitch_name = self._get_vswitch_name(network_type, physical_network)

        if network_type in [p_const.TYPE_VLAN, p_const.TYPE_FLAT]:
            #Nothing to do
            pass
        elif network_type == p_const.TYPE_LOCAL:
            #TODO(alexpilotti): Check that the switch type is private
            #or create it if not existing
            pass
        else:
            raise utils.HyperVException(
                msg=(_("Cannot provision unknown network type %(network_type)s"
                       " for network %(net_uuid)s") %
                     dict(network_type=network_type, net_uuid=net_uuid)))

        map = {
            'network_type': network_type,
            'vswitch_name': vswitch_name,
            'ports': [],
            'vlan_id': segmentation_id}
        self._network_vswitch_map[net_uuid] = map

    def _reclaim_local_network(self, net_uuid):
        LOG.info(_("Reclaiming local network %s"), net_uuid)
        del self._network_vswitch_map[net_uuid]

    def _port_bound(self, port_id,
                    net_uuid,
                    network_type,
                    physical_network,
                    segmentation_id):
        LOG.debug(_("Binding port %s"), port_id)

        if net_uuid not in self._network_vswitch_map:
            self._provision_network(
                port_id, net_uuid, network_type,
                physical_network, segmentation_id)

        map = self._network_vswitch_map[net_uuid]
        map['ports'].append(port_id)

        self._utils.connect_vnic_to_vswitch(map['vswitch_name'], port_id)

        if network_type == p_const.TYPE_VLAN:
            LOG.info(_('Binding VLAN ID %(segmentation_id)s '
                       'to switch port %(port_id)s'),
                     dict(segmentation_id=segmentation_id, port_id=port_id))
            self._utils.set_vswitch_port_vlan_id(
                segmentation_id,
                port_id)
        elif network_type == p_const.TYPE_FLAT:
            #Nothing to do
            pass
        elif network_type == p_const.TYPE_LOCAL:
            #Nothing to do
            pass
        else:
            LOG.error(_('Unsupported network type %s'), network_type)

        if CONF.AGENT.enable_metrics_collection:
            self._utils.enable_port_metrics_collection(port_id)
            self._port_metric_retries[port_id] = CONF.AGENT.metrics_max_retries

    def _port_unbound(self, port_id):
        (net_uuid, map) = self._get_network_vswitch_map_by_port_id(port_id)
        if net_uuid not in self._network_vswitch_map:
            LOG.info(_('Network %s is not avalailable on this agent'),
                     net_uuid)
            return

        LOG.debug(_("Unbinding port %s"), port_id)
        self._utils.disconnect_switch_port(map['vswitch_name'], port_id, True)

        if not map['ports']:
            self._reclaim_local_network(net_uuid)

    def _port_enable_control_metrics(self):
        if not CONF.AGENT.enable_metrics_collection:
            return

        for port_id in self._port_metric_retries.keys():
            if self._utils.can_enable_control_metrics(port_id):
                self._utils.enable_control_metrics(port_id)
                LOG.info(_('Port metrics enabled for port: %s'), port_id)
                del self._port_metric_retries[port_id]
            elif self._port_metric_retries[port_id] < 1:
                self._utils.enable_control_metrics(port_id)
                LOG.error(_('Port metrics raw enabling for port: %s'), port_id)
                del self._port_metric_retries[port_id]
            else:
                self._port_metric_retries[port_id] -= 1

    def _update_ports(self, registered_ports):
        ports = self._utils.get_vnic_ids()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def _treat_vif_port(self, port_id, network_id, network_type,
                        physical_network, segmentation_id,
                        admin_state_up):
        if self._utils.vnic_port_exists(port_id):
            if admin_state_up:
                self._port_bound(port_id, network_id, network_type,
                                 physical_network, segmentation_id)
            else:
                self._port_unbound(port_id)
        else:
            LOG.debug(_("No port %s defined on agent."), port_id)

    def _treat_devices_added(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Adding port %s"), device)
            try:
                device_details = self.plugin_rpc.get_device_details(
                    self.context,
                    device,
                    self.agent_id)
            except Exception as e:
                LOG.debug(
                    _("Unable to get port details for "
                      "device %(device)s: %(e)s"),
                    {'device': device, 'e': e})
                resync = True
                continue
            if 'port_id' in device_details:
                LOG.info(
                    _("Port %(device)s updated. Details: %(device_details)s"),
                    {'device': device, 'device_details': device_details})
                self._treat_vif_port(
                    device_details['port_id'],
                    device_details['network_id'],
                    device_details['network_type'],
                    device_details['physical_network'],
                    device_details['segmentation_id'],
                    device_details['admin_state_up'])

                # check if security groups is enabled.
                # if not, teardown the security group rules
                if CONF.SECURITYGROUP.enable_security_group:
                    self.sec_groups_agent.prepare_devices_filter([device])
                else:
                    self._utils.remove_all_security_rules(
                        device_details['port_id'])
                self.plugin_rpc.update_device_up(self.context,
                                                 device,
                                                 self.agent_id,
                                                 cfg.CONF.host)
        return resync

    def _treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Removing port %s"), device)
            try:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
            except Exception as e:
                LOG.debug(
                    _("Removing port failed for device %(device)s: %(e)s"),
                    dict(device=device, e=e))
                resync = True
                continue
            self._port_unbound(device)
        return resync

    def _process_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            resync_a = self._treat_devices_added(port_info['added'])
        if 'removed' in port_info:
            resync_b = self._treat_devices_removed(port_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def daemon_loop(self):
        sync = True
        ports = set()

        while True:
            try:
                start = time.time()
                if sync:
                    LOG.info(_("Agent out of sync with plugin!"))
                    ports.clear()
                    sync = False

                port_info = self._update_ports(ports)

                # notify plugin about port deltas
                if port_info:
                    LOG.debug(_("Agent loop has new devices!"))
                    # If treat devices fails - must resync with plugin
                    sync = self._process_network_ports(port_info)
                    ports = port_info['current']

                self._port_enable_control_metrics()
            except Exception as e:
                LOG.exception(_("Error in agent event loop: %s"), e)
                sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self._polling_interval):
                time.sleep(self._polling_interval - elapsed)
            else:
                LOG.debug(_("Loop iteration exceeded interval "
                            "(%(polling_interval)s vs. %(elapsed)s)"),
                          {'polling_interval': self._polling_interval,
                           'elapsed': elapsed})


def main():
    eventlet.monkey_patch()
    cfg.CONF(project='neutron')
    logging_config.setup_logging(cfg.CONF)

    plugin = HyperVNeutronAgent()

    # Start everything.
    LOG.info(_("Agent initialized successfully, now running... "))
    plugin.daemon_loop()
