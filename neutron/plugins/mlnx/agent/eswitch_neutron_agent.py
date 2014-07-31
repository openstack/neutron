# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import socket
import sys
import time

import eventlet
eventlet.monkey_patch()

from oslo.config import cfg

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as q_constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron import context
from neutron.openstack.common.gettextutils import _LE, _LI
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants as p_const
from neutron.plugins.mlnx.agent import utils
from neutron.plugins.mlnx.common import config  # noqa
from neutron.plugins.mlnx.common import exceptions

LOG = logging.getLogger(__name__)


class EswitchManager(object):
    def __init__(self, interface_mappings, endpoint, timeout):
        self.utils = utils.EswitchUtils(endpoint, timeout)
        self.interface_mappings = interface_mappings
        self.network_map = {}
        self.utils.define_fabric_mappings(interface_mappings)

    def get_port_id_by_mac(self, port_mac):
        for network_id, data in self.network_map.iteritems():
            for port in data['ports']:
                if port['port_mac'] == port_mac:
                    return port['port_id']
        err_msg = _("Agent cache inconsistency - port id "
                    "is not stored for %s") % port_mac
        LOG.error(err_msg)
        raise exceptions.MlnxException(err_msg=err_msg)

    def get_vnics_mac(self):
        return set(self.utils.get_attached_vnics().keys())

    def vnic_port_exists(self, port_mac):
        return port_mac in self.utils.get_attached_vnics()

    def remove_network(self, network_id):
        if network_id in self.network_map:
            del self.network_map[network_id]
        else:
            LOG.debug(_("Network %s not defined on Agent."), network_id)

    def port_down(self, network_id, physical_network, port_mac):
        """Sets port to down.

        Check internal network map for port data.
        If port exists set port to Down
        """
        for network_id, data in self.network_map.iteritems():
            for port in data['ports']:
                if port['port_mac'] == port_mac:
                    self.utils.port_down(physical_network, port_mac)
                    return
        LOG.info(_('Network %s is not available on this agent'), network_id)

    def port_up(self, network_id, network_type,
                physical_network, seg_id, port_id, port_mac):
        """Sets port to up.

        Update internal network map with port data.
        - Check if vnic defined
        - configure eswitch vport
        - set port to Up
        """
        LOG.debug(_("Connecting port %s"), port_id)

        if network_id not in self.network_map:
            self.provision_network(port_id, port_mac,
                                   network_id, network_type,
                                   physical_network, seg_id)
        net_map = self.network_map[network_id]
        net_map['ports'].append({'port_id': port_id, 'port_mac': port_mac})

        if network_type == p_const.TYPE_VLAN:
            LOG.info(_('Binding Segmentation ID %(seg_id)s'
                       'to eSwitch for vNIC mac_address %(mac)s'),
                     {'seg_id': seg_id,
                      'mac': port_mac})
            self.utils.set_port_vlan_id(physical_network,
                                        seg_id,
                                        port_mac)
            self.utils.port_up(physical_network, port_mac)
        else:
            LOG.error(_('Unsupported network type %s'), network_type)

    def port_release(self, port_mac):
        """Clear port configuration from eSwitch."""
        for network_id, net_data in self.network_map.iteritems():
            for port in net_data['ports']:
                if port['port_mac'] == port_mac:
                    self.utils.port_release(net_data['physical_network'],
                                            port['port_mac'])
                    return
        LOG.info(_('Port_mac %s is not available on this agent'), port_mac)

    def provision_network(self, port_id, port_mac,
                          network_id, network_type,
                          physical_network, segmentation_id):
        LOG.info(_("Provisioning network %s"), network_id)
        if network_type == p_const.TYPE_VLAN:
            LOG.debug(_("Creating VLAN Network"))
        else:
            LOG.error(_("Unknown network type %(network_type)s "
                        "for network %(network_id)s"),
                      {'network_type': network_type,
                       'network_id': network_id})
            return
        data = {
            'physical_network': physical_network,
            'network_type': network_type,
            'ports': [],
            'vlan_id': segmentation_id}
        self.network_map[network_id] = data


class MlnxEswitchRpcCallbacks(n_rpc.RpcCallback,
                              sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    def __init__(self, context, agent):
        super(MlnxEswitchRpcCallbacks, self).__init__()
        self.context = context
        self.agent = agent
        self.eswitch = agent.eswitch
        self.sg_agent = agent

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        if not network_id:
            LOG.warning(_("Invalid Network ID, cannot remove Network"))
        else:
            LOG.debug(_("Delete network %s"), network_id)
            self.eswitch.remove_network(network_id)

    def port_update(self, context, **kwargs):
        port = kwargs.get('port')
        self.agent.add_port_update(port['mac_address'])
        LOG.debug("port_update message processed for port with mac %s",
                  port['mac_address'])


class MlnxEswitchPluginApi(agent_rpc.PluginApi,
                           sg_rpc.SecurityGroupServerRpcApiMixin):
    pass


class MlnxEswitchNeutronAgent(sg_rpc.SecurityGroupAgentRpcMixin):
    # Set RPC API version to 1.0 by default.
    #RPC_API_VERSION = '1.0'

    def __init__(self, interface_mapping):
        self._polling_interval = cfg.CONF.AGENT.polling_interval
        self._setup_eswitches(interface_mapping)
        configurations = {'interface_mappings': interface_mapping}
        self.agent_state = {
            'binary': 'neutron-mlnx-agent',
            'host': cfg.CONF.host,
            'topic': q_constants.L2_AGENT_TOPIC,
            'configurations': configurations,
            'agent_type': q_constants.AGENT_TYPE_MLNX,
            'start_flag': True}
        # Stores port update notifications for processing in main rpc loop
        self.updated_ports = set()
        self._setup_rpc()
        self.init_firewall()

    def _setup_eswitches(self, interface_mapping):
        daemon = cfg.CONF.ESWITCH.daemon_endpoint
        timeout = cfg.CONF.ESWITCH.request_timeout
        self.eswitch = EswitchManager(interface_mapping, daemon, timeout)

    def _report_state(self):
        try:
            devices = len(self.eswitch.get_vnics_mac())
            self.agent_state.get('configurations')['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def _setup_rpc(self):
        self.agent_id = 'mlnx-agent.%s' % socket.gethostname()
        LOG.info(_("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.plugin_rpc = MlnxEswitchPluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.endpoints = [MlnxEswitchRpcCallbacks(self.context, self)]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE],
                     [topics.SECURITY_GROUP, topics.UPDATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers)

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def add_port_update(self, port):
        self.updated_ports.add(port)

    def scan_ports(self, previous, sync):
        cur_ports = self.eswitch.get_vnics_mac()
        port_info = {'current': cur_ports}
        updated_ports = self.updated_ports
        self.updated_ports = set()
        if sync:
            # Either it's the first iteration or previous iteration had
            # problems.
            port_info['added'] = cur_ports
            port_info['removed'] = ((previous['removed'] | previous['current'])
                                    - cur_ports)
            port_info['updated'] = ((previous['updated'] | updated_ports)
                                    & cur_ports)
        else:
            # Shouldn't process updates for not existing ports
            port_info['added'] = cur_ports - previous['current']
            port_info['removed'] = previous['current'] - cur_ports
            port_info['updated'] = updated_ports & cur_ports
        return port_info

    def process_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        device_added_updated = port_info['added'] | port_info['updated']

        if device_added_updated:
            resync_a = self.treat_devices_added_or_updated(
                device_added_updated)
        if port_info['removed']:
            resync_b = self.treat_devices_removed(port_info['removed'])
        # If one of the above opertaions fails => resync with plugin
        return (resync_a | resync_b)

    def treat_vif_port(self, port_id, port_mac,
                       network_id, network_type,
                       physical_network, segmentation_id,
                       admin_state_up):
        if self.eswitch.vnic_port_exists(port_mac):
            if admin_state_up:
                self.eswitch.port_up(network_id,
                                     network_type,
                                     physical_network,
                                     segmentation_id,
                                     port_id,
                                     port_mac)
            else:
                self.eswitch.port_down(network_id, physical_network, port_mac)
        else:
            LOG.debug(_("No port %s defined on agent."), port_id)

    def treat_devices_added_or_updated(self, devices):
        try:
            devs_details_list = self.plugin_rpc.get_devices_details_list(
                self.context,
                devices,
                self.agent_id)
        except Exception as e:
            LOG.debug("Unable to get device details for devices "
                      "with MAC address %(devices)s: due to %(exc)s",
                      {'devices': devices, 'exc': e})
            # resync is needed
            return True

        for dev_details in devs_details_list:
            device = dev_details['device']
            LOG.info(_("Adding or updating port with mac %s"), device)

            if 'port_id' in dev_details:
                LOG.info(_("Port %s updated"), device)
                LOG.debug("Device details %s", str(dev_details))
                self.treat_vif_port(dev_details['port_id'],
                                    dev_details['device'],
                                    dev_details['network_id'],
                                    dev_details['network_type'],
                                    dev_details['physical_network'],
                                    dev_details['segmentation_id'],
                                    dev_details['admin_state_up'])
                if dev_details.get('admin_state_up'):
                    LOG.debug("Setting status for %s to UP", device)
                    self.plugin_rpc.update_device_up(
                        self.context, device, self.agent_id)
                else:
                    LOG.debug("Setting status for %s to DOWN", device)
                    self.plugin_rpc.update_device_down(
                        self.context, device, self.agent_id)
            else:
                LOG.debug("Device with mac_address %s not defined "
                          "on Neutron Plugin", device)
        return False

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Removing device with mac_address %s"), device)
            try:
                port_id = self.eswitch.get_port_id_by_mac(device)
                dev_details = self.plugin_rpc.update_device_down(self.context,
                                                                 port_id,
                                                                 self.agent_id,
                                                                 cfg.CONF.host)
            except Exception as e:
                LOG.debug(_("Removing port failed for device %(device)s "
                          "due to %(exc)s"), {'device': device, 'exc': e})
                resync = True
                continue
            if dev_details['exists']:
                LOG.info(_("Port %s updated."), device)
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
            self.eswitch.port_release(device)
        return resync

    def _port_info_has_changes(self, port_info):
        return (port_info['added'] or
                port_info['removed'] or
                port_info['updated'])

    def daemon_loop(self):
        LOG.info(_("eSwitch Agent Started!"))
        sync = True
        port_info = {'current': set(),
                     'added': set(),
                     'removed': set(),
                     'updated': set()}
        while True:
            start = time.time()
            try:
                port_info = self.scan_ports(previous=port_info, sync=sync)
            except exceptions.RequestTimeout:
                LOG.exception(_("Request timeout in agent event loop "
                                "eSwitchD is not responding - exiting..."))
                raise SystemExit(1)
            if sync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                sync = False
            if self._port_info_has_changes(port_info):
                LOG.debug("Starting to process devices in:%s", port_info)
                try:
                    sync = self.process_network_ports(port_info)
                except Exception:
                    LOG.exception(_LE("Error in agent event loop"))
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
    common_config.init(sys.argv[1:])
    common_config.setup_logging()

    try:
        interface_mappings = q_utils.parse_mappings(
            cfg.CONF.ESWITCH.physical_interface_mappings)
    except ValueError as e:
        LOG.error(_("Parsing physical_interface_mappings failed: %s."
                    " Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_("Interface mappings: %s"), interface_mappings)

    try:
        agent = MlnxEswitchNeutronAgent(interface_mappings)
    except Exception as e:
        LOG.error(_("Failed on Agent initialisation : %s."
                    " Agent terminated!"), e)
        sys.exit(1)

    # Start everything.
    LOG.info(_("Agent initialised successfully, now running... "))
    agent.daemon_loop()
    sys.exit(0)


if __name__ == '__main__':
    main()
