# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
from oslo.config import cfg

from quantum.agent import rpc as agent_rpc
from quantum.common import config as logging_config
from quantum.common import constants as q_constants
from quantum.common import topics
from quantum.common import utils as q_utils
from quantum import context
from quantum.openstack.common import log as logging
from quantum.openstack.common import loopingcall
from quantum.openstack.common.rpc import dispatcher
from quantum.plugins.mlnx.agent import utils
from quantum.plugins.mlnx.common import config  # noqa
from quantum.plugins.mlnx.common import constants
from quantum.plugins.mlnx.common import exceptions

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
        raise exceptions.MlnxException(err_msg)

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

        Check  internal network map for port data.
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
        -Check if vnic defined
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

        if network_type == constants.TYPE_VLAN:
            LOG.info(_('Binding VLAN ID %(seg_id)s'
                       'to eSwitch for vNIC mac_address %(mac)s'),
                     {'seg_id': seg_id,
                      'mac': port_mac})
            self.utils.set_port_vlan_id(physical_network,
                                        seg_id,
                                        port_mac)
            self.utils.port_up(physical_network, port_mac)
        elif network_type == constants.TYPE_IB:
            LOG.debug(_('Network Type IB currently not supported'))
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
        if network_type == constants.TYPE_VLAN:
            LOG.debug(_("creating VLAN Network"))
        elif network_type == constants.TYPE_IB:
            LOG.debug(_("currently IB network provisioning is not supported"))
        else:
            LOG.error(_("Unknown network type %(network_type) "
                        "for network %(network_id)"),
                      {'network_type': network_type,
                       'network_id': network_id})
            return
        data = {
            'physical_network': physical_network,
            'network_type': network_type,
            'ports': [],
            'vlan_id': segmentation_id}
        self.network_map[network_id] = data


class MlnxEswitchRpcCallbacks():

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, context, eswitch):
        self.context = context
        self.eswitch = eswitch

    def network_delete(self, context, **kwargs):
        LOG.debug(_("network_delete received"))
        network_id = kwargs.get('network_id')
        if not network_id:
            LOG.warning(_("Invalid Network ID, cannot remove Network"))
        else:
            LOG.debug(_("Delete network %s"), network_id)
            self.eswitch.remove_network(network_id)

    def port_update(self, context, **kwargs):
        LOG.debug(_("port_update received"))
        port = kwargs.get('port')
        vlan_id = kwargs.get('vlan_id')
        physical_network = kwargs.get('physical_network')
        net_type = kwargs.get('network_type')
        net_id = port['network_id']
        if self.eswitch.vnic_port_exists(port['mac_address']):
            if port['admin_state_up']:
                self.eswitch.port_up(net_id,
                                     net_type,
                                     physical_network,
                                     vlan_id,
                                     port['id'],
                                     port['mac_address'])
            else:
                self.eswitch.port_down(net_id,
                                       physical_network,
                                       port['mac_address'])
        else:
            LOG.debug(_("No port %s defined on agent."), port['id'])

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version,
        or support more than one class as the target of rpc messages,
        override this method.
        """
        return dispatcher.RpcDispatcher([self])


class MlnxEswitchQuantumAgent(object):
    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, interface_mapping):
        self._polling_interval = cfg.CONF.AGENT.polling_interval
        self._setup_eswitches(interface_mapping)
        self.agent_state = {
            'binary': 'quantum-mlnx-agent',
            'host': cfg.CONF.host,
            'topic': q_constants.L2_AGENT_TOPIC,
            'configurations': interface_mapping,
            'agent_type': 'eSwitch agent',
            'start_flag': True}
        self._setup_rpc()

    def _setup_eswitches(self, interface_mapping):
        daemon = cfg.CONF.ESWITCH.daemon_endpoint
        timeout = cfg.CONF.ESWITCH.request_timeout
        self.eswitch = EswitchManager(interface_mapping, daemon, timeout)

    def _report_state(self):
        try:
            devices = len(self.eswitch.get_vnics_mac())
            self.agent_state['configurations']['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_("Failed reporting state!"))

    def _setup_rpc(self):
        self.agent_id = 'mlnx-agent.%s' % socket.gethostname()
        self.topic = topics.AGENT
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        # RPC network init
        self.context = context.get_admin_context_without_session()
        # Handle updates from service
        self.callbacks = MlnxEswitchRpcCallbacks(self.context, self.eswitch)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.DELETE]]
        self.connection = agent_rpc.create_consumers(self.dispatcher,
                                                     self.topic,
                                                     consumers)

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.LoopingCall(self._report_state)
            heartbeat.start(interval=report_interval)

    def update_ports(self, registered_ports):
        ports = self.eswitch.get_vnics_mac()
        if ports == registered_ports:
            return
        added = ports - registered_ports
        removed = registered_ports - ports
        return {'current': ports,
                'added': added,
                'removed': removed}

    def process_network_ports(self, port_info):
        resync_a = False
        resync_b = False
        if 'added' in port_info:
            LOG.debug(_("ports added!"))
            resync_a = self.treat_devices_added(port_info['added'])
        if 'removed' in port_info:
            LOG.debug(_("ports removed!"))
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

    def treat_devices_added(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Adding port with mac %s"), device)
            try:
                dev_details = self.plugin_rpc.get_device_details(
                    self.context,
                    device,
                    self.agent_id)
            except Exception as e:
                LOG.debug(_("Unable to get device dev_details for device "
                          "with mac_address %(device)s: due to %(exc)s"),
                          {'device': device, 'exc': e})
                resync = True
                continue
            if 'port_id' in dev_details:
                LOG.info(_("Port %s updated"), device)
                LOG.debug(_("Device details %s"), str(dev_details))
                self.treat_vif_port(dev_details['port_id'],
                                    dev_details['port_mac'],
                                    dev_details['network_id'],
                                    dev_details['network_type'],
                                    dev_details['physical_network'],
                                    dev_details['vlan_id'],
                                    dev_details['admin_state_up'])
            else:
                LOG.debug(_("Device with mac_address %s not defined "
                          "on Quantum Plugin"), device)
        return resync

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_("Removing device with mac_address %s"), device)
            try:
                port_id = self.eswitch.get_port_id_by_mac(device)
                dev_details = self.plugin_rpc.update_device_down(self.context,
                                                                 port_id,
                                                                 self.agent_id)
            except Exception as e:
                LOG.debug(_("Removing port failed for device %(device)s "
                          "due to %(exc)s"), {'device': device, 'exc': e})
                resync = True
                continue
            if dev_details['exists']:
                LOG.info(_("Port %s updated."), device)
                self.eswitch.port_release(device)
            else:
                LOG.debug(_("Device %s not defined on plugin"), device)
        return resync

    def daemon_loop(self):
        sync = True
        ports = set()

        LOG.info(_("eSwitch Agent Started!"))

        while True:
            try:
                start = time.time()
                if sync:
                    LOG.info(_("Agent out of sync with plugin!"))
                    ports.clear()
                    sync = False

                port_info = self.update_ports(ports)
                # notify plugin about port deltas
                if port_info:
                    LOG.debug(_("Agent loop has new devices!"))
                    # If treat devices fails - must resync with plugin
                    sync = self.process_network_ports(port_info)
                    ports = port_info['current']
            except Exception:
                LOG.exception(_("Error in agent event loop"))
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
    cfg.CONF(project='quantum')
    logging_config.setup_logging(cfg.CONF)

    try:
        interface_mappings = q_utils.parse_mappings(
            cfg.CONF.ESWITCH.physical_interface_mappings)
    except ValueError as e:
        LOG.error(_("Parsing physical_interface_mappings failed: %s."
                    " Agent terminated!"), e)
        sys.exit(1)
    LOG.info(_("Interface mappings: %s"), interface_mappings)

    try:
        agent = MlnxEswitchQuantumAgent(interface_mappings)
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
