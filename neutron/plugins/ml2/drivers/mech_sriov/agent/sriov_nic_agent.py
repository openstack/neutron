# Copyright 2014 Mellanox Technologies, Ltd
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


import collections
import itertools
import socket
import sys
import time

from neutron_lib.agent import topics
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants as n_constants
from neutron_lib import context
from neutron_lib.placement import utils as place_utils
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall
from osprofiler import profiler
import pyroute2
import six

from neutron._i18n import _
from neutron.agent.common import utils
from neutron.agent.l2 import l2_agent_extensions_manager as ext_manager
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as agent_sg_rpc
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import profiler as setup_profiler
from neutron.common import utils as n_utils
from neutron.conf.agent import common as agent_config
from neutron.conf import service as service_conf
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import config
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.agent import eswitch_manager as esm
from neutron.privileged.agent.linux import ip_lib as priv_ip_lib


LOG = logging.getLogger(__name__)


class SriovNicSwitchRpcCallbacks(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC (works with NoopFirewallDriver)
    #   1.2 Support DVR (Distributed Virtual Router) RPC (not supported)
    #   1.3 Added param devices_to_update to security_groups_provider_updated
    #       (works with NoopFirewallDriver)
    #   1.4 Added support for network_update
    #   1.5 Added support for binding_activate and binding_deactivate

    target = oslo_messaging.Target(version='1.5')

    def __init__(self, context, agent, sg_agent):
        super(SriovNicSwitchRpcCallbacks, self).__init__()
        self.context = context
        self.agent = agent
        self.sg_agent = sg_agent

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received")
        port = kwargs.get('port')

        vnic_type = port.get(portbindings.VNIC_TYPE)
        if vnic_type and vnic_type == portbindings.VNIC_DIRECT_PHYSICAL:
            LOG.debug("The SR-IOV agent doesn't handle %s ports.",
                      portbindings.VNIC_DIRECT_PHYSICAL)
            return

        # Put the port mac address in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        mac = port['mac_address']
        pci_slot = None
        if port.get(portbindings.PROFILE):
            pci_slot = port[portbindings.PROFILE].get('pci_slot')

        if pci_slot:
            self.agent.updated_devices.add((mac, pci_slot))
            LOG.debug("port_update RPC received for port: %(id)s with MAC "
                      "%(mac)s and PCI slot %(pci_slot)s slot",
                      {'id': port['id'], 'mac': mac, 'pci_slot': pci_slot})
        else:
            LOG.debug("No PCI Slot for port %(id)s with MAC %(mac)s; "
                      "skipping", {'id': port['id'], 'mac': mac,
                                   'pci_slot': pci_slot})

    def network_update(self, context, **kwargs):
        network_id = kwargs['network']['id']
        LOG.debug("network_update message received for network "
                  "%(network_id)s, with ports: %(ports)s",
                  {'network_id': network_id,
                   'ports': self.agent.network_ports[network_id]})
        for port_data in self.agent.network_ports[network_id]:
            self.agent.updated_devices.add(port_data['device'])

    def binding_activate(self, context, **kwargs):
        if kwargs.get('host') != self.agent.conf.host:
            return
        LOG.debug("binding activate for port %s", kwargs.get('port_id'))
        device_details = self.agent.get_device_details_from_port_id(
            kwargs.get('port_id'))
        mac = device_details.get('mac_address')
        binding_profile = device_details.get('profile')
        if binding_profile:
            pci_slot = binding_profile.get('pci_slot')
            self.agent.activated_bindings.add((mac, pci_slot))
        else:
            LOG.warning("binding_profile not found for port %s.",
                        kwargs.get('port_id'))

    def binding_deactivate(self, context, **kwargs):
        if kwargs.get('host') != self.agent.conf.host:
            return
        LOG.debug("binding deactivate for port %s. NOOP.",
                  kwargs.get('port_id'))


@profiler.trace_cls("rpc")
class SriovNicSwitchAgent(object):
    def __init__(self, physical_devices_mappings, exclude_devices,
                 polling_interval, rp_bandwidths, rp_inventory_defaults,
                 rp_hypervisors):

        self.polling_interval = polling_interval
        self.network_ports = collections.defaultdict(list)
        self.conf = cfg.CONF
        self.device_mappings = physical_devices_mappings
        self.exclude_devices = exclude_devices
        self.setup_eswitch_mgr(physical_devices_mappings,
                               exclude_devices)

        # Stores port update notifications for processing in the main loop
        self.updated_devices = set()
        # Stores <mac, pci_slot> pairs for ports whose binding has been
        # activated.
        self.activated_bindings = set()

        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.sg_agent = agent_sg_rpc.SecurityGroupAgentRpc(
            self.context, self.sg_plugin_rpc)
        self._setup_rpc()
        self.ext_manager = self._create_agent_extension_manager(
            self.connection)

        configurations = {'device_mappings': physical_devices_mappings,
                          n_constants.RP_BANDWIDTHS: rp_bandwidths,
                          n_constants.RP_INVENTORY_DEFAULTS:
                              rp_inventory_defaults,
                          'resource_provider_hypervisors': rp_hypervisors,
                          'extensions': self.ext_manager.names()}

        # TODO(mangelajo): optimize resource_versions (see ovs agent)
        self.agent_state = {
            'binary': 'neutron-sriov-nic-agent',
            'host': self.conf.host,
            'topic': n_constants.L2_AGENT_TOPIC,
            'configurations': configurations,
            'agent_type': n_constants.AGENT_TYPE_NIC_SWITCH,
            'resource_versions': resources.LOCAL_RESOURCE_VERSIONS,
            'start_flag': True}

        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()
        # Initialize iteration counter
        self.iter_num = 0

    def _setup_rpc(self):
        self.agent_id = 'nic-switch-agent.%s' % socket.gethostname()
        LOG.info("RPC agent_id: %s", self.agent_id)
        self.topic = topics.AGENT
        self.failed_report_state = False
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        # RPC network init
        # Handle updates from service
        self.endpoints = [SriovNicSwitchRpcCallbacks(self.context, self,
                                                     self.sg_agent)]
        # Define the listening consumers for the agent
        consumers = [[topics.PORT, topics.UPDATE],
                     [topics.NETWORK, topics.UPDATE],
                     [topics.SECURITY_GROUP, topics.UPDATE],
                     [topics.PORT_BINDING, topics.DEACTIVATE],
                     [topics.PORT_BINDING, topics.ACTIVATE]]
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self.state_rpc.report_state(self.context,
                                        self.agent_state)

            # we only want to update resource versions on startup
            self.agent_state.pop('resource_versions', None)
            self.agent_state.pop('start_flag', None)
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def _create_agent_extension_manager(self, connection):
        ext_manager.register_opts(self.conf)
        mgr = ext_manager.L2AgentExtensionsManager(self.conf)
        mgr.initialize(connection, 'sriov')
        return mgr

    def setup_eswitch_mgr(self, device_mappings, exclude_devices=None):
        exclude_devices = exclude_devices or {}
        self.eswitch_mgr = esm.ESwitchManager()
        self.eswitch_mgr.discover_devices(device_mappings, exclude_devices)

    def scan_devices(self, registered_devices, updated_devices):
        curr_devices = self.eswitch_mgr.get_assigned_devices_info()
        self.agent_state.get('configurations')['devices'] = len(curr_devices)
        device_info = {}
        device_info['current'] = curr_devices
        device_info['added'] = curr_devices - registered_devices
        # we need to clean up after devices are removed
        device_info['removed'] = registered_devices - curr_devices
        # we don't want to process updates for devices that don't exist
        device_info['updated'] = (updated_devices & curr_devices -
                                  device_info['removed'])
        return device_info

    def _device_info_has_changes(self, device_info):
        return (device_info.get('added') or
                device_info.get('updated') or
                device_info.get('removed'))

    def process_network_devices(self, device_info):
        resync_a = False
        resync_b = False

        self.sg_agent.prepare_devices_filter(device_info.get('added'))

        if device_info.get('updated'):
            self.sg_agent.refresh_firewall()
        # Updated devices are processed the same as new ones, as their
        # admin_state_up may have changed. The set union prevents duplicating
        # work when a device is new and updated in the same polling iteration.
        devices_added_updated = (set(device_info.get('added')) |
                                 set(device_info.get('updated')))
        if devices_added_updated:
            resync_a = self.treat_devices_added_updated(devices_added_updated)

        if device_info.get('removed'):
            resync_b = self.treat_devices_removed(device_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_device(self, device, pci_slot, admin_state_up, spoofcheck=True,
                     propagate_uplink_state=False):
        if self.eswitch_mgr.device_exists(device, pci_slot):
            try:
                self.eswitch_mgr.set_device_spoofcheck(device, pci_slot,
                                                       spoofcheck)
            except Exception:
                LOG.warning("Failed to set spoofcheck for device %s",
                            device)
            LOG.info("Device %(device)s spoofcheck %(spoofcheck)s",
                     {"device": device, "spoofcheck": spoofcheck})

            try:
                self.eswitch_mgr.set_device_state(device, pci_slot,
                                                  admin_state_up,
                                                  propagate_uplink_state)
            except priv_ip_lib.InterfaceOperationNotSupported:
                LOG.warning("Device %s does not support state change", device)
            except pyroute2.NetlinkError:
                LOG.warning("Failed to set device %s state", device)
                return False
        else:
            LOG.info("No device with MAC %s defined on agent.", device)
            return False
        return True

    def _update_network_ports(self, network_id, port_id, mac_pci_slot):
        self._clean_network_ports(mac_pci_slot)
        self.network_ports[network_id].append({
            "port_id": port_id,
            "device": mac_pci_slot})

    def _clean_network_ports(self, mac_pci_slot):
        for netid, ports_list in self.network_ports.items():
            for port_data in ports_list:
                if mac_pci_slot == port_data['device']:
                    ports_list.remove(port_data)
                    if ports_list == []:
                        self.network_ports.pop(netid)
                    return port_data['port_id']

    def treat_devices_added_updated(self, devices_info):
        try:
            macs_list = set([device_info[0] for device_info in devices_info])
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, macs_list, self.agent_id, self.conf.host)
        except Exception as e:
            LOG.debug("Unable to get port details for devices "
                      "with MAC addresses %(devices)s: %(e)s",
                      {'devices': macs_list, 'e': e})
            # resync is needed
            return True

        devices_up = set()
        devices_down = set()
        resync = False
        for device_details in devices_details_list:
            device = device_details['device']
            LOG.debug("Port with MAC address %s is added", device)

            if 'port_id' in device_details:
                LOG.info("Port %(device)s updated. Details: %(details)s",
                         {'device': device, 'details': device_details})
                port_id = device_details['port_id']
                profile = device_details['profile']
                spoofcheck = device_details.get('port_security_enabled', True)
                if self.treat_device(
                        device,
                        profile.get('pci_slot'),
                        device_details['admin_state_up'],
                        spoofcheck,
                        device_details['propagate_uplink_status']):
                    if device_details['admin_state_up']:
                        devices_up.add(device)
                    else:
                        devices_down.add(device)
                else:
                    resync = True
                self._update_network_ports(device_details['network_id'],
                                           port_id,
                                           (device, profile.get('pci_slot')))
                self.ext_manager.handle_port(self.context, device_details)
            elif n_constants.NO_ACTIVE_BINDING in device_details:
                # Port was added but its binding in this agent
                # hasn't been activated yet. It will be treated as
                # added when binding is activated
                LOG.info("Device with MAC %s has no active binding in host",
                         device)
            else:
                LOG.info("Device with MAC %s not defined on plugin",
                         device)
        self.plugin_rpc.update_device_list(self.context,
                                           devices_up,
                                           devices_down,
                                           self.agent_id,
                                           self.conf.host)
        return resync

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            mac, pci_slot = device
            LOG.info("Removing device with MAC address %(mac)s and "
                     "PCI slot %(pci_slot)s",
                     {'mac': mac, 'pci_slot': pci_slot})
            try:
                port_id = self._clean_network_ports(device)
                if port_id:
                    port = {'port_id': port_id,
                            'device': mac,
                            'profile': {'pci_slot': pci_slot}}
                    self.ext_manager.delete_port(self.context, port)
                else:
                    LOG.warning("port_id to device with MAC "
                                "%s not found", mac)
                dev_details = self.plugin_rpc.update_device_down(self.context,
                                                                 mac,
                                                                 self.agent_id,
                                                                 cfg.CONF.host)

            except Exception as e:
                LOG.debug("Removing port failed for device with MAC address "
                          "%(mac)s and PCI slot %(pci_slot)s due to %(exc)s",
                          {'mac': mac, 'pci_slot': pci_slot, 'exc': e})
                resync = True
                continue
            if dev_details['exists']:
                LOG.info("Port with MAC %(mac)s and PCI slot "
                         "%(pci_slot)s updated.",
                         {'mac': mac, 'pci_slot': pci_slot})
            else:
                LOG.debug("Device with MAC %(mac)s and PCI slot "
                          "%(pci_slot)s not defined on plugin",
                          {'mac': mac, 'pci_slot': pci_slot})
        return resync

    def process_activated_bindings(self, device_info, activated_bindings_copy):
        """Process activated bindings.

        Add activated bindings to the 'added' set in device info.

        :param device_info: A dict that contains the set of 'current', 'added',
                            'removed' and 'updated' ports.
        :param activated_bindings_copy: A set of activated port bindings.
        :return: None
        """
        LOG.debug("Processing activated bindings: %s", activated_bindings_copy)
        # Compute which ports for activated bindings are already present
        activated_bindings_copy &= device_info['current']
        # Treat them as just added
        device_info['added'] |= activated_bindings_copy

    def get_device_details_from_port_id(self, port_id):
        """Get device details from server

        :param port_id: Port identifier (UUID).
        :return: A dict containing various port attributes if the port is
                 bound to the host. In case the port is not bound to the host
                 then the method will return A dict with a minimal set of
                 attributes e.g  {'device': port_id}.
        """
        return self.plugin_rpc.get_device_details(self.context,
                                                  port_id,
                                                  self.agent_id,
                                                  host=cfg.CONF.host)

    def daemon_loop(self):
        sync = True
        devices = set()

        LOG.info("SRIOV NIC Agent RPC Daemon Started!")

        while True:
            start = time.time()
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            if sync:
                LOG.info("Agent out of sync with plugin!")
                devices.clear()
                sync = False
            device_info = {}
            # Save updated devices dict to perform rollback in case
            # resync would be needed, and then clear self.updated_devices.
            # As the greenthread should not yield between these
            # two statements, this will should be thread-safe.
            updated_devices_copy = self.updated_devices
            self.updated_devices = set()
            activated_bindings_copy = self.activated_bindings
            self.activated_bindings = set()
            try:
                self.eswitch_mgr.discover_devices(self.device_mappings,
                                                  self.exclude_devices)
                device_info = self.scan_devices(devices, updated_devices_copy)
                if activated_bindings_copy:
                    self.process_activated_bindings(device_info,
                                                    activated_bindings_copy)
                if self._device_info_has_changes(device_info):
                    LOG.debug("Agent loop found changes! %s", device_info)
                    # If treat devices fails - indicates must resync with
                    # plugin
                    sync = self.process_network_devices(device_info)
                    devices = device_info['current']
            except Exception:
                LOG.exception("Error in agent loop. Devices info: %s",
                              device_info)
                sync = True
                # Restore devices that were removed from this set earlier
                # without overwriting ones that may have arrived since.
                self.updated_devices |= updated_devices_copy
                self.activated_bindings |= activated_bindings_copy

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)!",
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})
            self.iter_num = self.iter_num + 1


class SriovNicAgentConfigParser(object):
    def __init__(self):
        self.device_mappings = {}
        self.exclude_devices = {}

    def parse(self):
        """Parses device_mappings and exclude_devices.

        Parse and validate the consistency in both mappings
        """
        self.device_mappings = helpers.parse_mappings(
            cfg.CONF.SRIOV_NIC.physical_device_mappings, unique_keys=False)
        self.exclude_devices = config.parse_exclude_devices(
            cfg.CONF.SRIOV_NIC.exclude_devices)
        self.rp_bandwidths = place_utils.parse_rp_bandwidths(
            cfg.CONF.SRIOV_NIC.resource_provider_bandwidths)
        self.rp_inventory_defaults = place_utils.parse_rp_inventory_defaults(
            cfg.CONF.SRIOV_NIC.resource_provider_inventory_defaults)
        self.rp_hypervisors = utils.default_rp_hypervisors(
            cfg.CONF.SRIOV_NIC.resource_provider_hypervisors,
            self.device_mappings,
            cfg.CONF.SRIOV_NIC.resource_provider_default_hypervisor,
        )
        self._validate()

    def _validate(self):
        """Validate configuration.

        Validate that network_device in excluded_device
        exists in device mappings.
        Validate that network_device in resource_provider_bandwidths
        exists in device mappings.
        """
        dev_net_set = set(itertools.chain.from_iterable(
                          six.itervalues(self.device_mappings)))
        for dev_name in self.exclude_devices.keys():
            if dev_name not in dev_net_set:
                raise ValueError(_(
                    "Invalid exclude_devices: "
                    "Device name %(dev_name)s is missing from "
                    "physical_device_mappings") % {'dev_name': dev_name})
        n_utils.validate_rp_bandwidth(self.rp_bandwidths, dev_net_set)


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    agent_config.setup_privsep()
    service_conf.register_service_opts(service_conf.RPC_EXTRA_OPTS, cfg.CONF)

    try:
        config_parser = SriovNicAgentConfigParser()
        config_parser.parse()
        device_mappings = config_parser.device_mappings
        exclude_devices = config_parser.exclude_devices
        rp_bandwidths = config_parser.rp_bandwidths
        rp_inventory_defaults = config_parser.rp_inventory_defaults
        rp_hypervisors = config_parser.rp_hypervisors

    except ValueError:
        LOG.exception("Failed on Agent configuration parse. "
                      "Agent terminated!")
        raise SystemExit(1)
    LOG.info("Physical Devices mappings: %s", device_mappings)
    LOG.info("Exclude Devices: %s", exclude_devices)
    LOG.info("Resource provider bandwidths: %s", rp_bandwidths)
    LOG.info("Resource provider inventory defaults: %s", rp_inventory_defaults)
    LOG.info("Resource provider hypervisors: %s", rp_hypervisors)

    polling_interval = cfg.CONF.AGENT.polling_interval
    try:
        agent = SriovNicSwitchAgent(device_mappings,
                                    exclude_devices,
                                    polling_interval,
                                    rp_bandwidths,
                                    rp_inventory_defaults,
                                    rp_hypervisors)
    except exc.SriovNicError:
        LOG.exception("Agent Initialization Failed")
        raise SystemExit(1)
    # Start everything.
    setup_profiler.setup("neutron-sriov-nic-agent", cfg.CONF.host)
    LOG.info("Agent initialized successfully, now running... ")
    agent.daemon_loop()
