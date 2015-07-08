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


import socket
import sys
import time

import eventlet
eventlet.monkey_patch()

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import loopingcall

from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_constants
from neutron.common import topics
from neutron.common import utils as n_utils
from neutron import context
from neutron.i18n import _LE, _LI
from neutron.plugins.ml2.drivers.mech_sriov.agent.common import config  # noqa
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc
from neutron.plugins.ml2.drivers.mech_sriov.agent import eswitch_manager as esm


LOG = logging.getLogger(__name__)


class SriovNicSwitchRpcCallbacks(sg_rpc.SecurityGroupAgentRpcCallbackMixin):

    # Set RPC API version to 1.0 by default.
    # history
    #   1.1 Support Security Group RPC
    target = oslo_messaging.Target(version='1.1')

    def __init__(self, context, agent, sg_agent):
        super(SriovNicSwitchRpcCallbacks, self).__init__()
        self.context = context
        self.agent = agent
        self.sg_agent = sg_agent

    def port_update(self, context, **kwargs):
        LOG.debug("port_update received")
        port = kwargs.get('port')
        # Put the port mac address in the updated_devices set.
        # Do not store port details, as if they're used for processing
        # notifications there is no guarantee the notifications are
        # processed in the same order as the relevant API requests.
        self.agent.updated_devices.add(port['mac_address'])
        LOG.debug("port_update RPC received for port: %s", port['id'])


class SriovNicSwitchAgent(object):
    def __init__(self, physical_devices_mappings, exclude_devices,
                 polling_interval):

        self.polling_interval = polling_interval
        self.setup_eswitch_mgr(physical_devices_mappings,
                               exclude_devices)
        configurations = {'device_mappings': physical_devices_mappings}
        self.agent_state = {
            'binary': 'neutron-sriov-nic-agent',
            'host': cfg.CONF.host,
            'topic': n_constants.L2_AGENT_TOPIC,
            'configurations': configurations,
            'agent_type': n_constants.AGENT_TYPE_NIC_SWITCH,
            'start_flag': True}

        # Stores port update notifications for processing in the main loop
        self.updated_devices = set()

        self.context = context.get_admin_context_without_session()
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.sg_agent = sg_rpc.SecurityGroupAgentRpc(self.context,
                self.sg_plugin_rpc)
        self._setup_rpc()
        # Initialize iteration counter
        self.iter_num = 0

    def _setup_rpc(self):
        self.agent_id = 'nic-switch-agent.%s' % socket.gethostname()
        LOG.info(_LI("RPC agent_id: %s"), self.agent_id)

        self.topic = topics.AGENT
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.PLUGIN)
        # RPC network init
        # Handle updates from service
        self.endpoints = [SriovNicSwitchRpcCallbacks(self.context, self,
                                                     self.sg_agent)]
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

    def _report_state(self):
        try:
            devices = len(self.eswitch_mgr.get_assigned_devices())
            self.agent_state.get('configurations')['devices'] = devices
            self.state_rpc.report_state(self.context,
                                        self.agent_state)
            self.agent_state.pop('start_flag', None)
        except Exception:
            LOG.exception(_LE("Failed reporting state!"))

    def setup_eswitch_mgr(self, device_mappings, exclude_devices={}):
        self.eswitch_mgr = esm.ESwitchManager(device_mappings, exclude_devices)

    def scan_devices(self, registered_devices, updated_devices):
        curr_devices = self.eswitch_mgr.get_assigned_devices()
        device_info = {}
        device_info['current'] = curr_devices
        device_info['added'] = curr_devices - registered_devices
        # we don't want to process updates for devices that don't exist
        device_info['updated'] = updated_devices & curr_devices
        # we need to clean up after devices are removed
        device_info['removed'] = registered_devices - curr_devices
        return device_info

    def _device_info_has_changes(self, device_info):
        return (device_info.get('added')
                or device_info.get('updated')
                or device_info.get('removed'))

    def process_network_devices(self, device_info):
        resync_a = False
        resync_b = False

        self.sg_agent.prepare_devices_filter(device_info.get('added'))

        if device_info.get('updated'):
            self.sg_agent.refresh_firewall()
        # Updated devices are processed the same as new ones, as their
        # admin_state_up may have changed. The set union prevents duplicating
        # work when a device is new and updated in the same polling iteration.
        devices_added_updated = (set(device_info.get('added'))
                                 | set(device_info.get('updated')))
        if devices_added_updated:
            resync_a = self.treat_devices_added_updated(devices_added_updated)

        if device_info.get('removed'):
            resync_b = self.treat_devices_removed(device_info['removed'])
        # If one of the above operations fails => resync with plugin
        return (resync_a | resync_b)

    def treat_device(self, device, pci_slot, admin_state_up):
        if self.eswitch_mgr.device_exists(device, pci_slot):
            try:
                self.eswitch_mgr.set_device_state(device, pci_slot,
                                                  admin_state_up)
            except exc.SriovNicError:
                LOG.exception(_LE("Failed to set device %s state"), device)
                return
            if admin_state_up:
                # update plugin about port status
                self.plugin_rpc.update_device_up(self.context,
                                                 device,
                                                 self.agent_id,
                                                 cfg.CONF.host)
            else:
                self.plugin_rpc.update_device_down(self.context,
                                                   device,
                                                   self.agent_id,
                                                   cfg.CONF.host)
        else:
            LOG.info(_LI("No device with MAC %s defined on agent."), device)

    def treat_devices_added_updated(self, devices):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, devices, self.agent_id)
        except Exception as e:
            LOG.debug("Unable to get port details for devices "
                      "with MAC address %(devices)s: %(e)s",
                      {'devices': devices, 'e': e})
            # resync is needed
            return True

        for device_details in devices_details_list:
            device = device_details['device']
            LOG.debug("Port with MAC address %s is added", device)

            if 'port_id' in device_details:
                LOG.info(_LI("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': device_details})
                profile = device_details['profile']
                self.treat_device(device_details['device'],
                                  profile.get('pci_slot'),
                                  device_details['admin_state_up'])
            else:
                LOG.info(_LI("Device with MAC %s not defined on plugin"),
                         device)
        return False

    def treat_devices_removed(self, devices):
        resync = False
        for device in devices:
            LOG.info(_LI("Removing device with mac_address %s"), device)
            try:
                dev_details = self.plugin_rpc.update_device_down(self.context,
                                                                 device,
                                                                 self.agent_id,
                                                                 cfg.CONF.host)
            except Exception as e:
                LOG.debug("Removing port failed for device %(device)s "
                          "due to %(exc)s", {'device': device, 'exc': e})
                resync = True
                continue
            if dev_details['exists']:
                LOG.info(_LI("Port %s updated."), device)
            else:
                LOG.debug("Device %s not defined on plugin", device)
        return resync

    def daemon_loop(self):
        sync = True
        devices = set()

        LOG.info(_LI("SRIOV NIC Agent RPC Daemon Started!"))

        while True:
            start = time.time()
            LOG.debug("Agent rpc_loop - iteration:%d started",
                      self.iter_num)
            if sync:
                LOG.info(_LI("Agent out of sync with plugin!"))
                devices.clear()
                sync = False
            device_info = {}
            # Save updated devices dict to perform rollback in case
            # resync would be needed, and then clear self.updated_devices.
            # As the greenthread should not yield between these
            # two statements, this will should be thread-safe.
            updated_devices_copy = self.updated_devices
            self.updated_devices = set()
            try:
                device_info = self.scan_devices(devices, updated_devices_copy)
                if self._device_info_has_changes(device_info):
                    LOG.debug("Agent loop found changes! %s", device_info)
                    # If treat devices fails - indicates must resync with
                    # plugin
                    sync = self.process_network_devices(device_info)
                    devices = device_info['current']
            except Exception:
                LOG.exception(_LE("Error in agent loop. Devices info: %s"),
                              device_info)
                sync = True
                # Restore devices that were removed from this set earlier
                # without overwriting ones that may have arrived since.
                self.updated_devices |= updated_devices_copy

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
        self.device_mappings = n_utils.parse_mappings(
            cfg.CONF.SRIOV_NIC.physical_device_mappings)
        self.exclude_devices = config.parse_exclude_devices(
            cfg.CONF.SRIOV_NIC.exclude_devices)
        self._validate()

    def _validate(self):
        """Validate configuration.

        Validate that network_device in excluded_device
        exists in device mappings
        """
        dev_net_set = set(self.device_mappings.values())
        for dev_name in self.exclude_devices.keys():
            if dev_name not in dev_net_set:
                raise ValueError(_("Device name %(dev_name)s is missing from "
                                   "physical_device_mappings") % {'dev_name':
                                                                  dev_name})


def main():
    common_config.init(sys.argv[1:])

    common_config.setup_logging()
    try:
        config_parser = SriovNicAgentConfigParser()
        config_parser.parse()
        device_mappings = config_parser.device_mappings
        exclude_devices = config_parser.exclude_devices

    except ValueError:
        LOG.exception(_LE("Failed on Agent configuration parse. "
                          "Agent terminated!"))
        raise SystemExit(1)
    LOG.info(_LI("Physical Devices mappings: %s"), device_mappings)
    LOG.info(_LI("Exclude Devices: %s"), exclude_devices)

    polling_interval = cfg.CONF.AGENT.polling_interval
    try:
        agent = SriovNicSwitchAgent(device_mappings,
                                    exclude_devices,
                                    polling_interval)
    except exc.SriovNicError:
        LOG.exception(_LE("Agent Initialization Failed"))
        raise SystemExit(1)
    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == '__main__':
    main()
