# Copyright (c) 2016 IBM Corp.
#
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
import contextlib
import sys
import time

from neutron_lib.agent import constants as agent_consts
from neutron_lib.agent import topics
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources as local_resources
from neutron_lib import constants
from neutron_lib import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_service import service
from oslo_utils import excutils
from osprofiler import profiler

from neutron.agent.l2 import l2_agent_extensions_manager as ext_manager
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as agent_sg_rpc
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import securitygroups_rpc as sg_rpc
from neutron.common import config as common_config
from neutron.plugins.ml2.drivers.agent import _agent_manager_base as amb
from neutron.plugins.ml2.drivers.agent import capabilities
from neutron.plugins.ml2.drivers.agent import config as cagt_config  # noqa

LOG = logging.getLogger(__name__)


@profiler.trace_cls("rpc")
class CommonAgentLoop(service.Service):

    def __init__(self, manager, polling_interval,
                 quitting_rpc_timeout, agent_type, agent_binary):
        """Constructor.

        :param manager: the manager object containing the impl specifics
        :param polling_interval: interval (secs) to poll DB.
        :param quitting_rpc_timeout: timeout in seconds for rpc calls after
               stop is called.
        :param agent_type: Specifies the type of the agent
        :param agent_binary: The agent binary string
        """
        super().__init__()
        self.mgr = manager
        self._validate_manager_class()
        self.polling_interval = polling_interval
        self.quitting_rpc_timeout = quitting_rpc_timeout
        self.agent_type = agent_type
        self.agent_binary = agent_binary
        self.connection = None
        self.iter_num = 0

    def _validate_manager_class(self):
        if not isinstance(self.mgr,
                          amb.CommonAgentManagerBase):
            LOG.error("Manager class must inherit from "
                      "CommonAgentManagerBase to ensure CommonAgent "
                      "works properly.")
            sys.exit(1)

    def start(self):
        # stores all configured ports on agent
        self.network_ports = collections.defaultdict(list)
        # flag to do a sync after revival
        self.fullsync = False
        self.context = context.get_admin_context_without_session()
        self.setup_rpc()
        self.init_extension_manager(self.connection)

        configurations = {'extensions': self.ext_manager.names()}
        configurations.update(self.mgr.get_agent_configurations())

        self.failed_report_state = False
        # TODO(mangelajo): optimize resource_versions (see ovs agent)
        self.agent_state = {
            'binary': self.agent_binary,
            'host': cfg.CONF.host,
            'topic': constants.L2_AGENT_TOPIC,
            'configurations': configurations,
            'agent_type': self.agent_type,
            'resource_versions': resources.LOCAL_RESOURCE_VERSIONS,
            'start_flag': True}

        report_interval = cfg.CONF.AGENT.report_interval
        if report_interval:
            heartbeat = loopingcall.FixedIntervalLoopingCall(
                f=self._report_state)
            heartbeat.start(interval=report_interval)

        capabilities.notify_init_event(self.agent_type, self)
        # The initialization is complete; we can start receiving messages
        self.connection.consume_in_threads()

        self.daemon_loop()

    def stop(self, graceful=True):
        LOG.info("Stopping %s agent.", self.agent_type)
        if graceful and self.quitting_rpc_timeout:
            self.set_rpc_timeout(self.quitting_rpc_timeout)
        if self.connection:
            self.connection.close()
        super().stop(graceful)

    def reset(self):
        common_config.setup_logging()

    def _report_state(self):
        try:
            devices = len(self.mgr.get_all_devices())
            self.agent_state.get('configurations')['devices'] = devices
            agent_status = self.state_rpc.report_state(self.context,
                                                       self.agent_state,
                                                       True)
            if agent_status == agent_consts.AGENT_REVIVED:
                LOG.info('%s Agent has just been revived. '
                         'Doing a full sync.',
                         self.agent_type)
                self.fullsync = True
            # we only want to update resource versions on startup
            self.agent_state.pop('resource_versions', None)
            if self.iter_num > 0:
                # agent is considered started after initial sync with
                # server (iter 0) is done
                self.agent_state.pop('start_flag', None)
        except Exception:
            self.failed_report_state = True
            LOG.exception("Failed reporting state!")
            return
        if self.failed_report_state:
            self.failed_report_state = False
            LOG.info("Successfully reported state after a previous failure.")

    def _validate_rpc_endpoints(self):
        if not isinstance(self.endpoints[0],
                          amb.CommonAgentManagerRpcCallBackBase):
            LOG.error("RPC Callback class must inherit from "
                      "CommonAgentManagerRpcCallBackBase to ensure "
                      "CommonAgent works properly.")
            sys.exit(1)

    def setup_rpc(self):
        self.plugin_rpc = agent_rpc.PluginApi(topics.PLUGIN)
        self.sg_plugin_rpc = sg_rpc.SecurityGroupServerRpcApi(topics.PLUGIN)
        self.sg_agent = agent_sg_rpc.SecurityGroupAgentRpc(
            self.context, self.sg_plugin_rpc, defer_refresh_firewall=True)

        self.agent_id = self.mgr.get_agent_id()
        LOG.info("RPC agent_id: %s", self.agent_id)

        self.topic = topics.AGENT
        self.state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        # RPC network init
        # Handle updates from service
        self.rpc_callbacks = self.mgr.get_rpc_callbacks(self.context, self,
                                                        self.sg_agent)
        self.endpoints = [self.rpc_callbacks]
        self._validate_rpc_endpoints()
        # Define the listening consumers for the agent
        consumers = self.mgr.get_rpc_consumers()
        self.connection = agent_rpc.create_consumers(self.endpoints,
                                                     self.topic,
                                                     consumers,
                                                     start_listening=False)

    def init_extension_manager(self, connection):
        ext_manager.register_opts(cfg.CONF)
        self.ext_manager = (
            ext_manager.L2AgentExtensionsManager(cfg.CONF))
        agent_api = self.mgr.get_agent_api(sg_agent=self.sg_agent)
        self.ext_manager.initialize(
            connection, self.mgr.get_extension_driver_type(), agent_api)

    def _clean_network_ports(self, device):
        for netid, ports_list in self.network_ports.items():
            for port_data in ports_list:
                if device == port_data['device']:
                    ports_list.remove(port_data)
                    if ports_list == []:
                        self.network_ports.pop(netid)
                    return port_data['port_id']

    def _update_network_ports(self, network_id, port_id, device):
        self._clean_network_ports(device)
        self.network_ports[network_id].append({
            "port_id": port_id,
            "device": device
        })

    def process_network_devices(self, device_info):
        resync_a = False
        resync_b = False

        self.sg_agent.setup_port_filters(device_info.get('added'),
                                         device_info.get('updated'))
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

    def treat_devices_added_updated(self, devices):
        try:
            devices_details_list = self.plugin_rpc.get_devices_details_list(
                self.context, devices, self.agent_id, host=cfg.CONF.host)
        except Exception:
            LOG.exception("Unable to get port details for %s", devices)
            # resync is needed
            return True

        for device_details in devices_details_list:
            self._process_device_if_exists(device_details)
        # no resync is needed
        return False

    def _process_device_if_exists(self, device_details):
        # ignore exceptions from devices that disappear because they will
        # be handled as removed in the next iteration
        device = device_details['device']
        with self._ignore_missing_device_exceptions(device):
            LOG.debug("Port %s added", device)

            if 'port_id' in device_details:
                LOG.info("Port %(device)s updated. Details: %(details)s",
                         {'device': device, 'details': device_details})
                self.mgr.setup_arp_spoofing_protection(device,
                                                       device_details)

                segment = amb.NetworkSegment(
                    device_details.get('network_type'),
                    device_details['physical_network'],
                    device_details.get('segmentation_id'),
                    device_details.get('mtu')
                )
                network_id = device_details['network_id']
                self.rpc_callbacks.add_network(network_id, segment)
                interface_plugged = self.mgr.plug_interface(
                    network_id, segment,
                    device, device_details['device_owner'])
                # REVISIT(scheuran): Changed the way how ports admin_state_up
                # is implemented.
                #
                # Old lb implementation:
                # - admin_state_up: ensure that tap is plugged into bridge
                # - admin_state_down: remove tap from bridge
                # New lb implementation:
                # - admin_state_up: set tap device state to up
                # - admin_state_down: set tap device state to down
                #
                # However both approaches could result in races with
                # nova/libvirt and therefore to an invalid system state in the
                # scenario, where an instance is booted with a port configured
                # with admin_state_up = False:
                #
                # Libvirt does the following actions in exactly
                # this order (see libvirt virnetdevtap.c)
                #     1) Create the tap device, set its MAC and MTU
                #     2) Plug the tap into the bridge
                #     3) Set the tap online
                #
                # Old lb implementation:
                #   A race could occur, if the lb agent removes the tap device
                #   right after step 1). Then libvirt will add it to the bridge
                #   again in step 2).
                # New lb implementation:
                #   The race could occur if the lb-agent sets the taps device
                #   state to down right after step 2). In step 3) libvirt
                #   might set it to up again.
                #
                # This is not an issue if an instance is booted with a port
                # configured with admin_state_up = True. Libvirt would just
                # set the tap device up again.
                #
                # This refactoring is recommended for the following reasons:
                # 1) An existing race with libvirt caused by the behavior of
                #    the old implementation. See Bug #1312016
                # 2) The new code is much more readable
                if interface_plugged:
                    self.mgr.ensure_port_admin_state(
                        device, device_details['admin_state_up'])
                # update plugin about port status if admin_state is up
                if device_details['admin_state_up']:
                    if interface_plugged:
                        self.plugin_rpc.update_device_up(self.context,
                                                         device,
                                                         self.agent_id,
                                                         cfg.CONF.host)
                    else:
                        self.plugin_rpc.update_device_down(self.context,
                                                           device,
                                                           self.agent_id,
                                                           cfg.CONF.host)
                self._update_network_ports(device_details['network_id'],
                                           device_details['port_id'],
                                           device_details['device'])
                self.ext_manager.handle_port(self.context, device_details)
                registry.publish(local_resources.PORT_DEVICE,
                                 events.AFTER_UPDATE, self,
                                 payload=events.DBEventPayload(
                                     self.context, states=(device_details,),
                                     resource_id=device))
            elif constants.NO_ACTIVE_BINDING in device_details:
                LOG.info("Device %s has no active binding in host", device)
            else:
                LOG.info("Device %s not defined on plugin", device)

    @contextlib.contextmanager
    def _ignore_missing_device_exceptions(self, device):
        try:
            yield
        except Exception:
            with excutils.save_and_reraise_exception() as ectx:
                if device not in self.mgr.get_all_devices():
                    ectx.reraise = False
                    LOG.debug("%s was removed during processing.", device)

    def treat_devices_removed(self, devices):
        resync = False
        self.sg_agent.remove_devices_filter(devices)
        for device in devices:
            LOG.info("Attachment %s removed", device)
            details = None
            try:
                details = self.plugin_rpc.update_device_down(self.context,
                                                             device,
                                                             self.agent_id,
                                                             cfg.CONF.host)
            except Exception:
                LOG.exception("Error occurred while removing port %s",
                              device)
                resync = True
            if details and details['exists']:
                LOG.info("Port %s updated.", device)
            else:
                LOG.debug("Device %s not defined on plugin", device)
            port_id = self._clean_network_ports(device)
            try:
                self.ext_manager.delete_port(self.context,
                                             {'device': device,
                                              'port_id': port_id})
            except Exception:
                LOG.exception("Error occurred while processing extensions "
                              "for port removal %s", device)
                resync = True
            registry.publish(local_resources.PORT_DEVICE, events.AFTER_DELETE,
                             self, payload=events.DBEventPayload(
                                 self.context, states=(details,),
                                 resource_id=device))
        self.mgr.delete_arp_spoofing_protection(devices)
        return resync

    @staticmethod
    def _get_devices_locally_modified(timestamps, previous_timestamps):
        """Returns devices with previous timestamps that do not match new.

        If a device did not have a timestamp previously, it will not be
        returned because this means it is new.
        """
        return {device for device, timestamp in timestamps.items()
                if device in previous_timestamps and
                timestamp != previous_timestamps.get(device)}

    def scan_devices(self, previous, sync):
        device_info = {}

        updated_devices = self.rpc_callbacks.get_and_clear_updated_devices()

        current_devices = self.mgr.get_all_devices()
        device_info['current'] = current_devices

        if previous is None:
            # This is the first iteration of daemon_loop().
            previous = {'added': set(),
                        'current': set(),
                        'updated': set(),
                        'removed': set(),
                        'timestamps': {}}
            # clear any orphaned ARP spoofing rules (e.g. interface was
            # manually deleted)
            self.mgr.delete_unreferenced_arp_protection(current_devices)

        # check to see if any devices were locally modified based on their
        # timestamps changing since the previous iteration. If a timestamp
        # doesn't exist for a device, this calculation is skipped for that
        # device.
        device_info['timestamps'] = self.mgr.get_devices_modified_timestamps(
            current_devices)
        locally_updated = self._get_devices_locally_modified(
            device_info['timestamps'], previous['timestamps'])
        if locally_updated:
            LOG.debug("Adding locally changed devices to updated set: %s",
                      locally_updated)
            updated_devices |= locally_updated

        if sync:
            # This is the first iteration, or the previous one had a problem.
            # Re-add all existing devices.
            device_info['added'] = current_devices

            # Retry cleaning devices that may not have been cleaned properly.
            # And clean any that disappeared since the previous iteration.
            device_info['removed'] = (previous['removed'] |
                                      previous['current'] -
                                      current_devices)

            # Retry updating devices that may not have been updated properly.
            # And any that were updated since the previous iteration.
            # Only update devices that currently exist.
            device_info['updated'] = (previous['updated'] | updated_devices &
                                      current_devices)
        else:
            device_info['added'] = current_devices - previous['current']
            device_info['removed'] = previous['current'] - current_devices
            device_info['updated'] = updated_devices & current_devices

        return device_info

    def _device_info_has_changes(self, device_info):
        return (device_info.get('added') or
                device_info.get('updated') or
                device_info.get('removed'))

    def daemon_loop(self):
        LOG.info("%s Agent RPC Daemon Started!", self.agent_type)
        device_info = None
        sync = True

        while True:
            start = time.time()
            LOG.info("%s Agent loop - iteration:%d started",
                     self.agent_type, self.iter_num)

            if self.fullsync:
                sync = True
                self.fullsync = False

            if sync:
                LOG.info("%s Agent out of sync with plugin!",
                         self.agent_type)

            device_info = self.scan_devices(previous=device_info, sync=sync)
            sync = False

            if (self._device_info_has_changes(device_info) or
                    self.sg_agent.firewall_refresh_needed()):
                LOG.debug("Agent loop found changes! %s", device_info)
                try:
                    sync = self.process_network_devices(device_info)
                except Exception:
                    LOG.exception("Error in agent loop. Devices info: %s",
                                  device_info)
                    sync = True

            # sleep till end of polling interval
            elapsed = (time.time() - start)
            if (elapsed < self.polling_interval):
                time.sleep(self.polling_interval - elapsed)
            else:
                LOG.debug("Loop iteration exceeded interval "
                          "(%(polling_interval)s vs. %(elapsed)s)!",
                          {'polling_interval': self.polling_interval,
                           'elapsed': elapsed})

            LOG.info("%s Agent loop - iteration:%d completed",
                     self.agent_type, self.iter_num)
            self.iter_num = self.iter_num + 1

    def set_rpc_timeout(self, timeout):
        for rpc_api in (self.plugin_rpc, self.sg_plugin_rpc,
                        self.state_rpc):
            rpc_api.client.timeout = timeout
