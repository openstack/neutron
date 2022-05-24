# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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
#

import functools

from neutron_lib.api.definitions import rbac_address_groups as rbac_ag_apidef
from neutron_lib.api.definitions import rbac_security_groups as rbac_sg_apidef
from neutron_lib.api.definitions import security_groups_normalized_cidr
from neutron_lib.api.definitions import security_groups_remote_address_group \
    as sgag_def
from neutron_lib.api.definitions import security_groups_shared_filtering \
    as sg_shared_filtering
from neutron_lib.api.definitions import stateful_security_group as stateful_sg
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent import firewall
from neutron.conf.agent import securitygroups_rpc as sc_cfg


LOG = logging.getLogger(__name__)


sc_cfg.register_securitygroups_opts()


def is_firewall_enabled():
    return cfg.CONF.SECURITYGROUP.enable_security_group


def _disable_extension(extension, aliases):
    if extension in aliases:
        aliases.remove(extension)


def disable_security_group_extension_by_config(aliases):
    if not is_firewall_enabled():
        LOG.info('Disabled security-group extension.')
        _disable_extension('security-group', aliases)
        _disable_extension(rbac_sg_apidef.ALIAS, aliases)
        _disable_extension(stateful_sg.ALIAS, aliases)
        _disable_extension(sgag_def.ALIAS, aliases)
        _disable_extension(security_groups_normalized_cidr.ALIAS, aliases)
        _disable_extension(sg_shared_filtering.ALIAS, aliases)
        LOG.info('Disabled allowed-address-pairs extension.')
        _disable_extension('allowed-address-pairs', aliases)
        LOG.info('Disabled address-group extension.')
        _disable_extension('address-group', aliases)
        _disable_extension(rbac_ag_apidef.ALIAS, aliases)


class SecurityGroupAgentRpc(object):
    """Enables SecurityGroup agent support in agent implementations."""

    def __init__(self, context, plugin_rpc, local_vlan_map=None,
                 defer_refresh_firewall=False, integration_bridge=None):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.init_firewall(defer_refresh_firewall, integration_bridge)
        # _latest_port_filter_lock will point to the lock created for the
        # most recent thread to enter _apply_port_filters().
        self._latest_port_filter_lock = lockutils.ReaderWriterLock()

    @property
    def noopfirewall_or_firewall_disabled(self):
        return (isinstance(self.firewall, firewall.NoopFirewallDriver) or
                not is_firewall_enabled())

    def _get_trusted_devices(self, device_ids, devices):
        trusted_devices = []
        # Devices which are already added in firewall ports should
        # not be treated as trusted devices but as regular ports
        all_devices = devices.copy()
        all_devices.update(self.firewall.ports)
        device_names = [
            dev['device'] for dev in all_devices.values()]
        for device_id in device_ids:
            if (device_id not in all_devices.keys() and
                    device_id not in device_names):
                trusted_devices.append(device_id)
        return trusted_devices

    def _port_filter_lock(func):
        """Decorator to acquire a new lock while applying port filters"""
        @functools.wraps(func)
        def decorated_function(self, *args, **kwargs):
            lock = lockutils.ReaderWriterLock()
            # Tracking the most recent lock at the instance level allows
            # waiters to only wait for the most recent lock to be released
            # instead of waiting until all locks have been released.
            self._latest_port_filter_lock = lock
            with lock.write_lock():
                return func(self, *args, **kwargs)
        return decorated_function

    def _port_filter_wait(func):
        """Decorator to wait for the latest port filter lock to be released"""
        @functools.wraps(func)
        def decorated_function(self, *args, **kwargs):
            with self._latest_port_filter_lock.read_lock():
                return func(self, *args, **kwargs)
        return decorated_function

    def init_firewall(self, defer_refresh_firewall=False,
                      integration_bridge=None):
        firewall_driver = cfg.CONF.SECURITYGROUP.firewall_driver or 'noop'
        LOG.debug("Init firewall settings (driver=%s)", firewall_driver)
        firewall_class = firewall.load_firewall_driver_class(firewall_driver)
        try:
            self.firewall = firewall_class(
                integration_bridge=integration_bridge)
        except TypeError:
            self.firewall = firewall_class()
        # The following flag will be set to true if port filter must not be
        # applied as soon as a rule or membership notification is received
        self.defer_refresh_firewall = defer_refresh_firewall
        # Stores devices for which firewall should be refreshed when
        # deferred refresh is enabled.
        self.devices_to_refilter = set()

    def skip_if_noopfirewall_or_firewall_disabled(func):
        @functools.wraps(func)
        def decorated_function(self, *args, **kwargs):
            if self.noopfirewall_or_firewall_disabled:
                LOG.info("Skipping method %s as firewall is disabled "
                         "or configured as NoopFirewallDriver.",
                         func.__name__)
            else:
                return func(self,  # pylint: disable=not-callable
                            *args, **kwargs)
        return decorated_function

    @skip_if_noopfirewall_or_firewall_disabled
    def init_ovs_dvr_firewall(self, dvr_agent):
        dvr_agent.set_firewall(self.firewall)

    @skip_if_noopfirewall_or_firewall_disabled
    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info("Preparing filters for devices %s", device_ids)
        self._apply_port_filter(device_ids)

    @_port_filter_lock
    def _apply_port_filter(self, device_ids, update_filter=False):
        step = cfg.CONF.rpc_resources_processing_step
        devices = {}
        security_groups = {}
        security_group_member_ips = {}
        for i in range(0, len(device_ids), step):
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, list(device_ids)[i:i + step])
            devices.update(devices_info['devices'])
            security_groups.update(devices_info['security_groups'])
            security_group_member_ips.update(devices_info['sg_member_ips'])
        trusted_devices = self._get_trusted_devices(device_ids, devices)

        with self.firewall.defer_apply():
            LOG.debug("Update security group information for ports %s",
                      devices.keys())
            self._update_security_group_info(
                security_groups, security_group_member_ips)
            for device in devices.values():
                if update_filter:
                    LOG.debug("Update port filter for %s", device['device'])
                    self.firewall.update_port_filter(device)
                else:
                    LOG.debug("Prepare port filter for %s", device['device'])
                    self.firewall.prepare_port_filter(device)
            self.firewall.process_trusted_ports(trusted_devices)

    def _update_security_group_info(self, security_groups,
                                    security_group_member_ips):
        LOG.debug("Update security group information")
        for sg_id, sg_rules in security_groups.items():
            self.firewall.update_security_group_rules(sg_id, sg_rules)
        # NOTE(hangyang) security_group_member_ips contains IPs from remote
        # security groups and remote address groups. Both are handled by
        # the same firewall functions.
        for remote_id, member_ips in security_group_member_ips.items():
            self.firewall.update_security_group_members(
                remote_id, member_ips)

    def security_groups_rule_updated(self, security_groups):
        LOG.info("Security group "
                 "rule updated %r", security_groups)
        self._security_group_updated(
            security_groups,
            'security_groups',
            'sg_rule')

    def security_groups_member_updated(self, security_groups):
        LOG.info("Security group "
                 "member updated %r", security_groups)
        self._security_group_updated(
            security_groups,
            'security_group_source_groups',
            'sg_member')

    @_port_filter_wait
    def _security_group_updated(self, security_groups, attribute, action_type):
        devices = []
        sec_grp_set = set(security_groups)
        for device in self.firewall.ports.values():
            if sec_grp_set & set(device.get(attribute, [])):
                devices.append(device['device'])
        if devices:
            self.firewall.security_group_updated(action_type, sec_grp_set)
            if self.defer_refresh_firewall:
                LOG.debug("Adding %s devices to the list of devices "
                          "for which firewall needs to be refreshed",
                          devices)
                self.devices_to_refilter |= set(devices)
            else:
                self.refresh_firewall(devices)

    def address_group_updated(self, address_group_id):
        LOG.info("Address group updated %r", address_group_id)
        security_group_ids = (
            self.plugin_rpc.get_secgroup_ids_for_address_group(
                address_group_id))
        self.security_groups_rule_updated(security_group_ids)

    def address_group_deleted(self, address_group_id):
        LOG.info("Address group deleted %r", address_group_id)
        security_group_ids = (
            self.plugin_rpc.get_secgroup_ids_for_address_group(
                address_group_id))
        self.security_groups_rule_updated(security_group_ids)

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info("Remove device filter for %r", device_ids)
        with self.firewall.defer_apply():
            for device_id in device_ids:
                device = self.firewall.ports.get(device_id)
                if device:
                    self.firewall.remove_port_filter(device)
                else:
                    self.firewall.remove_trusted_ports([device_id])

    @skip_if_noopfirewall_or_firewall_disabled
    def refresh_firewall(self, device_ids=None):
        LOG.info("Refresh firewall rules")
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info("No ports here to refresh firewall")
                return
        self._apply_port_filter(device_ids, update_filter=True)

    def firewall_refresh_needed(self):
        return bool(self.devices_to_refilter)

    def setup_port_filters(self, new_devices, updated_devices):
        """Configure port filters for devices.

        This routine applies filters for new devices and refreshes firewall
        rules when devices have been updated, or when there are changes in
        security group membership or rules.

        :param new_devices: set containing identifiers for new devices
        :param updated_devices: set containing identifiers for
        updated devices
        """
        # These data structures are cleared here in order to avoid
        # losing updates occurring during firewall refresh
        devices_to_refilter = self.devices_to_refilter
        self.devices_to_refilter = set()
        # We must call prepare_devices_filter() after we've grabbed
        # self.devices_to_refilter since an update for a new port
        # could arrive while we're processing, and we need to make
        # sure we don't skip it.  It will get handled the next time.
        if new_devices:
            LOG.debug("Preparing device filters for %d new devices",
                      len(new_devices))
            self.prepare_devices_filter(new_devices)
        if updated_devices:
            self.firewall.security_group_updated('sg_member', [],
                                                 updated_devices)
        # If a device is both in new and updated devices
        # avoid reprocessing it
        updated_devices = ((updated_devices | devices_to_refilter) -
                           new_devices)
        if updated_devices:
            LOG.debug("Refreshing firewall for %d devices",
                      len(updated_devices))
            self.refresh_firewall(updated_devices)
