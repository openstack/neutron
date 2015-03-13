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

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import importutils

from neutron.agent import firewall
from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.i18n import _LI, _LW

LOG = logging.getLogger(__name__)
# history
#   1.1 Support Security Group RPC
SG_RPC_VERSION = "1.1"

security_group_opts = [
    cfg.StrOpt(
        'firewall_driver',
        help=_('Driver for security groups firewall in the L2 agent')),
    cfg.BoolOpt(
        'enable_security_group',
        default=True,
        help=_(
            'Controls whether the neutron security group API is enabled '
            'in the server. It should be false when using no security '
            'groups or using the nova security group API.')),
    cfg.BoolOpt(
        'enable_ipset',
        default=True,
        help=_('Use ipset to speed-up the iptables based security groups.'))
]
cfg.CONF.register_opts(security_group_opts, 'SECURITYGROUP')


#This is backward compatibility check for Havana
def _is_valid_driver_combination():
    return ((cfg.CONF.SECURITYGROUP.enable_security_group and
             (cfg.CONF.SECURITYGROUP.firewall_driver and
              cfg.CONF.SECURITYGROUP.firewall_driver !=
             'neutron.agent.firewall.NoopFirewallDriver')) or
            (not cfg.CONF.SECURITYGROUP.enable_security_group and
             (cfg.CONF.SECURITYGROUP.firewall_driver ==
             'neutron.agent.firewall.NoopFirewallDriver' or
              cfg.CONF.SECURITYGROUP.firewall_driver is None)
             ))


def is_firewall_enabled():
    if not _is_valid_driver_combination():
        LOG.warn(_LW("Driver configuration doesn't match with "
                     "enable_security_group"))

    return cfg.CONF.SECURITYGROUP.enable_security_group


def _disable_extension(extension, aliases):
    if extension in aliases:
        aliases.remove(extension)


def disable_security_group_extension_by_config(aliases):
    if not is_firewall_enabled():
        LOG.info(_LI('Disabled security-group extension.'))
        _disable_extension('security-group', aliases)
        LOG.info(_LI('Disabled allowed-address-pairs extension.'))
        _disable_extension('allowed-address-pairs', aliases)


class SecurityGroupServerRpcApi(object):
    """RPC client for security group methods in the plugin.

    This class implements the client side of an rpc interface.  This interface
    is used by agents to call security group related methods implemented on the
    plugin side.  The other side of this interface can be found in
    neutron.api.rpc.handlers.SecurityGroupServerRpcCallback.  For more
    information about changing rpc interfaces, see
    doc/source/devref/rpc_api.rst.
    """
    def __init__(self, topic):
        target = oslo_messaging.Target(
            topic=topic, version='1.0',
            namespace=constants.RPC_NAMESPACE_SECGROUP)
        self.client = n_rpc.get_client(target)

    def security_group_rules_for_devices(self, context, devices):
        LOG.debug("Get security group rules "
                  "for devices via rpc %r", devices)
        cctxt = self.client.prepare(version='1.1')
        return cctxt.call(context, 'security_group_rules_for_devices',
                          devices=devices)

    def security_group_info_for_devices(self, context, devices):
        LOG.debug("Get security group information for devices via rpc %r",
                  devices)
        cctxt = self.client.prepare(version='1.2')
        return cctxt.call(context, 'security_group_info_for_devices',
                          devices=devices)


class SecurityGroupAgentRpcCallbackMixin(object):
    """A mix-in that enable SecurityGroup agent
    support in agent implementations.
    """
    #mix-in object should be have sg_agent
    sg_agent = None

    def _security_groups_agent_not_set(self):
        LOG.warning(_LW("Security group agent binding currently not set. "
                        "This should be set by the end of the init "
                        "process."))

    def security_groups_rule_updated(self, context, **kwargs):
        """Callback for security group rule update.

        :param security_groups: list of updated security_groups
        """
        security_groups = kwargs.get('security_groups', [])
        LOG.debug("Security group rule updated on remote: %s",
                  security_groups)
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_rule_updated(security_groups)

    def security_groups_member_updated(self, context, **kwargs):
        """Callback for security group member update.

        :param security_groups: list of updated security_groups
        """
        security_groups = kwargs.get('security_groups', [])
        LOG.debug("Security group member updated on remote: %s",
                  security_groups)
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_member_updated(security_groups)

    def security_groups_provider_updated(self, context, **kwargs):
        """Callback for security group provider update."""
        LOG.debug("Provider rule updated")
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_provider_updated()


class SecurityGroupAgentRpc(object):
    """Enables SecurityGroup agent support in agent implementations."""

    def __init__(self, context, plugin_rpc, defer_refresh_firewall=False):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.init_firewall(defer_refresh_firewall)

    def init_firewall(self, defer_refresh_firewall=False):
        firewall_driver = cfg.CONF.SECURITYGROUP.firewall_driver
        LOG.debug("Init firewall settings (driver=%s)", firewall_driver)
        if not _is_valid_driver_combination():
            LOG.warn(_LW("Driver configuration doesn't match "
                         "with enable_security_group"))
        if not firewall_driver:
            firewall_driver = 'neutron.agent.firewall.NoopFirewallDriver'
        self.firewall = importutils.import_object(firewall_driver)
        # The following flag will be set to true if port filter must not be
        # applied as soon as a rule or membership notification is received
        self.defer_refresh_firewall = defer_refresh_firewall
        # Stores devices for which firewall should be refreshed when
        # deferred refresh is enabled.
        self.devices_to_refilter = set()
        # Flag raised when a global refresh is needed
        self.global_refresh_firewall = False
        self._use_enhanced_rpc = None

    @property
    def use_enhanced_rpc(self):
        if self._use_enhanced_rpc is None:
            self._use_enhanced_rpc = (
                self._check_enhanced_rpc_is_supported_by_server())
        return self._use_enhanced_rpc

    def _check_enhanced_rpc_is_supported_by_server(self):
        try:
            self.plugin_rpc.security_group_info_for_devices(
                self.context, devices=[])
        except oslo_messaging.UnsupportedVersion:
            LOG.warning(_LW('security_group_info_for_devices rpc call not '
                            'supported by the server, falling back to old '
                            'security_group_rules_for_devices which scales '
                            'worse.'))
            return False
        return True

    def skip_if_noopfirewall_or_firewall_disabled(func):
        @functools.wraps(func)
        def decorated_function(self, *args, **kwargs):
            if (isinstance(self.firewall, firewall.NoopFirewallDriver) or
                not is_firewall_enabled()):
                LOG.info(_LI("Skipping method %s as firewall is disabled "
                         "or configured as NoopFirewallDriver."),
                         func.__name__)
            else:
                return func(self,  # pylint: disable=not-callable
                            *args, **kwargs)
        return decorated_function

    @skip_if_noopfirewall_or_firewall_disabled
    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Preparing filters for devices %s"), device_ids)
        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, list(device_ids))
            devices = devices_info['devices']
            security_groups = devices_info['security_groups']
            security_group_member_ips = devices_info['sg_member_ips']
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, list(device_ids))

        with self.firewall.defer_apply():
            for device in devices.values():
                self.firewall.prepare_port_filter(device)
            if self.use_enhanced_rpc:
                LOG.debug("Update security group information for ports %s",
                          devices.keys())
                self._update_security_group_info(
                    security_groups, security_group_member_ips)

    def _update_security_group_info(self, security_groups,
                                    security_group_member_ips):
        LOG.debug("Update security group information")
        for sg_id, sg_rules in security_groups.items():
            self.firewall.update_security_group_rules(sg_id, sg_rules)
        for remote_sg_id, member_ips in security_group_member_ips.items():
            self.firewall.update_security_group_members(
                remote_sg_id, member_ips)

    def security_groups_rule_updated(self, security_groups):
        LOG.info(_LI("Security group "
                 "rule updated %r"), security_groups)
        self._security_group_updated(
            security_groups,
            'security_groups')

    def security_groups_member_updated(self, security_groups):
        LOG.info(_LI("Security group "
                 "member updated %r"), security_groups)
        self._security_group_updated(
            security_groups,
            'security_group_source_groups')

    def _security_group_updated(self, security_groups, attribute):
        devices = []
        sec_grp_set = set(security_groups)
        for device in self.firewall.ports.values():
            if sec_grp_set & set(device.get(attribute, [])):
                devices.append(device['device'])
        if devices:
            if self.defer_refresh_firewall:
                LOG.debug("Adding %s devices to the list of devices "
                          "for which firewall needs to be refreshed",
                          devices)
                self.devices_to_refilter |= set(devices)
            else:
                self.refresh_firewall(devices)

    def security_groups_provider_updated(self):
        LOG.info(_LI("Provider rule updated"))
        if self.defer_refresh_firewall:
            # NOTE(salv-orlando): A 'global refresh' might not be
            # necessary if the subnet for which the provider rules
            # were updated is known
            self.global_refresh_firewall = True
        else:
            self.refresh_firewall()

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_LI("Remove device filter for %r"), device_ids)
        with self.firewall.defer_apply():
            for device_id in device_ids:
                device = self.firewall.ports.get(device_id)
                if not device:
                    continue
                self.firewall.remove_port_filter(device)

    @skip_if_noopfirewall_or_firewall_disabled
    def refresh_firewall(self, device_ids=None):
        LOG.info(_LI("Refresh firewall rules"))
        if not device_ids:
            device_ids = self.firewall.ports.keys()
            if not device_ids:
                LOG.info(_LI("No ports here to refresh firewall"))
                return
        if self.use_enhanced_rpc:
            devices_info = self.plugin_rpc.security_group_info_for_devices(
                self.context, device_ids)
            devices = devices_info['devices']
            security_groups = devices_info['security_groups']
            security_group_member_ips = devices_info['sg_member_ips']
        else:
            devices = self.plugin_rpc.security_group_rules_for_devices(
                self.context, device_ids)

        with self.firewall.defer_apply():
            for device in devices.values():
                LOG.debug("Update port filter for %s", device['device'])
                self.firewall.update_port_filter(device)
            if self.use_enhanced_rpc:
                LOG.debug("Update security group information for ports %s",
                          devices.keys())
                self._update_security_group_info(
                    security_groups, security_group_member_ips)

    def firewall_refresh_needed(self):
        return self.global_refresh_firewall or self.devices_to_refilter

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
        global_refresh_firewall = self.global_refresh_firewall
        self.devices_to_refilter = set()
        self.global_refresh_firewall = False
        # We must call prepare_devices_filter() after we've grabbed
        # self.devices_to_refilter since an update for a new port
        # could arrive while we're processing, and we need to make
        # sure we don't skip it.  It will get handled the next time.
        if new_devices:
            LOG.debug("Preparing device filters for %d new devices",
                      len(new_devices))
            self.prepare_devices_filter(new_devices)
        # TODO(salv-orlando): Avoid if possible ever performing the global
        # refresh providing a precise list of devices for which firewall
        # should be refreshed
        if global_refresh_firewall:
            LOG.debug("Refreshing firewall for all filtered devices")
            self.refresh_firewall()
        else:
            # If a device is both in new and updated devices
            # avoid reprocessing it
            updated_devices = ((updated_devices | devices_to_refilter) -
                               new_devices)
            if updated_devices:
                LOG.debug("Refreshing firewall for %d devices",
                          len(updated_devices))
                self.refresh_firewall(updated_devices)


class SecurityGroupAgentRpcApiMixin(object):

    def _get_security_group_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.SECURITY_GROUP,
                                     topics.UPDATE)

    def security_groups_rule_updated(self, context, security_groups):
        """Notify rule updated security groups."""
        if not security_groups:
            return
        cctxt = self.client.prepare(version=SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_rule_updated',
                   security_groups=security_groups)

    def security_groups_member_updated(self, context, security_groups):
        """Notify member updated security groups."""
        if not security_groups:
            return
        cctxt = self.client.prepare(version=SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_member_updated',
                   security_groups=security_groups)

    def security_groups_provider_updated(self, context):
        """Notify provider updated security groups."""
        cctxt = self.client.prepare(version=SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_provider_updated')
