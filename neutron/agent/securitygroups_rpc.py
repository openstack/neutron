# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

from oslo.config import cfg

from neutron.common import topics
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)
SG_RPC_VERSION = "1.1"

security_group_opts = [
    cfg.StrOpt(
        'firewall_driver',
        default='neutron.agent.firewall.NoopFirewallDriver',
        help=_('Driver for Security Groups Firewall'))
]
cfg.CONF.register_opts(security_group_opts, 'SECURITYGROUP')


def is_firewall_enabled():
    return (cfg.CONF.SECURITYGROUP.firewall_driver !=
            'neutron.agent.firewall.NoopFirewallDriver')


def disable_security_group_extension_if_noop_driver(
    supported_extension_aliases):
    if not is_firewall_enabled():
        LOG.debug(_('Disabled security-group extension.'))
        supported_extension_aliases.remove('security-group')


class SecurityGroupServerRpcApiMixin(object):
    """A mix-in that enable SecurityGroup support in plugin rpc."""
    def security_group_rules_for_devices(self, context, devices):
        LOG.debug(_("Get security group rules "
                    "for devices via rpc %r"), devices)
        return self.call(context,
                         self.make_msg('security_group_rules_for_devices',
                                       devices=devices),
                         version=SG_RPC_VERSION,
                         topic=self.topic)


class SecurityGroupAgentRpcCallbackMixin(object):
    """A mix-in that enable SecurityGroup agent
    support in agent implementations.
    """
    #mix-in object should be have sg_agent
    sg_agent = None

    def _security_groups_agent_not_set(self):
        LOG.warning(_("Security group agent binding currently not set. "
                      "This should be set by the end of the init "
                      "process."))

    def security_groups_rule_updated(self, context, **kwargs):
        """Callback for security group rule update.

        :param security_groups: list of updated security_groups
        """
        security_groups = kwargs.get('security_groups', [])
        LOG.debug(
            _("Security group rule updated on remote: %s"), security_groups)
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_rule_updated(security_groups)

    def security_groups_member_updated(self, context, **kwargs):
        """Callback for security group member update.

        :param security_groups: list of updated security_groups
        """
        security_groups = kwargs.get('security_groups', [])
        LOG.debug(
            _("Security group member updated on remote: %s"), security_groups)
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_member_updated(security_groups)

    def security_groups_provider_updated(self, context, **kwargs):
        """Callback for security group provider update."""
        LOG.debug(_("Provider rule updated"))
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_provider_updated()


class SecurityGroupAgentRpcMixin(object):
    """A mix-in that enable SecurityGroup agent
    support in agent implementations.
    """

    def init_firewall(self):
        firewall_driver = cfg.CONF.SECURITYGROUP.firewall_driver
        LOG.debug(_("Init firewall settings (driver=%s)"), firewall_driver)
        self.firewall = importutils.import_object(firewall_driver)

    def prepare_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_("Preparing filters for devices %s"), device_ids)
        devices = self.plugin_rpc.security_group_rules_for_devices(
            self.context, list(device_ids))
        with self.firewall.defer_apply():
            for device in devices.values():
                self.firewall.prepare_port_filter(device)

    def security_groups_rule_updated(self, security_groups):
        LOG.info(_("Security group "
                   "rule updated %r"), security_groups)
        self._security_group_updated(
            security_groups,
            'security_groups')

    def security_groups_member_updated(self, security_groups):
        LOG.info(_("Security group "
                   "member updated %r"), security_groups)
        self._security_group_updated(
            security_groups,
            'security_group_source_groups')

    def _security_group_updated(self, security_groups, attribute):
        devices = []
        sec_grp_set = set(security_groups)
        for device in self.firewall.ports.values():
            if sec_grp_set & set(device.get(attribute, [])):
                devices.append(device)

        if devices:
            self.refresh_firewall(devices)

    def security_groups_provider_updated(self):
        LOG.info(_("Provider rule updated"))
        self.refresh_firewall()

    def remove_devices_filter(self, device_ids):
        if not device_ids:
            return
        LOG.info(_("Remove device filter for %r"), device_ids)
        with self.firewall.defer_apply():
            for device_id in device_ids:
                device = self.firewall.ports.get(device_id)
                if not device:
                    continue
                self.firewall.remove_port_filter(device)

    def refresh_firewall(self, devices=None):
        LOG.info(_("Refresh firewall rules"))

        if devices:
            device_ids = [d['device'] for d in devices]
        else:
            device_ids = self.firewall.ports.keys()
        if not device_ids:
            LOG.info(_("No ports here to refresh firewall"))
            return
        devices = self.plugin_rpc.security_group_rules_for_devices(
            self.context, device_ids)
        with self.firewall.defer_apply():
            for device in devices.values():
                LOG.debug(_("Update port filter for %s"), device['device'])
                self.firewall.update_port_filter(device)


class SecurityGroupAgentRpcApiMixin(object):

    def _get_security_group_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.SECURITY_GROUP,
                                     topics.UPDATE)

    def security_groups_rule_updated(self, context, security_groups):
        """Notify rule updated security groups."""
        if not security_groups:
            return
        self.fanout_cast(context,
                         self.make_msg('security_groups_rule_updated',
                                       security_groups=security_groups),
                         version=SG_RPC_VERSION,
                         topic=self._get_security_group_topic())

    def security_groups_member_updated(self, context, security_groups):
        """Notify member updated security groups."""
        if not security_groups:
            return
        self.fanout_cast(context,
                         self.make_msg('security_groups_member_updated',
                                       security_groups=security_groups),
                         version=SG_RPC_VERSION,
                         topic=self._get_security_group_topic())

    def security_groups_provider_updated(self, context):
        """Notify provider updated security groups."""
        self.fanout_cast(context,
                         self.make_msg('security_groups_provider_updated'),
                         version=SG_RPC_VERSION,
                         topic=self._get_security_group_topic())
