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

import oslo_messaging

from oslo_log import log as logging

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.i18n import _LW
from neutron import manager

LOG = logging.getLogger(__name__)


class SecurityGroupServerRpcApi(object):
    """RPC client for security group methods in the plugin.

    This class implements the client side of an rpc interface.  This interface
    is used by agents to call security group related methods implemented on the
    plugin side.  The other side of this interface is defined in
    SecurityGroupServerRpcCallback.  For more information about changing rpc
    interfaces, see doc/source/devref/rpc_api.rst.
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


class SecurityGroupServerRpcCallback(object):
    """Callback for SecurityGroup agent RPC in plugin implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in SecurityGroupServerRpcApi. For more information on changing
    rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    # API version history:
    #   1.1 - Initial version
    #   1.2 - security_group_info_for_devices introduced as an optimization

    # NOTE: target must not be overridden in subclasses
    # to keep RPC API version consistent across plugins.
    target = oslo_messaging.Target(version='1.2',
                                   namespace=constants.RPC_NAMESPACE_SECGROUP)

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    def _get_devices_info(self, context, devices):
        return dict(
            (port['id'], port)
            for port in self.plugin.get_ports_from_devices(context, devices)
            if port and not port['device_owner'].startswith('network:')
        )

    def security_group_rules_for_devices(self, context, **kwargs):
        """Callback method to return security group rules for each port.

        also convert remote_group_id rule
        to source_ip_prefix and dest_ip_prefix rule

        :params devices: list of devices
        :returns: port correspond to the devices with security group rules
        """
        devices_info = kwargs.get('devices')
        ports = self._get_devices_info(context, devices_info)
        return self.plugin.security_group_rules_for_ports(context, ports)

    def security_group_info_for_devices(self, context, **kwargs):
        """Return security group information for requested devices.

        :params devices: list of devices
        :returns:
        sg_info{
          'security_groups': {sg_id: [rule1, rule2]}
          'sg_member_ips': {sg_id: {'IPv4': set(), 'IPv6': set()}}
          'devices': {device_id: {device_info}}
        }

        Note that sets are serialized into lists by rpc code.
        """
        devices_info = kwargs.get('devices')
        ports = self._get_devices_info(context, devices_info)
        return self.plugin.security_group_info_for_ports(context, ports)


class SecurityGroupAgentRpcApiMixin(object):
    """RPC client for security group methods to the agent.

    This class implements the client side of an rpc interface.  This interface
    is used by plugins to call security group methods implemented on the
    agent side.  The other side of this interface can be found in
    SecurityGroupAgentRpcCallbackMixin.  For more information about changing
    rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    # history
    #   1.1 Support Security Group RPC
    SG_RPC_VERSION = "1.1"

    def _get_security_group_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.SECURITY_GROUP,
                                     topics.UPDATE)

    def security_groups_rule_updated(self, context, security_groups):
        """Notify rule updated security groups."""
        if not security_groups:
            return
        cctxt = self.client.prepare(version=self.SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_rule_updated',
                   security_groups=security_groups)

    def security_groups_member_updated(self, context, security_groups):
        """Notify member updated security groups."""
        if not security_groups:
            return
        cctxt = self.client.prepare(version=self.SG_RPC_VERSION,
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_member_updated',
                   security_groups=security_groups)

    def security_groups_provider_updated(self, context,
                                         devices_to_update=None):
        """Notify provider updated security groups."""
        cctxt = self.client.prepare(version='1.3',
                                    topic=self._get_security_group_topic(),
                                    fanout=True)
        cctxt.cast(context, 'security_groups_provider_updated',
                   devices_to_update=devices_to_update)


class SecurityGroupAgentRpcCallbackMixin(object):
    """A mix-in that enable SecurityGroup support in agent implementations.

    This class implements the server side of an rpc interface.  The client side
    can be found in SecurityGroupServerRpcApi. For more information on changing
    rpc interfaces, see doc/source/devref/rpc_api.rst.

    The sg_agent reference implementation is available in neutron/agent
    """
    # mix-in object should be have sg_agent
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
        devices_to_update = kwargs.get('devices_to_update')
        if not self.sg_agent:
            return self._security_groups_agent_not_set()
        self.sg_agent.security_groups_provider_updated(devices_to_update)
