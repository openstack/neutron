# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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

import abc

import six

from neutron.common import rpc as n_rpc
from neutron.db.vpn import vpn_validator
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants

LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class VpnDriver(object):

    def __init__(self, service_plugin, validator=None):
        self.service_plugin = service_plugin
        if validator is None:
            validator = vpn_validator.VpnReferenceValidator()
        self.validator = validator

    @property
    def l3_plugin(self):
        return manager.NeutronManager.get_service_plugins().get(
            constants.L3_ROUTER_NAT)

    @property
    def service_type(self):
        pass

    @abc.abstractmethod
    def create_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def update_vpnservice(
        self, context, old_vpnservice, vpnservice):
        pass

    @abc.abstractmethod
    def delete_vpnservice(self, context, vpnservice):
        pass

    @abc.abstractmethod
    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        pass

    @abc.abstractmethod
    def update_ipsec_site_connection(self, context, old_ipsec_site_connection,
                                     ipsec_site_connection):
        pass

    @abc.abstractmethod
    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        pass


class BaseIPsecVpnAgentApi(n_rpc.RpcProxy):
    """Base class for IPSec API to agent."""

    def __init__(self, topic, default_version, driver):
        self.topic = topic
        self.driver = driver
        super(BaseIPsecVpnAgentApi, self).__init__(topic, default_version)

    def _agent_notification(self, context, method, router_id,
                            version=None, **kwargs):
        """Notify update for the agent.

        This method will find where is the router, and
        dispatch notification for the agent.
        """
        admin_context = context.is_admin and context or context.elevated()
        if not version:
            version = self.RPC_API_VERSION
        l3_agents = self.driver.l3_plugin.get_l3_agents_hosting_routers(
            admin_context, [router_id],
            admin_state_up=True,
            active=True)
        for l3_agent in l3_agents:
            LOG.debug(_('Notify agent at %(topic)s.%(host)s the message '
                        '%(method)s %(args)s'),
                      {'topic': self.topic,
                       'host': l3_agent.host,
                       'method': method,
                       'args': kwargs})
            self.cast(
                context, self.make_msg(method, **kwargs),
                version=version,
                topic='%s.%s' % (self.topic, l3_agent.host))

    def vpnservice_updated(self, context, router_id, **kwargs):
        """Send update event of vpnservices."""
        self._agent_notification(context, 'vpnservice_updated', router_id,
                                 **kwargs)
