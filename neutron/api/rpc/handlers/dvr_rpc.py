# Copyright 2014, Hewlett-Packard Development Company, L.P.
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

from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import oslo_messaging

from neutron.common import constants
from neutron.common import rpc as n_rpc
from neutron.common import topics

LOG = logging.getLogger(__name__)


class DVRServerRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction.

    This class implements the client side of an rpc interface.  The server side
    can be found below: DVRServerRpcCallback.  For more information on changing
    rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """
    # 1.0 Initial Version
    # 1.1 Support for passing 'fixed_ips' in get_subnet_for_dvr function.
    #     Passing 'subnet" will be deprecated in the next release.

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0',
                                       namespace=constants.RPC_NAMESPACE_DVR)
        self.client = n_rpc.get_client(target)

    @log_helpers.log_method_call
    def get_dvr_mac_address_by_host(self, context, host):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_dvr_mac_address_by_host', host=host)

    @log_helpers.log_method_call
    def get_dvr_mac_address_list(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_dvr_mac_address_list')

    @log_helpers.log_method_call
    def get_ports_on_host_by_subnet(self, context, host, subnet):
        """Get DVR serviced ports on given host and subnet."""

        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_ports_on_host_by_subnet',
                          host=host, subnet=subnet)

    @log_helpers.log_method_call
    def get_subnet_for_dvr(self, context, subnet, fixed_ips):
        cctxt = self.client.prepare()
        return cctxt.call(
            context, 'get_subnet_for_dvr', subnet=subnet, fixed_ips=fixed_ips)


class DVRServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction.

    This class implements the server side of an rpc interface.  The client side
    can be found above: DVRServerRpcApi.  For more information on changing rpc
    interfaces, see doc/source/contributor/internals/rpc_api.rst.
    """

    # History
    #   1.0 Initial version
    #   1.1 Support for passing the 'fixed_ips" in get_subnet_for_dvr.
    #       Passing subnet will be deprecated in the next release.

    target = oslo_messaging.Target(version='1.1',
                                   namespace=constants.RPC_NAMESPACE_DVR)

    @property
    def plugin(self):
        if not getattr(self, '_plugin', None):
            self._plugin = directory.get_plugin()
        return self._plugin

    def get_dvr_mac_address_list(self, context):
        return self.plugin.get_dvr_mac_address_list(context)

    def get_dvr_mac_address_by_host(self, context, **kwargs):
        host = kwargs.get('host')
        LOG.debug("DVR Agent requests mac_address for host %s", host)
        return self.plugin.get_dvr_mac_address_by_host(context, host)

    def get_ports_on_host_by_subnet(self, context, **kwargs):
        """Get DVR serviced ports for given host and subnet."""

        host = kwargs.get('host')
        subnet = kwargs.get('subnet')
        LOG.debug("DVR Agent requests list of VM ports on host %s", host)
        return self.plugin.get_ports_on_host_by_subnet(context,
            host, subnet)

    def get_subnet_for_dvr(self, context, **kwargs):
        fixed_ips = kwargs.get('fixed_ips')
        subnet = kwargs.get('subnet')
        return self.plugin.get_subnet_for_dvr(
            context, subnet, fixed_ips=fixed_ips)


class DVRAgentRpcApiMixin(object):
    """Plugin-side RPC (stub) for plugin-to-agent interaction."""

    DVR_RPC_VERSION = "1.0"

    def _get_dvr_update_topic(self):
        return topics.get_topic_name(self.topic,
                                     topics.DVR,
                                     topics.UPDATE)

    def dvr_mac_address_update(self, context, dvr_macs):
        """Notify dvr mac address updates."""
        if not dvr_macs:
            return
        cctxt = self.client.prepare(topic=self._get_dvr_update_topic(),
                                    version=self.DVR_RPC_VERSION, fanout=True)
        cctxt.cast(context, 'dvr_mac_address_update', dvr_macs=dvr_macs)


class DVRAgentRpcCallbackMixin(object):
    """Agent-side RPC (implementation) for plugin-to-agent interaction."""

    def dvr_mac_address_update(self, context, **kwargs):
        """Callback for dvr_mac_addresses update.

        :param dvr_macs: list of updated dvr_macs
        """
        dvr_macs = kwargs.get('dvr_macs', [])
        LOG.debug("dvr_macs updated on remote: %s", dvr_macs)
        self.dvr_agent.dvr_mac_address_update(dvr_macs)
