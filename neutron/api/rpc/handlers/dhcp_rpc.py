# Copyright (c) 2012 OpenStack Foundation.
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

import itertools
import operator

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.db import api as db_api
from neutron.extensions import portbindings
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import utils as p_utils
from neutron.quota import resource_registry


LOG = logging.getLogger(__name__)


class DhcpRpcCallback(object):
    """DHCP agent RPC callback in plugin implementations.

    This class implements the server side of an rpc interface.  The client
    side of this interface can be found in
    neutron.agent.dhcp.agent.DhcpPluginApi.  For more information about
    changing rpc interfaces, see doc/source/devref/rpc_api.rst.
    """

    # API version history:
    #     1.0 - Initial version.
    #     1.1 - Added get_active_networks_info, create_dhcp_port,
    #           and update_dhcp_port methods.
    #     1.2 - Removed get_dhcp_port. When removing a method (Making a
    #           backwards incompatible change) you would normally bump the
    #           major version. However, since the method was unused in the
    #           RPC client for many releases, it should be OK to bump the
    #           minor release instead and claim RPC compatibility with the
    #           last few client versions.
    target = oslo_messaging.Target(
        namespace=constants.RPC_NAMESPACE_DHCP_PLUGIN,
        version='1.2')

    def _get_active_networks(self, context, **kwargs):
        """Retrieve and return a list of the active networks."""
        host = kwargs.get('host')
        plugin = manager.NeutronManager.get_plugin()
        if utils.is_extension_supported(
            plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.network_auto_schedule:
                plugin.auto_schedule_networks(context, host)
            nets = plugin.list_active_networks_on_active_dhcp_agent(
                context, host)
        else:
            filters = dict(admin_state_up=[True])
            nets = plugin.get_networks(context, filters=filters)
        return nets

    def _port_action(self, plugin, context, port, action):
        """Perform port operations taking care of concurrency issues."""
        try:
            if action == 'create_port':
                return p_utils.create_port(plugin, context, port)
            elif action == 'update_port':
                return plugin.update_port(context, port['id'], port)
            else:
                msg = _('Unrecognized action')
                raise n_exc.Invalid(message=msg)
        except (db_exc.DBError, n_exc.NetworkNotFound,
                n_exc.SubnetNotFound, n_exc.IpAddressGenerationFailure) as e:
            with excutils.save_and_reraise_exception(reraise=False) as ctxt:
                if isinstance(e, n_exc.IpAddressGenerationFailure):
                    # Check if the subnet still exists and if it does not,
                    # this is the reason why the ip address generation failed.
                    # In any other unlikely event re-raise
                    try:
                        subnet_id = port['port']['fixed_ips'][0]['subnet_id']
                        plugin.get_subnet(context, subnet_id)
                    except n_exc.SubnetNotFound:
                        pass
                    else:
                        ctxt.reraise = True
                net_id = port['port']['network_id']
                LOG.warn(_LW("Action %(action)s for network %(net_id)s "
                             "could not complete successfully: %(reason)s"),
                         {"action": action, "net_id": net_id, 'reason': e})

    def get_active_networks(self, context, **kwargs):
        """Retrieve and return a list of the active network ids."""
        # NOTE(arosen): This method is no longer used by the DHCP agent but is
        # left so that neutron-dhcp-agents will still continue to work if
        # neutron-server is upgraded and not the agent.
        host = kwargs.get('host')
        LOG.debug('get_active_networks requested from %s', host)
        nets = self._get_active_networks(context, **kwargs)
        return [net['id'] for net in nets]

    def _group_by_network_id(self, res):
        grouped = {}
        keyfunc = operator.itemgetter('network_id')
        for net_id, values in itertools.groupby(sorted(res, key=keyfunc),
                                                keyfunc):
            grouped[net_id] = list(values)
        return grouped

    def get_active_networks_info(self, context, **kwargs):
        """Returns all the networks/subnets/ports in system."""
        host = kwargs.get('host')
        LOG.debug('get_active_networks_info from %s', host)
        networks = self._get_active_networks(context, **kwargs)
        plugin = manager.NeutronManager.get_plugin()
        filters = {'network_id': [network['id'] for network in networks]}
        ports = plugin.get_ports(context, filters=filters)
        filters['enable_dhcp'] = [True]
        subnets = plugin.get_subnets(context, filters=filters)

        grouped_subnets = self._group_by_network_id(subnets)
        grouped_ports = self._group_by_network_id(ports)
        for network in networks:
            network['subnets'] = grouped_subnets.get(network['id'], [])
            network['ports'] = grouped_ports.get(network['id'], [])

        return networks

    def get_network_info(self, context, **kwargs):
        """Retrieve and return a extended information about a network."""
        network_id = kwargs.get('network_id')
        host = kwargs.get('host')
        LOG.debug('Network %(network_id)s requested from '
                  '%(host)s', {'network_id': network_id,
                               'host': host})
        plugin = manager.NeutronManager.get_plugin()
        try:
            network = plugin.get_network(context, network_id)
        except n_exc.NetworkNotFound:
            LOG.warn(_LW("Network %s could not be found, it might have "
                         "been deleted concurrently."), network_id)
            return
        filters = dict(network_id=[network_id])
        network['subnets'] = plugin.get_subnets(context, filters=filters)
        network['ports'] = plugin.get_ports(context, filters=filters)
        return network

    @db_api.retry_db_errors
    def release_dhcp_port(self, context, **kwargs):
        """Release the port currently being used by a DHCP agent."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')

        LOG.debug('DHCP port deletion for %(network_id)s request from '
                  '%(host)s',
                  {'network_id': network_id, 'host': host})
        plugin = manager.NeutronManager.get_plugin()
        plugin.delete_ports_by_device_id(context, device_id, network_id)

    @db_api.retry_db_errors
    def release_port_fixed_ip(self, context, **kwargs):
        """Release the fixed_ip associated the subnet on a port."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')
        subnet_id = kwargs.get('subnet_id')

        LOG.debug('DHCP port remove fixed_ip for %(subnet_id)s request '
                  'from %(host)s',
                  {'subnet_id': subnet_id, 'host': host})
        plugin = manager.NeutronManager.get_plugin()
        filters = dict(network_id=[network_id], device_id=[device_id])
        ports = plugin.get_ports(context, filters=filters)

        if ports:
            port = ports[0]

            fixed_ips = port.get('fixed_ips', [])
            for i in range(len(fixed_ips)):
                if fixed_ips[i]['subnet_id'] == subnet_id:
                    del fixed_ips[i]
                    break
            plugin.update_port(context, port['id'], dict(port=port))

    def update_lease_expiration(self, context, **kwargs):
        """Release the fixed_ip associated the subnet on a port."""
        # NOTE(arosen): This method is no longer used by the DHCP agent but is
        # left so that neutron-dhcp-agents will still continue to work if
        # neutron-server is upgraded and not the agent.
        host = kwargs.get('host')

        LOG.warning(_LW('Updating lease expiration is now deprecated. Issued  '
                        'from host %s.'), host)

    @db_api.retry_db_errors
    @resource_registry.mark_resources_dirty
    def create_dhcp_port(self, context, **kwargs):
        """Create and return dhcp port information.

        If an expected failure occurs, a None port is returned.

        """
        host = kwargs.get('host')
        port = kwargs.get('port')
        LOG.debug('Create dhcp port %(port)s '
                  'from %(host)s.',
                  {'port': port,
                   'host': host})

        port['port']['device_owner'] = constants.DEVICE_OWNER_DHCP
        port['port'][portbindings.HOST_ID] = host
        if 'mac_address' not in port['port']:
            port['port']['mac_address'] = attributes.ATTR_NOT_SPECIFIED
        plugin = manager.NeutronManager.get_plugin()
        return self._port_action(plugin, context, port, 'create_port')

    @db_api.retry_db_errors
    def update_dhcp_port(self, context, **kwargs):
        """Update the dhcp port."""
        host = kwargs.get('host')
        port = kwargs.get('port')
        port['id'] = kwargs.get('port_id')
        LOG.debug('Update dhcp port %(port)s '
                  'from %(host)s.',
                  {'port': port,
                   'host': host})
        port['port'][portbindings.HOST_ID] = host
        plugin = manager.NeutronManager.get_plugin()
        return self._port_action(plugin, context, port, 'update_port')
