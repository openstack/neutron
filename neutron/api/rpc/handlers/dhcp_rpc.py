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

import copy
import itertools
import operator

from neutron_lib.api.definitions import portbindings
from neutron_lib.api import extensions
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from neutron_lib.exceptions import agent as agent_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils

from neutron._i18n import _
from neutron.common import utils
from neutron.db import provisioning_blocks
from neutron.extensions import segment as segment_ext
from neutron.objects import network as network_obj
from neutron.quota import resource_registry


LOG = logging.getLogger(__name__)


class DhcpRpcCallback(object):
    """DHCP agent RPC callback in plugin implementations.

    This class implements the server side of an rpc interface.  The client
    side of this interface can be found in
    neutron.agent.dhcp.agent.DhcpPluginApi.  For more information about
    changing rpc interfaces, see doc/source/contributor/internals/rpc_api.rst.
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
    #     1.3 - Removed release_port_fixed_ip. It's not used by reference DHCP
    #           agent since Juno, so similar rationale for not bumping the
    #           major version as above applies here too.
    #     1.4 - Removed update_lease_expiration. It's not used by reference
    #           DHCP agent since Juno, so similar rationale for not bumping the
    #           major version as above applies here too.
    #     1.5 - Added dhcp_ready_on_ports.
    #     1.6 - Removed get_active_networks. It's not used by reference
    #           DHCP agent since Havana, so similar rationale for not bumping
    #           the major version as above applies here too.
    #     1.7 - Add get_networks
    #     1.8 - Add get_dhcp_port
    #     1.9 - get_network_info returns info with only DHCP enabled subnets
    #     1.10 - get_network_info returns segments details when plugin is
    #            enabled

    target = oslo_messaging.Target(
        namespace=constants.RPC_NAMESPACE_DHCP_PLUGIN,
        version='1.10')

    def _get_active_networks(self, context, **kwargs):
        """Retrieve and return a list of the active networks."""
        host = kwargs.get('host')
        plugin = directory.get_plugin()
        if extensions.is_extension_supported(
                plugin, constants.DHCP_AGENT_SCHEDULER_EXT_ALIAS):
            if cfg.CONF.network_auto_schedule:
                plugin.auto_schedule_networks(context, host)
            nets = plugin.list_active_networks_on_active_dhcp_agent(
                context, host)
        else:
            # If no active DHCP agent or agent admin state is DOWN,
            # return empty network list for RPC to avoid unexpected
            # resource creation on remote host when the DHCP agent
            # scheduler extension is not supported.
            try:
                agent = plugin._get_agent_by_type_and_host(
                    context, constants.AGENT_TYPE_DHCP, host)
            except agent_exc.AgentNotFoundByTypeHost:
                LOG.debug("DHCP Agent not found on host %s", host)
                return []
            if not agent.admin_state_up:
                LOG.debug("DHCP Agent admin state is down on host %s", host)
                return []

            nets = network_obj.Network.get_objects(context,
                                                   admin_state_up=[True])
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
                raise exceptions.Invalid(message=msg)
        except (db_exc.DBReferenceError,
                exceptions.NetworkNotFound,
                exceptions.SubnetNotFound,
                exceptions.InvalidInput,
                exceptions.IpAddressGenerationFailure) as e:
            with excutils.save_and_reraise_exception(reraise=False) as ctxt:
                if isinstance(e, exceptions.IpAddressGenerationFailure):
                    # Check if the subnet still exists and if it does not,
                    # this is the reason why the ip address generation failed.
                    # In any other unlikely event re-raise
                    try:
                        subnet_id = port['port']['fixed_ips'][0]['subnet_id']
                        plugin.get_subnet(context, subnet_id)
                    except exceptions.SubnetNotFound:
                        pass
                    else:
                        ctxt.reraise = True
                if ctxt.reraise:
                    net_id = port['port']['network_id']
                    LOG.warning("Action %(action)s for network %(net_id)s "
                                "could not complete successfully: "
                                "%(reason)s",
                                {"action": action,
                                 "net_id": net_id,
                                 'reason': e})

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
        plugin = directory.get_plugin()
        filters = {'network_id': [network.id for network in networks]}
        ports = plugin.get_ports(context, filters=filters)
        grouped_ports = self._group_by_network_id(ports)
        # default is to filter subnets based on 'enable_dhcp' flag
        enable_dhcp = True if kwargs.get('enable_dhcp_filter', True) else None
        ret = []
        for network in networks:
            ret.append(self.get_network_info(
                context, network=network, enable_dhcp=enable_dhcp, host=host,
                ports=grouped_ports.get(network.id, [])))

        return ret

    def get_network_info(self, context, **kwargs):
        """Retrieve and return information about a network.

        Retrieve and return extended information about a network.
        The optional argument "enable_dhcp" can be used to filter the subnets
        using the same flag (True/False). If None is passed, no filtering is
        done.
        """
        enable_dhcp = kwargs.get('enable_dhcp', True)
        network = kwargs.get('network')
        host = kwargs.get('host')
        plugin = directory.get_plugin()
        if network:
            ports = kwargs['ports']
        else:
            network_id = kwargs.get('network_id')
            LOG.debug('Network %(network_id)s requested from '
                      '%(host)s', {'network_id': network_id,
                                   'host': host})
            network = network_obj.Network.get_object(context, id=network_id)
            if not network:
                LOG.debug('Network %s could not be found, it might have '
                          'been deleted concurrently.', network_id)
                return
            port_filters = {'network_id': [network_id]}
            ports = plugin.get_ports(context, filters=port_filters)

        seg_plug = directory.get_plugin(
            segment_ext.SegmentPluginBase.get_plugin_type())
        subnets = [plugin._make_subnet_dict(subnet) for subnet in
                   network.db_obj.subnets if
                   (enable_dhcp is None or subnet.enable_dhcp == enable_dhcp)]
        seg_subnets = [subnet for subnet in subnets if
                       subnet.get('segment_id')]
        nonlocal_subnets = []
        # If there are no subnets with segments, then this is not a routed
        # network and no filtering should take place.
        if seg_plug and seg_subnets:
            # Network subnets can be associated only to network segments.
            # From those segments, we retrieve only those ones mapped to
            # 'host'.
            segment_ids = {ns.id for ns in network.segments if
                           host in ns.hosts}
            # There might be something to do if no segment_ids exist that
            # are mapped to this host.  However, it seems that if this
            # host is not mapped to any segments and this is a routed
            # network, then this host shouldn't have even been scheduled
            # to.
            nonlocal_subnets = [subnet for subnet in seg_subnets
                                if subnet.get('segment_id') not in segment_ids]
            subnets = [subnet for subnet in seg_subnets
                       if subnet.get('segment_id') in segment_ids]
        # NOTE(kevinbenton): we sort these because the agent builds tags
        # based on position in the list and has to restart the process if
        # the order changes.
        # TODO(ralonsoh): in Z+, remove "tenant_id" parameter. DHCP agents
        # should read only "project_id".
        ret = {'id': network.id,
               'project_id': network.project_id,
               'tenant_id': network.project_id,
               'admin_state_up': network.admin_state_up,
               'subnets': sorted(subnets, key=operator.itemgetter('id')),
               'non_local_subnets': sorted(nonlocal_subnets,
                                           key=operator.itemgetter('id')),
               'ports': ports,
               'mtu': network.mtu}
        if seg_plug:
            ret['segments'] = [{
                'id': segment.id,
                'network_id': segment.network_id,
                'name': segment.name,
                'network_type': segment.network_type,
                'physical_network': segment.physical_network,
                'segmentation_id': segment.segmentation_id,
                'is_dynamic': segment.is_dynamic,
                'segment_index': segment.segment_index,
                'hosts': segment.hosts} for segment in network.segments]
        return ret

    @db_api.retry_db_errors
    def release_dhcp_port(self, context, **kwargs):
        """Release the port currently being used by a DHCP agent."""
        host = kwargs.get('host')
        network_id = kwargs.get('network_id')
        device_id = kwargs.get('device_id')

        LOG.debug('DHCP port deletion for %(network_id)s request from '
                  '%(host)s',
                  {'network_id': network_id, 'host': host})
        plugin = directory.get_plugin()
        plugin.delete_ports_by_device_id(context, device_id, network_id)

    @oslo_messaging.expected_exceptions(exceptions.IpAddressGenerationFailure)
    @db_api.retry_db_errors
    @resource_registry.mark_resources_dirty
    def create_dhcp_port(self, context, **kwargs):
        """Create and return dhcp port information.

        If an expected failure occurs, a None port is returned.

        """
        host = kwargs.get('host')
        # Note(pbondar): Create deep copy of port to prevent operating
        # on changed dict if RetryRequest is raised
        port = copy.deepcopy(kwargs.get('port'))
        LOG.debug('Create dhcp port %(port)s '
                  'from %(host)s.',
                  {'port': port,
                   'host': host})

        port['port']['device_owner'] = constants.DEVICE_OWNER_DHCP
        port['port'][portbindings.HOST_ID] = host
        if 'mac_address' not in port['port']:
            port['port']['mac_address'] = constants.ATTR_NOT_SPECIFIED
        plugin = directory.get_plugin()
        return self._port_action(plugin, context, port, 'create_port')

    def _is_dhcp_agent_hosting_network(self, plugin, context, host,
                                       network_id):
        """Check whether a DHCP agent (host) is hosting a network."""
        agents = plugin.get_dhcp_agents_hosting_networks(context, [network_id],
                                                         hosts=[host])
        return len(agents) != 0

    @oslo_messaging.expected_exceptions(exceptions.NetworkNotFound)
    @oslo_messaging.expected_exceptions(exceptions.IpAddressGenerationFailure)
    @db_api.retry_db_errors
    def update_dhcp_port(self, context, **kwargs):
        """Update the dhcp port."""
        host = kwargs.get('host')
        port = kwargs.get('port')
        port['id'] = kwargs.get('port_id')
        port['port'][portbindings.HOST_ID] = host
        plugin = directory.get_plugin()
        try:
            network_id = port['port']['network_id']
            old_port = plugin.get_port(context, port['id'])
            if (old_port['device_id'] !=
                    constants.DEVICE_ID_RESERVED_DHCP_PORT and
                    old_port['device_id'] !=
                    utils.get_dhcp_agent_device_id(network_id, host)):
                return
            if not self._is_dhcp_agent_hosting_network(plugin, context, host,
                                                       network_id):
                LOG.warning("The DHCP agent on %(host)s does not host the "
                            "network %(net_id)s.", {"host": host,
                                                    "net_id": network_id})
                raise exceptions.NetworkNotFound(net_id=network_id)
            LOG.debug('Update dhcp port %(port)s '
                      'from %(host)s.',
                      {'port': port,
                       'host': host})
            return self._port_action(plugin, context, port, 'update_port')
        except exceptions.PortNotFound:
            LOG.debug('Host %(host)s tried to update port '
                      '%(port_id)s which no longer exists.',
                      {'host': host, 'port_id': port['id']})

    @db_api.retry_db_errors
    def get_dhcp_port(self, context, **kwargs):
        """Retrieve the DHCP port"""
        port_id = kwargs.get('port_id')
        plugin = directory.get_plugin()
        return plugin.get_port(context, port_id)

    @db_api.retry_db_errors
    def dhcp_ready_on_ports(self, context, port_ids):
        for port_id in port_ids:
            provisioning_blocks.provisioning_complete(
                context, port_id, resources.PORT,
                provisioning_blocks.DHCP_ENTITY)

    def get_networks(self, context, filters=None, fields=None):
        """Retrieve and return a list of networks."""
        # NOTE(adrianc): This RPC is being used by out of tree interface
        # drivers, MultiInterfaceDriver and IPoIBInterfaceDriver, located in
        # networking-mlnx.
        plugin = directory.get_plugin()
        return plugin.get_networks(
            context, filters=filters, fields=fields)
