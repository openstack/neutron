# Copyright (c) 2013 OpenStack Foundation
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

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.common import constants as q_const
from neutron.common import rpc as q_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import api as db_api
from neutron.db import dhcp_rpc_base
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron import manager
from neutron.openstack.common import log
from neutron.openstack.common.rpc import proxy
from neutron.openstack.common import uuidutils
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_tunnel
# REVISIT(kmestery): Allow the type and mechanism drivers to supply the
# mixins and eventually remove the direct dependencies on type_tunnel.

LOG = log.getLogger(__name__)

TAP_DEVICE_PREFIX = 'tap'
TAP_DEVICE_PREFIX_LENGTH = 3


class RpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                   sg_db_rpc.SecurityGroupServerRpcCallbackMixin,
                   type_tunnel.TunnelRpcCallbackMixin):

    RPC_API_VERSION = '1.1'
    # history
    #   1.0 Initial version (from openvswitch/linuxbridge)
    #   1.1 Support Security Group RPC

    def __init__(self, notifier, type_manager):
        # REVISIT(kmestery): This depends on the first three super classes
        # not having their own __init__ functions. If an __init__() is added
        # to one, this could break. Fix this and add a unit test to cover this
        # test in H3.
        super(RpcCallbacks, self).__init__(notifier, type_manager)

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    @classmethod
    def _device_to_port_id(cls, device):
        # REVISIT(rkukura): Consider calling into MechanismDrivers to
        # process device names, or having MechanismDrivers supply list
        # of device prefixes to strip.
        if device.startswith(TAP_DEVICE_PREFIX):
            return device[TAP_DEVICE_PREFIX_LENGTH:]
        else:
            # REVISIT(irenab): Consider calling into bound MD to
            # handle the get_device_details RPC, then remove the 'else' clause
            if not uuidutils.is_uuid_like(device):
                port = db.get_port_from_device_mac(device)
                if port:
                    return port.id
        return device

    @classmethod
    def get_port_from_device(cls, device):
        port_id = cls._device_to_port_id(device)
        port = db.get_port_and_sgs(port_id)
        if port:
            port['device'] = device
        return port

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s details requested by agent "
                    "%(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        port_id = self._device_to_port_id(device)

        session = db_api.get_session()
        with session.begin(subtransactions=True):
            port = db.get_port(session, port_id)
            if not port:
                LOG.warning(_("Device %(device)s requested by agent "
                              "%(agent_id)s not found in database"),
                            {'device': device, 'agent_id': agent_id})
                return {'device': device}

            segments = db.get_network_segments(session, port.network_id)
            if not segments:
                LOG.warning(_("Device %(device)s requested by agent "
                              "%(agent_id)s has network %(network_id)s with "
                              "no segments"),
                            {'device': device,
                             'agent_id': agent_id,
                             'network_id': port.network_id})
                return {'device': device}

            binding = db.ensure_port_binding(session, port.id)
            if not binding.segment:
                LOG.warning(_("Device %(device)s requested by agent "
                              "%(agent_id)s on network %(network_id)s not "
                              "bound, vif_type: %(vif_type)s"),
                            {'device': device,
                             'agent_id': agent_id,
                             'network_id': port.network_id,
                             'vif_type': binding.vif_type})
                return {'device': device}

            segment = self._find_segment(segments, binding.segment)
            if not segment:
                LOG.warning(_("Device %(device)s requested by agent "
                              "%(agent_id)s on network %(network_id)s "
                              "invalid segment, vif_type: %(vif_type)s"),
                            {'device': device,
                             'agent_id': agent_id,
                             'network_id': port.network_id,
                             'vif_type': binding.vif_type})
                return {'device': device}

            new_status = (q_const.PORT_STATUS_BUILD if port.admin_state_up
                          else q_const.PORT_STATUS_DOWN)
            if port.status != new_status:
                plugin = manager.NeutronManager.get_plugin()
                plugin.update_port_status(rpc_context,
                                          port_id,
                                          new_status)
                port.status = new_status
            entry = {'device': device,
                     'network_id': port.network_id,
                     'port_id': port.id,
                     'admin_state_up': port.admin_state_up,
                     'network_type': segment[api.NETWORK_TYPE],
                     'segmentation_id': segment[api.SEGMENTATION_ID],
                     'physical_network': segment[api.PHYSICAL_NETWORK]}
            LOG.debug(_("Returning: %s"), entry)
            return entry

    def _find_segment(self, segments, segment_id):
        for segment in segments:
            if segment[api.ID] == segment_id:
                return segment

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""
        # TODO(garyk) - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug(_("Device %(device)s no longer exists at agent "
                    "%(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_id = self._device_to_port_id(device)
        port_exists = True
        if (host and not plugin.port_bound_to_host(port_id, host)):
            LOG.debug(_("Device %(device)s not bound to the"
                        " agent host %(host)s"),
                      {'device': device, 'host': host})
            return {'device': device,
                    'exists': port_exists}

        port_exists = plugin.update_port_status(rpc_context, port_id,
                                                q_const.PORT_STATUS_DOWN)

        return {'device': device,
                'exists': port_exists}

    def update_device_up(self, rpc_context, **kwargs):
        """Device is up on agent."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        host = kwargs.get('host')
        LOG.debug(_("Device %(device)s up at agent %(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        plugin = manager.NeutronManager.get_plugin()
        port_id = self._device_to_port_id(device)
        if (host and not plugin.port_bound_to_host(port_id, host)):
            LOG.debug(_("Device %(device)s not bound to the"
                        " agent host %(host)s"),
                      {'device': device, 'host': host})
            return

        plugin.update_port_status(rpc_context, port_id,
                                  q_const.PORT_STATUS_ACTIVE)


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin,
                       type_tunnel.TunnelAgentRpcApiMixin):
    """Agent side of the openvswitch rpc API.

    API version history:
        1.0 - Initial version.
        1.1 - Added get_active_networks_info, create_dhcp_port,
              update_dhcp_port, and removed get_dhcp_port methods.

    """

    BASE_RPC_API_VERSION = '1.1'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_network_delete = topics.get_topic_name(topic,
                                                          topics.NETWORK,
                                                          topics.DELETE)
        self.topic_port_update = topics.get_topic_name(topic,
                                                       topics.PORT,
                                                       topics.UPDATE)

    def network_delete(self, context, network_id):
        self.fanout_cast(context,
                         self.make_msg('network_delete',
                                       network_id=network_id),
                         topic=self.topic_network_delete)

    def port_update(self, context, port, network_type, segmentation_id,
                    physical_network):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       network_type=network_type,
                                       segmentation_id=segmentation_id,
                                       physical_network=physical_network),
                         topic=self.topic_port_update)
