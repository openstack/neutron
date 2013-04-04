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

import sys

from oslo.config import cfg

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.api.v2 import attributes
from quantum.common import constants as q_const
from quantum.common import exceptions as q_exc
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.db import api as db_api
from quantum.db import db_base_plugin_v2
from quantum.db import dhcp_rpc_base
from quantum.db import extraroute_db
from quantum.db import l3_rpc_base
from quantum.db import quota_db  # noqa
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.extensions import portbindings
from quantum.extensions import providernet as provider
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.linuxbridge.common import constants
from quantum.plugins.linuxbridge.db import l2network_db_v2 as db
from quantum import policy


LOG = logging.getLogger(__name__)


class LinuxBridgeRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                              l3_rpc_base.L3RpcCallbackMixin,
                              sg_db_rpc.SecurityGroupServerRpcCallbackMixin
                              ):

    # history
    #   1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'
    # Device names start with "tap"
    TAP_PREFIX_LEN = 3

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    @classmethod
    def get_port_from_device(cls, device):
        port = db.get_port_from_device(device[cls.TAP_PREFIX_LEN:])
        if port:
            port['device'] = device
        return port

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details"""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s details requested from %(agent_id)s"),
                  locals())
        port = self.get_port_from_device(device)
        if port:
            binding = db.get_network_binding(db_api.get_session(),
                                             port['network_id'])
            entry = {'device': device,
                     'physical_network': binding.physical_network,
                     'vlan_id': binding.vlan_id,
                     'network_id': port['network_id'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up']}
            new_status = (q_const.PORT_STATUS_ACTIVE if port['admin_state_up']
                          else q_const.PORT_STATUS_DOWN)
            if port['status'] != new_status:
                db.set_port_status(port['id'], new_status)
        else:
            entry = {'device': device}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent"""
        # (TODO) garyk - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s no longer exists on %(agent_id)s"),
                  locals())
        port = self.get_port_from_device(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            if port['status'] != q_const.PORT_STATUS_DOWN:
                # Set port status to DOWN
                db.set_port_status(port['id'], q_const.PORT_STATUS_DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def update_device_up(self, rpc_context, **kwargs):
        """Device is up on agent"""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s up %(agent_id)s"),
                  locals())
        port = self.get_port_from_device(device)
        if port:
            if port['status'] != q_const.PORT_STATUS_ACTIVE:
                # Set port status to ACTIVE
                db.set_port_status(port['id'], q_const.PORT_STATUS_ACTIVE)
        else:
            LOG.debug(_("%s can not be found in database"), device)


class AgentNotifierApi(proxy.RpcProxy,
                       sg_rpc.SecurityGroupAgentRpcApiMixin):
    '''Agent side of the linux bridge rpc API.

    API version history:
        1.0 - Initial version.

    '''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic = topic
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

    def port_update(self, context, port, physical_network, vlan_id):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port,
                                       physical_network=physical_network,
                                       vlan_id=vlan_id),
                         topic=self.topic_port_update)


class LinuxBridgePluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                          extraroute_db.ExtraRoute_db_mixin,
                          sg_db_rpc.SecurityGroupServerRpcMixin,
                          agentschedulers_db.AgentSchedulerDbMixin):
    """Implement the Quantum abstractions using Linux bridging.

    A new VLAN is created for each network.  An agent is relied upon
    to perform the actual Linux bridge configuration on each host.

    The provider extension is also supported. As discussed in
    https://bugs.launchpad.net/quantum/+bug/1023156, this class could
    be simplified, and filtering on extended attributes could be
    handled, by adding support for extended attributes to the
    QuantumDbPluginV2 base class. When that occurs, this class should
    be updated to take advantage of it.

    The port binding extension enables an external application relay
    information to and from the plugin.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk/pagination/sorting operations. Name mangling is used in
    # order to ensure it is qualified by class
    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    _supported_extension_aliases = ["provider", "router", "binding", "quotas",
                                    "security-group", "agent", "extraroute",
                                    "agent_scheduler"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_if_noop_driver(aliases)
            self._aliases = aliases
        return self._aliases

    network_view = "extension:provider_network:view"
    network_set = "extension:provider_network:set"
    binding_view = "extension:port_binding:view"
    binding_set = "extension:port_binding:set"

    def __init__(self):
        db.initialize()
        self._parse_network_vlan_ranges()
        db.sync_network_states(self.network_vlan_ranges)
        self.tenant_network_type = cfg.CONF.VLANS.tenant_network_type
        if self.tenant_network_type not in [constants.TYPE_LOCAL,
                                            constants.TYPE_VLAN,
                                            constants.TYPE_NONE]:
            LOG.error(_("Invalid tenant_network_type: %s. "
                        "Service terminated!"),
                      self.tenant_network_type)
            sys.exit(1)
        self._setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver)
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        LOG.debug(_("Linux Bridge Plugin initialization complete"))

    def _setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.callbacks = LinuxBridgeRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify

    def _parse_network_vlan_ranges(self):
        self.network_vlan_ranges = {}
        for entry in cfg.CONF.VLANS.network_vlan_ranges:
            if ':' in entry:
                try:
                    physical_network, vlan_min, vlan_max = entry.split(':')
                    self._add_network_vlan_range(physical_network,
                                                 int(vlan_min),
                                                 int(vlan_max))
                except ValueError as ex:
                    LOG.error(_("Invalid network VLAN range: "
                                "'%(entry)s' - %(ex)s. "
                                "Service terminated!"),
                              locals())
                    sys.exit(1)
            else:
                self._add_network(entry)
        LOG.debug(_("Network VLAN ranges: %s"), self.network_vlan_ranges)

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _enforce_set_auth(self, context, resource, action):
        policy.enforce(context, action, resource)

    def _add_network_vlan_range(self, physical_network, vlan_min, vlan_max):
        self._add_network(physical_network)
        self.network_vlan_ranges[physical_network].append((vlan_min, vlan_max))

    def _add_network(self, physical_network):
        if physical_network not in self.network_vlan_ranges:
            self.network_vlan_ranges[physical_network] = []

    # REVISIT(rkukura) Use core mechanism for attribute authorization
    # when available.

    def _extend_network_dict_provider(self, context, network):
        if self._check_view_auth(context, network, self.network_view):
            binding = db.get_network_binding(context.session, network['id'])
            if binding.vlan_id == constants.FLAT_VLAN_ID:
                network[provider.NETWORK_TYPE] = constants.TYPE_FLAT
                network[provider.PHYSICAL_NETWORK] = binding.physical_network
                network[provider.SEGMENTATION_ID] = None
            elif binding.vlan_id == constants.LOCAL_VLAN_ID:
                network[provider.NETWORK_TYPE] = constants.TYPE_LOCAL
                network[provider.PHYSICAL_NETWORK] = None
                network[provider.SEGMENTATION_ID] = None
            else:
                network[provider.NETWORK_TYPE] = constants.TYPE_VLAN
                network[provider.PHYSICAL_NETWORK] = binding.physical_network
                network[provider.SEGMENTATION_ID] = binding.vlan_id

    def _process_provider_create(self, context, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return (None, None, None)

        # Authorize before exposing plugin details to client
        self._enforce_set_auth(context, attrs, self.network_set)

        if not network_type_set:
            msg = _("provider:network_type required")
            raise q_exc.InvalidInput(error_message=msg)
        elif network_type == constants.TYPE_FLAT:
            if segmentation_id_set:
                msg = _("provider:segmentation_id specified for flat network")
                raise q_exc.InvalidInput(error_message=msg)
            else:
                segmentation_id = constants.FLAT_VLAN_ID
        elif network_type == constants.TYPE_VLAN:
            if not segmentation_id_set:
                msg = _("provider:segmentation_id required")
                raise q_exc.InvalidInput(error_message=msg)
            if segmentation_id < 1 or segmentation_id > 4094:
                msg = _("provider:segmentation_id out of range "
                        "(1 through 4094)")
                raise q_exc.InvalidInput(error_message=msg)
        elif network_type == constants.TYPE_LOCAL:
            if physical_network_set:
                msg = _("provider:physical_network specified for local "
                        "network")
                raise q_exc.InvalidInput(error_message=msg)
            else:
                physical_network = None
            if segmentation_id_set:
                msg = _("provider:segmentation_id specified for local "
                        "network")
                raise q_exc.InvalidInput(error_message=msg)
            else:
                segmentation_id = constants.LOCAL_VLAN_ID
        else:
            msg = _("provider:network_type %s not supported") % network_type
            raise q_exc.InvalidInput(error_message=msg)

        if network_type in [constants.TYPE_VLAN, constants.TYPE_FLAT]:
            if physical_network_set:
                if physical_network not in self.network_vlan_ranges:
                    msg = (_("Unknown provider:physical_network %s") %
                           physical_network)
                    raise q_exc.InvalidInput(error_message=msg)
            elif 'default' in self.network_vlan_ranges:
                physical_network = 'default'
            else:
                msg = _("provider:physical_network required")
                raise q_exc.InvalidInput(error_message=msg)

        return (network_type, physical_network, segmentation_id)

    def _check_provider_update(self, context, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)

        network_type_set = attributes.is_attr_set(network_type)
        physical_network_set = attributes.is_attr_set(physical_network)
        segmentation_id_set = attributes.is_attr_set(segmentation_id)

        if not (network_type_set or physical_network_set or
                segmentation_id_set):
            return

        # Authorize before exposing plugin details to client
        self._enforce_set_auth(context, attrs, self.network_set)

        msg = _("Plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def create_network(self, context, network):
        (network_type, physical_network,
         vlan_id) = self._process_provider_create(context,
                                                  network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            #set up default security groups
            tenant_id = self._get_tenant_id_for_create(
                context, network['network'])
            self._ensure_default_security_group(context, tenant_id)

            if not network_type:
                # tenant network
                network_type = self.tenant_network_type
                if network_type == constants.TYPE_NONE:
                    raise q_exc.TenantNetworksDisabled()
                elif network_type == constants.TYPE_VLAN:
                    physical_network, vlan_id = db.reserve_network(session)
                else:  # TYPE_LOCAL
                    vlan_id = constants.LOCAL_VLAN_ID
            else:
                # provider network
                if network_type in [constants.TYPE_VLAN, constants.TYPE_FLAT]:
                    db.reserve_specific_network(session, physical_network,
                                                vlan_id)
                # no reservation needed for TYPE_LOCAL
            net = super(LinuxBridgePluginV2, self).create_network(context,
                                                                  network)
            db.add_network_binding(session, net['id'],
                                   physical_network, vlan_id)
            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
            # note - exception will rollback entire transaction
        return net

    def update_network(self, context, id, network):
        self._check_provider_update(context, network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            net = super(LinuxBridgePluginV2, self).update_network(context, id,
                                                                  network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
        return net

    def delete_network(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            binding = db.get_network_binding(session, id)
            super(LinuxBridgePluginV2, self).delete_network(context, id)
            if binding.vlan_id != constants.LOCAL_VLAN_ID:
                db.release_network(session, binding.physical_network,
                                   binding.vlan_id, self.network_vlan_ranges)
            # the network_binding record is deleted via cascade from
            # the network record, so explicit removal is not necessary
        self.notifier.network_delete(context, id)

    def get_network(self, context, id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(LinuxBridgePluginV2, self).get_network(context,
                                                               id, None)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            nets = super(LinuxBridgePluginV2,
                         self).get_networks(context, filters, None, sorts,
                                            limit, marker, page_reverse)
            for net in nets:
                self._extend_network_dict_provider(context, net)
                self._extend_network_dict_l3(context, net)

        return [self._fields(net, fields) for net in nets]

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_BRIDGE
            port[portbindings.CAPABILITIES] = {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}
        return port

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(LinuxBridgePluginV2, self).get_port(context,
                                                             id,
                                                             fields)
            self._extend_port_dict_security_group(context, port)
        self._extend_port_dict_binding(context, port),
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None, page_reverse=False):
        res_ports = []
        with context.session.begin(subtransactions=True):
            ports = super(LinuxBridgePluginV2,
                          self).get_ports(context, filters, fields, sorts,
                                          limit, marker, page_reverse)
            #TODO(nati) filter by security group
            for port in ports:
                self._extend_port_dict_security_group(context, port)
                self._extend_port_dict_binding(context, port)
                res_ports.append(self._fields(port, fields))
        return res_ports

    def create_port(self, context, port):
        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            # Set port status as 'DOWN'. This will be updated by agent
            port['port']['status'] = q_const.PORT_STATUS_DOWN

            port = super(LinuxBridgePluginV2,
                         self).create_port(context, port)
            self._process_port_create_security_group(
                context, port['id'], sgids)
            self._extend_port_dict_security_group(context, port)
        self.notify_security_groups_member_updated(context, port)
        return self._extend_port_dict_binding(context, port)

    def update_port(self, context, id, port):
        original_port = self.get_port(context, id)
        session = context.session
        need_port_update_notify = False

        with session.begin(subtransactions=True):
            updated_port = super(LinuxBridgePluginV2, self).update_port(
                context, id, port)
            need_port_update_notify = self.update_security_group_on_port(
                context, id, port, original_port, updated_port)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        if original_port['admin_state_up'] != updated_port['admin_state_up']:
            need_port_update_notify = True

        if need_port_update_notify:
            self._notify_port_updated(context, updated_port)
        return self._extend_port_dict_binding(context, updated_port)

    def delete_port(self, context, id, l3_port_check=True):

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)

        session = context.session
        with session.begin(subtransactions=True):
            self.disassociate_floatingips(context, id)
            port = self.get_port(context, id)
            self._delete_port_security_group_bindings(context, id)
            super(LinuxBridgePluginV2, self).delete_port(context, id)

        self.notify_security_groups_member_updated(context, port)

    def _notify_port_updated(self, context, port):
        binding = db.get_network_binding(context.session,
                                         port['network_id'])
        self.notifier.port_update(context, port,
                                  binding.physical_network,
                                  binding.vlan_id)
