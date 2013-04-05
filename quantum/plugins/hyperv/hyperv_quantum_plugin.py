# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Cloudbase Solutions SRL
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
# @author: Alessandro Pilotti, Cloudbase Solutions Srl

from oslo.config import cfg

from quantum.api.v2 import attributes
from quantum.common import exceptions as q_exc
from quantum.common import topics
from quantum.db import db_base_plugin_v2
from quantum.db import l3_db
from quantum.db import quota_db  # noqa
from quantum.extensions import portbindings
from quantum.extensions import providernet as provider
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.plugins.hyperv import agent_notifier_api
from quantum.plugins.hyperv.common import constants
from quantum.plugins.hyperv import db as hyperv_db
from quantum.plugins.hyperv import rpc_callbacks
from quantum import policy


DEFAULT_VLAN_RANGES = []

hyperv_opts = [
    cfg.StrOpt('tenant_network_type', default='local',
               help=_("Network type for tenant networks "
               "(local, flat, vlan or none)")),
    cfg.ListOpt('network_vlan_ranges',
                default=DEFAULT_VLAN_RANGES,
                help=_("List of <physical_network>:<vlan_min>:<vlan_max> "
                "or <physical_network>")),
]

cfg.CONF.register_opts(hyperv_opts, "HYPERV")

LOG = logging.getLogger(__name__)


class BaseNetworkProvider(object):
    def __init__(self):
        self._db = hyperv_db.HyperVPluginDB()

    def create_network(self, session, attrs):
        pass

    def delete_network(self, session, binding):
        pass

    def extend_network_dict(self, network, binding):
        pass


class LocalNetworkProvider(BaseNetworkProvider):
    def create_network(self, session, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)
        if attributes.is_attr_set(segmentation_id):
            msg = _("segmentation_id specified "
                    "for %s network") % network_type
            raise q_exc.InvalidInput(error_message=msg)
        attrs[provider.SEGMENTATION_ID] = None

        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        if attributes.is_attr_set(physical_network):
            msg = _("physical_network specified "
                    "for %s network") % network_type
            raise q_exc.InvalidInput(error_message=msg)
        attrs[provider.PHYSICAL_NETWORK] = None

    def extend_network_dict(self, network, binding):
        network[provider.PHYSICAL_NETWORK] = None
        network[provider.SEGMENTATION_ID] = None


class FlatNetworkProvider(BaseNetworkProvider):
    def create_network(self, session, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)
        if attributes.is_attr_set(segmentation_id):
            msg = _("segmentation_id specified "
                    "for %s network") % network_type
            raise q_exc.InvalidInput(error_message=msg)
        segmentation_id = constants.FLAT_VLAN_ID
        attrs[provider.SEGMENTATION_ID] = segmentation_id

        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        if not attributes.is_attr_set(physical_network):
            physical_network = self._db.reserve_flat_net(session)
            attrs[provider.PHYSICAL_NETWORK] = physical_network
        else:
            self._db.reserve_specific_flat_net(session, physical_network)

    def delete_network(self, session, binding):
        self._db.release_vlan(session, binding.physical_network,
                              constants.FLAT_VLAN_ID)

    def extend_network_dict(self, network, binding):
        network[provider.PHYSICAL_NETWORK] = binding.physical_network


class VlanNetworkProvider(BaseNetworkProvider):
    def create_network(self, session, attrs):
        segmentation_id = attrs.get(provider.SEGMENTATION_ID)
        if attributes.is_attr_set(segmentation_id):
            physical_network = attrs.get(provider.PHYSICAL_NETWORK)
            if not attributes.is_attr_set(physical_network):
                msg = _("physical_network not provided")
                raise q_exc.InvalidInput(error_message=msg)
            self._db.reserve_specific_vlan(session, physical_network,
                                           segmentation_id)
        else:
            (physical_network,
             segmentation_id) = self._db.reserve_vlan(session)
            attrs[provider.SEGMENTATION_ID] = segmentation_id
            attrs[provider.PHYSICAL_NETWORK] = physical_network

    def delete_network(self, session, binding):
        self._db.release_vlan(
            session, binding.physical_network,
            binding.segmentation_id)

    def extend_network_dict(self, network, binding):
        network[provider.PHYSICAL_NETWORK] = binding.physical_network
        network[provider.SEGMENTATION_ID] = binding.segmentation_id


class HyperVQuantumPlugin(db_base_plugin_v2.QuantumDbPluginV2,
                          l3_db.L3_NAT_db_mixin):

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True
    supported_extension_aliases = ["provider", "router", "binding", "quotas"]

    network_view = "extension:provider_network:view"
    network_set = "extension:provider_network:set"
    binding_view = "extension:port_binding:view"
    binding_set = "extension:port_binding:set"

    def __init__(self, configfile=None):
        self._db = hyperv_db.HyperVPluginDB()
        self._db.initialize()

        self._set_tenant_network_type()

        self._parse_network_vlan_ranges()
        self._create_network_providers_map()

        self._db.sync_vlan_allocations(self._network_vlan_ranges)

        self._setup_rpc()

    def _set_tenant_network_type(self):
        tenant_network_type = cfg.CONF.HYPERV.tenant_network_type
        if tenant_network_type not in [constants.TYPE_LOCAL,
                                       constants.TYPE_FLAT,
                                       constants.TYPE_VLAN,
                                       constants.TYPE_NONE]:
            msg = _(
                "Invalid tenant_network_type: %(tenant_network_type)s. "
                "Agent terminated!") % locals()
            raise q_exc.InvalidInput(error_message=msg)
        self._tenant_network_type = tenant_network_type

    def _setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = agent_notifier_api.AgentNotifierApi(
            topics.AGENT)
        self.callbacks = rpc_callbacks.HyperVRpcCallbacks(self.notifier)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _enforce_set_auth(self, context, resource, action):
        policy.enforce(context, action, resource)

    def _parse_network_vlan_ranges(self):
        self._network_vlan_ranges = {}
        for entry in cfg.CONF.HYPERV.network_vlan_ranges:
            entry = entry.strip()
            if ':' in entry:
                try:
                    physical_network, vlan_min, vlan_max = entry.split(':')
                    self._add_network_vlan_range(physical_network.strip(),
                                                 int(vlan_min),
                                                 int(vlan_max))
                except ValueError as ex:
                    msg = _(
                        "Invalid network VLAN range: "
                        "'%(range)s' - %(e)s. Agent terminated!"), \
                        {'range': entry, 'e': ex}
                    raise q_exc.InvalidInput(error_message=msg)
            else:
                self._add_network(entry)
        LOG.info(_("Network VLAN ranges: %s"), self._network_vlan_ranges)

    def _add_network_vlan_range(self, physical_network, vlan_min, vlan_max):
        self._add_network(physical_network)
        self._network_vlan_ranges[physical_network].append(
            (vlan_min, vlan_max))

    def _add_network(self, physical_network):
        if physical_network not in self._network_vlan_ranges:
            self._network_vlan_ranges[physical_network] = []

    def _check_vlan_id_in_range(self, physical_network, vlan_id):
        for r in self._network_vlan_ranges[physical_network]:
            if vlan_id >= r[0] and vlan_id <= r[1]:
                return True
        return False

    def _create_network_providers_map(self):
        self._network_providers_map = {
            constants.TYPE_LOCAL: LocalNetworkProvider(),
            constants.TYPE_FLAT: FlatNetworkProvider(),
            constants.TYPE_VLAN: VlanNetworkProvider()
        }

    def _process_provider_create(self, context, session, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        network_type_set = attributes.is_attr_set(network_type)
        if not network_type_set:
            if self._tenant_network_type == constants.TYPE_NONE:
                raise q_exc.TenantNetworksDisabled()
            network_type = self._tenant_network_type
            attrs[provider.NETWORK_TYPE] = network_type

        if network_type not in self._network_providers_map:
            msg = _("Network type %s not supported") % network_type
            raise q_exc.InvalidInput(error_message=msg)
        p = self._network_providers_map[network_type]
        # Provider specific network creation
        p.create_network(session, attrs)

        if network_type_set:
            self._enforce_set_auth(context, attrs, self.network_set)

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            network_attrs = network['network']
            self._process_provider_create(context, session, network_attrs)

            net = super(HyperVQuantumPlugin, self).create_network(
                context, network)

            network_type = network_attrs[provider.NETWORK_TYPE]
            physical_network = network_attrs[provider.PHYSICAL_NETWORK]
            segmentation_id = network_attrs[provider.SEGMENTATION_ID]

            self._db.add_network_binding(
                session, net['id'], network_type,
                physical_network, segmentation_id)

            self._process_l3_create(context, network['network'], net['id'])
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)

            LOG.debug(_("Created network: %s"), net['id'])
            return net

    def _extend_network_dict_provider(self, context, network):
        if self._check_view_auth(context, network, self.network_view):
            binding = self._db.get_network_binding(
                context.session, network['id'])
            network[provider.NETWORK_TYPE] = binding.network_type
            p = self._network_providers_map[binding.network_type]
            p.extend_network_dict(network, binding)

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

        msg = _("plugin does not support updating provider attributes")
        raise q_exc.InvalidInput(error_message=msg)

    def update_network(self, context, id, network):
        network_attrs = network['network']
        self._check_provider_update(context, network_attrs)
        # Authorize before exposing plugin details to client
        self._enforce_set_auth(context, network_attrs, self.network_set)

        session = context.session
        with session.begin(subtransactions=True):
            net = super(HyperVQuantumPlugin, self).update_network(context, id,
                                                                  network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)
            return net

    def delete_network(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            binding = self._db.get_network_binding(session, id)
            super(HyperVQuantumPlugin, self).delete_network(context, id)
            p = self._network_providers_map[binding.network_type]
            p.delete_network(session, binding)
        # the network_binding record is deleted via cascade from
        # the network record, so explicit removal is not necessary
        self.notifier.network_delete(context, id)

    def get_network(self, context, id, fields=None):
        net = super(HyperVQuantumPlugin, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(HyperVQuantumPlugin, self).get_networks(
            context, filters, None)
        for net in nets:
            self._extend_network_dict_provider(context, net)
            self._extend_network_dict_l3(context, net)

        return [self._fields(net, fields) for net in nets]

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_HYPERV
        return port

    def create_port(self, context, port):
        port = super(HyperVQuantumPlugin, self).create_port(context, port)
        return self._extend_port_dict_binding(context, port)

    def get_port(self, context, id, fields=None):
        port = super(HyperVQuantumPlugin, self).get_port(context, id, fields)
        return self._fields(self._extend_port_dict_binding(context, port),
                            fields)

    def get_ports(self, context, filters=None, fields=None):
        ports = super(HyperVQuantumPlugin, self).get_ports(
            context, filters, fields)
        return [self._fields(self._extend_port_dict_binding(context, port),
                             fields) for port in ports]

    def update_port(self, context, id, port):
        original_port = super(HyperVQuantumPlugin, self).get_port(
            context, id)
        port = super(HyperVQuantumPlugin, self).update_port(context, id, port)
        if original_port['admin_state_up'] != port['admin_state_up']:
            binding = self._db.get_network_binding(
                None, port['network_id'])
            self.notifier.port_update(context, port,
                                      binding.network_type,
                                      binding.segmentation_id,
                                      binding.physical_network)
        return self._extend_port_dict_binding(context, port)

    def delete_port(self, context, id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)

        super(HyperVQuantumPlugin, self).delete_port(context, id)
        self.notifier.port_delete(context, id)
