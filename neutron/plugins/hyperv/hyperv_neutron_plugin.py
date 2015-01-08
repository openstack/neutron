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

from oslo_config import cfg

from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import l3_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_gwmode_db
from neutron.db import portbindings_base
from neutron.db import quota_db  # noqa
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.i18n import _LI
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as svc_constants
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.hyperv import agent_notifier_api
from neutron.plugins.hyperv.common import constants
from neutron.plugins.hyperv import db as hyperv_db
from neutron.plugins.hyperv import rpc_callbacks


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
            raise n_exc.InvalidInput(error_message=msg)
        attrs[provider.SEGMENTATION_ID] = None

        physical_network = attrs.get(provider.PHYSICAL_NETWORK)
        if attributes.is_attr_set(physical_network):
            msg = _("physical_network specified "
                    "for %s network") % network_type
            raise n_exc.InvalidInput(error_message=msg)
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
            raise n_exc.InvalidInput(error_message=msg)
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
                raise n_exc.InvalidInput(error_message=msg)
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


class HyperVNeutronPlugin(agents_db.AgentDbMixin,
                          db_base_plugin_v2.NeutronDbPluginV2,
                          external_net_db.External_net_db_mixin,
                          l3_gwmode_db.L3_NAT_db_mixin,
                          portbindings_base.PortBindingBaseMixin):

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True
    supported_extension_aliases = ["provider", "external-net", "router",
                                   "agent", "ext-gw-mode", "binding", "quotas"]

    def __init__(self, configfile=None):
        self._db = hyperv_db.HyperVPluginDB()
        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_HYPERV}
        portbindings_base.register_port_dict_function()
        self._set_tenant_network_type()

        self._parse_network_vlan_ranges()
        self._create_network_providers_map()
        self._db.sync_vlan_allocations(self._network_vlan_ranges)

        self._setup_rpc()

    def _set_tenant_network_type(self):
        tenant_network_type = cfg.CONF.HYPERV.tenant_network_type
        if tenant_network_type not in [svc_constants.TYPE_LOCAL,
                                       svc_constants.TYPE_FLAT,
                                       svc_constants.TYPE_VLAN,
                                       svc_constants.TYPE_NONE]:
            msg = _(
                "Invalid tenant_network_type: %s. "
                "Agent terminated!") % tenant_network_type
            raise n_exc.InvalidInput(error_message=msg)
        self._tenant_network_type = tenant_network_type

    def _setup_rpc(self):
        # RPC support
        self.service_topics = {svc_constants.CORE: topics.PLUGIN,
                               svc_constants.L3_ROUTER_NAT: topics.L3PLUGIN}
        self.conn = n_rpc.create_connection(new=True)
        self.notifier = agent_notifier_api.AgentNotifierApi(
            topics.AGENT)
        self.endpoints = [rpc_callbacks.HyperVRpcCallbacks(self.notifier),
                          dhcp_rpc.DhcpRpcCallback(),
                          l3_rpc.L3RpcCallback(),
                          agents_db.AgentExtRpcCallback(),
                          metadata_rpc.MetadataRpcCallback()]
        for svc_topic in self.service_topics.values():
            self.conn.create_consumer(svc_topic, self.endpoints, fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    def _parse_network_vlan_ranges(self):
        self._network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            cfg.CONF.HYPERV.network_vlan_ranges)
        LOG.info(_LI("Network VLAN ranges: %s"), self._network_vlan_ranges)

    def _check_vlan_id_in_range(self, physical_network, vlan_id):
        for r in self._network_vlan_ranges[physical_network]:
            if vlan_id >= r[0] and vlan_id <= r[1]:
                return True
        return False

    def _create_network_providers_map(self):
        self._network_providers_map = {
            svc_constants.TYPE_LOCAL: LocalNetworkProvider(),
            svc_constants.TYPE_FLAT: FlatNetworkProvider(),
            svc_constants.TYPE_VLAN: VlanNetworkProvider()
        }

    def _process_provider_create(self, context, session, attrs):
        network_type = attrs.get(provider.NETWORK_TYPE)
        network_type_set = attributes.is_attr_set(network_type)
        if not network_type_set:
            if self._tenant_network_type == svc_constants.TYPE_NONE:
                raise n_exc.TenantNetworksDisabled()
            network_type = self._tenant_network_type
            attrs[provider.NETWORK_TYPE] = network_type

        if network_type not in self._network_providers_map:
            msg = _("Network type %s not supported") % network_type
            raise n_exc.InvalidInput(error_message=msg)
        p = self._network_providers_map[network_type]
        # Provider specific network creation
        p.create_network(session, attrs)

    def create_network(self, context, network):
        session = context.session
        with session.begin(subtransactions=True):
            network_attrs = network['network']
            self._process_provider_create(context, session, network_attrs)

            net = super(HyperVNeutronPlugin, self).create_network(
                context, network)

            network_type = network_attrs[provider.NETWORK_TYPE]
            physical_network = network_attrs[provider.PHYSICAL_NETWORK]
            segmentation_id = network_attrs[provider.SEGMENTATION_ID]

            self._db.add_network_binding(
                session, net['id'], network_type,
                physical_network, segmentation_id)

            self._process_l3_create(context, net, network['network'])
            self._extend_network_dict_provider(context, net)

            LOG.debug("Created network: %s", net['id'])
            return net

    def _extend_network_dict_provider(self, context, network):
        binding = self._db.get_network_binding(
            context.session, network['id'])
        network[provider.NETWORK_TYPE] = binding.network_type
        p = self._network_providers_map[binding.network_type]
        p.extend_network_dict(network, binding)

    def update_network(self, context, id, network):
        provider._raise_if_updates_provider_attributes(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            net = super(HyperVNeutronPlugin, self).update_network(context, id,
                                                                  network)
            self._process_l3_update(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
            return net

    def delete_network(self, context, id):
        session = context.session
        with session.begin(subtransactions=True):
            binding = self._db.get_network_binding(session, id)
            self._process_l3_delete(context, id)
            super(HyperVNeutronPlugin, self).delete_network(context, id)
            p = self._network_providers_map[binding.network_type]
            p.delete_network(session, binding)
        # the network_binding record is deleted via cascade from
        # the network record, so explicit removal is not necessary
        self.notifier.network_delete(context, id)

    def get_network(self, context, id, fields=None):
        net = super(HyperVNeutronPlugin, self).get_network(context, id, None)
        self._extend_network_dict_provider(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(HyperVNeutronPlugin, self).get_networks(
            context, filters, None)
        for net in nets:
            self._extend_network_dict_provider(context, net)

        return [self._fields(net, fields) for net in nets]

    def create_port(self, context, port):
        port_data = port['port']
        port = super(HyperVNeutronPlugin, self).create_port(context, port)
        self._process_portbindings_create_and_update(context,
                                                     port_data,
                                                     port)
        return port

    def update_port(self, context, id, port):
        original_port = super(HyperVNeutronPlugin, self).get_port(
            context, id)
        port_data = port['port']
        port = super(HyperVNeutronPlugin, self).update_port(context, id, port)
        self._process_portbindings_create_and_update(context,
                                                     port_data,
                                                     port)
        if original_port['admin_state_up'] != port['admin_state_up']:
            binding = self._db.get_network_binding(
                None, port['network_id'])
            self.notifier.port_update(context, port,
                                      binding.network_type,
                                      binding.segmentation_id,
                                      binding.physical_network)
        return port

    def delete_port(self, context, id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)

        super(HyperVNeutronPlugin, self).delete_port(context, id)
        self.notifier.port_delete(context, id)
