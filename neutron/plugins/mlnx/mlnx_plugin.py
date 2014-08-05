# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Mellanox Technologies, Ltd
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

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as q_const
from neutron.common import exceptions as n_exc
from neutron.common import topics
from neutron.common import utils
from neutron.db import agentschedulers_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_gwmode_db
from neutron.db import portbindings_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.plugins.common import constants as svc_constants
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.mlnx import agent_notify_api
from neutron.plugins.mlnx.common import constants
from neutron.plugins.mlnx.db import mlnx_db_v2 as db
from neutron.plugins.mlnx import rpc_callbacks

LOG = logging.getLogger(__name__)


class MellanoxEswitchPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                            external_net_db.External_net_db_mixin,
                            extraroute_db.ExtraRoute_db_mixin,
                            l3_gwmode_db.L3_NAT_db_mixin,
                            sg_db_rpc.SecurityGroupServerRpcMixin,
                            l3_agentschedulers_db.L3AgentSchedulerDbMixin,
                            agentschedulers_db.DhcpAgentSchedulerDbMixin,
                            portbindings_db.PortBindingMixin):
    """Realization of Neutron API on Mellanox HCA embedded switch technology.

       Current plugin provides embedded HCA Switch connectivity.
       Code is based on the Linux Bridge plugin content to
       support consistency with L3 & DHCP Agents.

       A new VLAN is created for each network.  An agent is relied upon
       to perform the actual HCA configuration on each host.

       The provider extension is also supported.

       The port binding extension enables an external application relay
       information to and from the plugin.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True

    _supported_extension_aliases = ["provider", "external-net", "router",
                                    "ext-gw-mode", "binding", "quotas",
                                    "security-group", "agent", "extraroute",
                                    "l3_agent_scheduler",
                                    "dhcp_agent_scheduler"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        """Start Mellanox Neutron Plugin."""
        super(MellanoxEswitchPlugin, self).__init__()
        self._parse_network_config()
        db.sync_network_states(self.network_vlan_ranges)
        self._set_tenant_network_type()
        self.vnic_type = cfg.CONF.ESWITCH.vnic_type
        self.base_binding_dict = {
            portbindings.VIF_TYPE: self.vnic_type,
            portbindings.VIF_DETAILS: {
                # TODO(rkukura): Replace with new VIF security details
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        self._setup_rpc()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver
        )
        LOG.debug(_("Mellanox Embedded Switch Plugin initialisation complete"))

    def _setup_rpc(self):
        # RPC support
        self.service_topics = {svc_constants.CORE: topics.PLUGIN,
                               svc_constants.L3_ROUTER_NAT: topics.L3PLUGIN}
        self.conn = rpc.create_connection(new=True)
        self.callbacks = rpc_callbacks.MlnxRpcCallbacks()
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        for svc_topic in self.service_topics.values():
            self.conn.create_consumer(svc_topic, self.dispatcher, fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()
        self.notifier = agent_notify_api.AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[q_const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.agent_notifiers[q_const.AGENT_TYPE_L3] = (
            l3_rpc_agent_api.L3AgentNotify
        )

    def _parse_network_config(self):
        self._parse_physical_network_types()
        self._parse_network_vlan_ranges()
        for network in self.network_vlan_ranges.keys():
            if not self.phys_network_type_maps.get(network):
                self.phys_network_type_maps[network] = self.physical_net_type

    def _parse_physical_network_types(self):
        """Parse physical network types configuration.

        Verify default physical network type is valid.
        Parse physical network mappings.
        """
        self.physical_net_type = cfg.CONF.MLNX.physical_network_type
        if self.physical_net_type not in (constants.TYPE_ETH,
                                          constants.TYPE_IB):
            LOG.error(_("Invalid physical network type %(type)s."
                      "Server terminated!"), {'type': self.physical_net_type})
            raise SystemExit(1)
        try:
            self.phys_network_type_maps = utils.parse_mappings(
                cfg.CONF.MLNX.physical_network_type_mappings)
        except ValueError as e:
            LOG.error(_("Parsing physical_network_type failed: %s."
                      " Server terminated!"), e)
            raise SystemExit(1)
        for network, type in self.phys_network_type_maps.iteritems():
            if type not in (constants.TYPE_ETH, constants.TYPE_IB):
                LOG.error(_("Invalid physical network type %(type)s "
                          " for network %(net)s. Server terminated!"),
                          {'net': network, 'type': type})
                raise SystemExit(1)
        LOG.info(_("Physical Network type mappings: %s"),
                 self.phys_network_type_maps)

    def _parse_network_vlan_ranges(self):
        try:
            self.network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
                cfg.CONF.MLNX.network_vlan_ranges)
        except Exception as ex:
            LOG.error(_("%s. Server terminated!"), ex)
            sys.exit(1)
        LOG.info(_("Network VLAN ranges: %s"), self.network_vlan_ranges)

    def _extend_network_dict_provider(self, context, network):
        binding = db.get_network_binding(context.session, network['id'])
        network[provider.NETWORK_TYPE] = binding.network_type
        if binding.network_type == svc_constants.TYPE_FLAT:
            network[provider.PHYSICAL_NETWORK] = binding.physical_network
            network[provider.SEGMENTATION_ID] = None
        elif binding.network_type == svc_constants.TYPE_LOCAL:
            network[provider.PHYSICAL_NETWORK] = None
            network[provider.SEGMENTATION_ID] = None
        else:
            network[provider.PHYSICAL_NETWORK] = binding.physical_network
            network[provider.SEGMENTATION_ID] = binding.segmentation_id

    def _set_tenant_network_type(self):
        self.tenant_network_type = cfg.CONF.MLNX.tenant_network_type
        if self.tenant_network_type not in [svc_constants.TYPE_VLAN,
                                            svc_constants.TYPE_LOCAL,
                                            svc_constants.TYPE_NONE]:
            LOG.error(_("Invalid tenant_network_type: %s. "
                        "Service terminated!"),
                      self.tenant_network_type)
            sys.exit(1)

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

        if not network_type_set:
            msg = _("provider:network_type required")
            raise n_exc.InvalidInput(error_message=msg)
        elif network_type == svc_constants.TYPE_FLAT:
            self._process_flat_net(segmentation_id_set)
            segmentation_id = constants.FLAT_VLAN_ID

        elif network_type == svc_constants.TYPE_VLAN:
            self._process_vlan_net(segmentation_id, segmentation_id_set)

        elif network_type == svc_constants.TYPE_LOCAL:
            self._process_local_net(physical_network_set,
                                    segmentation_id_set)
            segmentation_id = constants.LOCAL_VLAN_ID
            physical_network = None

        else:
            msg = _("provider:network_type %s not supported") % network_type
            raise n_exc.InvalidInput(error_message=msg)
        physical_network = self._process_net_type(network_type,
                                                  physical_network,
                                                  physical_network_set)
        return (network_type, physical_network, segmentation_id)

    def _process_flat_net(self, segmentation_id_set):
        if segmentation_id_set:
            msg = _("provider:segmentation_id specified for flat network")
            raise n_exc.InvalidInput(error_message=msg)

    def _process_vlan_net(self, segmentation_id, segmentation_id_set):
        if not segmentation_id_set:
            msg = _("provider:segmentation_id required")
            raise n_exc.InvalidInput(error_message=msg)
        if not utils.is_valid_vlan_tag(segmentation_id):
            msg = (_("provider:segmentation_id out of range "
                     "(%(min_id)s through %(max_id)s)") %
                   {'min_id': q_const.MIN_VLAN_TAG,
                    'max_id': q_const.MAX_VLAN_TAG})
            raise n_exc.InvalidInput(error_message=msg)

    def _process_local_net(self, physical_network_set, segmentation_id_set):
        if physical_network_set:
            msg = _("provider:physical_network specified for local "
                    "network")
            raise n_exc.InvalidInput(error_message=msg)
        if segmentation_id_set:
            msg = _("provider:segmentation_id specified for local "
                    "network")
            raise n_exc.InvalidInput(error_message=msg)

    def _process_net_type(self, network_type,
                          physical_network,
                          physical_network_set):
        if network_type in [svc_constants.TYPE_VLAN,
                            svc_constants.TYPE_FLAT]:
            if physical_network_set:
                if physical_network not in self.network_vlan_ranges:
                    msg = _("Unknown provider:physical_network "
                            "%s") % physical_network
                    raise n_exc.InvalidInput(error_message=msg)
            elif 'default' in self.network_vlan_ranges:
                physical_network = 'default'
            else:
                msg = _("provider:physical_network required")
                raise n_exc.InvalidInput(error_message=msg)
        return physical_network

    def _check_port_binding_for_net_type(self, vnic_type, net_type):
        """
        VIF_TYPE_DIRECT is valid only for Ethernet fabric
        """
        if net_type == constants.TYPE_ETH:
            return vnic_type in (constants.VIF_TYPE_DIRECT,
                                 constants.VIF_TYPE_HOSTDEV)
        elif net_type == constants.TYPE_IB:
            return vnic_type == constants.VIF_TYPE_HOSTDEV
        return False

    def _process_port_binding_create(self, context, attrs):
        binding_profile = attrs.get(portbindings.PROFILE)
        binding_profile_set = attributes.is_attr_set(binding_profile)

        net_binding = db.get_network_binding(context.session,
                                             attrs.get('network_id'))
        phy_net = net_binding.physical_network

        if not binding_profile_set:
            return self.vnic_type
        if constants.VNIC_TYPE in binding_profile:
            vnic_type = binding_profile[constants.VNIC_TYPE]
            phy_net_type = self.phys_network_type_maps[phy_net]
            if vnic_type in (constants.VIF_TYPE_DIRECT,
                             constants.VIF_TYPE_HOSTDEV):
                if self._check_port_binding_for_net_type(vnic_type,
                                                         phy_net_type):
                    self.base_binding_dict[portbindings.VIF_TYPE] = vnic_type
                    return vnic_type
                else:
                    msg = (_("Unsupported vnic type %(vnic_type)s "
                             "for physical network type %(net_type)s") %
                           {'vnic_type': vnic_type, 'net_type': phy_net_type})
            else:
                msg = _("Invalid vnic_type on port_create")
        else:
            msg = _("vnic_type is not defined in port profile")
        raise n_exc.InvalidInput(error_message=msg)

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
                if network_type == svc_constants.TYPE_NONE:
                    raise n_exc.TenantNetworksDisabled()
                elif network_type == svc_constants.TYPE_VLAN:
                    physical_network, vlan_id = db.reserve_network(session)
                else:  # TYPE_LOCAL
                    vlan_id = constants.LOCAL_VLAN_ID
            else:
                # provider network
                if network_type in [svc_constants.TYPE_VLAN,
                                    svc_constants.TYPE_FLAT]:
                    db.reserve_specific_network(session,
                                                physical_network,
                                                vlan_id)
            net = super(MellanoxEswitchPlugin, self).create_network(context,
                                                                    network)
            db.add_network_binding(session, net['id'],
                                   network_type,
                                   physical_network,
                                   vlan_id)

            self._process_l3_create(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
            # note - exception will rollback entire transaction
            LOG.debug(_("Created network: %s"), net['id'])
            return net

    def update_network(self, context, net_id, network):
        LOG.debug(_("Update network"))
        provider._raise_if_updates_provider_attributes(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            net = super(MellanoxEswitchPlugin, self).update_network(context,
                                                                    net_id,
                                                                    network)
            self._process_l3_update(context, net, network['network'])
            self._extend_network_dict_provider(context, net)
        return net

    def delete_network(self, context, net_id):
        LOG.debug(_("Delete network"))
        session = context.session
        with session.begin(subtransactions=True):
            binding = db.get_network_binding(session, net_id)
            super(MellanoxEswitchPlugin, self).delete_network(context,
                                                              net_id)
            if binding.segmentation_id != constants.LOCAL_VLAN_ID:
                db.release_network(session, binding.physical_network,
                                   binding.segmentation_id,
                                   self.network_vlan_ranges)
            # the network_binding record is deleted via cascade from
            # the network record, so explicit removal is not necessary
        self.notifier.network_delete(context, net_id)

    def get_network(self, context, net_id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            net = super(MellanoxEswitchPlugin, self).get_network(context,
                                                                 net_id,
                                                                 None)
            self._extend_network_dict_provider(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            nets = super(MellanoxEswitchPlugin,
                         self).get_networks(context, filters, None, sorts,
                                            limit, marker, page_reverse)
            for net in nets:
                self._extend_network_dict_provider(context, net)

        return [self._fields(net, fields) for net in nets]

    def _extend_port_dict_binding(self, context, port):
        port_binding = db.get_port_profile_binding(context.session,
                                                   port['id'])
        if port_binding:
            port[portbindings.VIF_TYPE] = port_binding.vnic_type
        binding = db.get_network_binding(context.session,
                                         port['network_id'])
        fabric = binding.physical_network
        port[portbindings.PROFILE] = {'physical_network': fabric}
        return port

    def create_port(self, context, port):
        LOG.debug(_("create_port with %s"), port)
        session = context.session
        port_data = port['port']
        with session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            # Set port status as 'DOWN'. This will be updated by agent
            port['port']['status'] = q_const.PORT_STATUS_DOWN

            vnic_type = self._process_port_binding_create(context,
                                                          port['port'])

            port = super(MellanoxEswitchPlugin,
                         self).create_port(context, port)

            self._process_portbindings_create_and_update(context,
                                                         port_data,
                                                         port)
            db.add_port_profile_binding(context.session, port['id'], vnic_type)

            self._process_port_create_security_group(
                context, port, sgids)
        self.notify_security_groups_member_updated(context, port)
        return self._extend_port_dict_binding(context, port)

    def get_port(self, context, id, fields=None):
        port = super(MellanoxEswitchPlugin, self).get_port(context,
                                                           id,
                                                           fields)
        self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None, page_reverse=False):
        res_ports = []
        ports = super(MellanoxEswitchPlugin,
                      self).get_ports(context, filters, fields, sorts,
                                      limit, marker, page_reverse)
        for port in ports:
            port = self._extend_port_dict_binding(context, port)
            res_ports.append(self._fields(port, fields))
        return res_ports

    def update_port(self, context, port_id, port):
        original_port = self.get_port(context, port_id)
        session = context.session
        need_port_update_notify = False

        with session.begin(subtransactions=True):
            updated_port = super(MellanoxEswitchPlugin, self).update_port(
                context, port_id, port)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         updated_port)
            need_port_update_notify = self.update_security_group_on_port(
                context, port_id, port, original_port, updated_port)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        if original_port['admin_state_up'] != updated_port['admin_state_up']:
            need_port_update_notify = True

        if need_port_update_notify:
            binding = db.get_network_binding(context.session,
                                             updated_port['network_id'])
            self.notifier.port_update(context, updated_port,
                                      binding.physical_network,
                                      binding.network_type,
                                      binding.segmentation_id)
        return self._extend_port_dict_binding(context, updated_port)

    def delete_port(self, context, port_id, l3_port_check=True):
        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, port_id)

        session = context.session
        with session.begin(subtransactions=True):
            router_ids = self.disassociate_floatingips(
                context, port_id, do_notify=False)
            port = self.get_port(context, port_id)
            self._delete_port_security_group_bindings(context, port_id)
            super(MellanoxEswitchPlugin, self).delete_port(context, port_id)

        # now that we've left db transaction, we are safe to notify
        self.notify_routers_updated(context, router_ids)
        self.notify_security_groups_member_updated(context, port)
