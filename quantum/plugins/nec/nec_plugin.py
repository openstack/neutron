# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU
# @author: Akihiro MOTOKI

from quantum.agent import securitygroups_rpc as sg_rpc
from quantum.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from quantum.api.rpc.agentnotifiers import l3_rpc_agent_api
from quantum.common import rpc as q_rpc
from quantum.common import topics
from quantum.db import agents_db
from quantum.db import agentschedulers_db
from quantum.db import dhcp_rpc_base
from quantum.db import extraroute_db
from quantum.db import l3_rpc_base
from quantum.db import quota_db  # noqa
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.extensions import portbindings
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.openstack.common.rpc import proxy
from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import nec_plugin_base
from quantum.plugins.nec import ofc_manager
from quantum import policy

LOG = logging.getLogger(__name__)


class OperationalStatus:
    """Enumeration for operational status.

       ACTIVE: The resource is available.
       DOWN: The resource is not operational.  This might indicate
             admin_state_up=False, or lack of OpenFlow info for the port.
       BUILD: The plugin is creating the resource.
       ERROR: Some error occured.
    """
    ACTIVE = "ACTIVE"
    DOWN = "DOWN"
    BUILD = "BUILD"
    ERROR = "ERROR"


class NECPluginV2(nec_plugin_base.NECPluginV2Base,
                  extraroute_db.ExtraRoute_db_mixin,
                  sg_db_rpc.SecurityGroupServerRpcMixin,
                  agentschedulers_db.AgentSchedulerDbMixin):
    """NECPluginV2 controls an OpenFlow Controller.

    The Quantum NECPluginV2 maps L2 logical networks to L2 virtualized networks
    on an OpenFlow enabled network.  An OpenFlow Controller (OFC) provides
    L2 network isolation without VLAN and this plugin controls the OFC.

    NOTE: This is for Quantum API V2.  Codes for V1.0 and V1.1 are available
          at https://github.com/nec-openstack/quantum-openflow-plugin .

    The port binding extension enables an external application relay
    information to and from the plugin.
    """
    _supported_extension_aliases = ["router", "quotas", "binding",
                                    "security-group", "extraroute",
                                    "agent", "agent_scheduler",
                                    ]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_if_noop_driver(aliases)
            self._aliases = aliases
        return self._aliases

    binding_view = "extension:port_binding:view"
    binding_set = "extension:port_binding:set"

    def __init__(self):
        ndb.initialize()
        self.ofc = ofc_manager.OFCManager()

        self.packet_filter_enabled = (config.OFC.enable_packet_filter and
                                      self.ofc.driver.filter_supported())
        if self.packet_filter_enabled:
            self.supported_extension_aliases.append("PacketFilters")

        # Set the plugin default extension path
        # if no api_extensions_path is specified.
        if not config.CONF.api_extensions_path:
            config.CONF.set_override('api_extensions_path',
                                     'quantum/plugins/nec/extensions')

        self.setup_rpc()

        self.network_scheduler = importutils.import_object(
            config.CONF.network_scheduler_driver)
        self.router_scheduler = importutils.import_object(
            config.CONF.router_scheduler_driver)

    def setup_rpc(self):
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.notifier = NECPluginV2AgentNotifierApi(topics.AGENT)
        self.dhcp_agent_notifier = dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        self.l3_agent_notifier = l3_rpc_agent_api.L3AgentNotify

        # NOTE: callback_sg is referred to from the sg unit test.
        self.callback_sg = SecurityGroupServerRpcCallback()
        callbacks = [NECPluginV2RPCCallbacks(self),
                     DhcpRpcCallback(), L3RpcCallback(),
                     self.callback_sg,
                     agents_db.AgentExtRpcCallback()]
        self.dispatcher = q_rpc.PluginRpcDispatcher(callbacks)
        self.conn.create_consumer(self.topic, self.dispatcher, fanout=False)
        # Consume from all consumers in a thread
        self.conn.consume_in_thread()

    def _check_view_auth(self, context, resource, action):
        return policy.check(context, action, resource)

    def _enforce_set_auth(self, context, resource, action):
        policy.enforce(context, action, resource)

    def _update_resource_status(self, context, resource, id, status):
        """Update status of specified resource."""
        request = {}
        request[resource] = dict(status=status)
        obj_updater = getattr(super(NECPluginV2, self), "update_%s" % resource)
        obj_updater(context, id, request)

    def activate_port_if_ready(self, context, port, network=None):
        """Activate port by creating port on OFC if ready.

        Activate port and packet_filters associated with the port.
        Conditions to activate port on OFC are:
            * port admin_state is UP
            * network admin_state is UP
            * portinfo are available (to identify port on OFC)
        """
        if not network:
            network = super(NECPluginV2, self).get_network(context,
                                                           port['network_id'])

        port_status = OperationalStatus.ACTIVE
        if not port['admin_state_up']:
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "port.admin_state_up is False."))
            port_status = OperationalStatus.DOWN
        elif not network['admin_state_up']:
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "network.admin_state_up is False."))
            port_status = OperationalStatus.DOWN
        elif not ndb.get_portinfo(context.session, port['id']):
            LOG.debug(_("activate_port_if_ready(): skip, "
                        "no portinfo for this port."))
            port_status = OperationalStatus.DOWN

        # activate packet_filters before creating port on OFC.
        if self.packet_filter_enabled:
            if port_status is OperationalStatus.ACTIVE:
                filters = dict(in_port=[port['id']],
                               status=[OperationalStatus.DOWN],
                               admin_state_up=[True])
                pfs = (super(NECPluginV2, self).
                       get_packet_filters(context, filters=filters))
                for pf in pfs:
                    self._activate_packet_filter_if_ready(context, pf,
                                                          network=network,
                                                          in_port=port)

        if port_status in [OperationalStatus.ACTIVE]:
            if self.ofc.exists_ofc_port(context, port['id']):
                LOG.debug(_("activate_port_if_ready(): skip, "
                            "ofc_port already exists."))
            else:
                try:
                    self.ofc.create_ofc_port(context, port['id'], port)
                except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
                    reason = _("create_ofc_port() failed due to %s") % exc
                    LOG.error(reason)
                    port_status = OperationalStatus.ERROR

        if port_status is not port['status']:
            self._update_resource_status(context, "port", port['id'],
                                         port_status)

    def deactivate_port(self, context, port):
        """Deactivate port by deleting port from OFC if exists.

        Deactivate port and packet_filters associated with the port.
        """
        port_status = OperationalStatus.DOWN
        if self.ofc.exists_ofc_port(context, port['id']):
            try:
                self.ofc.delete_ofc_port(context, port['id'], port)
            except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
                reason = _("delete_ofc_port() failed due to %s") % exc
                LOG.error(reason)
                port_status = OperationalStatus.ERROR
        else:
            LOG.debug(_("deactivate_port(): skip, ofc_port does not "
                        "exist."))

        if port_status is not port['status']:
            self._update_resource_status(context, "port", port['id'],
                                         port_status)

        # deactivate packet_filters after the port has deleted from OFC.
        if self.packet_filter_enabled:
            filters = dict(in_port=[port['id']],
                           status=[OperationalStatus.ACTIVE])
            pfs = super(NECPluginV2, self).get_packet_filters(context,
                                                              filters=filters)
            for pf in pfs:
                self._deactivate_packet_filter(context, pf)

    # Quantm Plugin Basic methods

    def create_network(self, context, network):
        """Create a new network entry on DB, and create it on OFC."""
        LOG.debug(_("NECPluginV2.create_network() called, "
                    "network=%s ."), network)
        #set up default security groups
        tenant_id = self._get_tenant_id_for_create(
            context, network['network'])
        self._ensure_default_security_group(context, tenant_id)

        with context.session.begin(subtransactions=True):
            new_net = super(NECPluginV2, self).create_network(context, network)
            self._process_l3_create(context, network['network'], new_net['id'])
            self._extend_network_dict_l3(context, new_net)
            self._update_resource_status(context, "network", new_net['id'],
                                         OperationalStatus.BUILD)

        try:
            if not self.ofc.exists_ofc_tenant(context, new_net['tenant_id']):
                self.ofc.create_ofc_tenant(context, new_net['tenant_id'])
            self.ofc.create_ofc_network(context, new_net['tenant_id'],
                                        new_net['id'], new_net['name'])
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("create_network() failed due to %s") % exc
            LOG.error(reason)
            self._update_resource_status(context, "network", new_net['id'],
                                         OperationalStatus.ERROR)
        else:
            self._update_resource_status(context, "network", new_net['id'],
                                         OperationalStatus.ACTIVE)

        return new_net

    def update_network(self, context, id, network):
        """Update network and handle resources associated with the network.

        Update network entry on DB. If 'admin_state_up' was changed, activate
        or deactivate ports and packetfilters associated with the network.
        """
        LOG.debug(_("NECPluginV2.update_network() called, "
                    "id=%(id)s network=%(network)s ."),
                  {'id': id, 'network': network})
        session = context.session
        with session.begin(subtransactions=True):
            old_net = super(NECPluginV2, self).get_network(context, id)
            new_net = super(NECPluginV2, self).update_network(context, id,
                                                              network)
            self._process_l3_update(context, network['network'], id)
            self._extend_network_dict_l3(context, new_net)

        changed = (old_net['admin_state_up'] is not new_net['admin_state_up'])
        if changed and not new_net['admin_state_up']:
            self._update_resource_status(context, "network", id,
                                         OperationalStatus.DOWN)
            # disable all active ports and packet_filters of the network
            filters = dict(network_id=[id], status=[OperationalStatus.ACTIVE])
            ports = super(NECPluginV2, self).get_ports(context,
                                                       filters=filters)
            for port in ports:
                self.deactivate_port(context, port)
            if self.packet_filter_enabled:
                pfs = (super(NECPluginV2, self).
                       get_packet_filters(context, filters=filters))
                for pf in pfs:
                    self._deactivate_packet_filter(context, pf)
        elif changed and new_net['admin_state_up']:
            self._update_resource_status(context, "network", id,
                                         OperationalStatus.ACTIVE)
            # enable ports and packet_filters of the network
            filters = dict(network_id=[id], status=[OperationalStatus.DOWN],
                           admin_state_up=[True])
            ports = super(NECPluginV2, self).get_ports(context,
                                                       filters=filters)
            for port in ports:
                self.activate_port_if_ready(context, port, new_net)
            if self.packet_filter_enabled:
                pfs = (super(NECPluginV2, self).
                       get_packet_filters(context, filters=filters))
                for pf in pfs:
                    self._activate_packet_filter_if_ready(context, pf, new_net)

        return new_net

    def delete_network(self, context, id):
        """Delete network and packet_filters associated with the network.

        Delete network entry from DB and OFC. Then delete packet_filters
        associated with the network. If the network is the last resource
        of the tenant, delete unnessary ofc_tenant.
        """
        LOG.debug(_("NECPluginV2.delete_network() called, id=%s ."), id)
        net = super(NECPluginV2, self).get_network(context, id)
        tenant_id = net['tenant_id']

        # get packet_filters associated with the network
        if self.packet_filter_enabled:
            filters = dict(network_id=[id])
            pfs = (super(NECPluginV2, self).
                   get_packet_filters(context, filters=filters))

        super(NECPluginV2, self).delete_network(context, id)
        try:
            # 'net' parameter is required to lookup old OFC mapping
            self.ofc.delete_ofc_network(context, id, net)
        except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
            reason = _("delete_network() failed due to %s") % exc
            # NOTE: The OFC configuration of this network could be remained
            #       as an orphan resource. But, it does NOT harm any other
            #       resources, so this plugin just warns.
            LOG.warn(reason)

        # delete all packet_filters of the network
        if self.packet_filter_enabled:
            for pf in pfs:
                self.delete_packet_filter(context, pf['id'])

        # delete unnessary ofc_tenant
        filters = dict(tenant_id=[tenant_id])
        nets = super(NECPluginV2, self).get_networks(context, filters=filters)
        if not nets:
            try:
                self.ofc.delete_ofc_tenant(context, tenant_id)
            except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
                reason = _("delete_ofc_tenant() failed due to %s") % exc
                LOG.warn(reason)

    def get_network(self, context, id, fields=None):
        net = super(NECPluginV2, self).get_network(context, id, None)
        self._extend_network_dict_l3(context, net)
        return self._fields(net, fields)

    def get_networks(self, context, filters=None, fields=None):
        nets = super(NECPluginV2, self).get_networks(context, filters, None)
        for net in nets:
            self._extend_network_dict_l3(context, net)
        return [self._fields(net, fields) for net in nets]

    def _extend_port_dict_binding(self, context, port):
        if self._check_view_auth(context, port, self.binding_view):
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_OVS
            port[portbindings.CAPABILITIES] = {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}
        return port

    def create_port(self, context, port):
        """Create a new port entry on DB, then try to activate it."""
        LOG.debug(_("NECPluginV2.create_port() called, port=%s ."), port)
        with context.session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            port = super(NECPluginV2, self).create_port(context, port)
            self._process_port_create_security_group(
                context, port['id'], sgids)
            self._extend_port_dict_security_group(context, port)
        self.notify_security_groups_member_updated(context, port)
        self._update_resource_status(context, "port", port['id'],
                                     OperationalStatus.BUILD)
        self.activate_port_if_ready(context, port)
        return self._extend_port_dict_binding(context, port)

    def update_port(self, context, id, port):
        """Update port, and handle packetfilters associated with the port.

        Update network entry on DB. If admin_state_up was changed, activate
        or deactivate the port and packetfilters associated with it.
        """
        LOG.debug(_("NECPluginV2.update_port() called, "
                    "id=%(id)s port=%(port)s ."),
                  {'id': id, 'port': port})
        need_port_update_notify = False
        with context.session.begin(subtransactions=True):
            old_port = super(NECPluginV2, self).get_port(context, id)
            new_port = super(NECPluginV2, self).update_port(context, id, port)
            need_port_update_notify = self.update_security_group_on_port(
                context, id, port, old_port, new_port)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, old_port, new_port)
        if need_port_update_notify:
            self.notifier.port_update(context, new_port)

        changed = (old_port['admin_state_up'] != new_port['admin_state_up'])
        if changed:
            if new_port['admin_state_up']:
                self.activate_port_if_ready(context, new_port)
            else:
                self.deactivate_port(context, old_port)

        # NOTE: _extend_port_dict_security_group() is called in
        # update_security_group_on_port() above, so we don't need to
        # call it here.
        return self._extend_port_dict_binding(context, new_port)

    def delete_port(self, context, id, l3_port_check=True):
        """Delete port and packet_filters associated with the port."""
        LOG.debug(_("NECPluginV2.delete_port() called, id=%s ."), id)
        # ext_sg.SECURITYGROUPS attribute for the port is required
        # since notifier.security_groups_member_updated() need the attribute.
        # Thus we need to call self.get_port() instead of super().get_port()
        port = self.get_port(context, id)

        self.deactivate_port(context, port)

        # delete all packet_filters of the port
        if self.packet_filter_enabled:
            filters = dict(port_id=[id])
            pfs = (super(NECPluginV2, self).
                   get_packet_filters(context, filters=filters))
            for packet_filter in pfs:
                self.delete_packet_filter(context, packet_filter['id'])

        # if needed, check to see if this is a port owned by
        # and l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        with context.session.begin(subtransactions=True):
            self.disassociate_floatingips(context, id)
            self._delete_port_security_group_bindings(context, id)
            super(NECPluginV2, self).delete_port(context, id)
        self.notify_security_groups_member_updated(context, port)

    def get_port(self, context, id, fields=None):
        with context.session.begin(subtransactions=True):
            port = super(NECPluginV2, self).get_port(context, id, fields)
            self._extend_port_dict_security_group(context, port)
            self._extend_port_dict_binding(context, port)
        return self._fields(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        with context.session.begin(subtransactions=True):
            ports = super(NECPluginV2, self).get_ports(context, filters,
                                                       fields)
            # TODO(amotoki) filter by security group
            for port in ports:
                self._extend_port_dict_security_group(context, port)
                self._extend_port_dict_binding(context, port)
        return [self._fields(port, fields) for port in ports]

    # For PacketFilter Extension

    def _activate_packet_filter_if_ready(self, context, packet_filter,
                                         network=None, in_port=None):
        """Activate packet_filter by creating filter on OFC if ready.

        Conditions to create packet_filter on OFC are:
            * packet_filter admin_state is UP
            * network admin_state is UP
            * (if 'in_port' is specified) portinfo is available
        """
        net_id = packet_filter['network_id']
        if not network:
            network = super(NECPluginV2, self).get_network(context, net_id)
        in_port_id = packet_filter.get("in_port")
        if in_port_id and not in_port:
            in_port = super(NECPluginV2, self).get_port(context, in_port_id)

        pf_status = OperationalStatus.ACTIVE
        if not packet_filter['admin_state_up']:
            LOG.debug(_("_activate_packet_filter_if_ready(): skip, "
                        "packet_filter.admin_state_up is False."))
            pf_status = OperationalStatus.DOWN
        elif not network['admin_state_up']:
            LOG.debug(_("_activate_packet_filter_if_ready(): skip, "
                        "network.admin_state_up is False."))
            pf_status = OperationalStatus.DOWN
        elif in_port_id and in_port_id is in_port.get('id'):
            LOG.debug(_("_activate_packet_filter_if_ready(): skip, "
                        "invalid in_port_id."))
            pf_status = OperationalStatus.DOWN
        elif in_port_id and not ndb.get_portinfo(context.session, in_port_id):
            LOG.debug(_("_activate_packet_filter_if_ready(): skip, "
                        "no portinfo for in_port."))
            pf_status = OperationalStatus.DOWN

        if pf_status in [OperationalStatus.ACTIVE]:
            if self.ofc.exists_ofc_packet_filter(context, packet_filter['id']):
                LOG.debug(_("_activate_packet_filter_if_ready(): skip, "
                            "ofc_packet_filter already exists."))
            else:
                try:
                    (self.ofc.
                     create_ofc_packet_filter(context,
                                              packet_filter['id'],
                                              packet_filter))
                except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
                    reason = _("create_ofc_packet_filter() failed due to "
                               "%s") % exc
                    LOG.error(reason)
                    pf_status = OperationalStatus.ERROR

        if pf_status is not packet_filter['status']:
            self._update_resource_status(context, "packet_filter",
                                         packet_filter['id'], pf_status)

    def _deactivate_packet_filter(self, context, packet_filter):
        """Deactivate packet_filter by deleting filter from OFC if exixts."""
        pf_status = OperationalStatus.DOWN
        if not self.ofc.exists_ofc_packet_filter(context, packet_filter['id']):
            LOG.debug(_("_deactivate_packet_filter(): skip, "
                        "ofc_packet_filter does not exist."))
        else:
            try:
                self.ofc.delete_ofc_packet_filter(context, packet_filter['id'])
            except (nexc.OFCException, nexc.OFCConsistencyBroken) as exc:
                reason = _("delete_ofc_packet_filter() failed due to "
                           "%s") % exc
                LOG.error(reason)
                pf_status = OperationalStatus.ERROR

        if pf_status is not packet_filter['status']:
            self._update_resource_status(context, "packet_filter",
                                         packet_filter['id'], pf_status)

    def create_packet_filter(self, context, packet_filter):
        """Create a new packet_filter entry on DB, then try to activate it."""
        LOG.debug(_("NECPluginV2.create_packet_filter() called, "
                    "packet_filter=%s ."), packet_filter)
        new_pf = super(NECPluginV2, self).create_packet_filter(context,
                                                               packet_filter)
        self._update_resource_status(context, "packet_filter", new_pf['id'],
                                     OperationalStatus.BUILD)

        self._activate_packet_filter_if_ready(context, new_pf)

        return new_pf

    def update_packet_filter(self, context, id, packet_filter):
        """Update packet_filter entry on DB, and recreate it if changed.

        If any rule of the packet_filter was changed, recreate it on OFC.
        """
        LOG.debug(_("NECPluginV2.update_packet_filter() called, "
                    "id=%(id)s packet_filter=%(packet_filter)s ."),
                  {'id': id, 'packet_filter': packet_filter})
        with context.session.begin(subtransactions=True):
            old_pf = super(NECPluginV2, self).get_packet_filter(context, id)
            new_pf = super(NECPluginV2, self).update_packet_filter(
                context, id, packet_filter)

        changed = False
        exclude_items = ["id", "name", "tenant_id", "network_id", "status"]
        for key in new_pf['packet_filter'].keys():
            if key not in exclude_items:
                if old_pf[key] is not new_pf[key]:
                    changed = True
                    break

        if changed:
            self._deactivate_packet_filter(context, old_pf)
            self._activate_packet_filter_if_ready(context, new_pf)

        return new_pf

    def delete_packet_filter(self, context, id):
        """Deactivate and delete packet_filter."""
        LOG.debug(_("NECPluginV2.delete_packet_filter() called, id=%s ."), id)
        pf = super(NECPluginV2, self).get_packet_filter(context, id)
        self._deactivate_packet_filter(context, pf)

        super(NECPluginV2, self).delete_packet_filter(context, id)


class NECPluginV2AgentNotifierApi(proxy.RpcProxy,
                                  sg_rpc.SecurityGroupAgentRpcApiMixin):
    '''RPC API for NEC plugin agent'''

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self, topic):
        super(NECPluginV2AgentNotifierApi, self).__init__(
            topic=topic, default_version=self.BASE_RPC_API_VERSION)
        self.topic_port_update = topics.get_topic_name(
            topic, topics.PORT, topics.UPDATE)

    def port_update(self, context, port):
        self.fanout_cast(context,
                         self.make_msg('port_update',
                                       port=port),
                         topic=self.topic_port_update)


class DhcpRpcCallback(dhcp_rpc_base.DhcpRpcCallbackMixin):
    # DhcpPluginApi BASE_RPC_API_VERSION
    RPC_API_VERSION = '1.0'


class L3RpcCallback(l3_rpc_base.L3RpcCallbackMixin):
    # L3PluginApi BASE_RPC_API_VERSION
    RPC_API_VERSION = '1.0'


class SecurityGroupServerRpcCallback(
    sg_db_rpc.SecurityGroupServerRpcCallbackMixin):

    RPC_API_VERSION = sg_rpc.SG_RPC_VERSION

    @staticmethod
    def get_port_from_device(device):
        port = ndb.get_port_from_device(device)
        if port:
            port['device'] = device
        LOG.debug(_("NECPluginV2RPCCallbacks.get_port_from_device() called, "
                    "device=%(device)s => %(ret)s."),
                  {'device': device, 'ret': port})
        return port


class NECPluginV2RPCCallbacks(object):

    RPC_API_VERSION = '1.0'

    def __init__(self, plugin):
        self.plugin = plugin

    def create_rpc_dispatcher(self):
        '''Get the rpc dispatcher for this manager.

        If a manager would like to set an rpc API version, or support more than
        one class as the target of rpc messages, override this method.
        '''
        return q_rpc.PluginRpcDispatcher([self])

    def update_ports(self, rpc_context, **kwargs):
        """Update ports' information and activate/deavtivate them.

        Expected input format is:
            {'topic': 'q-agent-notifier',
             'agent_id': 'nec-q-agent.' + <hostname>,
             'datapath_id': <datapath_id of br-int on remote host>,
             'port_added': [<new PortInfo>,...],
             'port_removed': [<removed Port ID>,...]}
        """
        LOG.debug(_("NECPluginV2RPCCallbacks.update_ports() called, "
                    "kwargs=%s ."), kwargs)
        datapath_id = kwargs['datapath_id']
        session = rpc_context.session
        for p in kwargs.get('port_added', []):
            id = p['id']
            port = self.plugin.get_port(rpc_context, id)
            if port and ndb.get_portinfo(session, id):
                ndb.del_portinfo(session, id)
                self.plugin.deactivate_port(rpc_context, port)
            ndb.add_portinfo(session, id, datapath_id, p['port_no'],
                             mac=p.get('mac', ''))
            self.plugin.activate_port_if_ready(rpc_context, port)
        for id in kwargs.get('port_removed', []):
            portinfo = ndb.get_portinfo(session, id)
            if not portinfo:
                LOG.debug(_("update_ports(): ignore port_removed message "
                            "due to portinfo for port_id=%s was not "
                            "registered"), id)
                continue
            if portinfo.datapath_id is not datapath_id:
                LOG.debug(_("update_ports(): ignore port_removed message "
                            "received from different host "
                            "(registered_datapath_id=%(registered)s, "
                            "received_datapath_id=%(received)s)."),
                          {'registered': portinfo.datapath_id,
                           'received': datapath_id})
                continue
            port = self.plugin.get_port(rpc_context, id)
            if port:
                ndb.del_portinfo(session, id)
                self.plugin.deactivate_port(rpc_context, port)
