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
import contextlib

from oslo.config import cfg
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import exc as sa_exc

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.v2 import attributes
from neutron.common import constants as const
from neutron.common import exceptions as exc
from neutron.common import topics
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import models_v2
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import portbindings
from neutron.extensions import providernet as provider
from neutron import manager
from neutron.openstack.common import db as os_db
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import lockutils
from neutron.openstack.common import log
from neutron.openstack.common import rpc as c_rpc
from neutron.plugins.common import constants as service_constants
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import config  # noqa
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import rpc

LOG = log.getLogger(__name__)

# REVISIT(rkukura): Move this and other network_type constants to
# providernet.py?
TYPE_MULTI_SEGMENT = 'multi-segment'


class Ml2Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                external_net_db.External_net_db_mixin,
                sg_db_rpc.SecurityGroupServerRpcMixin,
                agentschedulers_db.DhcpAgentSchedulerDbMixin,
                addr_pair_db.AllowedAddressPairsMixin,
                extradhcpopt_db.ExtraDhcpOptMixin):

    """Implement the Neutron L2 abstractions using modules.

    Ml2Plugin is a Neutron plugin based on separately extensible sets
    of network types and mechanisms for connecting to networks of
    those types. The network types and mechanisms are implemented as
    drivers loaded via Python entry points. Networks can be made up of
    multiple segments (not yet fully implemented).
    """

    # This attribute specifies whether the plugin supports or not
    # bulk/pagination/sorting operations. Name mangling is used in
    # order to ensure it is qualified by class
    __native_bulk_support = True
    __native_pagination_support = True
    __native_sorting_support = True

    # List of supported extensions
    _supported_extension_aliases = ["provider", "external-net", "binding",
                                    "quotas", "security-group", "agent",
                                    "dhcp_agent_scheduler",
                                    "multi-provider", "allowed-address-pairs",
                                    "extra_dhcp_opt"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            sg_rpc.disable_security_group_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        # First load drivers, then initialize DB, then initialize drivers
        self.type_manager = managers.TypeManager()
        self.mechanism_manager = managers.MechanismManager()
        super(Ml2Plugin, self).__init__()
        self.type_manager.initialize()
        self.mechanism_manager.initialize()
        # bulk support depends on the underlying drivers
        self.__native_bulk_support = self.mechanism_manager.native_bulk_support

        self._setup_rpc()

        # REVISIT(rkukura): Use stevedore for these?
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )

        LOG.info(_("Modular L2 Plugin initialization complete"))

    def _setup_rpc(self):
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )

    def start_rpc_listener(self):
        self.callbacks = rpc.RpcCallbacks(self.notifier, self.type_manager)
        self.topic = topics.PLUGIN
        self.conn = c_rpc.create_connection(new=True)
        self.dispatcher = self.callbacks.create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher,
                                  fanout=False)
        return self.conn.consume_in_thread()

    def _process_provider_segment(self, segment):
        network_type = self._get_attribute(segment, provider.NETWORK_TYPE)
        physical_network = self._get_attribute(segment,
                                               provider.PHYSICAL_NETWORK)
        segmentation_id = self._get_attribute(segment,
                                              provider.SEGMENTATION_ID)

        if attributes.is_attr_set(network_type):
            segment = {api.NETWORK_TYPE: network_type,
                       api.PHYSICAL_NETWORK: physical_network,
                       api.SEGMENTATION_ID: segmentation_id}
            self.type_manager.validate_provider_segment(segment)
            return segment

        msg = _("network_type required")
        raise exc.InvalidInput(error_message=msg)

    def _process_provider_create(self, network):
        segments = []

        if any(attributes.is_attr_set(network.get(f))
               for f in (provider.NETWORK_TYPE, provider.PHYSICAL_NETWORK,
                         provider.SEGMENTATION_ID)):
            # Verify that multiprovider and provider attributes are not set
            # at the same time.
            if attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
                raise mpnet.SegmentsSetInConjunctionWithProviders()

            network_type = self._get_attribute(network, provider.NETWORK_TYPE)
            physical_network = self._get_attribute(network,
                                                   provider.PHYSICAL_NETWORK)
            segmentation_id = self._get_attribute(network,
                                                  provider.SEGMENTATION_ID)
            segments = [{provider.NETWORK_TYPE: network_type,
                         provider.PHYSICAL_NETWORK: physical_network,
                         provider.SEGMENTATION_ID: segmentation_id}]
        elif attributes.is_attr_set(network.get(mpnet.SEGMENTS)):
            segments = network[mpnet.SEGMENTS]
        else:
            return

        return [self._process_provider_segment(s) for s in segments]

    def _get_attribute(self, attrs, key):
        value = attrs.get(key)
        if value is attributes.ATTR_NOT_SPECIFIED:
            value = None
        return value

    def _extend_network_dict_provider(self, context, network):
        id = network['id']
        segments = db.get_network_segments(context.session, id)
        if not segments:
            LOG.error(_("Network %s has no segments"), id)
            network[provider.NETWORK_TYPE] = None
            network[provider.PHYSICAL_NETWORK] = None
            network[provider.SEGMENTATION_ID] = None
        elif len(segments) > 1:
            network[mpnet.SEGMENTS] = [
                {provider.NETWORK_TYPE: segment[api.NETWORK_TYPE],
                 provider.PHYSICAL_NETWORK: segment[api.PHYSICAL_NETWORK],
                 provider.SEGMENTATION_ID: segment[api.SEGMENTATION_ID]}
                for segment in segments]
        else:
            segment = segments[0]
            network[provider.NETWORK_TYPE] = segment[api.NETWORK_TYPE]
            network[provider.PHYSICAL_NETWORK] = segment[api.PHYSICAL_NETWORK]
            network[provider.SEGMENTATION_ID] = segment[api.SEGMENTATION_ID]

    def _filter_nets_provider(self, context, nets, filters):
        # TODO(rkukura): Implement filtering.
        return nets

    def _process_port_binding(self, mech_context, attrs):
        binding = mech_context._binding
        port = mech_context.current
        self._update_port_dict_binding(port, binding)

        host = attrs and attrs.get(portbindings.HOST_ID)
        host_set = attributes.is_attr_set(host)

        vnic_type = attrs and attrs.get(portbindings.VNIC_TYPE)
        vnic_type_set = attributes.is_attr_set(vnic_type)

        # CLI can't send {}, so treat None as {}
        profile = attrs and attrs.get(portbindings.PROFILE)
        profile_set = profile is not attributes.ATTR_NOT_SPECIFIED
        if profile_set and not profile:
            profile = {}

        if binding.vif_type != portbindings.VIF_TYPE_UNBOUND:
            if (not host_set and not vnic_type_set and not profile_set and
                binding.segment):
                return False
            self._delete_port_binding(mech_context)

        # Return True only if an agent notification is needed.
        # This will happen if a new host, vnic_type, or profile was specified
        # that differs from the current one. Note that host_set is True
        # even if the host is an empty string
        ret_value = ((host_set and binding.get('host') != host) or
                     (vnic_type_set and
                      binding.get('vnic_type') != vnic_type) or
                     (profile_set and self._get_profile(binding) != profile))

        if host_set:
            binding.host = host
            port[portbindings.HOST_ID] = host

        if vnic_type_set:
            binding.vnic_type = vnic_type
            port[portbindings.VNIC_TYPE] = vnic_type

        if profile_set:
            binding.profile = jsonutils.dumps(profile)
            if len(binding.profile) > models.BINDING_PROFILE_LEN:
                msg = _("binding:profile value too large")
                raise exc.InvalidInput(error_message=msg)
            port[portbindings.PROFILE] = profile

        # To try to [re]bind if host is non-empty.
        if binding.host:
            self.mechanism_manager.bind_port(mech_context)
            self._update_port_dict_binding(port, binding)

            # Update the port status if requested by the bound driver.
            if binding.segment and mech_context._new_port_status:
                # REVISIT(rkukura): This function is currently called
                # inside a transaction with the port either newly
                # created or locked for update. After the fix for bug
                # 1276391 is merged, this will no longer be true, and
                # the port status update will need to be handled in
                # the transaction that commits the new binding.
                port_db = db.get_port(mech_context._plugin_context.session,
                                      port['id'])
                port_db.status = mech_context._new_port_status
                port['status'] = mech_context._new_port_status

        return ret_value

    def _update_port_dict_binding(self, port, binding):
        port[portbindings.HOST_ID] = binding.host
        port[portbindings.VNIC_TYPE] = binding.vnic_type
        port[portbindings.PROFILE] = self._get_profile(binding)
        port[portbindings.VIF_TYPE] = binding.vif_type
        port[portbindings.VIF_DETAILS] = self._get_vif_details(binding)

    def _get_vif_details(self, binding):
        if binding.vif_details:
            try:
                return jsonutils.loads(binding.vif_details)
            except Exception:
                LOG.error(_("Serialized vif_details DB value '%(value)s' "
                            "for port %(port)s is invalid"),
                          {'value': binding.vif_details,
                           'port': binding.port_id})
        return {}

    def _get_profile(self, binding):
        if binding.profile:
            try:
                return jsonutils.loads(binding.profile)
            except Exception:
                LOG.error(_("Serialized profile DB value '%(value)s' for "
                            "port %(port)s is invalid"),
                          {'value': binding.profile,
                           'port': binding.port_id})
        return {}

    def _delete_port_binding(self, mech_context):
        binding = mech_context._binding
        binding.vif_type = portbindings.VIF_TYPE_UNBOUND
        binding.vif_details = ''
        binding.driver = None
        binding.segment = None
        port = mech_context.current
        self._update_port_dict_binding(port, binding)

    def _ml2_extend_port_dict_binding(self, port_res, port_db):
        # None when called during unit tests for other plugins.
        if port_db.port_binding:
            self._update_port_dict_binding(port_res, port_db.port_binding)

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_ml2_extend_port_dict_binding'])

    # Note - The following hook methods have "ml2" in their names so
    # that they are not called twice during unit tests due to global
    # registration of hooks in portbindings_db.py used by other
    # plugins.

    def _ml2_port_model_hook(self, context, original_model, query):
        query = query.outerjoin(models.PortBinding,
                                (original_model.id ==
                                 models.PortBinding.port_id))
        return query

    def _ml2_port_result_filter_hook(self, query, filters):
        values = filters and filters.get(portbindings.HOST_ID, [])
        if not values:
            return query
        return query.filter(models.PortBinding.host.in_(values))

    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Port,
        "ml2_port_bindings",
        '_ml2_port_model_hook',
        None,
        '_ml2_port_result_filter_hook')

    def _notify_port_updated(self, mech_context):
        port = mech_context._port
        segment = mech_context.bound_segment
        if not segment:
            # REVISIT(rkukura): This should notify agent to unplug port
            network = mech_context.network.current
            LOG.warning(_("In _notify_port_updated(), no bound segment for "
                          "port %(port_id)s on network %(network_id)s"),
                        {'port_id': port['id'],
                         'network_id': network['id']})
            return
        self.notifier.port_update(mech_context._plugin_context, port,
                                  segment[api.NETWORK_TYPE],
                                  segment[api.SEGMENTATION_ID],
                                  segment[api.PHYSICAL_NETWORK])

    # TODO(apech): Need to override bulk operations

    def create_network(self, context, network):
        net_data = network['network']
        segments = self._process_provider_create(net_data)
        tenant_id = self._get_tenant_id_for_create(context, net_data)

        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group(context, tenant_id)
            result = super(Ml2Plugin, self).create_network(context, network)
            network_id = result['id']
            self._process_l3_create(context, result, net_data)
            # REVISIT(rkukura): Consider moving all segment management
            # to TypeManager.
            if segments:
                for segment in segments:
                    self.type_manager.reserve_provider_segment(session,
                                                               segment)
                    db.add_network_segment(session, network_id, segment)
            else:
                segment = self.type_manager.allocate_tenant_segment(session)
                db.add_network_segment(session, network_id, segment)
            self._extend_network_dict_provider(context, result)
            mech_context = driver_context.NetworkContext(self, context,
                                                         result)
            self.mechanism_manager.create_network_precommit(mech_context)

        try:
            self.mechanism_manager.create_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager.create_network_postcommit "
                            "failed, deleting network '%s'"), result['id'])
                self.delete_network(context, result['id'])
        return result

    def update_network(self, context, id, network):
        provider._raise_if_updates_provider_attributes(network['network'])

        session = context.session
        with session.begin(subtransactions=True):
            original_network = super(Ml2Plugin, self).get_network(context, id)
            updated_network = super(Ml2Plugin, self).update_network(context,
                                                                    id,
                                                                    network)
            self._process_l3_update(context, updated_network,
                                    network['network'])
            self._extend_network_dict_provider(context, updated_network)
            mech_context = driver_context.NetworkContext(
                self, context, updated_network,
                original_network=original_network)
            self.mechanism_manager.update_network_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_network, potentially
        # by re-calling update_network with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_network_postcommit(mech_context)
        return updated_network

    def get_network(self, context, id, fields=None):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2Plugin, self).get_network(context, id, None)
            self._extend_network_dict_provider(context, result)

        return self._fields(result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            nets = super(Ml2Plugin,
                         self).get_networks(context, filters, None, sorts,
                                            limit, marker, page_reverse)
            for net in nets:
                self._extend_network_dict_provider(context, net)

            nets = self._filter_nets_provider(context, nets, filters)
            nets = self._filter_nets_l3(context, nets, filters)

        return [self._fields(net, fields) for net in nets]

    def delete_network(self, context, id):
        # REVISIT(rkukura) The super(Ml2Plugin, self).delete_network()
        # function is not used because it auto-deletes ports and
        # subnets from the DB without invoking the derived class's
        # delete_port() or delete_subnet(), preventing mechanism
        # drivers from being called. This approach should be revisited
        # when the API layer is reworked during icehouse.

        LOG.debug(_("Deleting network %s"), id)
        session = context.session
        while True:
            try:
                with session.begin(subtransactions=True):
                    # Get ports to auto-delete.
                    ports = (session.query(models_v2.Port).
                             enable_eagerloads(False).
                             filter_by(network_id=id).
                             with_lockmode('update').all())
                    LOG.debug(_("Ports to auto-delete: %s"), ports)
                    only_auto_del = all(p.device_owner
                                        in db_base_plugin_v2.
                                        AUTO_DELETE_PORT_OWNERS
                                        for p in ports)
                    if not only_auto_del:
                        LOG.debug(_("Tenant-owned ports exist"))
                        raise exc.NetworkInUse(net_id=id)

                    # Get subnets to auto-delete.
                    subnets = (session.query(models_v2.Subnet).
                               enable_eagerloads(False).
                               filter_by(network_id=id).
                               with_lockmode('update').all())
                    LOG.debug(_("Subnets to auto-delete: %s"), subnets)

                    if not (ports or subnets):
                        network = self.get_network(context, id)
                        mech_context = driver_context.NetworkContext(self,
                                                                     context,
                                                                     network)
                        self.mechanism_manager.delete_network_precommit(
                            mech_context)

                        record = self._get_network(context, id)
                        LOG.debug(_("Deleting network record %s"), record)
                        session.delete(record)

                        for segment in mech_context.network_segments:
                            self.type_manager.release_segment(session, segment)

                        # The segment records are deleted via cascade from the
                        # network record, so explicit removal is not necessary.
                        LOG.debug(_("Committing transaction"))
                        break
            except os_db.exception.DBError as e:
                with excutils.save_and_reraise_exception() as ctxt:
                    if isinstance(e.inner_exception, sql_exc.IntegrityError):
                        ctxt.reraise = False
                        msg = _("A concurrent port creation has occurred")
                        LOG.warning(msg)
                        continue

            for port in ports:
                try:
                    self.delete_port(context, port.id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Exception auto-deleting port %s"),
                                      port.id)

            for subnet in subnets:
                try:
                    self.delete_subnet(context, subnet.id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Exception auto-deleting subnet %s"),
                                      subnet.id)

        try:
            self.mechanism_manager.delete_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the network.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error(_("mechanism_manager.delete_network_postcommit failed"))
        self.notifier.network_delete(context, id)

    def create_subnet(self, context, subnet):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2Plugin, self).create_subnet(context, subnet)
            mech_context = driver_context.SubnetContext(self, context, result)
            self.mechanism_manager.create_subnet_precommit(mech_context)

        try:
            self.mechanism_manager.create_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager.create_subnet_postcommit "
                            "failed, deleting subnet '%s'"), result['id'])
                self.delete_subnet(context, result['id'])
        return result

    def update_subnet(self, context, id, subnet):
        session = context.session
        with session.begin(subtransactions=True):
            original_subnet = super(Ml2Plugin, self).get_subnet(context, id)
            updated_subnet = super(Ml2Plugin, self).update_subnet(
                context, id, subnet)
            mech_context = driver_context.SubnetContext(
                self, context, updated_subnet, original_subnet=original_subnet)
            self.mechanism_manager.update_subnet_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_subnet, potentially
        # by re-calling update_subnet with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_subnet_postcommit(mech_context)
        return updated_subnet

    def delete_subnet(self, context, id):
        # REVISIT(rkukura) The super(Ml2Plugin, self).delete_subnet()
        # function is not used because it auto-deletes ports from the
        # DB without invoking the derived class's delete_port(),
        # preventing mechanism drivers from being called. This
        # approach should be revisited when the API layer is reworked
        # during icehouse.

        LOG.debug(_("Deleting subnet %s"), id)
        session = context.session
        while True:
            with session.begin(subtransactions=True):
                subnet = self.get_subnet(context, id)
                # Get ports to auto-delete.
                allocated = (session.query(models_v2.IPAllocation).
                             filter_by(subnet_id=id).
                             join(models_v2.Port).
                             filter_by(network_id=subnet['network_id']).
                             with_lockmode('update').all())
                LOG.debug(_("Ports to auto-delete: %s"), allocated)
                only_auto_del = all(not a.port_id or
                                    a.ports.device_owner in db_base_plugin_v2.
                                    AUTO_DELETE_PORT_OWNERS
                                    for a in allocated)
                if not only_auto_del:
                    LOG.debug(_("Tenant-owned ports exist"))
                    raise exc.SubnetInUse(subnet_id=id)

                if not allocated:
                    mech_context = driver_context.SubnetContext(self, context,
                                                                subnet)
                    self.mechanism_manager.delete_subnet_precommit(
                        mech_context)

                    LOG.debug(_("Deleting subnet record"))
                    record = self._get_subnet(context, id)
                    session.delete(record)

                    LOG.debug(_("Committing transaction"))
                    break

            for a in allocated:
                try:
                    self.delete_port(context, a.port_id)
                except Exception:
                    with excutils.save_and_reraise_exception():
                        LOG.exception(_("Exception auto-deleting port %s"),
                                      a.port_id)

        try:
            self.mechanism_manager.delete_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the subnet.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error(_("mechanism_manager.delete_subnet_postcommit failed"))

    def create_port(self, context, port):
        attrs = port['port']
        attrs['status'] = const.PORT_STATUS_DOWN

        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group_on_port(context, port)
            sgids = self._get_security_groups_on_port(context, port)
            dhcp_opts = port['port'].get(edo_ext.EXTRADHCPOPTS, [])
            result = super(Ml2Plugin, self).create_port(context, port)
            self._process_port_create_security_group(context, result, sgids)
            network = self.get_network(context, result['network_id'])
            mech_context = driver_context.PortContext(self, context, result,
                                                      network)
            self._process_port_binding(mech_context, attrs)
            result[addr_pair.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, result,
                    attrs.get(addr_pair.ADDRESS_PAIRS)))
            self._process_port_create_extra_dhcp_opts(context, result,
                                                      dhcp_opts)
            self.mechanism_manager.create_port_precommit(mech_context)

        try:
            self.mechanism_manager.create_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_("mechanism_manager.create_port_postcommit "
                            "failed, deleting port '%s'"), result['id'])
                self.delete_port(context, result['id'])
        self.notify_security_groups_member_updated(context, result)
        return result

    def update_port(self, context, id, port):
        attrs = port['port']
        need_port_update_notify = False

        session = context.session
        changed_fixed_ips = 'fixed_ips' in port['port']
        with session.begin(subtransactions=True):
            try:
                port_db = (session.query(models_v2.Port).
                           enable_eagerloads(False).
                           filter_by(id=id).with_lockmode('update').one())
            except sa_exc.NoResultFound:
                raise exc.PortNotFound(port_id=id)
            original_port = self._make_port_dict(port_db)
            updated_port = super(Ml2Plugin, self).update_port(context, id,
                                                              port)
            if addr_pair.ADDRESS_PAIRS in port['port']:
                need_port_update_notify |= (
                    self.update_address_pairs_on_port(context, id, port,
                                                      original_port,
                                                      updated_port))
            elif changed_fixed_ips:
                self._check_fixed_ips_and_address_pairs_no_overlap(
                    context, updated_port)
            need_port_update_notify |= self.update_security_group_on_port(
                context, id, port, original_port, updated_port)
            network = self.get_network(context, original_port['network_id'])
            need_port_update_notify |= self._update_extra_dhcp_opts_on_port(
                context, id, port, updated_port)
            mech_context = driver_context.PortContext(
                self, context, updated_port, network,
                original_port=original_port)
            need_port_update_notify |= self._process_port_binding(
                mech_context, attrs)
            self.mechanism_manager.update_port_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_port, potentially
        # by re-calling update_port with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_port_postcommit(mech_context)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        if original_port['admin_state_up'] != updated_port['admin_state_up']:
            need_port_update_notify = True

        if need_port_update_notify:
            self._notify_port_updated(mech_context)

        return updated_port

    def delete_port(self, context, id, l3_port_check=True):
        LOG.debug(_("Deleting port %s"), id)
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if l3plugin and l3_port_check:
            l3plugin.prevent_l3_port_deletion(context, id)

        session = context.session
        # REVISIT: Serialize this operation with a semaphore to prevent
        # undesired eventlet yields leading to 'lock wait timeout' errors
        with contextlib.nested(lockutils.lock('db-access'),
                               session.begin(subtransactions=True)):
            try:
                port_db = (session.query(models_v2.Port).
                           enable_eagerloads(False).
                           filter_by(id=id).with_lockmode('update').one())
            except sa_exc.NoResultFound:
                # the port existed when l3plugin.prevent_l3_port_deletion
                # was called but now is already gone
                LOG.debug(_("The port '%s' was deleted"), id)
                return
            port = self._make_port_dict(port_db)

            network = self.get_network(context, port['network_id'])
            mech_context = driver_context.PortContext(self, context, port,
                                                      network)
            self.mechanism_manager.delete_port_precommit(mech_context)
            self._delete_port_security_group_bindings(context, id)
            LOG.debug(_("Calling base delete_port"))
            if l3plugin:
                router_ids = l3plugin.disassociate_floatingips(
                    context, id, do_notify=False)

            super(Ml2Plugin, self).delete_port(context, id)

        # now that we've left db transaction, we are safe to notify
        if l3plugin:
            l3plugin.notify_routers_updated(context, router_ids)

        try:
            self.mechanism_manager.delete_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the port.  Ideally we'd notify the caller of the
            # fact that an error occurred.
            LOG.error(_("mechanism_manager.delete_port_postcommit failed"))
        self.notify_security_groups_member_updated(context, port)

    def update_port_status(self, context, port_id, status):
        updated = False
        session = context.session
        # REVISIT: Serialize this operation with a semaphore to prevent
        # undesired eventlet yields leading to 'lock wait timeout' errors
        with contextlib.nested(lockutils.lock('db-access'),
                               session.begin(subtransactions=True)):
            port = db.get_port(session, port_id)
            if not port:
                LOG.warning(_("Port %(port)s updated up by agent not found"),
                            {'port': port_id})
                return False
            if port.status != status:
                original_port = self._make_port_dict(port)
                port.status = status
                updated_port = self._make_port_dict(port)
                network = self.get_network(context,
                                           original_port['network_id'])
                mech_context = driver_context.PortContext(
                    self, context, updated_port, network,
                    original_port=original_port)
                self.mechanism_manager.update_port_precommit(mech_context)
                updated = True

        if updated:
            self.mechanism_manager.update_port_postcommit(mech_context)

        return True

    def port_bound_to_host(self, port_id, host):
        port_host = db.get_port_binding_host(port_id)
        return (port_host == host)
