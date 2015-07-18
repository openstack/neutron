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

from eventlet import greenthread
from oslo_config import cfg
from oslo_db import api as oslo_db_api
from oslo_db import exception as os_db_exception
from oslo_log import helpers as log_helpers
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import uuidutils
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import exc as sa_exc

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import dvr_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import exceptions
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import constants as const
from neutron.common import exceptions as exc
from neutron.common import ipv6_utils
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils
from neutron.db import address_scope_db
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import api as db_api
from neutron.db import db_base_plugin_v2
from neutron.db import dvr_mac_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db import models_v2
from neutron.db import netmtu_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.db import vlantransparent_db
from neutron.extensions import allowedaddresspairs as addr_pair
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.extensions import portbindings
from neutron.extensions import portsecurity as psec
from neutron.extensions import providernet as provider
from neutron.extensions import vlantransparent
from neutron.i18n import _LE, _LI, _LW
from neutron import manager
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

MAX_BIND_TRIES = 10


class Ml2Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                dvr_mac_db.DVRDbMixin,
                external_net_db.External_net_db_mixin,
                sg_db_rpc.SecurityGroupServerRpcMixin,
                agentschedulers_db.DhcpAgentSchedulerDbMixin,
                addr_pair_db.AllowedAddressPairsMixin,
                vlantransparent_db.Vlantransparent_db_mixin,
                extradhcpopt_db.ExtraDhcpOptMixin,
                netmtu_db.Netmtu_db_mixin,
                address_scope_db.AddressScopeDbMixin):

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
                                    "extra_dhcp_opt", "subnet_allocation",
                                    "net-mtu", "vlan-transparent",
                                    "address-scope"]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            aliases += self.extension_manager.extension_aliases()
            sg_rpc.disable_security_group_extension_by_config(aliases)
            vlantransparent.disable_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __init__(self):
        # First load drivers, then initialize DB, then initialize drivers
        self.type_manager = managers.TypeManager()
        self.extension_manager = managers.ExtensionManager()
        self.mechanism_manager = managers.MechanismManager()
        super(Ml2Plugin, self).__init__()
        self.type_manager.initialize()
        self.extension_manager.initialize()
        self.mechanism_manager.initialize()

        self._setup_rpc()
        self._setup_dhcp()
        LOG.info(_LI("Modular L2 Plugin initialization complete"))

    def _setup_rpc(self):
        """Initialize components to support agent communication."""
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )
        self.endpoints = [
            rpc.RpcCallbacks(self.notifier, self.type_manager),
            securitygroups_rpc.SecurityGroupServerRpcCallback(),
            dvr_rpc.DVRServerRpcCallback(),
            dhcp_rpc.DhcpRpcCallback(),
            agents_db.AgentExtRpcCallback(),
            metadata_rpc.MetadataRpcCallback()
        ]

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.start_periodic_dhcp_agent_status_check()

    @log_helpers.log_method_call
    def start_rpc_listeners(self):
        """Start the RPC loop to let the plugin communicate with agents."""
        self.topic = topics.PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        return self.conn.consume_in_threads()

    def _filter_nets_provider(self, context, networks, filters):
        return [network
                for network in networks
                if self.type_manager.network_matches_filters(network, filters)
                ]

    def _get_host_port_if_changed(self, mech_context, attrs):
        binding = mech_context._binding
        host = attrs and attrs.get(portbindings.HOST_ID)
        if (attributes.is_attr_set(host) and binding.host != host):
            return mech_context.current

    def _check_mac_update_allowed(self, orig_port, port, binding):
        unplugged_types = (portbindings.VIF_TYPE_BINDING_FAILED,
                           portbindings.VIF_TYPE_UNBOUND)
        new_mac = port.get('mac_address')
        mac_change = (new_mac is not None and
                      orig_port['mac_address'] != new_mac)
        if (mac_change and binding.vif_type not in unplugged_types):
            raise exc.PortBound(port_id=orig_port['id'],
                                vif_type=binding.vif_type,
                                old_mac=orig_port['mac_address'],
                                new_mac=port['mac_address'])
        return mac_change

    def _process_port_binding(self, mech_context, attrs):
        session = mech_context._plugin_context.session
        binding = mech_context._binding
        port = mech_context.current
        port_id = port['id']
        changes = False

        host = attributes.ATTR_NOT_SPECIFIED
        if attrs and portbindings.HOST_ID in attrs:
            host = attrs.get(portbindings.HOST_ID) or ''

        original_host = binding.host
        if (attributes.is_attr_set(host) and
            original_host != host):
            binding.host = host
            changes = True

        vnic_type = attrs and attrs.get(portbindings.VNIC_TYPE)
        if (attributes.is_attr_set(vnic_type) and
            binding.vnic_type != vnic_type):
            binding.vnic_type = vnic_type
            changes = True

        # treat None as clear of profile.
        profile = None
        if attrs and portbindings.PROFILE in attrs:
            profile = attrs.get(portbindings.PROFILE) or {}

        if profile not in (None, attributes.ATTR_NOT_SPECIFIED,
                           self._get_profile(binding)):
            binding.profile = jsonutils.dumps(profile)
            if len(binding.profile) > models.BINDING_PROFILE_LEN:
                msg = _("binding:profile value too large")
                raise exc.InvalidInput(error_message=msg)
            changes = True

        # Unbind the port if needed.
        if changes:
            binding.vif_type = portbindings.VIF_TYPE_UNBOUND
            binding.vif_details = ''
            db.clear_binding_levels(session, port_id, original_host)
            mech_context._clear_binding_levels()

        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            binding.vif_type = portbindings.VIF_TYPE_UNBOUND
            binding.vif_details = ''
            db.clear_binding_levels(session, port_id, original_host)
            mech_context._clear_binding_levels()
            binding.host = ''

        self._update_port_dict_binding(port, binding)
        return changes

    def _bind_port_if_needed(self, context, allow_notify=False,
                             need_notify=False):
        plugin_context = context._plugin_context
        port_id = context.current['id']

        # Since the mechanism driver bind_port() calls must be made
        # outside a DB transaction locking the port state, it is
        # possible (but unlikely) that the port's state could change
        # concurrently while these calls are being made. If another
        # thread or process succeeds in binding the port before this
        # thread commits its results, the already committed results are
        # used. If attributes such as binding:host_id,
        # binding:profile, or binding:vnic_type are updated
        # concurrently, this loop retries binding using the new
        # values.
        count = 0
        while True:
            # First, determine whether it is necessary and possible to
            # bind the port.
            binding = context._binding
            if (binding.vif_type != portbindings.VIF_TYPE_UNBOUND
                or not binding.host):
                # We either don't need to bind the port, or can't, so
                # notify if needed and return.
                if allow_notify and need_notify:
                    self._notify_port_updated(context)
                return context

            # Limit binding attempts to avoid any possibility of
            # infinite looping and to ensure an error is logged
            # instead. This does not need to be tunable because no
            # more than a couple attempts should ever be required in
            # normal operation. Log at info level if not 1st attempt.
            count += 1
            if count > MAX_BIND_TRIES:
                LOG.error(_LE("Failed to commit binding results for %(port)s "
                              "after %(max)s tries"),
                          {'port': port_id, 'max': MAX_BIND_TRIES})
                return context
            if count > 1:
                greenthread.sleep(0)  # yield
                LOG.info(_LI("Attempt %(count)s to bind port %(port)s"),
                         {'count': count, 'port': port_id})

            # The port isn't already bound and the necessary
            # information is available, so attempt to bind the port.
            bind_context = self._bind_port(context)

            # Now try to commit result of attempting to bind the port.
            new_context, did_commit = self._commit_port_binding(
                plugin_context, port_id, binding, bind_context)
            if not new_context:
                # The port has been deleted concurrently, so just
                # return the unbound result from the initial
                # transaction that completed before the deletion.
                LOG.debug("Port %s has been deleted concurrently",
                          port_id)
                return context
            # Need to notify if we succeed and our results were
            # committed.
            if did_commit and (new_context._binding.vif_type !=
                               portbindings.VIF_TYPE_BINDING_FAILED):
                need_notify = True
            context = new_context

    def _bind_port(self, orig_context):
        # Construct a new PortContext from the one from the previous
        # transaction.
        port = orig_context.current
        orig_binding = orig_context._binding
        new_binding = models.PortBinding(
            host=orig_binding.host,
            vnic_type=orig_binding.vnic_type,
            profile=orig_binding.profile,
            vif_type=portbindings.VIF_TYPE_UNBOUND,
            vif_details=''
        )
        self._update_port_dict_binding(port, new_binding)
        new_context = driver_context.PortContext(
            self, orig_context._plugin_context, port,
            orig_context.network.current, new_binding, None)

        # Attempt to bind the port and return the context with the
        # result.
        self.mechanism_manager.bind_port(new_context)
        return new_context

    def _commit_port_binding(self, plugin_context, port_id, orig_binding,
                             new_context):
        session = plugin_context.session
        new_binding = new_context._binding

        # After we've attempted to bind the port, we begin a
        # transaction, get the current port state, and decide whether
        # to commit the binding results.
        with session.begin(subtransactions=True):
            # Get the current port state and build a new PortContext
            # reflecting this state as original state for subsequent
            # mechanism driver update_port_*commit() calls.
            port_db, cur_binding = db.get_locked_port_and_binding(session,
                                                                  port_id)
            if not port_db:
                # The port has been deleted concurrently.
                return (None, None)
            oport = self._make_port_dict(port_db)
            port = self._make_port_dict(port_db)
            network = new_context.network.current
            if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                # REVISIT(rkukura): The PortBinding instance from the
                # ml2_port_bindings table, returned as cur_binding
                # from db.get_locked_port_and_binding() above, is
                # currently not used for DVR distributed ports, and is
                # replaced here with the DVRPortBinding instance from
                # the ml2_dvr_port_bindings table specific to the host
                # on which the distributed port is being bound. It
                # would be possible to optimize this code to avoid
                # fetching the PortBinding instance in the DVR case,
                # and even to avoid creating the unused entry in the
                # ml2_port_bindings table. But the upcoming resolution
                # for bug 1367391 will eliminate the
                # ml2_dvr_port_bindings table, use the
                # ml2_port_bindings table to store non-host-specific
                # fields for both distributed and non-distributed
                # ports, and introduce a new ml2_port_binding_hosts
                # table for the fields that need to be host-specific
                # in the distributed case. Since the PortBinding
                # instance will then be needed, it does not make sense
                # to optimize this code to avoid fetching it.
                cur_binding = db.get_dvr_port_binding_by_host(
                    session, port_id, orig_binding.host)
            cur_context = driver_context.PortContext(
                self, plugin_context, port, network, cur_binding, None,
                original_port=oport)

            # Commit our binding results only if port has not been
            # successfully bound concurrently by another thread or
            # process and no binding inputs have been changed.
            commit = ((cur_binding.vif_type in
                       [portbindings.VIF_TYPE_UNBOUND,
                        portbindings.VIF_TYPE_BINDING_FAILED]) and
                      orig_binding.host == cur_binding.host and
                      orig_binding.vnic_type == cur_binding.vnic_type and
                      orig_binding.profile == cur_binding.profile)

            if commit:
                # Update the port's binding state with our binding
                # results.
                cur_binding.vif_type = new_binding.vif_type
                cur_binding.vif_details = new_binding.vif_details
                db.clear_binding_levels(session, port_id, cur_binding.host)
                db.set_binding_levels(session, new_context._binding_levels)
                cur_context._binding_levels = new_context._binding_levels

                # Update PortContext's port dictionary to reflect the
                # updated binding state.
                self._update_port_dict_binding(port, cur_binding)

                # Update the port status if requested by the bound driver.
                if (new_context._binding_levels and
                    new_context._new_port_status):
                    port_db.status = new_context._new_port_status
                    port['status'] = new_context._new_port_status

                # Call the mechanism driver precommit methods, commit
                # the results, and call the postcommit methods.
                self.mechanism_manager.update_port_precommit(cur_context)
        if commit:
            self.mechanism_manager.update_port_postcommit(cur_context)

        # Continue, using the port state as of the transaction that
        # just finished, whether that transaction committed new
        # results or discovered concurrent port state changes.
        return (cur_context, commit)

    def _update_port_dict_binding(self, port, binding):
        port[portbindings.VNIC_TYPE] = binding.vnic_type
        port[portbindings.PROFILE] = self._get_profile(binding)
        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            port[portbindings.HOST_ID] = ''
            port[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_DISTRIBUTED
            port[portbindings.VIF_DETAILS] = {}
        else:
            port[portbindings.HOST_ID] = binding.host
            port[portbindings.VIF_TYPE] = binding.vif_type
            port[portbindings.VIF_DETAILS] = self._get_vif_details(binding)

    def _get_vif_details(self, binding):
        if binding.vif_details:
            try:
                return jsonutils.loads(binding.vif_details)
            except Exception:
                LOG.error(_LE("Serialized vif_details DB value '%(value)s' "
                              "for port %(port)s is invalid"),
                          {'value': binding.vif_details,
                           'port': binding.port_id})
        return {}

    def _get_profile(self, binding):
        if binding.profile:
            try:
                return jsonutils.loads(binding.profile)
            except Exception:
                LOG.error(_LE("Serialized profile DB value '%(value)s' for "
                              "port %(port)s is invalid"),
                          {'value': binding.profile,
                           'port': binding.port_id})
        return {}

    def _ml2_extend_port_dict_binding(self, port_res, port_db):
        # None when called during unit tests for other plugins.
        if port_db.port_binding:
            self._update_port_dict_binding(port_res, port_db.port_binding)

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.PORTS, ['_ml2_extend_port_dict_binding'])

    # Register extend dict methods for network and port resources.
    # Each mechanism driver that supports extend attribute for the resources
    # can add those attribute to the result.
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               attributes.NETWORKS, ['_ml2_md_extend_network_dict'])
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               attributes.PORTS, ['_ml2_md_extend_port_dict'])
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
               attributes.SUBNETS, ['_ml2_md_extend_subnet_dict'])

    def _ml2_md_extend_network_dict(self, result, netdb):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            self.extension_manager.extend_network_dict(session, netdb, result)

    def _ml2_md_extend_port_dict(self, result, portdb):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            self.extension_manager.extend_port_dict(session, portdb, result)

    def _ml2_md_extend_subnet_dict(self, result, subnetdb):
        session = db_api.get_session()
        with session.begin(subtransactions=True):
            self.extension_manager.extend_subnet_dict(
                session, subnetdb, result)

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
        port = mech_context.current
        segment = mech_context.bottom_bound_segment
        if not segment:
            # REVISIT(rkukura): This should notify agent to unplug port
            network = mech_context.network.current
            LOG.warning(_LW("In _notify_port_updated(), no bound segment for "
                            "port %(port_id)s on network %(network_id)s"),
                        {'port_id': port['id'],
                         'network_id': network['id']})
            return
        self.notifier.port_update(mech_context._plugin_context, port,
                                  segment[api.NETWORK_TYPE],
                                  segment[api.SEGMENTATION_ID],
                                  segment[api.PHYSICAL_NETWORK])

    def _delete_objects(self, context, resource, objects):
        delete_op = getattr(self, 'delete_%s' % resource)
        for obj in objects:
            try:
                delete_op(context, obj['result']['id'])
            except KeyError:
                LOG.exception(_LE("Could not find %s to delete."),
                              resource)
            except Exception:
                LOG.exception(_LE("Could not delete %(res)s %(id)s."),
                              {'res': resource,
                               'id': obj['result']['id']})

    def _create_bulk_ml2(self, resource, context, request_items):
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        try:
            with context.session.begin(subtransactions=True):
                obj_creator = getattr(self, '_create_%s_db' % resource)
                for item in items:
                    attrs = item[resource]
                    result, mech_context = obj_creator(context, item)
                    objects.append({'mech_context': mech_context,
                                    'result': result,
                                    'attributes': attrs})

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_LE("An exception occurred while creating "
                                  "the %(resource)s:%(item)s"),
                              {'resource': resource, 'item': item})

        try:
            postcommit_op = getattr(self.mechanism_manager,
                                    'create_%s_postcommit' % resource)
            for obj in objects:
                postcommit_op(obj['mech_context'])
            return objects
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                resource_ids = [res['result']['id'] for res in objects]
                LOG.exception(_LE("mechanism_manager.create_%(res)s"
                                  "_postcommit failed for %(res)s: "
                                  "'%(failed_id)s'. Deleting "
                                  "%(res)ss %(resource_ids)s"),
                              {'res': resource,
                               'failed_id': obj['result']['id'],
                               'resource_ids': ', '.join(resource_ids)})
                self._delete_objects(context, resource, objects)

    def _create_network_db(self, context, network):
        net_data = network[attributes.NETWORK]
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        session = context.session
        with session.begin(subtransactions=True):
            self._ensure_default_security_group(context, tenant_id)
            result = super(Ml2Plugin, self).create_network(context, network)
            self.extension_manager.process_create_network(context, net_data,
                                                          result)
            self._process_l3_create(context, result, net_data)
            net_data['id'] = result['id']
            self.type_manager.create_network_segments(context, net_data,
                                                      tenant_id)
            self.type_manager.extend_network_dict_provider(context, result)
            mech_context = driver_context.NetworkContext(self, context,
                                                         result)
            self.mechanism_manager.create_network_precommit(mech_context)

            if net_data.get(api.MTU, 0) > 0:
                res = super(Ml2Plugin, self).update_network(context,
                    result['id'], {'network': {api.MTU: net_data[api.MTU]}})
                result[api.MTU] = res.get(api.MTU, 0)

        return result, mech_context

    @oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES,
                               retry_on_request=True)
    def _create_network_with_retries(self, context, network):
        return self._create_network_db(context, network)

    def create_network(self, context, network):
        result, mech_context = self._create_network_with_retries(context,
                                                                 network)
        try:
            self.mechanism_manager.create_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("mechanism_manager.create_network_postcommit "
                              "failed, deleting network '%s'"), result['id'])
                self.delete_network(context, result['id'])

        return result

    def create_network_bulk(self, context, networks):
        objects = self._create_bulk_ml2(attributes.NETWORK, context, networks)
        return [obj['result'] for obj in objects]

    def update_network(self, context, id, network):
        net_data = network[attributes.NETWORK]
        provider._raise_if_updates_provider_attributes(net_data)

        session = context.session
        with session.begin(subtransactions=True):
            original_network = super(Ml2Plugin, self).get_network(context, id)
            updated_network = super(Ml2Plugin, self).update_network(context,
                                                                    id,
                                                                    network)
            self.extension_manager.process_update_network(context, net_data,
                                                          updated_network)
            self._process_l3_update(context, updated_network, net_data)
            self.type_manager.extend_network_dict_provider(context,
                                                           updated_network)
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
            self.type_manager.extend_network_dict_provider(context, result)

        return self._fields(result, fields)

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        session = context.session
        with session.begin(subtransactions=True):
            nets = super(Ml2Plugin,
                         self).get_networks(context, filters, None, sorts,
                                            limit, marker, page_reverse)
            for net in nets:
                self.type_manager.extend_network_dict_provider(context, net)

            nets = self._filter_nets_provider(context, nets, filters)

        return [self._fields(net, fields) for net in nets]

    def _delete_ports(self, context, ports):
        for port in ports:
            try:
                self.delete_port(context, port.id)
            except (exc.PortNotFound, sa_exc.ObjectDeletedError):
                context.session.expunge(port)
                # concurrent port deletion can be performed by
                # release_dhcp_port caused by concurrent subnet_delete
                LOG.info(_LI("Port %s was deleted concurrently"), port.id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Exception auto-deleting port %s"),
                                  port.id)

    def _delete_subnets(self, context, subnets):
        for subnet in subnets:
            try:
                self.delete_subnet(context, subnet.id)
            except (exc.SubnetNotFound, sa_exc.ObjectDeletedError):
                context.session.expunge(subnet)
                LOG.info(_LI("Subnet %s was deleted concurrently"),
                         subnet.id)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Exception auto-deleting subnet %s"),
                                  subnet.id)

    def delete_network(self, context, id):
        # REVISIT(rkukura) The super(Ml2Plugin, self).delete_network()
        # function is not used because it auto-deletes ports and
        # subnets from the DB without invoking the derived class's
        # delete_port() or delete_subnet(), preventing mechanism
        # drivers from being called. This approach should be revisited
        # when the API layer is reworked during icehouse.

        LOG.debug("Deleting network %s", id)
        session = context.session
        while True:
            try:
                # REVISIT: Serialize this operation with a semaphore
                # to prevent deadlock waiting to acquire a DB lock
                # held by another thread in the same process, leading
                # to 'lock wait timeout' errors.
                #
                # Process L3 first, since, depending on the L3 plugin, it may
                # involve sending RPC notifications, and/or calling delete_port
                # on this plugin.
                # Additionally, a rollback may not be enough to undo the
                # deletion of a floating IP with certain L3 backends.
                self._process_l3_delete(context, id)
                # Using query().with_lockmode isn't necessary. Foreign-key
                # constraints prevent deletion if concurrent creation happens.
                with session.begin(subtransactions=True):
                    # Get ports to auto-delete.
                    ports = (session.query(models_v2.Port).
                             enable_eagerloads(False).
                             filter_by(network_id=id).all())
                    LOG.debug("Ports to auto-delete: %s", ports)
                    only_auto_del = all(p.device_owner
                                        in db_base_plugin_v2.
                                        AUTO_DELETE_PORT_OWNERS
                                        for p in ports)
                    if not only_auto_del:
                        LOG.debug("Tenant-owned ports exist")
                        raise exc.NetworkInUse(net_id=id)

                    # Get subnets to auto-delete.
                    subnets = (session.query(models_v2.Subnet).
                               enable_eagerloads(False).
                               filter_by(network_id=id).all())
                    LOG.debug("Subnets to auto-delete: %s", subnets)

                    if not (ports or subnets):
                        network = self.get_network(context, id)
                        mech_context = driver_context.NetworkContext(self,
                                                                     context,
                                                                     network)
                        self.mechanism_manager.delete_network_precommit(
                            mech_context)

                        self.type_manager.release_network_segments(session, id)
                        record = self._get_network(context, id)
                        LOG.debug("Deleting network record %s", record)
                        session.delete(record)

                        # The segment records are deleted via cascade from the
                        # network record, so explicit removal is not necessary.
                        LOG.debug("Committing transaction")
                        break
            except os_db_exception.DBError as e:
                with excutils.save_and_reraise_exception() as ctxt:
                    if isinstance(e.inner_exception, sql_exc.IntegrityError):
                        ctxt.reraise = False
                        LOG.warning(_LW("A concurrent port creation has "
                                        "occurred"))
                        continue
            self._delete_ports(context, ports)
            self._delete_subnets(context, subnets)

        try:
            self.mechanism_manager.delete_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the network.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error(_LE("mechanism_manager.delete_network_postcommit"
                          " failed"))
        self.notifier.network_delete(context, id)

    def _create_subnet_db(self, context, subnet):
        session = context.session
        with session.begin(subtransactions=True):
            result = super(Ml2Plugin, self).create_subnet(context, subnet)
            self.extension_manager.process_create_subnet(
                context, subnet[attributes.SUBNET], result)
            mech_context = driver_context.SubnetContext(self, context, result)
            self.mechanism_manager.create_subnet_precommit(mech_context)

        return result, mech_context

    def create_subnet(self, context, subnet):
        result, mech_context = self._create_subnet_db(context, subnet)
        try:
            self.mechanism_manager.create_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("mechanism_manager.create_subnet_postcommit "
                              "failed, deleting subnet '%s'"), result['id'])
                self.delete_subnet(context, result['id'])
        return result

    def create_subnet_bulk(self, context, subnets):
        objects = self._create_bulk_ml2(attributes.SUBNET, context, subnets)
        return [obj['result'] for obj in objects]

    def update_subnet(self, context, id, subnet):
        session = context.session
        with session.begin(subtransactions=True):
            original_subnet = super(Ml2Plugin, self).get_subnet(context, id)
            updated_subnet = super(Ml2Plugin, self).update_subnet(
                context, id, subnet)
            self.extension_manager.process_update_subnet(
                context, subnet[attributes.SUBNET], updated_subnet)
            mech_context = driver_context.SubnetContext(
                self, context, updated_subnet, original_subnet=original_subnet)
            self.mechanism_manager.update_subnet_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_subnet, potentially
        # by re-calling update_subnet with the previous attributes. For
        # now the error is propogated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_subnet_postcommit(mech_context)
        return updated_subnet

    @oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES,
                               retry_on_request=True)
    def delete_subnet(self, context, id):
        # REVISIT(rkukura) The super(Ml2Plugin, self).delete_subnet()
        # function is not used because it deallocates the subnet's addresses
        # from ports in the DB without invoking the derived class's
        # update_port(), preventing mechanism drivers from being called.
        # This approach should be revisited when the API layer is reworked
        # during icehouse.

        LOG.debug("Deleting subnet %s", id)
        session = context.session
        while True:
            with session.begin(subtransactions=True):
                record = self._get_subnet(context, id)
                subnet = self._make_subnet_dict(record, None, context=context)
                qry_allocated = (session.query(models_v2.IPAllocation).
                                 filter_by(subnet_id=id).
                                 join(models_v2.Port))
                is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
                # Remove network owned ports, and delete IP allocations
                # for IPv6 addresses which were automatically generated
                # via SLAAC
                if is_auto_addr_subnet:
                    self._subnet_check_ip_allocations_internal_router_ports(
                            context, id)
                else:
                    qry_allocated = (
                        qry_allocated.filter(models_v2.Port.device_owner.
                        in_(db_base_plugin_v2.AUTO_DELETE_PORT_OWNERS)))
                allocated = qry_allocated.all()
                # Delete all the IPAllocation that can be auto-deleted
                if allocated:
                    for x in allocated:
                        session.delete(x)
                LOG.debug("Ports to auto-deallocate: %s", allocated)
                # Check if there are more IP allocations, unless
                # is_auto_address_subnet is True. In that case the check is
                # unnecessary. This additional check not only would be wasteful
                # for this class of subnet, but is also error-prone since when
                # the isolation level is set to READ COMMITTED allocations made
                # concurrently will be returned by this query
                if not is_auto_addr_subnet:
                    alloc = self._subnet_check_ip_allocations(context, id)
                    if alloc:
                        user_alloc = self._subnet_get_user_allocation(
                            context, id)
                        if user_alloc:
                            LOG.info(_LI("Found port (%(port_id)s, %(ip)s) "
                                         "having IP allocation on subnet "
                                         "%(subnet)s, cannot delete"),
                                     {'ip': user_alloc.ip_address,
                                      'port_id': user_alloc.port_id,
                                      'subnet': id})
                            raise exc.SubnetInUse(subnet_id=id)
                        else:
                            # allocation found and it was DHCP port
                            # that appeared after autodelete ports were
                            # removed - need to restart whole operation
                            raise os_db_exception.RetryRequest(
                                exc.SubnetInUse(subnet_id=id))

                db_base_plugin_v2._check_subnet_not_used(context, id)

                # If allocated is None, then all the IPAllocation were
                # correctly deleted during the previous pass.
                if not allocated:
                    mech_context = driver_context.SubnetContext(self, context,
                                                                subnet)
                    self.mechanism_manager.delete_subnet_precommit(
                        mech_context)

                    LOG.debug("Deleting subnet record")
                    session.delete(record)

                    LOG.debug("Committing transaction")
                    break

            for a in allocated:
                if a.port_id:
                    # calling update_port() for each allocation to remove the
                    # IP from the port and call the MechanismDrivers
                    data = {attributes.PORT:
                            {'fixed_ips': [{'subnet_id': ip.subnet_id,
                                            'ip_address': ip.ip_address}
                                           for ip in a.port.fixed_ips
                                           if ip.subnet_id != id]}}
                    try:
                        self.update_port(context, a.port_id, data)
                    except Exception:
                        with excutils.save_and_reraise_exception():
                            LOG.exception(_LE("Exception deleting fixed_ip "
                                              "from port %s"), a.port_id)

        try:
            self.mechanism_manager.delete_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the subnet.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error(_LE("mechanism_manager.delete_subnet_postcommit failed"))

    # TODO(yalei) - will be simplified after security group and address pair be
    # converted to ext driver too.
    def _portsec_ext_port_create_processing(self, context, port_data, port):
        attrs = port[attributes.PORT]
        port_security = ((port_data.get(psec.PORTSECURITY) is None) or
                         port_data[psec.PORTSECURITY])

        # allowed address pair checks
        if self._check_update_has_allowed_address_pairs(port):
            if not port_security:
                raise addr_pair.AddressPairAndPortSecurityRequired()
        else:
            # remove ATTR_NOT_SPECIFIED
            attrs[addr_pair.ADDRESS_PAIRS] = []

        if port_security:
            self._ensure_default_security_group_on_port(context, port)
        elif self._check_update_has_security_groups(port):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()

    def _create_port_db(self, context, port):
        attrs = port[attributes.PORT]
        if not attrs.get('status'):
            attrs['status'] = const.PORT_STATUS_DOWN

        session = context.session
        with session.begin(subtransactions=True):
            dhcp_opts = attrs.get(edo_ext.EXTRADHCPOPTS, [])
            result = super(Ml2Plugin, self).create_port(context, port)
            self.extension_manager.process_create_port(context, attrs, result)
            self._portsec_ext_port_create_processing(context, result, port)

            # sgids must be got after portsec checked with security group
            sgids = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(context, result, sgids)
            network = self.get_network(context, result['network_id'])
            binding = db.add_port_binding(session, result['id'])
            mech_context = driver_context.PortContext(self, context, result,
                                                      network, binding, None)
            self._process_port_binding(mech_context, attrs)

            result[addr_pair.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, result,
                    attrs.get(addr_pair.ADDRESS_PAIRS)))
            self._process_port_create_extra_dhcp_opts(context, result,
                                                      dhcp_opts)
            self.mechanism_manager.create_port_precommit(mech_context)

        return result, mech_context

    def create_port(self, context, port):
        attrs = port[attributes.PORT]
        result, mech_context = self._create_port_db(context, port)
        new_host_port = self._get_host_port_if_changed(mech_context, attrs)
        # notify any plugin that is interested in port create events
        kwargs = {'context': context, 'port': new_host_port}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)

        try:
            self.mechanism_manager.create_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("mechanism_manager.create_port_postcommit "
                              "failed, deleting port '%s'"), result['id'])
                self.delete_port(context, result['id'])

        # REVISIT(rkukura): Is there any point in calling this before
        # a binding has been successfully established?
        self.notify_security_groups_member_updated(context, result)

        try:
            bound_context = self._bind_port_if_needed(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("_bind_port_if_needed "
                              "failed, deleting port '%s'"), result['id'])
                self.delete_port(context, result['id'])

        return bound_context.current

    def create_port_bulk(self, context, ports):
        objects = self._create_bulk_ml2(attributes.PORT, context, ports)

        # REVISIT(rkukura): Is there any point in calling this before
        # a binding has been successfully established?
        results = [obj['result'] for obj in objects]
        self.notify_security_groups_member_updated_bulk(context, results)

        for obj in objects:
            attrs = obj['attributes']
            if attrs and attrs.get(portbindings.HOST_ID):
                new_host_port = self._get_host_port_if_changed(
                    obj['mech_context'], attrs)
                kwargs = {'context': context, 'port': new_host_port}
                registry.notify(
                    resources.PORT, events.AFTER_CREATE, self, **kwargs)

        try:
            for obj in objects:
                obj['bound_context'] = self._bind_port_if_needed(
                    obj['mech_context'])
            return [obj['bound_context'].current for obj in objects]
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                resource_ids = [res['result']['id'] for res in objects]
                LOG.error(_LE("_bind_port_if_needed failed. "
                              "Deleting all ports from create bulk '%s'"),
                          resource_ids)
                self._delete_objects(context, attributes.PORT, objects)

    # TODO(yalei) - will be simplified after security group and address pair be
    # converted to ext driver too.
    def _portsec_ext_port_update_processing(self, updated_port, context, port,
                                            id):
        port_security = ((updated_port.get(psec.PORTSECURITY) is None) or
                         updated_port[psec.PORTSECURITY])

        if port_security:
            return

        # check the address-pairs
        if self._check_update_has_allowed_address_pairs(port):
            #  has address pairs in request
            raise addr_pair.AddressPairAndPortSecurityRequired()
        elif (not
         self._check_update_deletes_allowed_address_pairs(port)):
            # not a request for deleting the address-pairs
            updated_port[addr_pair.ADDRESS_PAIRS] = (
                    self.get_allowed_address_pairs(context, id))

            # check if address pairs has been in db, if address pairs could
            # be put in extension driver, we can refine here.
            if updated_port[addr_pair.ADDRESS_PAIRS]:
                raise addr_pair.AddressPairAndPortSecurityRequired()

        # checks if security groups were updated adding/modifying
        # security groups, port security is set
        if self._check_update_has_security_groups(port):
            raise psec.PortSecurityAndIPRequiredForSecurityGroups()
        elif (not
          self._check_update_deletes_security_groups(port)):
            # Update did not have security groups passed in. Check
            # that port does not have any security groups already on it.
            filters = {'port_id': [id]}
            security_groups = (
                super(Ml2Plugin, self)._get_port_security_group_bindings(
                        context, filters)
                     )
            if security_groups:
                raise psec.PortSecurityPortHasSecurityGroup()

    def update_port(self, context, id, port):
        attrs = port[attributes.PORT]
        need_port_update_notify = False
        session = context.session
        bound_mech_contexts = []

        with session.begin(subtransactions=True):
            port_db, binding = db.get_locked_port_and_binding(session, id)
            if not port_db:
                raise exc.PortNotFound(port_id=id)
            mac_address_updated = self._check_mac_update_allowed(
                port_db, attrs, binding)
            need_port_update_notify |= mac_address_updated
            original_port = self._make_port_dict(port_db)
            updated_port = super(Ml2Plugin, self).update_port(context, id,
                                                              port)
            self.extension_manager.process_update_port(context, attrs,
                                                       updated_port)
            self._portsec_ext_port_update_processing(updated_port, context,
                                                     port, id)

            if (psec.PORTSECURITY in attrs) and (
                        original_port[psec.PORTSECURITY] !=
                        updated_port[psec.PORTSECURITY]):
                need_port_update_notify = True

            if addr_pair.ADDRESS_PAIRS in attrs:
                need_port_update_notify |= (
                    self.update_address_pairs_on_port(context, id, port,
                                                      original_port,
                                                      updated_port))
            need_port_update_notify |= self.update_security_group_on_port(
                context, id, port, original_port, updated_port)
            network = self.get_network(context, original_port['network_id'])
            need_port_update_notify |= self._update_extra_dhcp_opts_on_port(
                context, id, port, updated_port)
            levels = db.get_binding_levels(session, id, binding.host)
            mech_context = driver_context.PortContext(
                self, context, updated_port, network, binding, levels,
                original_port=original_port)
            # For DVR router interface ports we need to retrieve the
            # DVRPortbinding context instead of the normal port context.
            # The normal Portbinding context does not have the status
            # of the ports that are required by the l2pop to process the
            # postcommit events.

            # NOTE:Sometimes during the update_port call, the DVR router
            # interface port may not have the port binding, so we cannot
            # create a generic bindinglist that will address both the
            # DVR and non-DVR cases here.
            # TODO(Swami): This code need to be revisited.
            if port_db['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                dvr_binding_list = db.get_dvr_port_bindings(session, id)
                for dvr_binding in dvr_binding_list:
                    levels = db.get_binding_levels(session, id,
                                                   dvr_binding.host)
                    dvr_mech_context = driver_context.PortContext(
                        self, context, updated_port, network,
                        dvr_binding, levels, original_port=original_port)
                    self.mechanism_manager.update_port_precommit(
                        dvr_mech_context)
                    bound_mech_contexts.append(dvr_mech_context)
            else:
                self.mechanism_manager.update_port_precommit(mech_context)
                bound_mech_contexts.append(mech_context)

            new_host_port = self._get_host_port_if_changed(
                mech_context, attrs)
            need_port_update_notify |= self._process_port_binding(
                mech_context, attrs)
        # Notifications must be sent after the above transaction is complete
        kwargs = {
            'context': context,
            'port': new_host_port,
            'mac_address_updated': mac_address_updated,
        }
        registry.notify(resources.PORT, events.AFTER_UPDATE, self, **kwargs)

        # Note that DVR Interface ports will have bindings on
        # multiple hosts, and so will have multiple mech_contexts,
        # while other ports typically have just one.
        # Since bound_mech_contexts has both the DVR and non-DVR
        # contexts we can manage just with a single for loop.
        try:
            for mech_context in bound_mech_contexts:
                self.mechanism_manager.update_port_postcommit(
                    mech_context)
        except ml2_exc.MechanismDriverError:
            LOG.error(_LE("mechanism_manager.update_port_postcommit "
                          "failed for port %s"), id)

        self.check_and_notify_security_group_member_changed(
            context, original_port, updated_port)
        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        if original_port['admin_state_up'] != updated_port['admin_state_up']:
            need_port_update_notify = True
        # NOTE: In the case of DVR ports, the port-binding is done after
        # router scheduling when sync_routers is callede and so this call
        # below may not be required for DVR routed interfaces. But still
        # since we don't have the mech_context for the DVR router interfaces
        # at certain times, we just pass the port-context and return it, so
        # that we don't disturb other methods that are expecting a return
        # value.
        bound_context = self._bind_port_if_needed(
            mech_context,
            allow_notify=True,
            need_notify=need_port_update_notify)
        return bound_context.current

    def _process_dvr_port_binding(self, mech_context, context, attrs):
        session = mech_context._plugin_context.session
        binding = mech_context._binding
        port = mech_context.current
        port_id = port['id']

        if binding.vif_type != portbindings.VIF_TYPE_UNBOUND:
            binding.vif_details = ''
            binding.vif_type = portbindings.VIF_TYPE_UNBOUND
            if binding.host:
                db.clear_binding_levels(session, port_id, binding.host)
            binding.host = ''

        self._update_port_dict_binding(port, binding)
        binding.host = attrs and attrs.get(portbindings.HOST_ID)
        binding.router_id = attrs and attrs.get('device_id')

    def update_dvr_port_binding(self, context, id, port):
        attrs = port[attributes.PORT]

        host = attrs and attrs.get(portbindings.HOST_ID)
        host_set = attributes.is_attr_set(host)

        if not host_set:
            LOG.error(_LE("No Host supplied to bind DVR Port %s"), id)
            return

        session = context.session
        binding = db.get_dvr_port_binding_by_host(session, id, host)
        device_id = attrs and attrs.get('device_id')
        router_id = binding and binding.get('router_id')
        update_required = (not binding or
            binding.vif_type == portbindings.VIF_TYPE_BINDING_FAILED or
            router_id != device_id)
        if update_required:
            with session.begin(subtransactions=True):
                try:
                    orig_port = super(Ml2Plugin, self).get_port(context, id)
                except exc.PortNotFound:
                    LOG.debug("DVR Port %s has been deleted concurrently", id)
                    return
                if not binding:
                    binding = db.ensure_dvr_port_binding(
                        session, id, host, router_id=device_id)
                network = self.get_network(context, orig_port['network_id'])
                levels = db.get_binding_levels(session, id, host)
                mech_context = driver_context.PortContext(self,
                    context, orig_port, network,
                    binding, levels, original_port=orig_port)
                self._process_dvr_port_binding(mech_context, context, attrs)
            self._bind_port_if_needed(mech_context)

    def _pre_delete_port(self, context, port_id, port_check):
        """Do some preliminary operations before deleting the port."""
        LOG.debug("Deleting port %s", port_id)
        try:
            # notify interested parties of imminent port deletion;
            # a failure here prevents the operation from happening
            kwargs = {
                'context': context,
                'port_id': port_id,
                'port_check': port_check
            }
            registry.notify(
                resources.PORT, events.BEFORE_DELETE, self, **kwargs)
        except exceptions.CallbackFailure as e:
            # NOTE(armax): preserve old check's behavior
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise exc.ServicePortInUse(port_id=port_id, reason=e)

    @oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES,
                               retry_on_deadlock=True)
    def delete_port(self, context, id, l3_port_check=True):
        self._pre_delete_port(context, id, l3_port_check)
        # TODO(armax): get rid of the l3 dependency in the with block
        removed_routers = []
        router_ids = []
        l3plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        is_dvr_enabled = utils.is_extension_supported(
            l3plugin, const.L3_DISTRIBUTED_EXT_ALIAS)

        session = context.session
        with session.begin(subtransactions=True):
            port_db, binding = db.get_locked_port_and_binding(session, id)
            if not port_db:
                LOG.debug("The port '%s' was deleted", id)
                return
            port = self._make_port_dict(port_db)

            network = self.get_network(context, port['network_id'])
            bound_mech_contexts = []
            device_owner = port['device_owner']
            if device_owner == const.DEVICE_OWNER_DVR_INTERFACE:
                bindings = db.get_dvr_port_bindings(context.session, id)
                for bind in bindings:
                    levels = db.get_binding_levels(context.session, id,
                                                   bind.host)
                    mech_context = driver_context.PortContext(
                        self, context, port, network, bind, levels)
                    self.mechanism_manager.delete_port_precommit(mech_context)
                    bound_mech_contexts.append(mech_context)
            else:
                levels = db.get_binding_levels(context.session, id,
                                               binding.host)
                mech_context = driver_context.PortContext(
                    self, context, port, network, binding, levels)
                if is_dvr_enabled and utils.is_dvr_serviced(device_owner):
                    removed_routers = l3plugin.dvr_deletens_if_no_port(
                        context, id)
                self.mechanism_manager.delete_port_precommit(mech_context)
                bound_mech_contexts.append(mech_context)
            if l3plugin:
                router_ids = l3plugin.disassociate_floatingips(
                    context, id, do_notify=False)

            LOG.debug("Calling delete_port for %(port_id)s owned by %(owner)s",
                      {"port_id": id, "owner": device_owner})
            super(Ml2Plugin, self).delete_port(context, id)

        self._post_delete_port(
            context, port, router_ids, removed_routers, bound_mech_contexts)

    def _post_delete_port(
        self, context, port, router_ids, removed_routers, bound_mech_contexts):
        kwargs = {
            'context': context,
            'port': port,
            'router_ids': router_ids,
            'removed_routers': removed_routers
        }
        registry.notify(resources.PORT, events.AFTER_DELETE, self, **kwargs)
        try:
            # Note that DVR Interface ports will have bindings on
            # multiple hosts, and so will have multiple mech_contexts,
            # while other ports typically have just one.
            for mech_context in bound_mech_contexts:
                self.mechanism_manager.delete_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the port.  Ideally we'd notify the caller of the
            # fact that an error occurred.
            LOG.error(_LE("mechanism_manager.delete_port_postcommit failed for"
                          " port %s"), port['id'])
        self.notifier.port_delete(context, port['id'])
        self.notify_security_groups_member_updated(context, port)

    def get_bound_port_context(self, plugin_context, port_id, host=None,
                               cached_networks=None):
        session = plugin_context.session
        with session.begin(subtransactions=True):
            try:
                port_db = (session.query(models_v2.Port).
                           enable_eagerloads(False).
                           filter(models_v2.Port.id.startswith(port_id)).
                           one())
            except sa_exc.NoResultFound:
                LOG.debug("No ports have port_id starting with %s",
                          port_id)
                return
            except sa_exc.MultipleResultsFound:
                LOG.error(_LE("Multiple ports have port_id starting with %s"),
                          port_id)
                return
            port = self._make_port_dict(port_db)
            network = (cached_networks or {}).get(port['network_id'])

            if not network:
                network = self.get_network(plugin_context, port['network_id'])

            if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                binding = db.get_dvr_port_binding_by_host(
                    session, port['id'], host)
                if not binding:
                    LOG.error(_LE("Binding info for DVR port %s not found"),
                              port_id)
                    return None
                levels = db.get_binding_levels(session, port_db.id, host)
                port_context = driver_context.PortContext(
                    self, plugin_context, port, network, binding, levels)
            else:
                # since eager loads are disabled in port_db query
                # related attribute port_binding could disappear in
                # concurrent port deletion.
                # It's not an error condition.
                binding = port_db.port_binding
                if not binding:
                    LOG.info(_LI("Binding info for port %s was not found, "
                                 "it might have been deleted already."),
                             port_id)
                    return
                levels = db.get_binding_levels(session, port_db.id,
                                               port_db.port_binding.host)
                port_context = driver_context.PortContext(
                    self, plugin_context, port, network, binding, levels)

        return self._bind_port_if_needed(port_context)

    @oslo_db_api.wrap_db_retry(max_retries=db_api.MAX_RETRIES,
                               retry_on_deadlock=True,
                               retry_on_request=True)
    @db_api.convert_db_exception_to_retry(stale_data=True)
    def update_port_status(self, context, port_id, status, host=None,
                           network=None):
        """
        Returns port_id (non-truncated uuid) if the port exists.
        Otherwise returns None.
        network can be passed in to avoid another get_network call if
        one was already performed by the caller.
        """
        updated = False
        session = context.session
        with session.begin(subtransactions=True):
            port = db.get_port(session, port_id)
            if not port:
                LOG.debug("Port %(port)s update to %(val)s by agent not found",
                          {'port': port_id, 'val': status})
                return None
            if (port.status != status and
                port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE):
                original_port = self._make_port_dict(port)
                port.status = status
                updated_port = self._make_port_dict(port)
                network = network or self.get_network(
                    context, original_port['network_id'])
                levels = db.get_binding_levels(session, port.id,
                                               port.port_binding.host)
                mech_context = driver_context.PortContext(
                    self, context, updated_port, network, port.port_binding,
                    levels, original_port=original_port)
                self.mechanism_manager.update_port_precommit(mech_context)
                updated = True
            elif port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                binding = db.get_dvr_port_binding_by_host(
                    session, port['id'], host)
                if not binding:
                    return
                binding['status'] = status
                binding.update(binding)
                updated = True

        if (updated and
            port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE):
            with session.begin(subtransactions=True):
                port = db.get_port(session, port_id)
                if not port:
                    LOG.warning(_LW("Port %s not found during update"),
                                port_id)
                    return
                original_port = self._make_port_dict(port)
                network = network or self.get_network(
                    context, original_port['network_id'])
                port.status = db.generate_dvr_port_status(session, port['id'])
                updated_port = self._make_port_dict(port)
                levels = db.get_binding_levels(session, port_id, host)
                mech_context = (driver_context.PortContext(
                    self, context, updated_port, network,
                    binding, levels, original_port=original_port))
                self.mechanism_manager.update_port_precommit(mech_context)

        if updated:
            self.mechanism_manager.update_port_postcommit(mech_context)

        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            db.delete_dvr_port_binding_if_stale(session, binding)

        return port['id']

    def port_bound_to_host(self, context, port_id, host):
        port = db.get_port(context.session, port_id)
        if not port:
            LOG.debug("No Port match for: %s", port_id)
            return False
        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            bindings = db.get_dvr_port_bindings(context.session, port_id)
            for b in bindings:
                if b.host == host:
                    return True
            LOG.debug("No binding found for DVR port %s", port['id'])
            return False
        else:
            port_host = db.get_port_binding_host(context.session, port_id)
            return (port_host == host)

    def get_ports_from_devices(self, context, devices):
        port_ids_to_devices = dict(
            (self._device_to_port_id(context, device), device)
            for device in devices)
        port_ids = port_ids_to_devices.keys()
        ports = db.get_ports_and_sgs(context, port_ids)
        for port in ports:
            # map back to original requested id
            port_id = next((port_id for port_id in port_ids
                           if port['id'].startswith(port_id)), None)
            port['device'] = port_ids_to_devices.get(port_id)

        return ports

    @staticmethod
    def _device_to_port_id(context, device):
        # REVISIT(rkukura): Consider calling into MechanismDrivers to
        # process device names, or having MechanismDrivers supply list
        # of device prefixes to strip.
        for prefix in const.INTERFACE_PREFIXES:
            if device.startswith(prefix):
                return device[len(prefix):]
        # REVISIT(irenab): Consider calling into bound MD to
        # handle the get_device_details RPC
        if not uuidutils.is_uuid_like(device):
            port = db.get_port_from_device_mac(context, device)
            if port:
                return port.id
        return device
