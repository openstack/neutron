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
import netaddr
from netaddr.strategy import eui48
from neutron_lib.agent import constants as agent_consts
from neutron_lib.agent import topics
from neutron_lib.api.definitions import address_group as addrgrp_def
from neutron_lib.api.definitions import address_scope
from neutron_lib.api.definitions import agent as agent_apidef
from neutron_lib.api.definitions import agent_resources_synced
from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import availability_zone as az_def
from neutron_lib.api.definitions import availability_zone_filter
from neutron_lib.api.definitions import default_subnetpools
from neutron_lib.api.definitions import dhcpagentscheduler
from neutron_lib.api.definitions import empty_string_filtering
from neutron_lib.api.definitions import external_net
from neutron_lib.api.definitions import extra_dhcp_opt as edo_ext
from neutron_lib.api.definitions import filter_validation as filter_apidef
from neutron_lib.api.definitions import ip_allocation as ipalloc_apidef
from neutron_lib.api.definitions import ip_substring_port_filtering
from neutron_lib.api.definitions import multiprovidernet
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import network_availability_zone
from neutron_lib.api.definitions import network_mtu as mtu_apidef
from neutron_lib.api.definitions import network_mtu_writable as mtuw_apidef
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import port_mac_address_regenerate
from neutron_lib.api.definitions import port_security as psec
from neutron_lib.api.definitions import portbindings
from neutron_lib.api.definitions import portbindings_extended as pbe_ext
from neutron_lib.api.definitions import provider_net
from neutron_lib.api.definitions import rbac_address_scope
from neutron_lib.api.definitions import rbac_security_groups as rbac_sg_apidef
from neutron_lib.api.definitions import rbac_subnetpool
from neutron_lib.api.definitions import security_groups_port_filtering
from neutron_lib.api.definitions import stateful_security_group
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnet_onboard as subnet_onboard_def
from neutron_lib.api.definitions import subnetpool_prefix_ops \
    as subnetpool_prefix_ops_def
from neutron_lib.api.definitions import vlantransparent as vlan_apidef
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.api.validators import availability_zone as az_validator
from neutron_lib.callbacks import events
from neutron_lib.callbacks import exceptions
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as exc
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.exceptions import port_security as psec_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as p_utils
from neutron_lib import rpc as n_rpc
from neutron_lib.services.qos import constants as qos_consts
from oslo_config import cfg
from oslo_db import exception as os_db_exception
from oslo_log import helpers as log_helpers
from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import excutils
from oslo_utils import importutils
from oslo_utils import uuidutils
import sqlalchemy
from sqlalchemy import or_
from sqlalchemy.orm import exc as sa_exc

from neutron._i18n import _
from neutron.agent import rpc as agent_rpc
from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.api.rpc.handlers import dhcp_rpc
from neutron.api.rpc.handlers import dvr_rpc
from neutron.api.rpc.handlers import metadata_rpc
from neutron.api.rpc.handlers import resources_rpc
from neutron.api.rpc.handlers import securitygroups_rpc
from neutron.common import utils
from neutron.db import address_group_db
from neutron.db import address_scope_db
from neutron.db import agents_db
from neutron.db import agentschedulers_db
from neutron.db import allowedaddresspairs_db as addr_pair_db
from neutron.db import db_base_plugin_v2
from neutron.db import dvr_mac_db
from neutron.db import external_net_db
from neutron.db import extradhcpopt_db
from neutron.db.models import securitygroup as sg_models
from neutron.db import models_v2
from neutron.db import provisioning_blocks
from neutron.db.quota import driver  # noqa
from neutron.db import securitygroups_rpc_base as sg_db_rpc
from neutron.db import segments_db
from neutron.db import subnet_service_type_mixin
from neutron.db import vlantransparent_db
from neutron.extensions import filter_validation
from neutron.extensions import vlantransparent
from neutron.ipam import exceptions as ipam_exc
from neutron.objects import base as base_obj
from neutron.objects import ports as ports_obj
from neutron.plugins.ml2.common import exceptions as ml2_exc
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2.drivers import mech_agent
from neutron.plugins.ml2.extensions import qos as qos_ext
from neutron.plugins.ml2 import managers
from neutron.plugins.ml2 import models
from neutron.plugins.ml2 import ovo_rpc
from neutron.plugins.ml2 import rpc
from neutron.quota import resource_registry
from neutron.services.segments import plugin as segments_plugin

LOG = log.getLogger(__name__)

MAX_BIND_TRIES = 10


SERVICE_PLUGINS_REQUIRED_DRIVERS = {
    'qos': [qos_ext.QOS_EXT_DRIVER_ALIAS]
}


def _ml2_port_result_filter_hook(query, filters):
    values = filters and filters.get(portbindings.HOST_ID, [])
    if not values:
        return query
    bind_criteria = models.PortBinding.host.in_(values)
    return query.filter(models_v2.Port.port_bindings.any(bind_criteria))


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class Ml2Plugin(db_base_plugin_v2.NeutronDbPluginV2,
                dvr_mac_db.DVRDbMixin,
                external_net_db.External_net_db_mixin,
                sg_db_rpc.SecurityGroupServerRpcMixin,
                agentschedulers_db.AZDhcpAgentSchedulerDbMixin,
                addr_pair_db.AllowedAddressPairsMixin,
                vlantransparent_db.Vlantransparent_db_mixin,
                extradhcpopt_db.ExtraDhcpOptMixin,
                address_scope_db.AddressScopeDbMixin,
                subnet_service_type_mixin.SubnetServiceTypeMixin,
                address_group_db.AddressGroupDbMixin):

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
    # This attribute specifies whether the plugin supports or not
    # filter validations. Name mangling is used in
    # order to ensure it is qualified by class
    __filter_validation_support = True

    # List of supported extensions
    _supported_extension_aliases = [provider_net.ALIAS,
                                    external_net.ALIAS, portbindings.ALIAS,
                                    "quotas", "security-group",
                                    rbac_address_scope.ALIAS,
                                    rbac_sg_apidef.ALIAS,
                                    rbac_subnetpool.ALIAS,
                                    agent_apidef.ALIAS,
                                    dhcpagentscheduler.ALIAS,
                                    multiprovidernet.ALIAS,
                                    addr_apidef.ALIAS,
                                    edo_ext.ALIAS, "subnet_allocation",
                                    mtu_apidef.ALIAS,
                                    mtuw_apidef.ALIAS,
                                    vlan_apidef.ALIAS,
                                    address_scope.ALIAS,
                                    az_def.ALIAS,
                                    network_availability_zone.ALIAS,
                                    availability_zone_filter.ALIAS,
                                    default_subnetpools.ALIAS,
                                    "subnet-service-types",
                                    ip_substring_port_filtering.ALIAS,
                                    security_groups_port_filtering.ALIAS,
                                    empty_string_filtering.ALIAS,
                                    filter_apidef.ALIAS,
                                    port_mac_address_regenerate.ALIAS,
                                    pbe_ext.ALIAS,
                                    agent_resources_synced.ALIAS,
                                    subnet_onboard_def.ALIAS,
                                    subnetpool_prefix_ops_def.ALIAS,
                                    stateful_security_group.ALIAS,
                                    addrgrp_def.ALIAS]

    # List of agent types for which all binding_failed ports should try to be
    # rebound when agent revive
    _rebind_on_revive_agent_types = [const.AGENT_TYPE_OVS]

    @property
    def supported_extension_aliases(self):
        if not hasattr(self, '_aliases'):
            aliases = self._supported_extension_aliases[:]
            aliases += self.extension_manager.extension_aliases()
            sg_rpc.disable_security_group_extension_by_config(aliases)
            vlantransparent._disable_extension_by_config(aliases)
            filter_validation._disable_extension_by_config(aliases)
            self._aliases = aliases
        return self._aliases

    def __new__(cls, *args, **kwargs):
        model_query.register_hook(
            models_v2.Port,
            "ml2_port_bindings",
            query_hook=None,
            filter_hook=None,
            result_filters=_ml2_port_result_filter_hook)
        return super(Ml2Plugin, cls).__new__(cls, *args, **kwargs)

    @resource_registry.tracked_resources(
        network=models_v2.Network,
        port=models_v2.Port,
        subnet=models_v2.Subnet,
        subnetpool=models_v2.SubnetPool,
        security_group=sg_models.SecurityGroup,
        security_group_rule=sg_models.SecurityGroupRule)
    def __init__(self):
        # First load drivers, then initialize DB, then initialize drivers
        self.type_manager = managers.TypeManager()
        self.extension_manager = managers.ExtensionManager()
        self.mechanism_manager = managers.MechanismManager()
        super(Ml2Plugin, self).__init__()
        self.type_manager.initialize()
        self.extension_manager.initialize()
        self.mechanism_manager.initialize()
        self._setup_dhcp()
        self._start_rpc_notifiers()
        self.add_agent_status_check_worker(self.agent_health_check)
        self.add_workers(self.mechanism_manager.get_workers())
        self._verify_service_plugins_requirements()
        LOG.info("Modular L2 Plugin initialization complete")

    def _setup_rpc(self):
        """Initialize components to support agent communication."""
        self.endpoints = [
            rpc.RpcCallbacks(self.notifier, self.type_manager),
            securitygroups_rpc.SecurityGroupServerRpcCallback(),
            dvr_rpc.DVRServerRpcCallback(),
            dhcp_rpc.DhcpRpcCallback(),
            agents_db.AgentExtRpcCallback(),
            metadata_rpc.MetadataRpcCallback(),
            resources_rpc.ResourcesPullRpcCallback()
        ]

    def _setup_dhcp(self):
        """Initialize components to support DHCP."""
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.add_periodic_dhcp_agent_status_check()

    def _verify_service_plugins_requirements(self):
        for service_plugin in cfg.CONF.service_plugins:
            extension_drivers = SERVICE_PLUGINS_REQUIRED_DRIVERS.get(
                service_plugin, []
            )
            for extension_driver in extension_drivers:
                if extension_driver not in self.extension_manager.names():
                    raise ml2_exc.ExtensionDriverNotFound(
                        driver=extension_driver, service_plugin=service_plugin
                    )

    @registry.receives(resources.PORT,
                       [provisioning_blocks.PROVISIONING_COMPLETE])
    def _port_provisioned(self, rtype, event, trigger, payload=None):
        port_id = payload.resource_id
        port = db.get_port(payload.context, port_id)
        port_binding = p_utils.get_port_binding_by_status_and_host(
            getattr(port, 'port_bindings', []), const.ACTIVE)
        if not port or not port_binding:
            LOG.debug("Port %s was deleted so its status cannot be updated.",
                      port_id)
            return
        if port_binding.vif_type in (portbindings.VIF_TYPE_BINDING_FAILED,
                                     portbindings.VIF_TYPE_UNBOUND):
            # NOTE(kevinbenton): we hit here when a port is created without
            # a host ID and the dhcp agent notifies that its wiring is done
            LOG.debug("Port %s cannot update to ACTIVE because it "
                      "is not bound.", port_id)
            return
        else:
            # port is bound, but we have to check for new provisioning blocks
            # one last time to detect the case where we were triggered by an
            # unbound port and the port became bound with new provisioning
            # blocks before 'get_port' was called above
            if provisioning_blocks.is_object_blocked(payload.context, port_id,
                                                     resources.PORT):
                LOG.debug("Port %s had new provisioning blocks added so it "
                          "will not transition to active.", port_id)
                return
        if not port.admin_state_up:
            LOG.debug("Port %s is administratively disabled so it will "
                      "not transition to active.", port_id)
            return

        host_migrating = agent_rpc.migrating_to_host(
            getattr(port, 'port_bindings', []))
        if (host_migrating and cfg.CONF.nova.live_migration_events and
                self.nova_notifier):
            send_nova_event = bool(trigger ==
                                   provisioning_blocks.L2_AGENT_ENTITY)
            with self.nova_notifier.context_enabled(send_nova_event):
                self.update_port_status(payload.context, port_id,
                                        const.PORT_STATUS_ACTIVE)
        else:
            self.update_port_status(payload.context, port_id,
                                    const.PORT_STATUS_ACTIVE)

    @log_helpers.log_method_call
    def _start_rpc_notifiers(self):
        """Initialize RPC notifiers for agents."""
        self.ovo_notifier = ovo_rpc.OVOServerRpcInterface()
        self.notifier = rpc.AgentNotifierApi(topics.AGENT)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            dhcp_rpc_agent_api.DhcpAgentNotifyAPI()
        )

    @log_helpers.log_method_call
    def start_rpc_listeners(self):
        """Start the RPC loop to let the plugin communicate with agents."""
        self._setup_rpc()
        self.topic = topics.PLUGIN
        self.conn = n_rpc.Connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.create_consumer(
            topics.SERVER_RESOURCE_VERSIONS,
            [resources_rpc.ResourcesPushToServerRpcCallback()],
            fanout=True)
        # process state reports despite dedicated rpc workers
        self.conn.create_consumer(topics.REPORTS,
                                  [agents_db.AgentExtRpcCallback()],
                                  fanout=False)
        return self.conn.consume_in_threads()

    def start_rpc_state_reports_listener(self):
        self.conn_reports = n_rpc.Connection()
        self.conn_reports.create_consumer(topics.REPORTS,
                                          [agents_db.AgentExtRpcCallback()],
                                          fanout=False)
        return self.conn_reports.consume_in_threads()

    def _filter_nets_provider(self, context, networks, filters):
        return [network
                for network in networks
                if self.type_manager.network_matches_filters(network, filters)
                ]

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

    def _reset_mac_for_direct_physical(self, orig_port, port, binding):
        # when unbinding direct-physical port we need to free
        # physical device MAC address so that other ports may reuse it
        if (binding.vnic_type == portbindings.VNIC_DIRECT_PHYSICAL and
                port.get('device_id') == '' and
                port.get('device_owner') == '' and
                orig_port['device_id'] != ''):
            port['mac_address'] = self._generate_macs()[0]
            return True
        else:
            return False

    @registry.receives(resources.AGENT, [events.AFTER_UPDATE])
    def _retry_binding_revived_agents(self, resource, event, trigger,
                                      payload=None):
        context = payload.context
        host = payload.metadata.get('host')
        agent = payload.desired_state
        agent_status = agent.get('agent_status')

        agent_type = agent.get('agent_type')

        if (agent_status != agent_consts.AGENT_REVIVED or
                not agent.get('admin_state_up') or
                agent_type not in self._rebind_on_revive_agent_types):
            return

        ports = ports_obj.Port.get_ports_by_binding_type_and_host(
            context, portbindings.VIF_TYPE_BINDING_FAILED, host)
        for port in ports:
            binding = self._get_binding_for_host(port.bindings, host)
            if not binding:
                LOG.debug('No bindings found for port %(port_id)s '
                          'on host %(host)s',
                          {'port_id': port.id, 'host': host})
                continue
            port_dict = self._make_port_dict(port.db_obj)
            network = self.get_network(context, port.network_id)
            try:
                levels = db.get_binding_level_objs(
                    context, port.id, binding.host)
                # TODO(slaweq): use binding OVO instead of binding.db_obj when
                # ML2 plugin will switch to use Port Binding OVO everywhere
                mech_context = driver_context.PortContext(
                    self, context, port_dict, network, binding.db_obj, levels)
                self._bind_port_if_needed(mech_context)
            except Exception as e:
                LOG.warning('Attempt to bind port %(port_id)s after agent '
                            '%(agent_type)s on host %(host)s revived failed. '
                            'Error: %(error)s',
                            {'port_id': port.id,
                             'agent_type': agent_type,
                             'host': host,
                             'error': e})

    def _clear_port_binding(self, mech_context, binding, port, original_host):
        binding.vif_type = portbindings.VIF_TYPE_UNBOUND
        binding.vif_details = ''
        db.clear_binding_levels(mech_context._plugin_context, port['id'],
                                original_host)
        mech_context._clear_binding_levels()

    def _process_port_binding_attributes(self, binding, attrs):
        changes = False
        host = const.ATTR_NOT_SPECIFIED
        if attrs and portbindings.HOST_ID in attrs:
            host = attrs.get(portbindings.HOST_ID) or ''

        original_host = binding.host
        if validators.is_attr_set(host) and original_host != host:
            binding.host = host
            changes = True

        vnic_type = attrs.get(portbindings.VNIC_TYPE) if attrs else None
        if (validators.is_attr_set(vnic_type) and
                binding.vnic_type != vnic_type):
            binding.vnic_type = vnic_type
            changes = True

        # treat None as clear of profile.
        profile = None
        if attrs and portbindings.PROFILE in attrs:
            profile = attrs.get(portbindings.PROFILE) or {}

        if profile not in (None, const.ATTR_NOT_SPECIFIED,
                           self._get_profile(binding)):
            binding.profile = jsonutils.dumps(profile)
            if len(binding.profile) > models.BINDING_PROFILE_LEN:
                msg = _("binding:profile value too large")
                raise exc.InvalidInput(error_message=msg)
            changes = True
        return changes, original_host

    def _process_port_binding(self, mech_context, attrs):
        plugin_context = mech_context._plugin_context
        binding = mech_context._binding
        port = mech_context.current
        changes, original_host = self._process_port_binding_attributes(binding,
                                                                       attrs)

        # Unbind the port if needed.
        if changes:
            self._clear_port_binding(mech_context, binding, port,
                                     original_host)
            port['status'] = const.PORT_STATUS_DOWN
            super(Ml2Plugin, self).update_port(
                mech_context._plugin_context, port['id'],
                {port_def.RESOURCE_NAME:
                    {'status': const.PORT_STATUS_DOWN}})

        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            self._clear_port_binding(mech_context, binding, port,
                                     original_host)
            binding.host = ''

        self._update_port_dict_binding(port, binding)
        binding.persist_state_to_session(plugin_context.session)
        return changes

    @db_api.retry_db_errors
    def _bind_port_if_needed(self, context, allow_notify=False,
                             need_notify=False, allow_commit=True):
        if not context.network.network_segments:
            LOG.debug("Network %s has no segments, skipping binding",
                      context.network.current['id'])
            return context
        for count in range(1, MAX_BIND_TRIES + 1):
            if count > 1:
                # yield for binding retries so that we give other threads a
                # chance to do their work
                greenthread.sleep(0)

                # multiple attempts shouldn't happen very often so we log each
                # attempt after the 1st.
                LOG.info("Attempt %(count)s to bind port %(port)s",
                         {'count': count, 'port': context.current['id']})

            bind_context, need_notify, try_again = self._attempt_binding(
                context, need_notify)

            if count == MAX_BIND_TRIES or not try_again:
                if self._should_bind_port(context) and allow_commit:
                    # At this point, we attempted to bind a port and reached
                    # its final binding state. Binding either succeeded or
                    # exhausted all attempts, thus no need to try again.
                    # Now, the port and its binding state should be committed.
                    context, need_notify, try_again = (
                        self._commit_port_binding(context, bind_context,
                                                  need_notify))
                else:
                    context = bind_context

            if not try_again:
                if allow_notify and need_notify:
                    self._notify_port_updated(context)
                return context

        LOG.error("Failed to commit binding results for %(port)s "
                  "after %(max)s tries",
                  {'port': context.current['id'], 'max': MAX_BIND_TRIES})
        return context

    def _should_bind_port(self, context):
        return (context._binding.host and context._binding.vif_type
                in (portbindings.VIF_TYPE_UNBOUND,
                    portbindings.VIF_TYPE_BINDING_FAILED))

    def _attempt_binding(self, context, need_notify):
        try_again = False

        if self._should_bind_port(context):
            bind_context = self._bind_port(context)

            if bind_context.vif_type != portbindings.VIF_TYPE_BINDING_FAILED:
                # Binding succeeded. Suggest notifying of successful binding.
                need_notify = True
            else:
                # Current attempt binding failed, try to bind again.
                try_again = True
            context = bind_context

        return context, need_notify, try_again

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
            orig_context.network.current, new_binding, None,
            original_port=orig_context.original)

        # Attempt to bind the port and return the context with the
        # result.
        self.mechanism_manager.bind_port(new_context)
        return new_context

    def _commit_port_binding(self, orig_context, bind_context,
                             need_notify, update_binding_levels=True):
        port_id = orig_context.current['id']
        plugin_context = orig_context._plugin_context
        orig_binding = orig_context._binding
        new_binding = bind_context._binding

        # TODO(yamahata): revise what to be passed or new resource
        # like PORTBINDING should be introduced?
        # It would be addressed during EventPayload conversion.
        registry.notify(resources.PORT, events.BEFORE_UPDATE, self,
                        context=plugin_context, port=orig_context.current,
                        original_port=orig_context.current,
                        orig_binding=orig_binding, new_binding=new_binding)

        # After we've attempted to bind the port, we begin a
        # transaction, get the current port state, and decide whether
        # to commit the binding results.
        with db_api.CONTEXT_WRITER.using(plugin_context):
            # Get the current port state and build a new PortContext
            # reflecting this state as original state for subsequent
            # mechanism driver update_port_*commit() calls.
            try:
                port_db = self._get_port(plugin_context, port_id)
                cur_binding = p_utils.get_port_binding_by_status_and_host(
                    port_db.port_bindings, const.ACTIVE)
            except exc.PortNotFound:
                port_db, cur_binding = None, None
            if not port_db or not cur_binding:
                # The port has been deleted concurrently, so just
                # return the unbound result from the initial
                # transaction that completed before the deletion.
                LOG.debug("Port %s has been deleted concurrently", port_id)
                return orig_context, False, False
            # Since the mechanism driver bind_port() calls must be made
            # outside a DB transaction locking the port state, it is
            # possible (but unlikely) that the port's state could change
            # concurrently while these calls are being made. If another
            # thread or process succeeds in binding the port before this
            # thread commits its results, the already committed results are
            # used. If attributes such as binding:host_id, binding:profile,
            # or binding:vnic_type are updated concurrently, the try_again
            # flag is returned to indicate that the commit was unsuccessful.
            oport = self._make_port_dict(port_db)
            port = self._make_port_dict(port_db)
            network = bind_context.network.current
            if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                # REVISIT(rkukura): The PortBinding instance from the
                # ml2_port_bindings table, returned as cur_binding
                # from port_db.port_binding above, is
                # currently not used for DVR distributed ports, and is
                # replaced here with the DistributedPortBinding instance from
                # the ml2_distributed_port_bindings table specific to the host
                # on which the distributed port is being bound. It
                # would be possible to optimize this code to avoid
                # fetching the PortBinding instance in the DVR case,
                # and even to avoid creating the unused entry in the
                # ml2_port_bindings table. But the upcoming resolution
                # for bug 1367391 will eliminate the
                # ml2_distributed_port_bindings table, use the
                # ml2_port_bindings table to store non-host-specific
                # fields for both distributed and non-distributed
                # ports, and introduce a new ml2_port_binding_hosts
                # table for the fields that need to be host-specific
                # in the distributed case. Since the PortBinding
                # instance will then be needed, it does not make sense
                # to optimize this code to avoid fetching it.
                cur_binding = db.get_distributed_port_binding_by_host(
                    plugin_context, port_id, orig_binding.host)
            cur_context_binding = cur_binding
            if new_binding.status == const.INACTIVE:
                cur_context_binding = (
                    p_utils.get_port_binding_by_status_and_host(
                        port_db.port_bindings, const.INACTIVE,
                        host=new_binding.host))
            cur_context = driver_context.PortContext(
                self, plugin_context, port, network, cur_context_binding, None,
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
                if new_binding.status == const.INACTIVE:
                    cur_context_binding.status = const.ACTIVE
                    cur_binding.status = const.INACTIVE
                else:
                    cur_context_binding.vif_type = new_binding.vif_type
                    cur_context_binding.vif_details = new_binding.vif_details
                if update_binding_levels:
                    db.clear_binding_levels(plugin_context, port_id,
                                            cur_binding.host)
                    db.set_binding_levels(plugin_context,
                                          bind_context._binding_levels)
                # refresh context with a snapshot of updated state
                cur_context._binding = driver_context.InstanceSnapshot(
                    cur_context_binding)
                cur_context._binding_levels = bind_context._binding_levels

                # Update PortContext's port dictionary to reflect the
                # updated binding state.
                self._update_port_dict_binding(port, cur_context_binding)

                # Update the port status if requested by the bound driver.
                if (bind_context._binding_levels and
                        bind_context._new_port_status):
                    port_db.status = bind_context._new_port_status
                    port['status'] = bind_context._new_port_status

                # Call the mechanism driver precommit methods, commit
                # the results, and call the postcommit methods.
                self.mechanism_manager.update_port_precommit(cur_context)
            else:
                # Try to populate the PortContext with the current binding
                # levels so that the RPC notification won't get suppressed.
                # This is to avoid leaving ports stuck in a DOWN state.
                # For more information see bug:
                # https://bugs.launchpad.net/neutron/+bug/1755810
                LOG.warning("Concurrent port binding operations failed on "
                            "port %s", port_id)
                levels = db.get_binding_level_objs(plugin_context, port_id,
                                                   cur_binding.host)
                for level in levels:
                    cur_context._push_binding_level(level)
                # refresh context with a snapshot of the current binding state
                cur_context._binding = driver_context.InstanceSnapshot(
                    cur_binding)

        if commit:
            # Continue, using the port state as of the transaction that
            # just finished, whether that transaction committed new
            # results or discovered concurrent port state changes.
            # Also, Trigger notification for successful binding commit.
            kwargs = {
                'context': plugin_context,
                'port': self._make_port_dict(port_db),  # ensure latest state
                'mac_address_updated': False,
                'original_port': oport,
            }
            registry.notify(resources.PORT, events.AFTER_UPDATE,
                            self, **kwargs)
            self.mechanism_manager.update_port_postcommit(cur_context)
            need_notify = True
            try_again = False
        else:
            try_again = True

        return cur_context, need_notify, try_again

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
                LOG.error("Serialized vif_details DB value '%(value)s' "
                          "for port %(port)s is invalid",
                          {'value': binding.vif_details,
                           'port': binding.port_id})
        return {}

    def _get_profile(self, binding):
        if binding.profile:
            try:
                return jsonutils.loads(binding.profile)
            except Exception:
                LOG.error("Serialized profile DB value '%(value)s' for "
                          "port %(port)s is invalid",
                          {'value': binding.profile,
                           'port': binding.port_id})
        return {}

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _ml2_extend_port_dict_binding(port_res, port_db):
        plugin = directory.get_plugin()
        if isinstance(port_db, ports_obj.Port):
            bindings = port_db.bindings
        else:
            bindings = port_db.port_bindings
        port_binding = p_utils.get_port_binding_by_status_and_host(
            bindings, const.ACTIVE)
        # None when called during unit tests for other plugins.
        if port_binding:
            plugin._update_port_dict_binding(port_res, port_binding)

    # ML2's resource extend functions allow extension drivers that extend
    # attributes for the resources to add those attributes to the result.

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _ml2_md_extend_network_dict(result, netdb):
        plugin = directory.get_plugin()
        session = plugin._object_session_or_new_session(netdb)
        plugin.extension_manager.extend_network_dict(session, netdb, result)

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _ml2_md_extend_port_dict(result, portdb):
        plugin = directory.get_plugin()
        session = plugin._object_session_or_new_session(portdb)
        plugin.extension_manager.extend_port_dict(session, portdb, result)

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _ml2_md_extend_subnet_dict(result, subnetdb):
        plugin = directory.get_plugin()
        session = plugin._object_session_or_new_session(subnetdb)
        plugin.extension_manager.extend_subnet_dict(session, subnetdb, result)

    @staticmethod
    def _object_session_or_new_session(sql_obj):
        session = sqlalchemy.inspect(sql_obj).session
        if not session:
            session = db_api.get_reader_session()
        return session

    def _notify_port_updated(self, mech_context):
        port = mech_context.current
        segment = mech_context.bottom_bound_segment
        if not segment:
            # REVISIT(rkukura): This should notify agent to unplug port
            network = mech_context.network.current
            LOG.debug("In _notify_port_updated(), no bound segment for "
                      "port %(port_id)s on network %(network_id)s",
                      {'port_id': port['id'], 'network_id': network['id']})
            return
        self.notifier.port_update(mech_context._plugin_context, port,
                                  segment[api.NETWORK_TYPE],
                                  segment[api.SEGMENTATION_ID],
                                  segment[api.PHYSICAL_NETWORK])

    def _update_segmentation_id(self, context, network, net_data):
        """Update segmentation ID in a single provider network"""
        segments = segments_db.get_networks_segments(
            context, [network['id']])[network['id']]
        if len(segments) > 1:
            msg = _('Provider network attributes can be updated only in '
                    'provider networks with a single segment.')
            raise exc.InvalidInput(error_message=msg)

        vif_types = [portbindings.VIF_TYPE_UNBOUND,
                     portbindings.VIF_TYPE_BINDING_FAILED]
        for mech_driver in self.mechanism_manager.ordered_mech_drivers:
            if (isinstance(mech_driver.obj,
                           mech_agent.AgentMechanismDriverBase) and
                    provider_net.SEGMENTATION_ID in mech_driver.obj.
                    provider_network_attribute_updates_supported()):
                agent_type = mech_driver.obj.agent_type
                agents = self.get_agents(
                    context, filters={'agent_type': [agent_type]})
                for agent in agents:
                    vif_types.append(
                        mech_driver.obj.get_supported_vif_type(agent))

        if ports_obj.Port.check_network_ports_by_binding_types(
                context, network['id'], vif_types, negative_search=True):
            msg = (_('Provider network attribute %(attr)s cannot be updated '
                     'if any port in the network has not the following '
                     '%(vif_field)s: %(vif_types)s') %
                   {'attr': provider_net.SEGMENTATION_ID,
                    'vif_field': portbindings.VIF_TYPE,
                    'vif_types': ', '.join(vif_types)})
            raise exc.InvalidInput(error_message=msg)

        self.type_manager.update_network_segment(context, network,
                                                 net_data, segments[0])

    def _update_provider_network_attributes(self, context, network, net_data):
        """Raise exception if provider network attrs update are not supported.

        This function will raise an exception if the provider network attribute
        update is not supported.
        """
        provider_net_attrs = (set(provider_net.ATTRIBUTES) -
                              {provider_net.SEGMENTATION_ID})
        requested_provider_net_attrs = set(net_data) & provider_net_attrs
        for attr in requested_provider_net_attrs:
            if (validators.is_attr_set(net_data.get(attr)) and
                    net_data.get(attr) != network[attr]):
                msg = (_('Plugin does not support updating the following '
                         'provider network attributes: %s') %
                       ', '.join(provider_net_attrs))
                raise exc.InvalidInput(error_message=msg)

        if net_data.get(provider_net.SEGMENTATION_ID):
            self._update_segmentation_id(context, network, net_data)

    def _delete_objects(self, context, resource, objects):
        delete_op = getattr(self, 'delete_%s' % resource)
        for obj in objects:
            try:
                delete_op(context, obj['result']['id'])
            except KeyError:
                LOG.exception("Could not find %s to delete.",
                              resource)
            except Exception:
                LOG.exception("Could not delete %(res)s %(id)s.",
                              {'res': resource,
                               'id': obj['result']['id']})

    def _create_bulk_ml2(self, resource, context, request_items):
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        obj_before_create = getattr(self, '_before_create_%s' % resource)
        for item in items:
            obj_before_create(context, item)
        with db_api.CONTEXT_WRITER.using(context):
            obj_creator = getattr(self, '_create_%s_db' % resource)
            for item in items:
                try:
                    attrs = item[resource]
                    result, mech_context = obj_creator(context, item)
                    objects.append({'mech_context': mech_context,
                                    'result': result,
                                    'attributes': attrs})

                except Exception as e:
                    with excutils.save_and_reraise_exception():
                        utils.attach_exc_details(
                            e, ("An exception occurred while creating "
                                "the %(resource)s:%(item)s"),
                            {'resource': resource, 'item': item})

        postcommit_op = getattr(self, '_after_create_%s' % resource)
        for obj in objects:
            try:
                postcommit_op(context, obj['result'], obj['mech_context'])
            except Exception:
                with excutils.save_and_reraise_exception():
                    resource_ids = [res['result']['id'] for res in objects]
                    LOG.exception("ML2 _after_create_%(res)s "
                                  "failed for %(res)s: "
                                  "'%(failed_id)s'. Deleting "
                                  "%(res)ss %(resource_ids)s",
                                  {'res': resource,
                                   'failed_id': obj['result']['id'],
                                   'resource_ids': ', '.join(resource_ids)})
                    # _after_handler will have deleted the object that threw
                    to_delete = [o for o in objects if o != obj]
                    self._delete_objects(context, resource, to_delete)
        return objects

    def _get_network_mtu(self, network_db, validate=True):
        mtus = []
        try:
            segments = network_db['segments']
        except KeyError:
            segments = [network_db]
        for s in segments:
            segment_type = s.get('network_type')
            if segment_type is None:
                continue
            try:
                type_driver = self.type_manager.drivers[segment_type].obj
            except KeyError:
                # NOTE(ihrachys) This can happen when type driver is not loaded
                # for an existing segment, or simply when the network has no
                # segments at the specific time this is computed.
                # In the former case, while it's probably an indication of
                # a bad setup, it's better to be safe than sorry here. Also,
                # several unit tests use non-existent driver types that may
                # trigger the exception here.
                if segment_type and s['segmentation_id']:
                    LOG.warning(
                        "Failed to determine MTU for segment "
                        "%(segment_type)s:%(segment_id)s; network "
                        "%(network_id)s MTU calculation may be not "
                        "accurate",
                        {
                            'segment_type': segment_type,
                            'segment_id': s['segmentation_id'],
                            'network_id': network_db['id'],
                        }
                    )
            else:
                mtu = type_driver.get_mtu(s['physical_network'])
                # Some drivers, like 'local', may return None; the assumption
                # then is that for the segment type, MTU has no meaning or
                # unlimited, and so we should then ignore those values.
                if mtu:
                    mtus.append(mtu)

        max_mtu = min(mtus) if mtus else p_utils.get_deployment_physnet_mtu()
        net_mtu = network_db.get('mtu')

        if validate:
            # validate that requested mtu conforms to allocated segments
            if net_mtu and max_mtu and max_mtu < net_mtu:
                msg = _("Requested MTU is too big, maximum is %d") % max_mtu
                raise exc.InvalidInput(error_message=msg)

        # if mtu is not set in database, use the maximum possible
        return net_mtu or max_mtu

    def _before_create_network(self, context, network):
        net_data = network[net_def.RESOURCE_NAME]
        registry.notify(resources.NETWORK, events.BEFORE_CREATE, self,
                        context=context, network=net_data)

    def _create_network_db(self, context, network):
        net_data = network[net_def.RESOURCE_NAME]
        tenant_id = net_data['tenant_id']
        with db_api.CONTEXT_WRITER.using(context):
            net_db = self.create_network_db(context, network)
            net_data['id'] = net_db.id
            self.type_manager.create_network_segments(context, net_data,
                                                      tenant_id)
            net_db.mtu = self._get_network_mtu(net_db)

            result = self._make_network_dict(net_db, process_extensions=False,
                                             context=context)

            self.extension_manager.process_create_network(
                context,
                # NOTE(ihrachys) extensions expect no id in the dict
                {k: v for k, v in net_data.items() if k != 'id'},
                result)

            self._process_l3_create(context, result, net_data)
            self.type_manager.extend_network_dict_provider(context, result)

            # Update the transparent vlan if configured
            if extensions.is_extension_supported(self, 'vlan-transparent'):
                vlt = vlan_apidef.get_vlan_transparent(net_data)
                net_db['vlan_transparent'] = vlt
                result['vlan_transparent'] = vlt

            if az_def.AZ_HINTS in net_data:
                self.validate_availability_zones(context, 'network',
                                                 net_data[az_def.AZ_HINTS])
                az_hints = az_validator.convert_az_list_to_string(
                                                net_data[az_def.AZ_HINTS])
                net_db[az_def.AZ_HINTS] = az_hints
                result[az_def.AZ_HINTS] = az_hints
            registry.notify(resources.NETWORK, events.PRECOMMIT_CREATE, self,
                            context=context, request=net_data, network=result)

            resource_extend.apply_funcs('networks', result, net_db)
            mech_context = driver_context.NetworkContext(self, context,
                                                         result)
            self.mechanism_manager.create_network_precommit(mech_context)
        return result, mech_context

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_network(self, context, network):
        self._before_create_network(context, network)
        result, mech_context = self._create_network_db(context, network)
        return self._after_create_network(context, result, mech_context)

    def _after_create_network(self, context, result, mech_context):
        kwargs = {'context': context, 'network': result}
        registry.notify(resources.NETWORK, events.AFTER_CREATE, self, **kwargs)
        try:
            self.mechanism_manager.create_network_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("mechanism_manager.create_network_postcommit "
                          "failed, deleting network '%s'", result['id'])
                self.delete_network(context, result['id'])

        return result

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_network_bulk(self, context, networks):
        objects = self._create_bulk_ml2(
            net_def.RESOURCE_NAME, context, networks)
        return [obj['result'] for obj in objects]

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def update_network(self, context, id, network):
        net_data = network[net_def.RESOURCE_NAME]
        need_network_update_notify = False

        with db_api.CONTEXT_WRITER.using(context):
            db_network = self._get_network(context, id)
            original_network = self.get_network(context, id, net_db=db_network)
            self._update_provider_network_attributes(
                context, original_network, net_data)

            updated_network = super(Ml2Plugin, self).update_network(
                context, id, network, db_network=db_network)
            self.extension_manager.process_update_network(context, net_data,
                                                          updated_network)
            self._process_l3_update(context, updated_network, net_data)

            if mtuw_apidef.MTU in net_data:
                db_network.mtu = self._get_network_mtu(db_network)
                # agents should now update all ports to reflect new MTU
                need_network_update_notify = True

            updated_network = self._make_network_dict(
                db_network, context=context)
            self.type_manager.extend_network_dict_provider(
                context, updated_network)

            registry.publish(resources.NETWORK, events.PRECOMMIT_UPDATE, self,
                             payload=events.DBEventPayload(
                                 context, request_body=net_data,
                                 states=(original_network,),
                                 resource_id=id,
                                 desired_state=updated_network))

            # TODO(QoS): Move out to the extension framework somehow.
            need_network_update_notify |= (
                qos_consts.QOS_POLICY_ID in net_data and
                original_network[qos_consts.QOS_POLICY_ID] !=
                updated_network[qos_consts.QOS_POLICY_ID])

            mech_context = driver_context.NetworkContext(
                self, context, updated_network,
                original_network=original_network)
            self.mechanism_manager.update_network_precommit(mech_context)

        # TODO(apech) - handle errors raised by update_network, potentially
        # by re-calling update_network with the previous attributes. For
        # now the error is propagated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        kwargs = {'context': context, 'network': updated_network,
                  'original_network': original_network}
        registry.notify(resources.NETWORK, events.AFTER_UPDATE, self, **kwargs)
        self.mechanism_manager.update_network_postcommit(mech_context)
        if need_network_update_notify:
            self.notifier.network_update(context, updated_network)
        return updated_network

    @db_api.retry_if_session_inactive()
    def get_network(self, context, id, fields=None, net_db=None):
        with db_api.CONTEXT_READER.using(context):
            net_db = net_db or self._get_network(context, id)
            net_data = self._make_network_dict(net_db, context=context)
            self.type_manager.extend_network_dict_provider(context, net_data)

        return db_utils.resource_fields(net_data, fields)

    @db_api.retry_if_session_inactive()
    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        with db_api.CONTEXT_READER.using(context):
            nets_db = super(Ml2Plugin, self)._get_networks(
                context, filters, None, sorts, limit, marker, page_reverse)

            net_data = []
            for net in nets_db:
                net_data.append(self._make_network_dict(net, context=context))

            self.type_manager.extend_networks_dict_provider(context, net_data)
            nets = self._filter_nets_provider(context, net_data, filters)
        return [db_utils.resource_fields(net, fields) for net in nets]

    def get_network_contexts(self, context, network_ids):
        """Return a map of network_id to NetworkContext for network_ids."""
        net_filters = {'id': list(set(network_ids))}
        nets_by_netid = {
            n['id']: n for n in self.get_networks(context,
                                                  filters=net_filters)
        }
        segments_by_netid = segments_db.get_networks_segments(
            context, list(nets_by_netid.keys()))
        netctxs_by_netid = {
            net_id: driver_context.NetworkContext(
                self, context, nets_by_netid[net_id],
                segments=segments_by_netid[net_id])
            for net_id in nets_by_netid.keys()
        }
        return netctxs_by_netid

    @utils.transaction_guard
    def delete_network(self, context, id):
        # the only purpose of this override is to protect this from being
        # called inside of a transaction.
        return super(Ml2Plugin, self).delete_network(context, id)

    # NOTE(mgoddard): Use a priority of zero to ensure this handler runs before
    # other precommit handlers. This is necessary to ensure we avoid another
    # handler deleting a subresource of the network, e.g. segments.
    @registry.receives(resources.NETWORK, [events.PRECOMMIT_DELETE],
                       priority=0)
    def _network_delete_precommit_handler(self, rtype, event, trigger,
                                          context, network_id, **kwargs):
        network = (kwargs.get('network') or
                   self.get_network(context, network_id))
        mech_context = driver_context.NetworkContext(self,
                                                     context,
                                                     network)
        # TODO(kevinbenton): move this mech context into something like
        # a 'delete context' so it's not polluting the real context object
        setattr(context, '_mech_context', mech_context)
        self.mechanism_manager.delete_network_precommit(
            mech_context)

    @registry.receives(resources.NETWORK, [events.AFTER_DELETE])
    def _network_delete_after_delete_handler(self, rtype, event, trigger,
                                             context, network, **kwargs):
        try:
            self.mechanism_manager.delete_network_postcommit(
                context._mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the network.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error("mechanism_manager.delete_network_postcommit"
                      " failed")
        self.notifier.network_delete(context, network['id'])

    def _before_create_subnet(self, context, subnet):
        subnet_data = subnet[subnet_def.RESOURCE_NAME]
        registry.notify(resources.SUBNET, events.BEFORE_CREATE, self,
                        context=context, subnet=subnet_data)

    def _create_subnet_db(self, context, subnet):
        with db_api.CONTEXT_WRITER.using(context):
            result, net_db, ipam_sub = self._create_subnet_precommit(
                context, subnet)

            self.extension_manager.process_create_subnet(
                context, subnet[subnet_def.RESOURCE_NAME], result)
            network = self._make_network_dict(net_db, context=context)
            self.type_manager.extend_network_dict_provider(context, network)
            mech_context = driver_context.SubnetContext(self, context,
                                                        result, network)
            self.mechanism_manager.create_subnet_precommit(mech_context)

        return result, mech_context

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_subnet(self, context, subnet):
        self._before_create_subnet(context, subnet)
        result, mech_context = self._create_subnet_db(context, subnet)
        return self._after_create_subnet(context, result, mech_context)

    def _after_create_subnet(self, context, result, mech_context):
        # db base plugin post commit ops
        self._create_subnet_postcommit(context, result,
            network=mech_context.network.current)

        # add network to subnet dict to save a DB call on dhcp notification
        result['network'] = mech_context.network.current
        kwargs = {'context': context, 'subnet': result}
        registry.notify(resources.SUBNET, events.AFTER_CREATE, self, **kwargs)
        try:
            self.mechanism_manager.create_subnet_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("mechanism_manager.create_subnet_postcommit "
                          "failed, deleting subnet '%s'", result['id'])
                self.delete_subnet(context, result['id'])
        return result

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_subnet_bulk(self, context, subnets):
        objects = self._create_bulk_ml2(
            subnet_def.RESOURCE_NAME, context, subnets)
        return [obj['result'] for obj in objects]

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def update_subnet(self, context, id, subnet):
        with db_api.CONTEXT_WRITER.using(context):
            updated_subnet, original_subnet = self._update_subnet_precommit(
                context, id, subnet)
            self.extension_manager.process_update_subnet(
                context, subnet[subnet_def.RESOURCE_NAME], updated_subnet)
            updated_subnet = self.get_subnet(context, id)
            mech_context = driver_context.SubnetContext(
                self, context, updated_subnet, network=None,
                original_subnet=original_subnet)
            self.mechanism_manager.update_subnet_precommit(mech_context)

        self._update_subnet_postcommit(context, original_subnet,
                                       updated_subnet)
        # TODO(apech) - handle errors raised by update_subnet, potentially
        # by re-calling update_subnet with the previous attributes. For
        # now the error is propagated to the caller, which is expected to
        # either undo/retry the operation or delete the resource.
        self.mechanism_manager.update_subnet_postcommit(mech_context)
        return updated_subnet

    @utils.transaction_guard
    def delete_subnet(self, context, id):
        # the only purpose of this override is to protect this from being
        # called inside of a transaction.
        return super(Ml2Plugin, self).delete_subnet(context, id)

    # NOTE(mgoddard): Use a priority of zero to ensure this handler runs before
    # other precommit handlers. This is necessary to ensure we avoid another
    # handler deleting a subresource of the subnet.
    @registry.receives(resources.SUBNET, [events.PRECOMMIT_DELETE], priority=0)
    def _subnet_delete_precommit_handler(self, rtype, event, trigger,
                                         context, subnet_id, **kwargs):
        subnet_obj = (kwargs.get('subnet_obj') or
                      self._get_subnet_object(context, subnet_id))
        subnet = self._make_subnet_dict(subnet_obj, context=context)
        mech_context = driver_context.SubnetContext(self, context,
                                                    subnet, network=None)
        # TODO(kevinbenton): move this mech context into something like
        # a 'delete context' so it's not polluting the real context object
        setattr(context, '_mech_context', mech_context)
        self.mechanism_manager.delete_subnet_precommit(mech_context)

    @registry.receives(resources.SUBNET, [events.AFTER_DELETE])
    def _subnet_delete_after_delete_handler(self, rtype, event, trigger,
                                            context, subnet, **kwargs):
        try:
            self.mechanism_manager.delete_subnet_postcommit(
                context._mech_context)
        except ml2_exc.MechanismDriverError:
            # TODO(apech) - One or more mechanism driver failed to
            # delete the subnet.  Ideally we'd notify the caller of
            # the fact that an error occurred.
            LOG.error("mechanism_manager.delete_subnet_postcommit failed")

    # TODO(yalei) - will be simplified after security group and address pair be
    # converted to ext driver too.
    def _portsec_ext_port_create_processing(self, context, port_data, port):
        attrs = port[port_def.RESOURCE_NAME]
        port_security = ((port_data.get(psec.PORTSECURITY) is None) or
                         port_data[psec.PORTSECURITY])

        # allowed address pair checks
        if self._check_update_has_allowed_address_pairs(port):
            if not port_security:
                raise addr_exc.AddressPairAndPortSecurityRequired()
        else:
            # remove ATTR_NOT_SPECIFIED
            attrs[addr_apidef.ADDRESS_PAIRS] = []

        if port_security:
            self._ensure_default_security_group_on_port(context, port)
        elif self._check_update_has_security_groups(port):
            raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()

    def _setup_dhcp_agent_provisioning_component(self, context, port):
        subnet_ids = [f['subnet_id'] for f in port['fixed_ips']]
        if (db.is_dhcp_active_on_any_subnet(context, subnet_ids) and
            len(self.get_dhcp_agents_hosting_networks(context,
                                                      [port['network_id']]))):
            # the agents will tell us when the dhcp config is ready so we setup
            # a provisioning component to prevent the port from going ACTIVE
            # until a dhcp_ready_on_port notification is received.
            provisioning_blocks.add_provisioning_component(
                context, port['id'], resources.PORT,
                provisioning_blocks.DHCP_ENTITY)
        else:
            provisioning_blocks.remove_provisioning_component(
                context, port['id'], resources.PORT,
                provisioning_blocks.DHCP_ENTITY)

    def _before_create_port(self, context, port):
        attrs = port[port_def.RESOURCE_NAME]
        if not attrs.get('status'):
            attrs['status'] = const.PORT_STATUS_DOWN

        registry.notify(resources.PORT, events.BEFORE_CREATE, self,
                        context=context, port=attrs)

    def _create_port_db(self, context, port):
        attrs = port[port_def.RESOURCE_NAME]
        with db_api.CONTEXT_WRITER.using(context):
            dhcp_opts = attrs.get(edo_ext.EXTRADHCPOPTS, [])
            port_db = self.create_port_db(context, port)
            result = self._make_port_dict(port_db, process_extensions=False)
            self.extension_manager.process_create_port(context, attrs, result)
            self._portsec_ext_port_create_processing(context, result, port)

            # sgids must be got after portsec checked with security group
            sgs = self._get_security_groups_on_port(context, port)
            self._process_port_create_security_group(context, result, sgs)
            network = self.get_network(context, result['network_id'])
            binding = db.add_port_binding(context, result['id'])
            mech_context = driver_context.PortContext(self, context, result,
                                                      network, binding, None)
            self._process_port_binding(mech_context, attrs)

            result[addr_apidef.ADDRESS_PAIRS] = (
                self._process_create_allowed_address_pairs(
                    context, result,
                    attrs.get(addr_apidef.ADDRESS_PAIRS)))
            self._process_port_create_extra_dhcp_opts(context, result,
                                                      dhcp_opts)
            kwargs = {'context': context, 'port': result}
            registry.notify(
                resources.PORT, events.PRECOMMIT_CREATE, self, **kwargs)
            self.mechanism_manager.create_port_precommit(mech_context)
            self._setup_dhcp_agent_provisioning_component(context, result)

        resource_extend.apply_funcs('ports', result, port_db)
        return result, mech_context

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_port(self, context, port):
        self._before_create_port(context, port)
        result, mech_context = self._create_port_db(context, port)
        return self._after_create_port(context, result, mech_context)

    def _after_create_port(self, context, result, mech_context):
        # add network to port dict to save a DB call on dhcp notification
        result['network'] = mech_context.network.current
        # notify any plugin that is interested in port create events
        kwargs = {'context': context, 'port': result}
        registry.notify(resources.PORT, events.AFTER_CREATE, self, **kwargs)

        try:
            self.mechanism_manager.create_port_postcommit(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("mechanism_manager.create_port_postcommit "
                          "failed, deleting port '%s'", result['id'])
                self.delete_port(context, result['id'], l3_port_check=False)
        try:
            bound_context = self._bind_port_if_needed(mech_context)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("_bind_port_if_needed "
                          "failed, deleting port '%s'", result['id'])
                self.delete_port(context, result['id'], l3_port_check=False)

        return bound_context.current

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_port_bulk(self, context, ports):
        # TODO(njohnston): Break this up into smaller functions.
        port_list = ports.get('ports')
        for port in port_list:
            self._before_create_port(context, port)

        port_data = []
        network_cache = dict()
        macs = self._generate_macs(len(port_list))
        with db_api.CONTEXT_WRITER.using(context):
            for port in port_list:
                # Set up the port request dict
                pdata = port.get('port')
                project_id = pdata.get('project_id') or pdata.get('tenant_id')
                security_group_ids = pdata.get('security_groups')
                if security_group_ids is const.ATTR_NOT_SPECIFIED:
                    security_group_ids = None
                else:
                    security_group_ids = set(security_group_ids)
                if pdata.get('device_owner'):
                    self._enforce_device_owner_not_router_intf_or_device_id(
                        context, pdata.get('device_owner'),
                        pdata.get('device_id'), project_id)
                bulk_port_data = dict(
                    project_id=project_id,
                    name=pdata.get('name'),
                    network_id=pdata.get('network_id'),
                    admin_state_up=pdata.get('admin_state_up'),
                    status=pdata.get('status',
                        const.PORT_STATUS_ACTIVE),
                    device_id=pdata.get('device_id'),
                    device_owner=pdata.get('device_owner'),
                    description=pdata.get('description'))

                # Ensure that the networks exist.
                network_id = pdata.get('network_id')
                if network_id not in network_cache:
                    network = self.get_network(context, network_id)
                    network_cache[network_id] = network
                else:
                    network = network_cache[network_id]

                # Determine the MAC address
                raw_mac_address = pdata.get('mac_address',
                    const.ATTR_NOT_SPECIFIED)
                if raw_mac_address is const.ATTR_NOT_SPECIFIED:
                    raw_mac_address = macs.pop()
                elif self._is_mac_in_use(context, network_id, raw_mac_address):
                    raise exc.MacAddressInUse(net_id=network_id,
                                              mac=raw_mac_address)
                eui_mac_address = netaddr.EUI(raw_mac_address,
                                              dialect=eui48.mac_unix_expanded)
                port['port']['mac_address'] = str(eui_mac_address)

                # Create the Port object
                db_port_obj = ports_obj.Port(context,
                                            mac_address=eui_mac_address,
                                            id=uuidutils.generate_uuid(),
                                            **bulk_port_data)
                db_port_obj.create()

                # Call IPAM to allocate IP addresses
                try:
                    # TODO(njohnston): IPAM allocation needs to be revamped to
                    # be bulk-friendly.
                    ips = self.ipam.allocate_ips_for_port_and_store(
                            context, port, db_port_obj['id'])
                    ipam_fixed_ips = []
                    for ip in ips:
                        fixed_ip = ports_obj.IPAllocation(
                                port_id=db_port_obj['id'],
                                subnet_id=ip['subnet_id'],
                                network_id=network_id,
                                ip_address=ip['ip_address'])
                        ipam_fixed_ips.append(fixed_ip)

                    db_port_obj['fixed_ips'] = ipam_fixed_ips
                    db_port_obj['ip_allocation'] = (ipalloc_apidef.
                                                IP_ALLOCATION_IMMEDIATE)
                except ipam_exc.DeferIpam:
                    db_port_obj['ip_allocation'] = (ipalloc_apidef.
                                                IP_ALLOCATION_DEFERRED)

                fixed_ips = pdata.get('fixed_ips')
                if validators.is_attr_set(fixed_ips) and not fixed_ips:
                    # [] was passed explicitly as fixed_ips: unaddressed port.
                    db_port_obj['ip_allocation'] = (ipalloc_apidef.
                                                    IP_ALLOCATION_NONE)

                # Make port dict
                port_dict = self._make_port_dict(db_port_obj,
                                                 process_extensions=False)
                port_dict[portbindings.HOST_ID] = pdata.get(
                    portbindings.HOST_ID)

                # Activities immediately post-port-creation
                self.extension_manager.process_create_port(context, pdata,
                                                           port_dict)
                self._portsec_ext_port_create_processing(context, port_dict,
                                                         port)

                sgs = self._get_security_groups_on_port(context, port)
                self._process_port_create_security_group(context, port_dict,
                                                         sgs)

                # process port binding
                binding = db.add_port_binding(context, port_dict['id'])
                binding_host = pdata.get(
                    portbindings.HOST_ID, const.ATTR_NOT_SPECIFIED)
                if binding_host != const.ATTR_NOT_SPECIFIED:
                    binding.host = binding_host
                mech_context = driver_context.PortContext(self, context,
                                                          port_dict, network,
                                                          binding, None)
                self._process_port_binding(mech_context, port_dict)

                # process allowed address pairs
                db_port_obj[addr_apidef.ADDRESS_PAIRS] = (
                    self._process_create_allowed_address_pairs(
                        context, port_dict,
                        port_dict.get(addr_apidef.ADDRESS_PAIRS)))

                # handle DHCP setup
                dhcp_opts = port_dict.get(edo_ext.EXTRADHCPOPTS, [])
                self._process_port_create_extra_dhcp_opts(context, port_dict,
                                                          dhcp_opts)
                # send PRECOMMIT_CREATE notification
                kwargs = {'context': context, 'port': db_port_obj}
                registry.notify(
                    resources.PORT, events.PRECOMMIT_CREATE, self, **kwargs)
                self.mechanism_manager.create_port_precommit(mech_context)

                # handle DHCP agent provisioning
                self._setup_dhcp_agent_provisioning_component(context,
                                                              port_dict)

                port_data.append(
                        {
                            'id': db_port_obj['id'],
                            'port_obj': db_port_obj,
                            'mech_context': mech_context,
                            'port_dict': port_dict
                        })

        # Perform actions after the transaction is committed
        completed_ports = []
        for port in port_data:
            resource_extend.apply_funcs('ports',
                                        port['port_dict'],
                                        port['port_obj'].db_obj)
            completed_ports.append(
                    self._after_create_port(context,
                                            port['port_dict'],
                                            port['mech_context']))
        return completed_ports

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
            raise addr_exc.AddressPairAndPortSecurityRequired()
        if not self._check_update_deletes_allowed_address_pairs(port):
            # not a request for deleting the address-pairs
            updated_port[addr_apidef.ADDRESS_PAIRS] = (
                    self.get_allowed_address_pairs(context, id))

            # check if address pairs has been in db, if address pairs could
            # be put in extension driver, we can refine here.
            if updated_port[addr_apidef.ADDRESS_PAIRS]:
                raise addr_exc.AddressPairAndPortSecurityRequired()

        # checks if security groups were updated adding/modifying
        # security groups, port security is set
        if self._check_update_has_security_groups(port):
            raise psec_exc.PortSecurityAndIPRequiredForSecurityGroups()
        if not self._check_update_deletes_security_groups(port):
            if not extensions.is_extension_supported(self, 'security-group'):
                return
            # Update did not have security groups passed in. Check
            # that port does not have any security groups already on it.
            filters = {'port_id': [id]}
            security_groups = (
                super(Ml2Plugin, self)._get_port_security_group_bindings(
                        context, filters)
                     )
            if security_groups:
                raise psec_exc.PortSecurityPortHasSecurityGroup()

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def update_port(self, context, id, port):
        attrs = port[port_def.RESOURCE_NAME]
        need_port_update_notify = False
        bound_mech_contexts = []
        original_port = self.get_port(context, id)
        registry.notify(resources.PORT, events.BEFORE_UPDATE, self,
                        context=context, port=attrs,
                        original_port=original_port)
        with db_api.CONTEXT_WRITER.using(context):
            port_db = self._get_port(context, id)
            binding = p_utils.get_port_binding_by_status_and_host(
                port_db.port_bindings, const.ACTIVE)
            if not binding:
                raise exc.PortNotFound(port_id=id)
            mac_address_updated = self._check_mac_update_allowed(
                port_db, attrs, binding)
            mac_address_updated |= self._reset_mac_for_direct_physical(
                port_db, attrs, binding)
            need_port_update_notify |= mac_address_updated
            original_port = self._make_port_dict(port_db)
            updated_port = super(Ml2Plugin, self).update_port(context, id,
                                                              port,
                                                              db_port=port_db)
            self.extension_manager.process_update_port(context, attrs,
                                                       updated_port)
            self._portsec_ext_port_update_processing(updated_port, context,
                                                     port, id)

            if (psec.PORTSECURITY in attrs) and (
                        original_port[psec.PORTSECURITY] !=
                        updated_port[psec.PORTSECURITY]):
                need_port_update_notify = True
            # TODO(QoS): Move out to the extension framework somehow.
            # Follow https://review.opendev.org/#/c/169223 for a solution.
            if (qos_consts.QOS_POLICY_ID in attrs and
                    original_port[qos_consts.QOS_POLICY_ID] !=
                    updated_port[qos_consts.QOS_POLICY_ID]):
                need_port_update_notify = True

            if addr_apidef.ADDRESS_PAIRS in attrs:
                need_port_update_notify |= (
                    self.update_address_pairs_on_port(context, id, port,
                                                      original_port,
                                                      updated_port))
            need_port_update_notify |= self.update_security_group_on_port(
                context, id, port, original_port, updated_port)
            network = self.get_network(context, original_port['network_id'])
            need_port_update_notify |= self._update_extra_dhcp_opts_on_port(
                context, id, port, updated_port)
            levels = db.get_binding_level_objs(context, id, binding.host)
            # one of the operations above may have altered the model call
            # _make_port_dict again to ensure latest state is reflected so mech
            # drivers, callback handlers, and the API caller see latest state.
            # We expire here to reflect changed relationships on the obj.
            # Repeatable read will ensure we still get the state from this
            # transaction in spite of concurrent updates/deletes.
            context.session.expire(port_db)
            updated_port.update(self._make_port_dict(port_db))
            mech_context = driver_context.PortContext(
                self, context, updated_port, network, binding, levels,
                original_port=original_port)
            need_port_update_notify |= self._process_port_binding(
                mech_context, attrs)

            registry.publish(
                resources.PORT, events.PRECOMMIT_UPDATE, self,
                payload=events.DBEventPayload(
                    context, request_body=attrs, states=(original_port,),
                    resource_id=id, desired_state=updated_port))

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
                dist_binding_list = db.get_distributed_port_bindings(context,
                                                                     id)
                for dist_binding in dist_binding_list:
                    levels = db.get_binding_level_objs(context, id,
                                                       dist_binding.host)
                    dist_mech_context = driver_context.PortContext(
                        self, context, updated_port, network,
                        dist_binding, levels, original_port=original_port)
                    self.mechanism_manager.update_port_precommit(
                        dist_mech_context)
                    bound_mech_contexts.append(dist_mech_context)
            else:
                self.mechanism_manager.update_port_precommit(mech_context)
                if any(updated_port[k] != original_port[k]
                       for k in ('fixed_ips', 'mac_address')):
                    # only add block if fixed_ips or mac_address changed
                    self._setup_dhcp_agent_provisioning_component(
                        context, updated_port)
                bound_mech_contexts.append(mech_context)

        # Notifications must be sent after the above transaction is complete
        kwargs = {
            'context': context,
            'port': updated_port,
            'mac_address_updated': mac_address_updated,
            'original_port': original_port,
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
            LOG.error("mechanism_manager.update_port_postcommit "
                      "failed for port %s", id)

        need_port_update_notify |= self.is_security_group_member_updated(
            context, original_port, updated_port)

        if original_port['admin_state_up'] != updated_port['admin_state_up']:
            need_port_update_notify = True
        if original_port['status'] != updated_port['status']:
            need_port_update_notify = True
        # NOTE: In the case of DVR ports, the port-binding is done after
        # router scheduling when sync_routers is called and so this call
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

    def _process_distributed_port_binding(self, mech_context, context, attrs):
        plugin_context = mech_context._plugin_context
        binding = mech_context._binding
        port = mech_context.current
        port_id = port['id']

        if binding.vif_type != portbindings.VIF_TYPE_UNBOUND:
            binding.vif_details = ''
            binding.vif_type = portbindings.VIF_TYPE_UNBOUND
            if binding.host:
                db.clear_binding_levels(plugin_context, port_id, binding.host)
            binding.host = ''

        self._update_port_dict_binding(port, binding)
        binding.host = attrs and attrs.get(portbindings.HOST_ID)
        binding.router_id = attrs and attrs.get('device_id')
        # merge into session to reflect changes
        binding.persist_state_to_session(plugin_context.session)

    def delete_distributed_port_bindings_by_router_id(self, context,
                                                      router_id):
        for binding in (context.session.query(models.DistributedPortBinding).
                filter_by(router_id=router_id)):
            db.clear_binding_levels(context, binding.port_id, binding.host)
            context.session.delete(binding)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def update_distributed_port_binding(self, context, id, port):
        attrs = port[port_def.RESOURCE_NAME]

        host = attrs and attrs.get(portbindings.HOST_ID)
        host_set = validators.is_attr_set(host)

        if not host_set:
            LOG.error("No Host supplied to bind DVR Port %s", id)
            return

        binding = db.get_distributed_port_binding_by_host(context,
                                                          id, host)
        device_id = attrs and attrs.get('device_id')
        router_id = binding and binding.get('router_id')
        update_required = (
            not binding or
            binding.vif_type == portbindings.VIF_TYPE_BINDING_FAILED or
            router_id != device_id)
        if update_required:
            try:
                with db_api.CONTEXT_WRITER.using(context):
                    orig_port = self.get_port(context, id)
                    if not binding:
                        binding = db.ensure_distributed_port_binding(
                            context, id, host, router_id=device_id)
                    network = self.get_network(context,
                                               orig_port['network_id'])
                    levels = db.get_binding_level_objs(context, id, host)
                    mech_context = driver_context.PortContext(
                        self, context, orig_port, network,
                        binding, levels, original_port=orig_port)
                    self._process_distributed_port_binding(
                        mech_context, context, attrs)
            except (os_db_exception.DBReferenceError, exc.PortNotFound):
                LOG.debug("DVR Port %s has been deleted concurrently", id)
                return
            self._bind_port_if_needed(mech_context)

    def _pre_delete_port(self, context, port_id, port_check):
        """Do some preliminary operations before deleting the port."""
        LOG.debug("Deleting port %s", port_id)
        try:
            # notify interested parties of imminent port deletion;
            # a failure here prevents the operation from happening
            registry.publish(
                resources.PORT, events.BEFORE_DELETE, self,
                payload=events.DBEventPayload(
                    context, metadata={'port_check': port_check},
                    resource_id=port_id))
        except exceptions.CallbackFailure as e:
            # NOTE(armax): preserve old check's behavior
            if len(e.errors) == 1:
                raise e.errors[0].error
            raise exc.ServicePortInUse(port_id=port_id, reason=e)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def delete_port(self, context, id, l3_port_check=True):
        self._pre_delete_port(context, id, l3_port_check)
        # TODO(armax): get rid of the l3 dependency in the with block
        router_ids = []
        l3plugin = directory.get_plugin(plugin_constants.L3)

        with db_api.CONTEXT_WRITER.using(context):
            try:
                port_db = self._get_port(context, id)
                binding = p_utils.get_port_binding_by_status_and_host(
                    port_db.port_bindings, const.ACTIVE,
                    raise_if_not_found=True, port_id=id)
            except exc.PortNotFound:
                LOG.debug("The port '%s' was deleted", id)
                return
            port = self._make_port_dict(port_db)

            network = self.get_network(context, port['network_id'])
            bound_mech_contexts = []
            kwargs = {
                'context': context,
                'id': id,
                'network': network,
                'port': port,
                'port_db': port_db,
                'bindings': binding,
            }
            device_owner = port['device_owner']
            if device_owner == const.DEVICE_OWNER_DVR_INTERFACE:
                bindings = db.get_distributed_port_bindings(context,
                                                            id)
                for bind in bindings:
                    levels = db.get_binding_level_objs(context, id, bind.host)
                    kwargs['bind'] = bind
                    kwargs['levels'] = levels
                    registry.notify(resources.PORT, events.PRECOMMIT_DELETE,
                                    self, **kwargs)
                    mech_context = driver_context.PortContext(
                        self, context, port, network, bind, levels)
                    self.mechanism_manager.delete_port_precommit(mech_context)
                    bound_mech_contexts.append(mech_context)
            else:
                levels = db.get_binding_level_objs(context, id, binding.host)
                kwargs['bind'] = None
                kwargs['levels'] = levels
                registry.notify(resources.PORT, events.PRECOMMIT_DELETE,
                                self, **kwargs)
                mech_context = driver_context.PortContext(
                    self, context, port, network, binding, levels)
                self.mechanism_manager.delete_port_precommit(mech_context)
                bound_mech_contexts.append(mech_context)
            if l3plugin:
                router_ids = l3plugin.disassociate_floatingips(
                    context, id, do_notify=False)

            LOG.debug("Calling delete_port for %(port_id)s owned by %(owner)s",
                      {"port_id": id, "owner": device_owner})
            super(Ml2Plugin, self).delete_port(context, id)

        self._post_delete_port(
            context, port, router_ids, bound_mech_contexts)

    def _post_delete_port(self, context, port, router_ids,
                          bound_mech_contexts):
        kwargs = {
            'context': context,
            'port': port,
            'router_ids': router_ids,
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
            LOG.error("mechanism_manager.delete_port_postcommit failed for"
                      " port %s", port['id'])
        self.notifier.port_delete(context, port['id'])

    @utils.transaction_guard
    @db_api.retry_if_session_inactive(context_var_name='plugin_context')
    def get_bound_port_context(self, plugin_context, port_id, host=None,
                               cached_networks=None):
        with db_api.CONTEXT_READER.using(plugin_context) as session:
            try:
                port_db = (session.query(models_v2.Port).
                           enable_eagerloads(False).
                           filter(models_v2.Port.id.startswith(port_id)).
                           one())
            except sa_exc.NoResultFound:
                LOG.info("No ports have port_id starting with %s",
                         port_id)
                return
            except sa_exc.MultipleResultsFound:
                LOG.error("Multiple ports have port_id starting with %s",
                          port_id)
                return
            port = self._make_port_dict(port_db)
            network = (cached_networks or {}).get(port['network_id'])

            if not network:
                network = self.get_network(plugin_context, port['network_id'])

            if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                binding = db.get_distributed_port_binding_by_host(
                    plugin_context, port['id'], host)
                if not binding:
                    LOG.error("Binding info for DVR port %s not found",
                              port_id)
                    return None
                levels = db.get_binding_level_objs(
                    plugin_context, port_db.id, host)
                port_context = driver_context.PortContext(
                    self, plugin_context, port, network, binding, levels)
            else:
                # since eager loads are disabled in port_db query
                # related attribute port_binding could disappear in
                # concurrent port deletion.
                # It's not an error condition.
                binding = p_utils.get_port_binding_by_status_and_host(
                    port_db.port_bindings, const.ACTIVE)
                if not binding:
                    LOG.info("Binding info for port %s was not found, "
                             "it might have been deleted already.",
                             port_id)
                    return
                levels = db.get_binding_level_objs(
                    plugin_context, port_db.id, binding.host)
                port_context = driver_context.PortContext(
                    self, plugin_context, port, network, binding, levels)

        return self._bind_port_if_needed(port_context)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive(context_var_name='plugin_context')
    def get_bound_ports_contexts(self, plugin_context, dev_ids, host=None):
        result = {}
        with db_api.CONTEXT_READER.using(plugin_context):
            dev_to_full_pids = db.partial_port_ids_to_full_ids(
                plugin_context, dev_ids)
            # get all port objects for IDs
            port_dbs_by_id = db.get_port_db_objects(
                plugin_context, dev_to_full_pids.values())
            # get all networks for PortContext construction
            netctxs_by_netid = self.get_network_contexts(
                plugin_context,
                {p.network_id for p in port_dbs_by_id.values()})
            for dev_id in dev_ids:
                port_id = dev_to_full_pids.get(dev_id)
                port_db = port_dbs_by_id.get(port_id)
                if (not port_id or not port_db or
                        port_db.network_id not in netctxs_by_netid):
                    result[dev_id] = None
                    continue
                port = self._make_port_dict(port_db)
                if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                    binding = db.get_distributed_port_binding_by_host(
                        plugin_context, port['id'], host)
                    bindlevelhost_match = host
                else:
                    binding = p_utils.get_port_binding_by_status_and_host(
                        port_db.port_bindings, const.ACTIVE)
                    bindlevelhost_match = binding.host if binding else None
                if not binding:
                    LOG.info("Binding info for port %s was not found, "
                             "it might have been deleted already.",
                             port_id)
                    result[dev_id] = None
                    continue
                levels = [bl for bl in port_db.binding_levels
                          if bl.host == bindlevelhost_match]
                levels = sorted(levels, key=lambda bl: bl.level)
                network_ctx = netctxs_by_netid.get(port_db.network_id)
                port_context = driver_context.PortContext(
                    self, plugin_context, port, network_ctx, binding, levels)
                result[dev_id] = port_context

        return {d: self._bind_port_if_needed(pctx) if pctx else None
                for d, pctx in result.items()}

    def update_port_status(self, context, port_id, status, host=None,
                           network=None):
        """Update port status

        Returns port_id (non-truncated uuid) if the port exists.
        Otherwise returns None.
        'network' is deprecated and has no effect
        """
        full = db.partial_port_ids_to_full_ids(context, [port_id])
        if port_id not in full:
            return None
        port_id = full[port_id]
        return self.update_port_statuses(
            context, {port_id: status}, host)[port_id]

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def update_port_statuses(self, context, port_id_to_status, host=None):
        result = {}
        port_ids = port_id_to_status.keys()
        port_dbs_by_id = db.get_port_db_objects(context, port_ids)
        for port_id, status in port_id_to_status.items():
            if not port_dbs_by_id.get(port_id):
                LOG.debug("Port %(port)s update to %(val)s by agent not found",
                          {'port': port_id, 'val': status})
                result[port_id] = None
                continue
            result[port_id] = self._safe_update_individual_port_db_status(
                context, port_dbs_by_id[port_id], status, host)
        return result

    def _safe_update_individual_port_db_status(self, context, port,
                                               status, host):
        port_id = port.id
        try:
            return self._update_individual_port_db_status(
                context, port, status, host)
        except Exception:
            with excutils.save_and_reraise_exception() as ectx:
                # don't reraise if port doesn't exist anymore
                ectx.reraise = bool(db.get_port(context, port_id))

    def _update_individual_port_db_status(self, context, port, status, host):
        updated = False
        network = None
        port_id = port.id
        if ((port.status != status and
                port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE) or
                port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE):
            attr = {
                'id': port.id,
                portbindings.HOST_ID: host,
                'status': status
            }
            registry.notify(resources.PORT, events.BEFORE_UPDATE, self,
                            original_port=port,
                            context=context, port=attr)
        with db_api.CONTEXT_WRITER.using(context):
            context.session.add(port)  # bring port into writer session
            if (port.status != status and
                    port['device_owner'] != const.DEVICE_OWNER_DVR_INTERFACE):
                original_port = self._make_port_dict(port)
                port.status = status
                # explicit flush before _make_port_dict to ensure extensions
                # listening for db events can modify the port if necessary
                context.session.flush()
                updated_port = self._make_port_dict(port)
                binding = p_utils.get_port_binding_by_status_and_host(
                    port.port_bindings, const.ACTIVE, raise_if_not_found=True,
                    port_id=port_id)
                levels = db.get_binding_level_objs(
                    context, port.id, binding.host)
                mech_context = driver_context.PortContext(
                    self, context, updated_port, network, binding, levels,
                    original_port=original_port)
                self.mechanism_manager.update_port_precommit(mech_context)
                updated = True
            elif port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
                binding = db.get_distributed_port_binding_by_host(
                    context, port['id'], host)
                if not binding:
                    return
                if binding.status != status:
                    binding.status = status
                    updated = True

        if (updated and
                port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE):
            with db_api.CONTEXT_WRITER.using(context):
                port = db.get_port(context, port_id)
                if not port:
                    LOG.warning("Port %s not found during update",
                                port_id)
                    return
                original_port = self._make_port_dict(port)
                network = network or self.get_network(
                    context, original_port['network_id'])
                port.status = db.generate_distributed_port_status(context,
                                                                  port['id'])
                updated_port = self._make_port_dict(port)
                levels = db.get_binding_level_objs(context, port_id, host)
                mech_context = (driver_context.PortContext(
                    self, context, updated_port, network,
                    binding, levels, original_port=original_port))
                self.mechanism_manager.update_port_precommit(mech_context)

        if updated:
            self.mechanism_manager.update_port_postcommit(mech_context)
            kwargs = {'context': context, 'port': mech_context.current,
                      'original_port': original_port}
            registry.notify(resources.PORT, events.AFTER_UPDATE, self,
                            **kwargs)

        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            db.delete_distributed_port_binding_if_stale(context, binding)

        return port['id']

    @db_api.retry_if_session_inactive()
    def port_bound_to_host(self, context, port_id, host):
        if not host:
            return
        port = db.get_port(context, port_id)
        if not port:
            LOG.debug("No Port match for: %s", port_id)
            return
        if port['device_owner'] == const.DEVICE_OWNER_DVR_INTERFACE:
            bindings = db.get_distributed_port_bindings(context,
                                                        port_id)
            for b in bindings:
                if b.host == host:
                    return port
            LOG.debug("No binding found for DVR port %s", port['id'])
            return
        else:
            port_host = db.get_port_binding_host(context, port_id)
            return port if (port_host == host) else None

    @db_api.retry_if_session_inactive()
    def get_ports_from_devices(self, context, devices):
        port_ids_to_devices = dict(
            (self._device_to_port_id(context, device), device)
            for device in devices)
        port_ids = list(port_ids_to_devices.keys())
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

    def _get_ports_query(self, context, filters=None, *args, **kwargs):
        filters = filters or {}
        security_groups = filters.pop("security_groups", None)
        limit = kwargs.pop('limit', None)
        if security_groups:
            port_bindings = self._get_port_security_group_bindings(
                context, filters={'security_group_id':
                                  security_groups})
            if 'id' in filters:
                filters['id'] = [entry['port_id'] for
                                 entry in port_bindings
                                 if entry['port_id'] in filters['id']]
            else:
                filters['id'] = [entry['port_id'] for entry in port_bindings]
        fixed_ips = filters.get('fixed_ips', {})
        ip_addresses_s = fixed_ips.get('ip_address_substr')
        query = super(Ml2Plugin, self)._get_ports_query(context, filters,
                                                        *args, **kwargs)
        if ip_addresses_s:
            substr_filter = or_(*[models_v2.Port.fixed_ips.any(
                models_v2.IPAllocation.ip_address.like('%%%s%%' % ip))
                for ip in ip_addresses_s])
            query = query.filter(substr_filter)
        if limit:
            query = query.limit(limit)
        return query

    def filter_hosts_with_network_access(
            self, context, network_id, candidate_hosts):
        segments = segments_db.get_network_segments(context, network_id)
        return self.mechanism_manager.filter_hosts_with_segment_access(
            context, segments, candidate_hosts, self.get_agents)

    def check_segment_for_agent(self, segment, agent):
        for mech_driver in self.mechanism_manager.ordered_mech_drivers:
            driver_agent_type = getattr(mech_driver.obj, 'agent_type', None)
            if driver_agent_type and driver_agent_type == agent['agent_type']:
                if mech_driver.obj.check_segment_for_agent(segment, agent):
                    return True
        return False

    @registry.receives(resources.SEGMENT, [events.AFTER_DELETE])
    def _handle_after_delete_segment_change(
            self, rtype, event, trigger, payload=None):
        # TODO(boden); refactor into _handle_segment_change once all
        # event types use payloads
        return self._handle_segment_change(
            rtype, event, trigger, payload.context, payload.latest_state,
            for_net_delete=payload.metadata.get('for_net_delete'))

    @registry.receives(resources.SEGMENT, (events.PRECOMMIT_CREATE,
                                           events.PRECOMMIT_DELETE,
                                           events.AFTER_CREATE))
    def _handle_segment_change(self, rtype, event, trigger, context, segment,
                               for_net_delete=False):
        if (event == events.PRECOMMIT_CREATE and
                not isinstance(trigger, segments_plugin.Plugin)):
            # TODO(xiaohhui): Now, when create network, ml2 will reserve
            # segment and trigger this event handler. This event handler
            # will reserve segment again, which will lead to error as the
            # segment has already been reserved. This check could be removed
            # by unifying segment creation procedure.
            return

        network_id = segment.get('network_id')

        if event == events.PRECOMMIT_CREATE:
            updated_segment = self.type_manager.reserve_network_segment(
                context, segment)
            # The segmentation id might be from ML2 type driver, update it
            # in the original segment.
            segment[api.SEGMENTATION_ID] = updated_segment[api.SEGMENTATION_ID]
        elif event == events.PRECOMMIT_DELETE:
            self.type_manager.release_network_segment(context, segment)

        if for_net_delete:
            return

        # change in segments could affect resulting network mtu, so let's
        # recalculate it
        network_db = self._get_network(context, network_id)
        network_db.mtu = self._get_network_mtu(
            network_db,
            validate=(event != events.PRECOMMIT_DELETE))
        network_db.save(session=context.session)

        try:
            self._notify_mechanism_driver_for_segment_change(
                event, context, network_id)
        except ml2_exc.MechanismDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("mechanism_manager error occurred when "
                          "handle event %(event)s for segment "
                          "'%(segment)s'",
                          {'event': event, 'segment': segment['id']})

    def _notify_mechanism_driver_for_segment_change(self, event,
                                                    context, network_id):
        network_with_segments = self.get_network(context, network_id)
        mech_context = driver_context.NetworkContext(
            self, context, network_with_segments,
            original_network=network_with_segments)
        if event in [events.PRECOMMIT_CREATE, events.PRECOMMIT_DELETE]:
            self.mechanism_manager.update_network_precommit(mech_context)
        elif event in [events.AFTER_CREATE, events.AFTER_DELETE]:
            self.mechanism_manager.update_network_postcommit(mech_context)

    @staticmethod
    def _validate_compute_port(port):
        if not port['device_owner'].startswith(
                const.DEVICE_OWNER_COMPUTE_PREFIX):
            msg = _('Invalid port %s. Operation only valid on compute '
                    'ports') % port['id']
            raise exc.BadRequest(resource='port', msg=msg)

    def _make_port_binding_dict(self, binding, fields=None):
        res = {key: binding[key] for key in (
                    pbe_ext.HOST, pbe_ext.VIF_TYPE, pbe_ext.VNIC_TYPE,
                    pbe_ext.STATUS)}
        if isinstance(binding, ports_obj.PortBinding):
            res[pbe_ext.PROFILE] = binding.profile or {}
            res[pbe_ext.VIF_DETAILS] = binding.vif_details or {}
        else:
            res[pbe_ext.PROFILE] = self._get_profile(binding)
            res[pbe_ext.VIF_DETAILS] = self._get_vif_details(binding)
        return db_utils.resource_fields(res, fields)

    def _get_port_binding_attrs(self, binding, host=None):
        return {portbindings.VNIC_TYPE: binding.get(pbe_ext.VNIC_TYPE),
                portbindings.HOST_ID: binding.get(pbe_ext.HOST) or host,
                portbindings.PROFILE: binding.get(pbe_ext.PROFILE, {})}

    def _process_active_binding_change(self, changes, mech_context, port_dict,
                                       original_host):
        if changes:
            self._clear_port_binding(mech_context,
                                     mech_context._binding, port_dict,
                                     original_host)
            port_dict['status'] = const.PORT_STATUS_DOWN
            super(Ml2Plugin, self).update_port(
                mech_context._plugin_context, port_dict['id'],
                {port_def.RESOURCE_NAME:
                    {'status': const.PORT_STATUS_DOWN}})
        self._update_port_dict_binding(port_dict,
                                       mech_context._binding)
        mech_context._binding.persist_state_to_session(
            mech_context._plugin_context.session)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def create_port_binding(self, context, port_id, binding):
        attrs = binding[pbe_ext.RESOURCE_NAME]
        with db_api.CONTEXT_WRITER.using(context):
            port_db = self._get_port(context, port_id)
            self._validate_compute_port(port_db)
            if self._get_binding_for_host(port_db.port_bindings,
                                          attrs[pbe_ext.HOST]):
                raise exc.PortBindingAlreadyExists(
                    port_id=port_id, host=attrs[pbe_ext.HOST])
            status = const.ACTIVE
            is_active_binding = True
            active_binding = p_utils.get_port_binding_by_status_and_host(
                port_db.port_bindings, const.ACTIVE)
            if active_binding:
                status = const.INACTIVE
                is_active_binding = False
            network = self.get_network(context, port_db['network_id'])
            port_dict = self._make_port_dict(port_db)
            new_binding = models.PortBinding(
                port_id=port_id,
                vif_type=portbindings.VIF_TYPE_UNBOUND,
                status=status)
            mech_context = driver_context.PortContext(self, context, port_dict,
                                                      network, new_binding,
                                                      None)
            changes, original_host = self._process_port_binding_attributes(
                mech_context._binding, self._get_port_binding_attrs(attrs))
            if is_active_binding:
                self._process_active_binding_change(changes, mech_context,
                                                    port_dict, original_host)
        bind_context = self._bind_port_if_needed(
            mech_context, allow_commit=is_active_binding)
        if (bind_context._binding.vif_type ==
                portbindings.VIF_TYPE_BINDING_FAILED):
            raise exc.PortBindingError(port_id=port_id,
                                       host=attrs[pbe_ext.HOST])
        bind_context._binding.port_id = port_id
        bind_context._binding.status = status
        if not is_active_binding:
            with db_api.CONTEXT_WRITER.using(context):
                bind_context._binding.persist_state_to_session(context.session)
                db.set_binding_levels(context, bind_context._binding_levels)
        return self._make_port_binding_dict(bind_context._binding)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def get_port_bindings(self, context, port_id, filters=None, fields=None,
                          sorts=None, limit=None, marker=None,
                          page_reverse=False):
        port = ports_obj.Port.get_object(context, id=port_id)
        if not port:
            raise exc.PortNotFound(port_id=port_id)
        self._validate_compute_port(port)
        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        bindings = ports_obj.PortBinding.get_objects(
            context, _pager=pager, port_id=port_id, **filters)

        return [self._make_port_binding_dict(binding, fields)
                for binding in bindings]

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def get_port_binding(self, context, host, port_id, fields=None):
        port = ports_obj.Port.get_object(context, id=port_id)
        if not port:
            raise exc.PortNotFound(port_id=port_id)
        self._validate_compute_port(port)
        binding = ports_obj.PortBinding.get_object(context, host=host,
                                                   port_id=port_id)
        if not binding:
            raise exc.PortBindingNotFound(port_id=port_id, host=host)
        return self._make_port_binding_dict(binding, fields)

    def _get_binding_for_host(self, bindings, host):
        for binding in bindings:
            if binding.host == host:
                return binding

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def update_port_binding(self, context, host, port_id, binding):
        attrs = binding[pbe_ext.RESOURCE_NAME]
        with db_api.CONTEXT_WRITER.using(context):
            port_db = self._get_port(context, port_id)
            self._validate_compute_port(port_db)
            original_binding = self._get_binding_for_host(
                port_db.port_bindings, host)
            if not original_binding:
                raise exc.PortBindingNotFound(port_id=port_id, host=host)
            is_active_binding = (original_binding.status == const.ACTIVE)
            network = self.get_network(context, port_db['network_id'])
            port_dict = self._make_port_dict(port_db)
            mech_context = driver_context.PortContext(self, context, port_dict,
                                                      network,
                                                      original_binding, None)
            changes, original_host = self._process_port_binding_attributes(
                mech_context._binding, self._get_port_binding_attrs(attrs,
                                                                    host=host))
            if is_active_binding:
                self._process_active_binding_change(changes, mech_context,
                                                    port_dict, original_host)
        bind_context = self._bind_port_if_needed(
            mech_context, allow_commit=is_active_binding)
        if (bind_context._binding.vif_type ==
                portbindings.VIF_TYPE_BINDING_FAILED):
            raise exc.PortBindingError(port_id=port_id, host=host)
        if not is_active_binding:
            with db_api.CONTEXT_WRITER.using(context):
                bind_context._binding.persist_state_to_session(context.session)
                db.set_binding_levels(context, bind_context._binding_levels)
        return self._make_port_binding_dict(bind_context._binding)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def activate(self, context, host, port_id):
        with db_api.CONTEXT_WRITER.using(context):
            # TODO(mlavalle) Next two lines can be removed when bug #1770267 is
            # fixed
            if isinstance(port_id, dict):
                port_id = port_id['port_id']
            port_db = self._get_port(context, port_id)
            self._validate_compute_port(port_db)
            active_binding = p_utils.get_port_binding_by_status_and_host(
                port_db.port_bindings, const.ACTIVE)
            if host == (active_binding and active_binding.host):
                raise exc.PortBindingAlreadyActive(port_id=port_id,
                                                   host=host)
            inactive_binding = p_utils.get_port_binding_by_status_and_host(
                port_db.port_bindings, const.INACTIVE, host=host)
            if not inactive_binding or inactive_binding.host != host:
                raise exc.PortBindingNotFound(port_id=port_id, host=host)
            network = self.get_network(context, port_db['network_id'])
            port_dict = self._make_port_dict(port_db)
            levels = db.get_binding_level_objs(context, port_id,
                                               active_binding.host)
            original_context = driver_context.PortContext(self, context,
                                                          port_dict, network,
                                                          active_binding,
                                                          levels)
            self._clear_port_binding(original_context, active_binding,
                                     port_dict, active_binding.host)
            port_dict['status'] = const.PORT_STATUS_DOWN
            super(Ml2Plugin, self).update_port(
                context, port_dict['id'],
                {port_def.RESOURCE_NAME:
                    {'status': const.PORT_STATUS_DOWN}})
            levels = db.get_binding_level_objs(context, port_id,
                                               inactive_binding.host)
            bind_context = driver_context.PortContext(self, context, port_dict,
                                                      network,
                                                      inactive_binding, levels)
        for count in range(MAX_BIND_TRIES):
            cur_context, _, try_again = self._commit_port_binding(
                original_context, bind_context, need_notify=True,
                update_binding_levels=False)
            if not try_again:
                self.notifier.binding_deactivate(context, port_id,
                                                 active_binding.host,
                                                 network['id'])
                self.notifier.binding_activate(context, port_id,
                                               inactive_binding.host)
                return self._make_port_binding_dict(cur_context._binding)
        raise exc.PortBindingError(port_id=port_id, host=host)

    @utils.transaction_guard
    @db_api.retry_if_session_inactive()
    def delete_port_binding(self, context, host, port_id):
        ports_obj.PortBinding.delete_objects(context,
                                             host=host,
                                             port_id=port_id)
        db.clear_binding_levels(context,
                                port_id=port_id,
                                host=host)

    @db_api.retry_if_session_inactive()
    def get_ports_by_vnic_type_and_host(self, context, **kwargs):
        host = kwargs['host']
        vnic_type = kwargs['vnic_type']
        ports = ports_obj.Port.get_ports_by_vnic_type_and_host(
            context, vnic_type, host)
        return [self._make_port_dict(port.db_obj) for port in ports]
