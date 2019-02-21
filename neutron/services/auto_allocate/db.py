# Copyright 2015-2016 Hewlett Packard Enterprise Development Company, LP
#
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

from neutron_lib.api.definitions import constants as api_const
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api.definitions import network as net_def
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from neutron_lib.plugins import utils as p_utils
from oslo_log import log as logging

from neutron._i18n import _
from neutron.db import common_db_mixin
from neutron.objects import auto_allocate as auto_allocate_obj
from neutron.objects import base as base_obj
from neutron.objects import network as net_obj
from neutron.services.auto_allocate import exceptions

LOG = logging.getLogger(__name__)
CHECK_REQUIREMENTS = 'dry-run'


def _ensure_external_network_default_value_callback(
        resource, event, trigger, **kwargs):
    """Ensure the is_default db field matches the create/update request."""

    # TODO(boden): remove shim once all callbacks use payloads
    if 'payload' in kwargs:
        _request = kwargs['payload'].request_body
        _context = kwargs['payload'].context
        _network = kwargs['payload'].desired_state
        _orig = kwargs['payload'].states[0]
    else:
        _request = kwargs['request']
        _context = kwargs['context']
        _network = kwargs['network']
        _orig = kwargs.get('original_network')

    @db_api.retry_if_session_inactive()
    def _do_ensure_external_network_default_value_callback(
            context, request, orig, network):
        is_default = request.get(api_const.IS_DEFAULT)
        if is_default is None:
            return
        if is_default:
            # ensure only one default external network at any given time
            pager = base_obj.Pager(limit=1)
            objs = net_obj.ExternalNetwork.get_objects(context, _pager=pager,
                                                       is_default=True)
            if objs:
                if objs[0] and network['id'] != objs[0].network_id:
                    raise exceptions.DefaultExternalNetworkExists(
                        net_id=objs[0].network_id)

        if orig and orig.get(api_const.IS_DEFAULT) == is_default:
            return
        network[api_const.IS_DEFAULT] = is_default
        # Reflect the status of the is_default on the create/update request
        obj = net_obj.ExternalNetwork.get_object(context,
                                                 network_id=network['id'])
        if obj:
            obj.is_default = is_default
            obj.update()

    _do_ensure_external_network_default_value_callback(
        _context, _request, _orig, _network)


@resource_extend.has_resource_extenders
class AutoAllocatedTopologyMixin(common_db_mixin.CommonDbMixin):

    def __new__(cls, *args, **kwargs):
        # NOTE(kevinbenton): we subscribe on object construction because
        # the tests blow away the callback manager for each run
        new = super(AutoAllocatedTopologyMixin, cls).__new__(cls, *args,
                                                             **kwargs)
        registry.subscribe(_ensure_external_network_default_value_callback,
                           resources.NETWORK, events.PRECOMMIT_UPDATE)
        registry.subscribe(_ensure_external_network_default_value_callback,
                           resources.NETWORK, events.PRECOMMIT_CREATE)
        return new

    # TODO(armax): if a tenant modifies auto allocated resources under
    # the hood the behavior of the get_auto_allocated_topology API is
    # undetermined. Consider adding callbacks to deal with the following
    # situations:
    # - insert subnet -> plug router interface
    # - delete router -> remove the entire topology
    # - update subnet -> prevent operation
    # - update router gateway -> prevent operation
    # - ...

    @property
    def core_plugin(self):
        if not getattr(self, '_core_plugin', None):
            self._core_plugin = directory.get_plugin()
        return self._core_plugin

    @property
    def l3_plugin(self):
        if not getattr(self, '_l3_plugin', None):
            self._l3_plugin = directory.get_plugin(constants.L3)
        return self._l3_plugin

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_external_network_default(net_res, net_db):
        """Add is_default field to 'show' response."""
        if net_db.external is not None:
            net_res[api_const.IS_DEFAULT] = net_db.external.is_default
        return net_res

    def get_auto_allocated_topology(self, context, tenant_id, fields=None):
        """Return tenant's network associated to auto-allocated topology.

        The topology will be provisioned upon return, if network is missing.
        """
        fields = fields or []
        tenant_id = self._validate(context, tenant_id)
        if CHECK_REQUIREMENTS in fields:
            # for dry-run requests, simply validates that subsequent
            # requests can be fulfilled based on a set of requirements
            # such as existence of default networks, pools, etc.
            return self._check_requirements(context, tenant_id)
        elif fields:
            raise n_exc.BadRequest(resource='auto_allocate',
                                   msg=_("Unrecognized field"))

        # Check for an existent topology
        network_id = self._get_auto_allocated_network(context, tenant_id)
        if network_id:
            return self._response(network_id, tenant_id, fields=fields)
        # See if we indeed have an external network to connect to, otherwise
        # we will fail fast
        default_external_network = self._get_default_external_network(
            context)

        # If we reach this point, then we got some work to do!
        network_id = self._build_topology(
            context, tenant_id, default_external_network)
        return self._response(network_id, tenant_id, fields=fields)

    def delete_auto_allocated_topology(self, context, tenant_id):
        tenant_id = self._validate(context, tenant_id)
        topology = self._get_auto_allocated_topology(context, tenant_id)
        if topology:
            subnets = self.core_plugin.get_subnets(
                context,
                filters={'network_id': [topology['network_id']]})
            self._cleanup(
                context, network_id=topology['network_id'],
                router_id=topology['router_id'], subnets=subnets)

    def _build_topology(self, context, tenant_id, default_external_network):
        """Build the network topology and returns its network UUID."""
        try:
            subnets = self._provision_tenant_private_network(
                context, tenant_id)
            network_id = subnets[0]['network_id']
            router = self._provision_external_connectivity(
                context, default_external_network, subnets, tenant_id)
            network_id = self._save(
                context, tenant_id, network_id, router['id'], subnets)
            return network_id
        except exceptions.UnknownProvisioningError as e:
            # Clean partially provisioned topologies, and reraise the
            # error. If it can be retried, so be it.
            LOG.error("Unknown error while provisioning topology for "
                      "tenant %(tenant_id)s. Reason: %(reason)s",
                      {'tenant_id': tenant_id, 'reason': e})
            self._cleanup(
                context, network_id=e.network_id,
                router_id=e.router_id, subnets=e.subnets)
            raise e.error

    def _check_requirements(self, context, tenant_id):
        """Raise if requirements are not met."""
        self._get_default_external_network(context)
        try:
            self._get_supported_subnetpools(context)
        except n_exc.NotFound:
            raise exceptions.AutoAllocationFailure(
                reason=_("No default subnetpools defined"))
        return {'id': 'dry-run=pass', 'tenant_id': tenant_id}

    def _validate(self, context, tenant_id):
        """Validate and return the tenant to be associated to the topology."""
        if tenant_id == 'None':
            # NOTE(HenryG): the client might be sending us astray by
            # passing no tenant; this is really meant to be the tenant
            # issuing the request, therefore let's get it from the context
            tenant_id = context.tenant_id

        if not context.is_admin and tenant_id != context.tenant_id:
            raise n_exc.NotAuthorized()

        return tenant_id

    def _get_auto_allocated_topology(self, context, tenant_id):
        """Return the auto allocated topology record if present or None."""
        return auto_allocate_obj.AutoAllocatedTopology.get_object(
            context, project_id=tenant_id)

    def _get_auto_allocated_network(self, context, tenant_id):
        """Get the auto allocated network for the tenant."""
        network = self._get_auto_allocated_topology(context, tenant_id)
        if network:
            return network['network_id']

    @staticmethod
    def _response(network_id, tenant_id, fields=None):
        """Build response for auto-allocated network."""
        res = {
            'id': network_id,
            'tenant_id': tenant_id
        }
        return db_utils.resource_fields(res, fields)

    def _get_default_external_network(self, context):
        """Get the default external network for the deployment."""

        default_external_networks = net_obj.ExternalNetwork.get_objects(
            context, is_default=True)

        if not default_external_networks:
            LOG.error("Unable to find default external network "
                      "for deployment, please create/assign one to "
                      "allow auto-allocation to work correctly.")
            raise exceptions.AutoAllocationFailure(
                reason=_("No default router:external network"))
        if len(default_external_networks) > 1:
            LOG.error("Multiple external default networks detected. "
                      "Network %s is true 'default'.",
                      default_external_networks[0]['network_id'])
        return default_external_networks[0].network_id

    def _get_supported_subnetpools(self, context):
        """Return the default subnet pools available."""
        default_subnet_pools = [
            self.core_plugin.get_default_subnetpool(
                context, ver) for ver in (4, 6)
        ]
        available_pools = [
            s for s in default_subnet_pools if s
        ]
        if not available_pools:
            LOG.error("No default pools available")
            raise n_exc.NotFound()

        return available_pools

    def _provision_tenant_private_network(self, context, tenant_id):
        """Create a tenant private network/subnets."""
        network = None
        try:
            network_args = {
                'name': 'auto_allocated_network',
                'admin_state_up': False,
                'tenant_id': tenant_id,
                'shared': False
            }
            network = p_utils.create_network(
                self.core_plugin, context, {'network': network_args})
            subnets = []
            for pool in self._get_supported_subnetpools(context):
                subnet_args = {
                    'name': 'auto_allocated_subnet_v%s' % pool['ip_version'],
                    'network_id': network['id'],
                    'tenant_id': tenant_id,
                    'ip_version': pool['ip_version'],
                    'subnetpool_id': pool['id'],
                }
                subnets.append(p_utils.create_subnet(
                    self.core_plugin, context, {'subnet': subnet_args}))
            return subnets
        except (n_exc.SubnetAllocationError, ValueError,
                n_exc.BadRequest, n_exc.NotFound) as e:
            LOG.error("Unable to auto allocate topology for tenant "
                      "%(tenant_id)s due to missing or unmet "
                      "requirements. Reason: %(reason)s",
                      {'tenant_id': tenant_id, 'reason': e})
            if network:
                self._cleanup(context, network['id'])
            raise exceptions.AutoAllocationFailure(
                reason=_("Unable to provide tenant private network"))
        except Exception as e:
            network_id = network['id'] if network else None
            raise exceptions.UnknownProvisioningError(e, network_id=network_id)

    def _provision_external_connectivity(
        self, context, default_external_network, subnets, tenant_id):
        """Uplink tenant subnet(s) to external network."""
        router_args = {
            'name': 'auto_allocated_router',
            l3_apidef.EXTERNAL_GW_INFO: {
                'network_id': default_external_network},
            'tenant_id': tenant_id,
            'admin_state_up': True
        }
        router = None
        attached_subnets = []
        try:
            router = self.l3_plugin.create_router(
                context, {'router': router_args})
            for subnet in subnets:
                self.l3_plugin.add_router_interface(
                    context, router['id'], {'subnet_id': subnet['id']})
                attached_subnets.append(subnet)
            return router
        except n_exc.BadRequest as e:
            LOG.error("Unable to auto allocate topology for tenant "
                      "%(tenant_id)s because of router errors. "
                      "Reason: %(reason)s",
                      {'tenant_id': tenant_id, 'reason': e})
            router_id = router['id'] if router else None
            self._cleanup(context,
                          network_id=subnets[0]['network_id'],
                          router_id=router_id, subnets=attached_subnets)
            raise exceptions.AutoAllocationFailure(
                reason=_("Unable to provide external connectivity"))
        except Exception as e:
            router_id = router['id'] if router else None
            raise exceptions.UnknownProvisioningError(
                e, network_id=subnets[0]['network_id'],
                router_id=router_id, subnets=subnets)

    def _save(self, context, tenant_id, network_id, router_id, subnets):
        """Save auto-allocated topology, or revert in case of DB errors."""
        try:
            auto_allocate_obj.AutoAllocatedTopology(
                context, project_id=tenant_id, network_id=network_id,
                router_id=router_id).create()
            self.core_plugin.update_network(
                context, network_id,
                {'network': {'admin_state_up': True}})
        except obj_exc.NeutronDbObjectDuplicateEntry:
            LOG.debug("Multiple auto-allocated networks detected for "
                      "tenant %s. Attempting clean up for network %s "
                      "and router %s.",
                      tenant_id, network_id, router_id)
            self._cleanup(
                context, network_id=network_id,
                router_id=router_id, subnets=subnets)
            network_id = self._get_auto_allocated_network(context, tenant_id)
        except Exception as e:
            raise exceptions.UnknownProvisioningError(
                e, network_id=network_id,
                router_id=router_id, subnets=subnets)
        return network_id

    def _cleanup(self, context, network_id=None, router_id=None, subnets=None):
        """Clean up auto allocated resources."""
        # Concurrent attempts to delete the topology may interleave and
        # cause some operations to fail with NotFound exceptions. Rather
        # than fail partially, the exceptions should be ignored and the
        # cleanup should proceed uninterrupted.
        if router_id:
            for subnet in subnets or []:
                ignore_notfound(
                    self.l3_plugin.remove_router_interface,
                    context, router_id, {'subnet_id': subnet['id']})
            ignore_notfound(self.l3_plugin.delete_router, context, router_id)

        if network_id:
            ignore_notfound(
                self.core_plugin.delete_network, context, network_id)


def ignore_notfound(func, *args, **kwargs):
    """Call the given function and pass if a `NotFound` exception is raised."""
    try:
        return func(*args, **kwargs)
    except n_exc.NotFound:
        pass
