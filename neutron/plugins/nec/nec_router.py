# Copyright 2013 NEC Corporation.  All rights reserved.
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

from neutron.api.rpc.agentnotifiers import l3_rpc_agent_api
from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_agentschedulers_db
from neutron.db import l3_db
from neutron.db import l3_gwmode_db
from neutron.db import models_v2
from neutron.extensions import l3
from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import constants as nconst
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import router as rdb
from neutron.plugins.nec.extensions import router_provider as ext_provider

LOG = logging.getLogger(__name__)

PROVIDER_L3AGENT = nconst.ROUTER_PROVIDER_L3AGENT
PROVIDER_OPENFLOW = nconst.ROUTER_PROVIDER_OPENFLOW

ROUTER_DRIVER_PATH = 'neutron.plugins.nec.router_drivers.'
ROUTER_DRIVER_MAP = {
    PROVIDER_L3AGENT: ROUTER_DRIVER_PATH + 'RouterL3AgentDriver',
    PROVIDER_OPENFLOW: ROUTER_DRIVER_PATH + 'RouterOpenFlowDriver'
}

ROUTER_DRIVERS = {}

STATUS_ACTIVE = nconst.ROUTER_STATUS_ACTIVE
STATUS_ERROR = nconst.ROUTER_STATUS_ERROR


class RouterMixin(extraroute_db.ExtraRoute_db_mixin,
                  l3_gwmode_db.L3_NAT_db_mixin):

    def create_router(self, context, router):
        """Create a new router entry on DB, and create it on OFC."""
        LOG.debug(_("RouterMixin.create_router() called, "
                    "router=%s ."), router)
        tenant_id = self._get_tenant_id_for_create(context, router['router'])

        provider = get_provider_with_default(
            router['router'].get(ext_provider.ROUTER_PROVIDER))
        driver = get_driver_by_provider(provider)

        with context.session.begin(subtransactions=True):
            new_router = super(RouterMixin, self).create_router(context,
                                                                router)
            new_router['gw_port'] = self._get_gw_port_detail(
                context, driver, new_router['gw_port_id'])
            rdb.add_router_provider_binding(context.session,
                                            provider, str(new_router['id']))
            self._extend_router_dict_provider(new_router, provider)

        # create router on the network controller
        try:
            return driver.create_router(context, tenant_id, new_router)
        except nexc.RouterOverLimit:
            with excutils.save_and_reraise_exception():
                super(RouterMixin, self).delete_router(context,
                                                       new_router['id'])

    def update_router(self, context, router_id, router):
        LOG.debug(_("RouterMixin.update_router() called, "
                    "id=%(id)s, router=%(router)s ."),
                  {'id': router_id, 'router': router})

        with context.session.begin(subtransactions=True):
            old_rtr = super(RouterMixin, self).get_router(context, router_id)
            provider = old_rtr[ext_provider.ROUTER_PROVIDER]
            driver = get_driver_by_provider(provider)
            old_rtr['gw_port'] = self._get_gw_port_detail(
                context, driver, old_rtr['gw_port_id'])
            new_rtr = super(RouterMixin, self).update_router(
                context, router_id, router)
            new_rtr['gw_port'] = self._get_gw_port_detail(
                context, driver, new_rtr['gw_port_id'])
        driver.update_router(context, router_id, old_rtr, new_rtr)
        return new_rtr

    def delete_router(self, context, router_id):
        LOG.debug(_("RouterMixin.delete_router() called, id=%s."), router_id)

        router = super(RouterMixin, self).get_router(context, router_id)
        tenant_id = router['tenant_id']
        # Since l3_db.delete_router() has no interaction with the plugin layer,
        # we need to check if the router can be deleted first.
        self._check_router_in_use(context, router_id)
        driver = self._get_router_driver_by_id(context, router_id)
        # If gw_port exists, remove it.
        gw_port = self._get_gw_port(context, router_id)
        if gw_port:
            driver.delete_interface(context, router_id, gw_port)
        driver.delete_router(context, router_id, router)

        super(RouterMixin, self).delete_router(context, router_id)

        self._cleanup_ofc_tenant(context, tenant_id)

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("RouterMixin.add_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  {'id': router_id, 'interface': interface_info})
        return super(RouterMixin, self).add_router_interface(
            context, router_id, interface_info)

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(_("RouterMixin.remove_router_interface() called, "
                    "id=%(id)s, interface=%(interface)s."),
                  {'id': router_id, 'interface': interface_info})
        return super(RouterMixin, self).remove_router_interface(
            context, router_id, interface_info)

    def create_router_port(self, context, port):
        # This method is called from plugin.create_port()
        router_id = port['device_id']
        driver = self._get_router_driver_by_id(context, router_id)
        port = driver.add_interface(context, router_id, port)
        return port

    def delete_router_port(self, context, port):
        # This method is called from plugin.delete_port()
        router_id = port['device_id']
        driver = self._get_router_driver_by_id(context, router_id)
        return driver.delete_interface(context, router_id, port)

    def _get_gw_port_detail(self, context, driver, gw_port_id):
        if not gw_port_id or not driver.need_gw_info:
            return
        ctx_elevated = context.elevated()
        gw_port = self._get_port(ctx_elevated, gw_port_id)
        # At this moment gw_port has been created, so it is guaranteed
        # that fixed_ip is assigned for the gw_port.
        ext_subnet_id = gw_port['fixed_ips'][0]['subnet_id']
        ext_subnet = self._get_subnet(ctx_elevated, ext_subnet_id)
        gw_info = {'network_id': gw_port['network_id'],
                   'ip_address': gw_port['fixed_ips'][0]['ip_address'],
                   'mac_address': gw_port['mac_address'],
                   'cidr': ext_subnet['cidr'],
                   'gateway_ip': ext_subnet['gateway_ip']}
        return gw_info

    def _get_gw_port(self, context, router_id):
        device_filter = {'device_id': [router_id],
                         'device_owner': [l3_db.DEVICE_OWNER_ROUTER_GW]}
        ports = self.get_ports(context.elevated(), filters=device_filter)
        if ports:
            return ports[0]

    def _check_router_in_use(self, context, router_id):
        with context.session.begin(subtransactions=True):
            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_filter = {'device_id': [router_id],
                             'device_owner': [l3_db.DEVICE_OWNER_ROUTER_INTF]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)

    def _get_router_for_floatingip(self, context, internal_port,
                                   internal_subnet_id,
                                   external_network_id):
        """Get a router for a requested floating IP.

        OpenFlow vrouter does not support NAT, so we need to exclude them
        from candidate routers for floating IP association.
        This method is called in l3_db.get_assoc_data().
        """
        subnet_db = self._get_subnet(context, internal_subnet_id)
        if not subnet_db['gateway_ip']:
            msg = (_('Cannot add floating IP to port on subnet %s '
                     'which has no gateway_ip') % internal_subnet_id)
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

        # find router interface ports on this network
        router_intf_qry = context.session.query(models_v2.Port)
        router_intf_ports = router_intf_qry.filter_by(
            network_id=internal_port['network_id'],
            device_owner=l3_db.DEVICE_OWNER_ROUTER_INTF)

        for intf_p in router_intf_ports:
            if intf_p['fixed_ips'][0]['subnet_id'] == internal_subnet_id:
                router_id = intf_p['device_id']
                router_gw_qry = context.session.query(models_v2.Port)
                has_gw_port = router_gw_qry.filter_by(
                    network_id=external_network_id,
                    device_id=router_id,
                    device_owner=l3_db.DEVICE_OWNER_ROUTER_GW).count()
                driver = self._get_router_driver_by_id(context, router_id)
                if (has_gw_port and driver.floating_ip_support()):
                    return router_id

        raise l3.ExternalGatewayForFloatingIPNotFound(
            subnet_id=internal_subnet_id,
            external_network_id=external_network_id,
            port_id=internal_port['id'])

    def _get_sync_routers(self, context, router_ids=None, active=None):
        """Query routers and their gw ports for l3 agent.

        The difference from the superclass in l3_db is that this method
        only lists routers hosted on l3-agents.
        """
        router_list = super(RouterMixin, self)._get_sync_routers(
            context, router_ids, active)
        if router_list:
            _router_ids = [r['id'] for r in router_list]
            agent_routers = rdb.get_routers_by_provider(
                context.session, 'l3-agent',
                router_ids=_router_ids)
            router_list = [r for r in router_list
                           if r['id'] in agent_routers]
        return router_list

    def _get_router_driver_by_id(self, context, router_id):
        provider = self._get_provider_by_router_id(context, router_id)
        return get_driver_by_provider(provider)

    def _get_provider_by_router_id(self, context, router_id):
        return rdb.get_provider_by_router(context.session, router_id)

    def _extend_router_dict_provider(self, router_res, provider):
        router_res[ext_provider.ROUTER_PROVIDER] = provider

    def extend_router_dict_provider(self, router_res, router_db):
        # NOTE: router_db.provider is None just after creating a router,
        # so we need to skip setting router_provider here.
        if not router_db.provider:
            return
        self._extend_router_dict_provider(router_res,
                                          router_db.provider['provider'])

    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.ROUTERS, [extend_router_dict_provider])


class L3AgentSchedulerDbMixin(l3_agentschedulers_db.L3AgentSchedulerDbMixin):

    def auto_schedule_routers(self, context, host, router_ids):
        router_ids = rdb.get_routers_by_provider(
            context.session, nconst.ROUTER_PROVIDER_L3AGENT, router_ids)
        # If no l3-agent hosted router, there is no need to schedule.
        if not router_ids:
            return
        return super(L3AgentSchedulerDbMixin, self).auto_schedule_routers(
            context, host, router_ids)

    def schedule_router(self, context, router, candidates=None):
        if (self._get_provider_by_router_id(context, router) ==
            nconst.ROUTER_PROVIDER_L3AGENT):
            return super(L3AgentSchedulerDbMixin, self).schedule_router(
                context, router, candidates=candidates)

    def add_router_to_l3_agent(self, context, id, router_id):
        provider = self._get_provider_by_router_id(context, router_id)
        if provider != nconst.ROUTER_PROVIDER_L3AGENT:
            raise nexc.RouterProviderMismatch(
                router_id=router_id, provider=provider,
                expected_provider=nconst.ROUTER_PROVIDER_L3AGENT)
        return super(L3AgentSchedulerDbMixin, self).add_router_to_l3_agent(
            context, id, router_id)


class L3AgentNotifyAPI(l3_rpc_agent_api.L3AgentNotifyAPI):

    def _notification(self, context, method, router_ids, operation,
                      shuffle_agents):
        """Notify all the agents that are hosting the routers.

        _notification() is called in L3 db plugin for all routers regardless
        the routers are hosted on l3 agents or not. When the routers are
        not hosted on l3 agents, there is no need to notify.
        This method filters routers not hosted by l3 agents.
        """
        router_ids = rdb.get_routers_by_provider(
            context.session, nconst.ROUTER_PROVIDER_L3AGENT, router_ids)
        super(L3AgentNotifyAPI, self)._notification(
            context, method, router_ids, operation, shuffle_agents)


def load_driver(plugin, ofc_manager):

    if (PROVIDER_OPENFLOW in ROUTER_DRIVER_MAP and
        not ofc_manager.driver.router_supported):
        LOG.warning(
            _('OFC does not support router with provider=%(provider)s, '
              'so removed it from supported provider '
              '(new router driver map=%(driver_map)s)'),
            {'provider': PROVIDER_OPENFLOW,
             'driver_map': ROUTER_DRIVER_MAP})
        del ROUTER_DRIVER_MAP[PROVIDER_OPENFLOW]

    if config.PROVIDER.default_router_provider not in ROUTER_DRIVER_MAP:
        LOG.error(_('default_router_provider %(default)s is supported! '
                    'Please specify one of %(supported)s'),
                  {'default': config.PROVIDER.default_router_provider,
                   'supported': ROUTER_DRIVER_MAP.keys()})
        raise SystemExit(1)

    enabled_providers = (set(config.PROVIDER.router_providers +
                             [config.PROVIDER.default_router_provider]) &
                         set(ROUTER_DRIVER_MAP.keys()))

    for driver in enabled_providers:
        driver_klass = importutils.import_class(ROUTER_DRIVER_MAP[driver])
        ROUTER_DRIVERS[driver] = driver_klass(plugin, ofc_manager)

    LOG.info(_('Enabled router drivers: %s'), ROUTER_DRIVERS.keys())

    if not ROUTER_DRIVERS:
        LOG.error(_('No router provider is enabled. neutron-server terminated!'
                    ' (supported=%(supported)s, configured=%(config)s)'),
                  {'supported': ROUTER_DRIVER_MAP.keys(),
                   'config': config.PROVIDER.router_providers})
        raise SystemExit(1)


def get_provider_with_default(provider):
    if not attr.is_attr_set(provider):
        provider = config.PROVIDER.default_router_provider
    elif provider not in ROUTER_DRIVERS:
        raise nexc.ProviderNotFound(provider=provider)
    return provider


def get_driver_by_provider(provider):
    if provider is None:
        provider = config.PROVIDER.default_router_provider
    elif provider not in ROUTER_DRIVERS:
        raise nexc.ProviderNotFound(provider=provider)
    return ROUTER_DRIVERS[provider]
