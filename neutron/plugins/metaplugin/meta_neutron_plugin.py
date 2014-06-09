# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012, Nachi Ueno, NTT MCL, Inc.
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

from oslo.config import cfg

from neutron.common import exceptions as exc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import extraroute_db
from neutron.db import l3_db
from neutron.db import models_v2
from neutron.extensions.flavor import (FLAVOR_NETWORK, FLAVOR_ROUTER)
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.metaplugin.common import config  # noqa
from neutron.plugins.metaplugin import meta_db_v2
from neutron.plugins.metaplugin.meta_models_v2 import (NetworkFlavor,
                                                       RouterFlavor)


LOG = logging.getLogger(__name__)


# Hooks used to select records which belong a target plugin.
def _meta_network_model_hook(context, original_model, query):
    return query.outerjoin(NetworkFlavor,
                           NetworkFlavor.network_id == models_v2.Network.id)


def _meta_port_model_hook(context, original_model, query):
    return query.join(NetworkFlavor,
                      NetworkFlavor.network_id == models_v2.Port.network_id)


def _meta_flavor_filter_hook(query, filters):
    if FLAVOR_NETWORK in filters:
        return query.filter(NetworkFlavor.flavor ==
                            filters[FLAVOR_NETWORK][0])
    return query


# Metaplugin  Exceptions
class FlavorNotFound(exc.NotFound):
    message = _("Flavor %(flavor)s could not be found")


class FaildToAddFlavorBinding(exc.NeutronException):
    message = _("Failed to add flavor binding")


class MetaPluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                   external_net_db.External_net_db_mixin,
                   extraroute_db.ExtraRoute_db_mixin):

    def __init__(self, configfile=None):
        super(MetaPluginV2, self).__init__()
        LOG.debug(_("Start initializing metaplugin"))
        self.supported_extension_aliases = ['flavor', 'external-net']
        if cfg.CONF.META.supported_extension_aliases:
            cfg_aliases = cfg.CONF.META.supported_extension_aliases.split(',')
            self.supported_extension_aliases += cfg_aliases

        # Ignore config option overapping
        def _is_opt_registered(opts, opt):
            if opt.dest in opts:
                return True
            else:
                return False

        cfg._is_opt_registered = _is_opt_registered

        # Keep existing tables if multiple plugin use same table name.
        db.model_base.NeutronBase.__table_args__ = {'keep_existing': True}

        self.plugins = {}

        plugin_list = [plugin_set.split(':')
                       for plugin_set
                       in cfg.CONF.META.plugin_list.split(',')]
        self.rpc_flavor = cfg.CONF.META.rpc_flavor
        topic_save = topics.PLUGIN
        topic_fake = topic_save + '-metaplugin'
        for flavor, plugin_provider in plugin_list:
            # Rename topic used by a plugin other than rpc_flavor during
            # loading the plugin instance if rpc_flavor is specified.
            # This enforces the plugin specified by rpc_flavor is only
            # consumer of 'q-plugin'. It is a bit tricky but there is no
            # bad effect.
            if self.rpc_flavor and self.rpc_flavor != flavor:
                topics.PLUGIN = topic_fake
            self.plugins[flavor] = self._load_plugin(plugin_provider)
            topics.PLUGIN = topic_save

        self.l3_plugins = {}
        if cfg.CONF.META.l3_plugin_list:
            l3_plugin_list = [plugin_set.split(':')
                              for plugin_set
                              in cfg.CONF.META.l3_plugin_list.split(',')]
            for flavor, plugin_provider in l3_plugin_list:
                if flavor in self.plugins:
                    self.l3_plugins[flavor] = self.plugins[flavor]
                else:
                    # For l3 only plugin
                    self.l3_plugins[flavor] = self._load_plugin(
                        plugin_provider)

        self.default_flavor = cfg.CONF.META.default_flavor
        if self.default_flavor not in self.plugins:
            raise exc.Invalid(_('default_flavor %s is not plugin list') %
                              self.default_flavor)

        if self.l3_plugins:
            self.default_l3_flavor = cfg.CONF.META.default_l3_flavor
            if self.default_l3_flavor not in self.l3_plugins:
                raise exc.Invalid(_('default_l3_flavor %s is not plugin list')
                                  % self.default_l3_flavor)
            self.supported_extension_aliases += ['router', 'ext-gw-mode',
                                                 'extraroute']

        if self.rpc_flavor and self.rpc_flavor not in self.plugins:
            raise exc.Invalid(_('rpc_flavor %s is not plugin list') %
                              self.rpc_flavor)

        self.extension_map = {}
        if not cfg.CONF.META.extension_map == '':
            extension_list = [method_set.split(':')
                              for method_set
                              in cfg.CONF.META.extension_map.split(',')]
            for method_name, flavor in extension_list:
                self.extension_map[method_name] = flavor

        # Register hooks.
        # The hooks are applied for each target plugin instance when
        # calling the base class to get networks/ports so that only records
        # which belong to the plugin are selected.
        #NOTE: Doing registration here (within __init__()) is to avoid
        # registration when merely importing this file. This is only
        # for running whole unit tests.
        db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
            models_v2.Network,
            'metaplugin_net',
            _meta_network_model_hook,
            None,
            _meta_flavor_filter_hook)
        db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
            models_v2.Port,
            'metaplugin_port',
            _meta_port_model_hook,
            None,
            _meta_flavor_filter_hook)

    def _load_plugin(self, plugin_provider):
        LOG.debug(_("Plugin location: %s"), plugin_provider)
        plugin_klass = importutils.import_class(plugin_provider)
        return plugin_klass()

    def _get_plugin(self, flavor):
        if flavor not in self.plugins:
            raise FlavorNotFound(flavor=flavor)
        return self.plugins[flavor]

    def _get_l3_plugin(self, flavor):
        if flavor not in self.l3_plugins:
            raise FlavorNotFound(flavor=flavor)
        return self.l3_plugins[flavor]

    def __getattr__(self, key):
        # At first,  try to pickup extension command from extension_map

        if key in self.extension_map:
            flavor = self.extension_map[key]
            plugin = self._get_plugin(flavor)
            if plugin and hasattr(plugin, key):
                return getattr(plugin, key)

        # Second, try to match extension method in order of plugin list
        for flavor, plugin in self.plugins.items():
            if hasattr(plugin, key):
                return getattr(plugin, key)

        # if no plugin support the method, then raise
        raise AttributeError

    def _extend_network_dict(self, context, network):
        flavor = self._get_flavor_by_network_id(context, network['id'])
        network[FLAVOR_NETWORK] = flavor

    def start_rpc_listener(self):
        return self.plugins[self.rpc_flavor].start_rpc_listener()

    def rpc_workers_supported(self):
        #NOTE: If a plugin which supports multiple RPC workers is desired
        # to handle RPC, rpc_flavor must be specified.
        return (self.rpc_flavor and
                self.plugins[self.rpc_flavor].rpc_workers_supported())

    def create_network(self, context, network):
        n = network['network']
        flavor = n.get(FLAVOR_NETWORK)
        if str(flavor) not in self.plugins:
            flavor = self.default_flavor
        plugin = self._get_plugin(flavor)
        net = plugin.create_network(context, network)
        LOG.debug(_("Created network: %(net_id)s with flavor "
                    "%(flavor)s"), {'net_id': net['id'], 'flavor': flavor})
        try:
            meta_db_v2.add_network_flavor_binding(context.session,
                                                  flavor, str(net['id']))
        except Exception:
            LOG.exception(_('Failed to add flavor bindings'))
            plugin.delete_network(context, net['id'])
            raise FaildToAddFlavorBinding()

        LOG.debug(_("Created network: %s"), net['id'])
        self._extend_network_dict(context, net)
        return net

    def update_network(self, context, id, network):
        flavor = meta_db_v2.get_flavor_by_network(context.session, id)
        plugin = self._get_plugin(flavor)
        return plugin.update_network(context, id, network)

    def delete_network(self, context, id):
        flavor = meta_db_v2.get_flavor_by_network(context.session, id)
        plugin = self._get_plugin(flavor)
        return plugin.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        flavor = meta_db_v2.get_flavor_by_network(context.session, id)
        plugin = self._get_plugin(flavor)
        net = plugin.get_network(context, id, fields)
        net['id'] = id
        if not fields or FLAVOR_NETWORK in fields:
            self._extend_network_dict(context, net)
        if fields and 'id' not in fields:
            del net['id']
        return net

    def get_networks(self, context, filters=None, fields=None):
        nets = []
        for flavor, plugin in self.plugins.items():
            if (filters and FLAVOR_NETWORK in filters and
                    not flavor in filters[FLAVOR_NETWORK]):
                continue
            if filters:
                #NOTE: copy each time since a target plugin may modify
                # plugin_filters.
                plugin_filters = filters.copy()
            else:
                plugin_filters = {}
            plugin_filters[FLAVOR_NETWORK] = [flavor]
            plugin_nets = plugin.get_networks(context, plugin_filters, fields)
            for net in plugin_nets:
                if not fields or FLAVOR_NETWORK in fields:
                    net[FLAVOR_NETWORK] = flavor
                nets.append(net)
        return nets

    def _get_flavor_by_network_id(self, context, network_id):
        return meta_db_v2.get_flavor_by_network(context.session, network_id)

    def _get_flavor_by_router_id(self, context, router_id):
        return meta_db_v2.get_flavor_by_router(context.session, router_id)

    def _get_plugin_by_network_id(self, context, network_id):
        flavor = self._get_flavor_by_network_id(context, network_id)
        return self._get_plugin(flavor)

    def create_port(self, context, port):
        p = port['port']
        if 'network_id' not in p:
            raise exc.NotFound
        plugin = self._get_plugin_by_network_id(context, p['network_id'])
        return plugin.create_port(context, port)

    def update_port(self, context, id, port):
        port_in_db = self._get_port(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                port_in_db['network_id'])
        return plugin.update_port(context, id, port)

    def delete_port(self, context, id, l3_port_check=True):
        port_in_db = self._get_port(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                port_in_db['network_id'])
        return plugin.delete_port(context, id, l3_port_check)

    # This is necessary since there is a case that
    # NeutronManager.get_plugin()._make_port_dict is called.
    def _make_port_dict(self, port):
        context = neutron_context.get_admin_context()
        plugin = self._get_plugin_by_network_id(context,
                                                port['network_id'])
        return plugin._make_port_dict(port)

    def get_port(self, context, id, fields=None):
        port_in_db = self._get_port(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                port_in_db['network_id'])
        return plugin.get_port(context, id, fields)

    def get_ports(self, context, filters=None, fields=None):
        all_ports = []
        for flavor, plugin in self.plugins.items():
            if filters:
                #NOTE: copy each time since a target plugin may modify
                # plugin_filters.
                plugin_filters = filters.copy()
            else:
                plugin_filters = {}
            plugin_filters[FLAVOR_NETWORK] = [flavor]
            ports = plugin.get_ports(context, plugin_filters, fields)
            all_ports += ports
        return all_ports

    def create_subnet(self, context, subnet):
        s = subnet['subnet']
        if 'network_id' not in s:
            raise exc.NotFound
        plugin = self._get_plugin_by_network_id(context,
                                                s['network_id'])
        return plugin.create_subnet(context, subnet)

    def update_subnet(self, context, id, subnet):
        s = self.get_subnet(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                s['network_id'])
        return plugin.update_subnet(context, id, subnet)

    def delete_subnet(self, context, id):
        s = self.get_subnet(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                s['network_id'])
        return plugin.delete_subnet(context, id)

    def _extend_router_dict(self, context, router):
        flavor = self._get_flavor_by_router_id(context, router['id'])
        router[FLAVOR_ROUTER] = flavor

    def create_router(self, context, router):
        r = router['router']
        flavor = r.get(FLAVOR_ROUTER)
        if str(flavor) not in self.l3_plugins:
            flavor = self.default_l3_flavor
        plugin = self._get_l3_plugin(flavor)
        r_in_db = plugin.create_router(context, router)
        LOG.debug(_("Created router: %(router_id)s with flavor "
                    "%(flavor)s"),
                  {'router_id': r_in_db['id'], 'flavor': flavor})
        try:
            meta_db_v2.add_router_flavor_binding(context.session,
                                                 flavor, str(r_in_db['id']))
        except Exception:
            LOG.exception(_('Failed to add flavor bindings'))
            plugin.delete_router(context, r_in_db['id'])
            raise FaildToAddFlavorBinding()

        LOG.debug(_("Created router: %s"), r_in_db['id'])
        self._extend_router_dict(context, r_in_db)
        return r_in_db

    def update_router(self, context, id, router):
        flavor = meta_db_v2.get_flavor_by_router(context.session, id)
        plugin = self._get_l3_plugin(flavor)
        return plugin.update_router(context, id, router)

    def delete_router(self, context, id):
        flavor = meta_db_v2.get_flavor_by_router(context.session, id)
        plugin = self._get_l3_plugin(flavor)
        return plugin.delete_router(context, id)

    def get_router(self, context, id, fields=None):
        flavor = meta_db_v2.get_flavor_by_router(context.session, id)
        plugin = self._get_l3_plugin(flavor)
        router = plugin.get_router(context, id, fields)
        if not fields or FLAVOR_ROUTER in fields:
            self._extend_router_dict(context, router)
        return router

    def get_routers_with_flavor(self, context, filters=None,
                                fields=None):
        collection = self._model_query(context, l3_db.Router)
        r_model = RouterFlavor
        collection = collection.join(r_model,
                                     l3_db.Router.id == r_model.router_id)
        if filters:
            for key, value in filters.iteritems():
                if key == FLAVOR_ROUTER:
                    column = RouterFlavor.flavor
                else:
                    column = getattr(l3_db.Router, key, None)
                if column:
                    collection = collection.filter(column.in_(value))
        return [self._make_router_dict(c, fields) for c in collection]

    def get_routers(self, context, filters=None, fields=None):
        routers = self.get_routers_with_flavor(context, filters,
                                               None)
        return [self.get_router(context, router['id'],
                                fields)
                for router in routers]
