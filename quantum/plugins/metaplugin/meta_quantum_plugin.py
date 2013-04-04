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

from quantum.common import exceptions as exc
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import extraroute_db
from quantum.db import l3_db
from quantum.db import models_v2
from quantum.extensions.flavor import (FLAVOR_NETWORK, FLAVOR_ROUTER)
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.plugins.metaplugin.common import config  # noqa
from quantum.plugins.metaplugin import meta_db_v2
from quantum.plugins.metaplugin.meta_models_v2 import (NetworkFlavor,
                                                       RouterFlavor)


LOG = logging.getLogger(__name__)


# Metaplugin  Exceptions
class FlavorNotFound(exc.NotFound):
    message = _("Flavor %(flavor)s could not be found")


class FaildToAddFlavorBinding(exc.QuantumException):
    message = _("Failed to add flavor binding")


class MetaPluginV2(db_base_plugin_v2.QuantumDbPluginV2,
                   extraroute_db.ExtraRoute_db_mixin):

    def __init__(self, configfile=None):
        LOG.debug(_("Start initializing metaplugin"))
        self.supported_extension_aliases = \
            cfg.CONF.META.supported_extension_aliases.split(',')
        self.supported_extension_aliases += ['flavor', 'router', 'extraroute']

        # Ignore config option overapping
        def _is_opt_registered(opts, opt):
            if opt.dest in opts:
                return True
            else:
                return False

        cfg._is_opt_registered = _is_opt_registered

        # Keep existing tables if multiple plugin use same table name.
        db.model_base.QuantumBase.__table_args__ = {'keep_existing': True}

        self.plugins = {}

        plugin_list = [plugin_set.split(':')
                       for plugin_set
                       in cfg.CONF.META.plugin_list.split(',')]
        for flavor, plugin_provider in plugin_list:
            self.plugins[flavor] = self._load_plugin(plugin_provider)
            # Needed to clear _ENGINE for each plugin
            db._ENGINE = None

        self.l3_plugins = {}
        l3_plugin_list = [plugin_set.split(':')
                          for plugin_set
                          in cfg.CONF.META.l3_plugin_list.split(',')]
        for flavor, plugin_provider in l3_plugin_list:
            if flavor in self.plugins:
                self.l3_plugins[flavor] = self.plugins[flavor]
            else:
                # For l3 only plugin
                self.l3_plugins[flavor] = self._load_plugin(plugin_provider)
                db._ENGINE = None

        self.default_flavor = cfg.CONF.META.default_flavor
        if self.default_flavor not in self.plugins:
            raise exc.Invalid(_('default_flavor %s is not plugin list') %
                              self.default_flavor)

        self.default_l3_flavor = cfg.CONF.META.default_l3_flavor
        if self.default_l3_flavor not in self.l3_plugins:
            raise exc.Invalid(_('default_l3_flavor %s is not plugin list') %
                              self.default_l3_flavor)

        db.configure_db()

        self.extension_map = {}
        if not cfg.CONF.META.extension_map == '':
            extension_list = [method_set.split(':')
                              for method_set
                              in cfg.CONF.META.extension_map.split(',')]
            for method_name, flavor in extension_list:
                self.extension_map[method_name] = flavor

        self.default_flavor = cfg.CONF.META.default_flavor

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

    def _is_l3_plugin(self, plugin):
        if hasattr(plugin, 'supported_extension_aliases'):
            return 'router' in plugin.supported_extension_aliases
        return False

    def create_network(self, context, network):
        n = network['network']
        flavor = n.get(FLAVOR_NETWORK)
        if str(flavor) not in self.plugins:
            flavor = self.default_flavor
        plugin = self._get_plugin(flavor)
        with context.session.begin(subtransactions=True):
            net = plugin.create_network(context, network)
            if not self._is_l3_plugin(plugin):
                self._process_l3_create(context, network['network'], net['id'])
                self._extend_network_dict_l3(context, net)
            LOG.debug(_("Created network: %(net_id)s with flavor "
                        "%(flavor)s"), {'net_id': net['id'], 'flavor': flavor})
            try:
                meta_db_v2.add_network_flavor_binding(context.session,
                                                      flavor, str(net['id']))
            except:
                LOG.exception(_('Failed to add flavor bindings'))
                plugin.delete_network(context, net['id'])
                raise FaildToAddFlavorBinding()

        LOG.debug(_("Created network: %s"), net['id'])
        self._extend_network_dict(context, net)
        return net

    def update_network(self, context, id, network):
        flavor = meta_db_v2.get_flavor_by_network(context.session, id)
        plugin = self._get_plugin(flavor)
        with context.session.begin(subtransactions=True):
            net = plugin.update_network(context, id, network)
            if not self._is_l3_plugin(plugin):
                self._process_l3_update(context, network['network'], id)
                self._extend_network_dict_l3(context, net)
        return net

    def delete_network(self, context, id):
        flavor = meta_db_v2.get_flavor_by_network(context.session, id)
        plugin = self._get_plugin(flavor)
        return plugin.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        flavor = meta_db_v2.get_flavor_by_network(context.session, id)
        plugin = self._get_plugin(flavor)
        net = plugin.get_network(context, id, fields)
        net['id'] = id
        if not fields or 'router:external' in fields:
            self._extend_network_dict_l3(context, net)
        if not fields or FLAVOR_NETWORK in fields:
            self._extend_network_dict(context, net)
        if fields and 'id' not in fields:
            del net['id']
        return net

    def get_networks_with_flavor(self, context, filters=None,
                                 fields=None):
        collection = self._model_query(context, models_v2.Network)
        model = NetworkFlavor
        collection = collection.join(model,
                                     models_v2.Network.id == model.network_id)
        if filters:
            for key, value in filters.iteritems():
                if key == FLAVOR_NETWORK:
                    column = NetworkFlavor.flavor
                else:
                    column = getattr(models_v2.Network, key, None)
                if column:
                    collection = collection.filter(column.in_(value))
        return [self._make_network_dict(c, fields) for c in collection.all()]

    def get_networks(self, context, filters=None, fields=None):
        nets = self.get_networks_with_flavor(context, filters, None)
        if filters:
            nets = self._filter_nets_l3(context, nets, filters)
        nets = [self.get_network(context, net['id'], fields)
                for net in nets]
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
        port_in_db = self.get_port(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                port_in_db['network_id'])
        return plugin.update_port(context, id, port)

    def delete_port(self, context, id, l3_port_check=True):
        port_in_db = self.get_port(context, id)
        plugin = self._get_plugin_by_network_id(context,
                                                port_in_db['network_id'])
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
            self.disassociate_floatingips(context, id)
        return plugin.delete_port(context, id, l3_port_check)

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
        with context.session.begin(subtransactions=True):
            r_in_db = plugin.create_router(context, router)
            LOG.debug(_("Created router: %(router_id)s with flavor "
                        "%(flavor)s"),
                      {'router_id': r_in_db['id'], 'flavor': flavor})
            meta_db_v2.add_router_flavor_binding(context.session,
                                                 flavor, str(r_in_db['id']))

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
        return [self._make_router_dict(c, fields) for c in collection.all()]

    def get_routers(self, context, filters=None, fields=None):
        routers = self.get_routers_with_flavor(context, filters,
                                               None)
        return [self.get_router(context, router['id'],
                                fields)
                for router in routers]
