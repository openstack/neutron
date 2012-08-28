# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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

import logging

from quantum.common import exceptions as exc

from quantum.api.v2 import attributes
from quantum.common.utils import find_config_file
from quantum.db import api as db
from quantum.db import db_base_plugin_v2
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantum.plugins.metaplugin.common import config
from quantum.plugins.metaplugin import meta_db_v2
from quantum.plugins.metaplugin.meta_models_v2 import Flavor
from quantum import policy

LOG = logging.getLogger("metaplugin")


class MetaPluginV2(db_base_plugin_v2.QuantumDbPluginV2):
    def __init__(self, configfile=None):
        LOG.debug("Start initializing metaplugin")
        options = {"sql_connection": cfg.CONF.DATABASE.sql_connection}
        options.update({'base': models_v2.model_base.BASEV2})
        sql_max_retries = cfg.CONF.DATABASE.sql_max_retries
        options.update({"sql_max_retries": sql_max_retries})
        reconnect_interval = cfg.CONF.DATABASE.reconnect_interval
        options.update({"reconnect_interval": reconnect_interval})
        self.supported_extension_aliases = \
            cfg.CONF.META.supported_extension_aliases.split(',')
        self.supported_extension_aliases.append('flavor')

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

        db.configure_db(options)
        self.extension_map = {}
        if not cfg.CONF.META.extension_map == '':
            extension_list = [method_set.split(':')
                              for method_set
                              in cfg.CONF.META.extension_map.split(',')]
            for method_name, flavor in extension_list:
                self.extension_map[method_name] = flavor

        self.default_flavor = cfg.CONF.META.default_flavor

        if not self.default_flavor in self.plugins:
            raise exc.Invalid('default_flavor %s is not plugin list' %
                              self.default_flavor)

    def _load_plugin(self, plugin_provider):
        LOG.debug("Plugin location:%s", plugin_provider)
        # If the plugin can't be found let them know gracefully
        try:
            LOG.info("Loading Plugin: %s" % plugin_provider)
            plugin_klass = importutils.import_class(plugin_provider)
        except exc.ClassNotFound:
            LOG.exception("Error loading plugin")
            raise Exception("Plugin not found.  You can install a "
                            "plugin with: pip install <plugin-name>\n"
                            "Example: pip install quantum-sample-plugin")
        return plugin_klass()

    def _get_plugin(self, flavor):
        if not flavor in self.plugins:
            raise Exception("Plugin for flavor %s not found." % flavor)
        return self.plugins[flavor]

    def __getattr__(self, key):
        # At first,  try to pickup extension command from extension_map

        if key in self.extension_map:
            flavor = self.extension_map[key]
            plugin = self._get_plugin(flavor)
            if plugin and hasattr(plugin, key):
                return getattr(plugin, key)

        # Second, try to match extension method in order of pluign list

        for flavor, plugin in self.plugins.items():
            if hasattr(plugin, key):
                return getattr(plugin, key)

        # if no plugin support the method, then raise
        raise AttributeError

    def _extend_network_dict(self, context, network):
        network['flavor:id'] = self._get_flavor_by_network_id(network['id'])

    def create_network(self, context, network):
        n = network['network']
        flavor = n.get('flavor:id')
        if not str(flavor) in self.plugins:
            flavor = self.default_flavor
        plugin = self._get_plugin(flavor)
        net = plugin.create_network(context, network)
        LOG.debug("Created network: %s with flavor %s " % (net['id'], flavor))
        try:
            meta_db_v2.add_flavor_binding(flavor, str(net['id']))
        except Exception as e:
            LOG.error('failed to add flavor bindings')
            plugin.delete_network(context, net['id'])
            raise Exception('Failed to create network')

        LOG.debug("Created network: %s" % net['id'])
        self._extend_network_dict(context, net)
        return net

    def delete_network(self, context, id):
        flavor = meta_db_v2.get_flavor_by_network(id)
        plugin = self._get_plugin(flavor)
        return plugin.delete_network(context, id)

    def get_network(self, context, id, fields=None):
        flavor = meta_db_v2.get_flavor_by_network(id)
        plugin = self._get_plugin(flavor)
        net = plugin.get_network(context, id, fields)
        if not fields or 'flavor:id' in fields:
            self._extend_network_dict(context, net)
        return net

    def get_networks_with_flavor(self, context, filters=None,
                                 fields=None):
        collection = self._model_query(context, models_v2.Network)
        collection = collection.join(Flavor,
                                     models_v2.Network.id == Flavor.network_id)
        if filters:
            for key, value in filters.iteritems():
                if key == 'flavor:id':
                    column = Flavor.flavor
                else:
                    column = getattr(models_v2.Network, key, None)
                if column:
                    collection = collection.filter(column.in_(value))
        return [self._make_network_dict(c, fields) for c in collection.all()]

    def get_networks(self, context, filters=None, fields=None):
        nets = self.get_networks_with_flavor(context, filters, None)
        return [self.get_network(context, net['id'], fields)
                for net in nets]

    def _get_flavor_by_network_id(self, network_id):
        return meta_db_v2.get_flavor_by_network(network_id)

    def _get_plugin_by_network_id(self, network_id):
        flavor = self._get_flavor_by_network_id(network_id)
        return self._get_plugin(flavor)

    def create_port(self, context, port):
        p = port['port']
        if not 'network_id' in p:
            raise exc.NotFound
        plugin = self._get_plugin_by_network_id(p['network_id'])
        return plugin.create_port(context, port)

    def update_port(self, context, id, port):
        port_in_db = self.get_port(context, id)
        plugin = self._get_plugin_by_network_id(port_in_db['network_id'])
        return plugin.update_port(context, id, port)

    def delete_port(self, context, id):
        port_in_db = self.get_port(context, id)
        plugin = self._get_plugin_by_network_id(port_in_db['network_id'])
        return plugin.delete_port(context, id)

    def create_subnet(self, context, subnet):
        s = subnet['subnet']
        if not 'network_id' in s:
            raise exc.NotFound
        plugin = self._get_plugin_by_network_id(s['network_id'])
        return plugin.create_subnet(context, subnet)

    def update_subnet(self, context, id, subnet):
        s = self.get_subnet(context, id)
        plugin = self._get_plugin_by_network_id(s['network_id'])
        return plugin.update_subnet(context, id, subnet)

    def delete_subnet(self, context, id):
        s = self.get_subnet(context, id)
        plugin = self._get_plugin_by_network_id(s['network_id'])
        return plugin.delete_subnet(context, id)
