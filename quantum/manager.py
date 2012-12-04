# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc
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
# @author: Somik Behera, Nicira Networks, Inc.

from quantum.common.exceptions import ClassNotFound
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import periodic_task
from quantum.plugins.common import constants


LOG = logging.getLogger(__name__)


class Manager(periodic_task.PeriodicTasks):

    # Set RPC API version to 1.0 by default.
    RPC_API_VERSION = '1.0'

    def __init__(self, host=None):
        if not host:
            host = cfg.CONF.host
        self.host = host
        super(Manager, self).__init__()

    def periodic_tasks(self, context, raise_on_error=False):
        self.run_periodic_tasks(context, raise_on_error=raise_on_error)

    def init_host(self):
        """Handle initialization if this is a standalone service.

        Child classes should override this method.

        """
        pass

    def after_start(self):
        """Handler post initialization stuff.

        Child classes can override this method.
        """
        pass


class QuantumManager(object):
    """
    Quantum's Manager class is responsible for parsing a config file and
    instantiating the correct plugin that concretely implement
    quantum_plugin_base class.
    The caller should make sure that QuantumManager is a singleton.
    """
    _instance = None

    def __init__(self, options=None, config_file=None):
        # If no options have been provided, create an empty dict
        if not options:
            options = {}

        # NOTE(jkoelker) Testing for the subclass with the __subclasshook__
        #                breaks tach monitoring. It has been removed
        #                intentianally to allow v2 plugins to be monitored
        #                for performance metrics.
        plugin_provider = cfg.CONF.core_plugin
        LOG.debug(_("Plugin location: %s"), plugin_provider)
        # If the plugin can't be found let them know gracefully
        try:
            LOG.info(_("Loading Plugin: %s"), plugin_provider)
            plugin_klass = importutils.import_class(plugin_provider)
        except ClassNotFound:
            LOG.exception(_("Error loading plugin"))
            raise Exception(_("Plugin not found.  You can install a "
                            "plugin with: pip install <plugin-name>\n"
                            "Example: pip install quantum-sample-plugin"))
        self.plugin = plugin_klass()

        # core plugin as a part of plugin collection simplifies
        # checking extensions
        # TODO (enikanorov): make core plugin the same as
        # the rest of service plugins
        self.service_plugins = {constants.CORE: self.plugin}
        self._load_service_plugins()

    def _load_service_plugins(self):
        plugin_providers = cfg.CONF.service_plugins
        LOG.debug(_("Loading service plugins: %s"), plugin_providers)
        for provider in plugin_providers:
            if provider == '':
                continue
            try:
                LOG.info(_("Loading Plugin: %s"), provider)
                plugin_class = importutils.import_class(provider)
            except ClassNotFound:
                LOG.exception(_("Error loading plugin"))
                raise Exception(_("Plugin not found."))
            plugin_inst = plugin_class()

            # only one implementation of svc_type allowed
            # specifying more than one plugin
            # for the same type is a fatal exception
            if plugin_inst.get_plugin_type() in self.service_plugins:
                raise Exception(_("Multiple plugins for service "
                                "%s were configured"),
                                plugin_inst.get_plugin_type())

            self.service_plugins[plugin_inst.get_plugin_type()] = plugin_inst

            LOG.debug(_("Successfully loaded %(type)s plugin. "
                        "Description: %(desc)s"),
                      {"type": plugin_inst.get_plugin_type(),
                       "desc": plugin_inst.get_plugin_description()})

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def get_plugin(cls):
        return cls.get_instance().plugin

    @classmethod
    def get_service_plugins(cls):
        return cls.get_instance().service_plugins
