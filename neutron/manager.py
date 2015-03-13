# Copyright 2011 VMware, Inc
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

import weakref

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import importutils

from neutron.common import utils
from neutron.i18n import _LE, _LI
from neutron.openstack.common import periodic_task
from neutron.plugins.common import constants

from stevedore import driver


LOG = logging.getLogger(__name__)

CORE_PLUGINS_NAMESPACE = 'neutron.core_plugins'


class Manager(periodic_task.PeriodicTasks):

    # Set RPC API version to 1.0 by default.
    target = oslo_messaging.Target(version='1.0')

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


def validate_post_plugin_load():
    """Checks if the configuration variables are valid.

    If the configuration is invalid then the method will return an error
    message. If all is OK then it will return None.
    """
    if ('dhcp_agents_per_network' in cfg.CONF and
        cfg.CONF.dhcp_agents_per_network <= 0):
        msg = _("dhcp_agents_per_network must be >= 1. '%s' "
                "is invalid.") % cfg.CONF.dhcp_agents_per_network
        return msg


def validate_pre_plugin_load():
    """Checks if the configuration variables are valid.

    If the configuration is invalid then the method will return an error
    message. If all is OK then it will return None.
    """
    if cfg.CONF.core_plugin is None:
        msg = _('Neutron core_plugin not configured!')
        return msg


class NeutronManager(object):
    """Neutron's Manager class.

    Neutron's Manager class is responsible for parsing a config file and
    instantiating the correct plugin that concretely implements
    neutron_plugin_base class.
    The caller should make sure that NeutronManager is a singleton.
    """
    _instance = None

    def __init__(self, options=None, config_file=None):
        # If no options have been provided, create an empty dict
        if not options:
            options = {}

        msg = validate_pre_plugin_load()
        if msg:
            LOG.critical(msg)
            raise Exception(msg)

        # NOTE(jkoelker) Testing for the subclass with the __subclasshook__
        #                breaks tach monitoring. It has been removed
        #                intentionally to allow v2 plugins to be monitored
        #                for performance metrics.
        plugin_provider = cfg.CONF.core_plugin
        LOG.info(_LI("Loading core plugin: %s"), plugin_provider)
        self.plugin = self._get_plugin_instance(CORE_PLUGINS_NAMESPACE,
                                                plugin_provider)
        msg = validate_post_plugin_load()
        if msg:
            LOG.critical(msg)
            raise Exception(msg)

        # core plugin as a part of plugin collection simplifies
        # checking extensions
        # TODO(enikanorov): make core plugin the same as
        # the rest of service plugins
        self.service_plugins = {constants.CORE: self.plugin}
        self._load_service_plugins()

    def _get_plugin_instance(self, namespace, plugin_provider):
        try:
            # Try to resolve plugin by name
            mgr = driver.DriverManager(namespace, plugin_provider)
            plugin_class = mgr.driver
        except RuntimeError as e1:
            # fallback to class name
            try:
                plugin_class = importutils.import_class(plugin_provider)
            except ImportError as e2:
                LOG.exception(_LE("Error loading plugin by name, %s"), e1)
                LOG.exception(_LE("Error loading plugin by class, %s"), e2)
                raise ImportError(_("Plugin not found."))
        return plugin_class()

    def _load_services_from_core_plugin(self):
        """Puts core plugin in service_plugins for supported services."""
        LOG.debug("Loading services supported by the core plugin")

        # supported service types are derived from supported extensions
        for ext_alias in getattr(self.plugin,
                                 "supported_extension_aliases", []):
            if ext_alias in constants.EXT_TO_SERVICE_MAPPING:
                service_type = constants.EXT_TO_SERVICE_MAPPING[ext_alias]
                self.service_plugins[service_type] = self.plugin
                LOG.info(_LI("Service %s is supported by the core plugin"),
                         service_type)

    def _load_service_plugins(self):
        """Loads service plugins.

        Starts from the core plugin and checks if it supports
        advanced services then loads classes provided in configuration.
        """
        # load services from the core plugin first
        self._load_services_from_core_plugin()

        plugin_providers = cfg.CONF.service_plugins
        LOG.debug("Loading service plugins: %s", plugin_providers)
        for provider in plugin_providers:
            if provider == '':
                continue

            LOG.info(_LI("Loading Plugin: %s"), provider)
            plugin_inst = self._get_plugin_instance('neutron.service_plugins',
                                                    provider)

            # only one implementation of svc_type allowed
            # specifying more than one plugin
            # for the same type is a fatal exception
            if plugin_inst.get_plugin_type() in self.service_plugins:
                raise ValueError(_("Multiple plugins for service "
                                   "%s were configured") %
                                 plugin_inst.get_plugin_type())

            self.service_plugins[plugin_inst.get_plugin_type()] = plugin_inst

            # search for possible agent notifiers declared in service plugin
            # (needed by agent management extension)
            if (hasattr(self.plugin, 'agent_notifiers') and
                    hasattr(plugin_inst, 'agent_notifiers')):
                self.plugin.agent_notifiers.update(plugin_inst.agent_notifiers)

            LOG.debug("Successfully loaded %(type)s plugin. "
                      "Description: %(desc)s",
                      {"type": plugin_inst.get_plugin_type(),
                       "desc": plugin_inst.get_plugin_description()})

    @classmethod
    @utils.synchronized("manager")
    def _create_instance(cls):
        if not cls.has_instance():
            cls._instance = cls()

    @classmethod
    def has_instance(cls):
        return cls._instance is not None

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    @classmethod
    def get_instance(cls):
        # double checked locking
        if not cls.has_instance():
            cls._create_instance()
        return cls._instance

    @classmethod
    def get_plugin(cls):
        # Return a weakref to minimize gc-preventing references.
        return weakref.proxy(cls.get_instance().plugin)

    @classmethod
    def get_service_plugins(cls):
        # Return weakrefs to minimize gc-preventing references.
        return dict((x, weakref.proxy(y))
                    for x, y in cls.get_instance().service_plugins.iteritems())
