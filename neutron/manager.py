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

from collections import defaultdict

from neutron_lib.plugins import constants as lib_const
from neutron_lib.plugins import directory
from neutron_lib.utils import runtime
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_service import periodic_task
from oslo_utils import excutils
from osprofiler import profiler

from neutron._i18n import _
from neutron.common import utils
from neutron.plugins.common import constants


LOG = logging.getLogger(__name__)

CORE_PLUGINS_NAMESPACE = 'neutron.core_plugins'


class ManagerMeta(profiler.TracedMeta,
                  type(periodic_task.PeriodicTasks)):  # type:ignore[misc]
    pass


class Manager(periodic_task.PeriodicTasks, metaclass=ManagerMeta):
    __trace_args__ = {"name": "rpc"}

    # Set RPC API version to 1.0 by default.
    target = oslo_messaging.Target(version='1.0')

    def __init__(self, host=None):
        if not host:
            host = cfg.CONF.host
        self.host = host
        conf = getattr(self, "conf", cfg.CONF)
        super().__init__(conf)

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

    def stop(self):
        """Handle stop.

        Child classes can override this method.
        """
        pass


def validate_pre_plugin_load():
    """Checks if the configuration variables are valid.

    If the configuration is invalid then the method will return an error
    message. If all is OK then it will return None.
    """
    if cfg.CONF.core_plugin is None:
        msg = _('Neutron core_plugin not configured!')
        return msg


class NeutronManager(metaclass=profiler.TracedMeta):
    """Neutron's Manager class.

    Neutron's Manager class is responsible for parsing a config file and
    instantiating the correct plugin that concretely implements
    neutron_plugin_base class.
    """
    # TODO(armax): use of the singleton pattern for this class is vestigial,
    # and it is mainly relied on by the unit tests. It is safer to get rid
    # of it once the entire codebase (neutron + subprojects) has switched
    # entirely to using the plugins directory.
    _instance = None
    __trace_args__ = {"name": "rpc"}

    def __init__(self, options=None, config_file=None):
        # Store instances of already loaded plugins to avoid instantiate same
        # plugin more than once
        self._loaded_plugins = {}
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
        LOG.info("Loading core plugin: %s", plugin_provider)
        # NOTE(armax): keep hold of the actual plugin object
        plugin = self._get_plugin_instance(CORE_PLUGINS_NAMESPACE,
                                           plugin_provider)
        directory.add_plugin(lib_const.CORE, plugin)

        # load services from the core plugin first
        self._load_services_from_core_plugin(plugin)
        self._load_service_plugins()
        # Used by pecan WSGI
        self.resource_plugin_mappings = {}
        self.resource_controller_mappings = {}
        self.path_prefix_resource_mappings = defaultdict(list)

    @staticmethod
    def load_class_for_provider(namespace, plugin_provider):
        """Loads plugin using alias or class name

        :param namespace: namespace where alias is defined
        :param plugin_provider: plugin alias or class name
        :returns: plugin that is loaded
        :raises ImportError: if fails to load plugin
        """

        try:
            return runtime.load_class_by_alias_or_classname(namespace,
                                                            plugin_provider)
        except ImportError:
            with excutils.save_and_reraise_exception():
                LOG.error("Plugin '%s' not found.", plugin_provider)

    def _get_plugin_class(self, namespace, plugin_provider):
        return self.load_class_for_provider(namespace, plugin_provider)

    def _get_plugin_instance(self, namespace, plugin_provider):
        plugin_class = self._get_plugin_class(namespace, plugin_provider)
        plugin_inst = self._loaded_plugins.get(plugin_class)
        if not plugin_inst:
            plugin_inst = plugin_class()
            self._loaded_plugins[plugin_class] = plugin_inst
        return plugin_inst

    def _load_services_from_core_plugin(self, plugin):
        """Puts core plugin in service_plugins for supported services."""
        LOG.debug("Loading services supported by the core plugin")

        # supported service types are derived from supported extensions
        for ext_alias in getattr(plugin, "supported_extension_aliases", []):
            if ext_alias in constants.EXT_TO_SERVICE_MAPPING:
                service_type = constants.EXT_TO_SERVICE_MAPPING[ext_alias]
                directory.add_plugin(service_type, plugin)
                LOG.info("Service %s is supported by the core plugin",
                         service_type)

    def _get_default_service_plugins(self):
        """Get default service plugins to be loaded."""
        core_plugin = directory.get_plugin()
        if core_plugin.has_native_datastore():
            return constants.DEFAULT_SERVICE_PLUGINS.keys()
        return []

    def _load_service_plugins(self):
        """Loads service plugins.

        Starts from the core plugin and checks if it supports
        advanced services then loads classes provided in configuration.
        """
        plugin_providers = cfg.CONF.service_plugins
        plugin_providers.extend(self._get_default_service_plugins())
        LOG.debug("Loading service plugins: %s", plugin_providers)
        for provider in plugin_providers:
            if provider == '':
                continue

            LOG.info("Loading Plugin: %s", provider)
            plugin_class = self._get_plugin_class(
                'neutron.service_plugins', provider)
            required_plugins = getattr(
                plugin_class, "required_service_plugins", [])
            for req_plugin in required_plugins:
                LOG.info("Loading service plugin %s, it is required by %s",
                         req_plugin, provider)
                self._create_and_add_service_plugin(req_plugin)
            # NOTE(liuyulong): adding one plugin multiple times does not have
            # bad effect for it. Since all the plugin has its own specific
            # unique name.
            self._create_and_add_service_plugin(provider)

    def _create_and_add_service_plugin(self, provider):
        plugin_inst = self._get_plugin_instance('neutron.service_plugins',
                                                provider)
        plugin_type = plugin_inst.get_plugin_type()
        directory.add_plugin(plugin_type, plugin_inst)

        # search for possible agent notifiers declared in service plugin
        # (needed by agent management extension)
        plugin = directory.get_plugin()
        if (hasattr(plugin, 'agent_notifiers') and
                hasattr(plugin_inst, 'agent_notifiers')):
            plugin.agent_notifiers.update(plugin_inst.agent_notifiers)

        # disable incompatible extensions in core plugin if any
        utils.disable_extension_by_service_plugin(plugin, plugin_inst)

        LOG.debug("Successfully loaded %(type)s plugin. "
                  "Description: %(desc)s",
                  {"type": plugin_type,
                   "desc": plugin_inst.get_plugin_description()})

    @classmethod
    @runtime.synchronized("manager")
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
    def set_plugin_for_resource(cls, resource, plugin):
        cls.get_instance().resource_plugin_mappings[resource] = plugin

    @classmethod
    def get_plugin_for_resource(cls, resource):
        return cls.get_instance().resource_plugin_mappings.get(resource)

    @classmethod
    def set_controller_for_resource(cls, resource, controller):
        cls.get_instance().resource_controller_mappings[resource] = controller

    @classmethod
    def get_controller_for_resource(cls, resource):
        resource = resource.replace('_', '-')
        res_ctrl_mappings = cls.get_instance().resource_controller_mappings
        # If no controller is found for resource, try replacing dashes with
        # underscores
        return res_ctrl_mappings.get(
            resource,
            res_ctrl_mappings.get(resource.replace('-', '_')))

    @classmethod
    def add_resource_for_path_prefix(cls, resource, path_prefix):
        resources = cls.get_instance().path_prefix_resource_mappings[
            path_prefix].append(resource)
        return resources

    @classmethod
    def get_resources_for_path_prefix(cls, path_prefix):
        return cls.get_instance().path_prefix_resource_mappings[path_prefix]


def init():
    """Call to load the plugins (core+services) machinery."""
    if not directory.is_loaded():
        NeutronManager.get_instance()
