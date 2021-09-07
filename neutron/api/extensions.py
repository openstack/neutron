# Copyright 2011 OpenStack Foundation.
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

import collections
import imp
import os

from keystoneauth1 import loading as ks_loading
from neutron_lib.api import extensions as api_extensions
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from openstack import connection
from oslo_config import cfg
from oslo_log import log as logging
from oslo_middleware import base
import routes
import webob.dec
import webob.exc

from neutron._i18n import _
from neutron import extensions as core_extensions
from neutron.plugins.common import constants as const
from neutron.services import provider_configuration
from neutron import wsgi


LOG = logging.getLogger(__name__)


EXTENSION_SUPPORTED_CHECK_MAP = {}
_PLUGIN_AGNOSTIC_EXTENSIONS = set()
_NOVA_CONNECTION = None


def register_custom_supported_check(alias, f, plugin_agnostic=False):
    '''Register a custom function to determine if extension is supported.

    Consequent calls for the same alias replace the registered function.

    :param alias: API extension alias name
    :param f: custom check function that returns True if extension is supported
    :param plugin_agnostic: if False, don't require a plugin to claim support
    with supported_extension_aliases. If True, a plugin must claim the
    extension is supported.
    '''

    EXTENSION_SUPPORTED_CHECK_MAP[alias] = f
    if plugin_agnostic:
        _PLUGIN_AGNOSTIC_EXTENSIONS.add(alias)


class ActionExtensionController(wsgi.Controller):

    def __init__(self, application):
        self.application = application
        self.action_handlers = {}

    def add_action(self, action_name, handler):
        self.action_handlers[action_name] = handler

    def action(self, request, id):
        input_dict = self._deserialize(request.body,
                                       request.get_content_type())
        for action_name, handler in self.action_handlers.items():
            if action_name in input_dict:
                return handler(input_dict, request, id)
        # no action handler found (bump to downstream application)
        response = self.application
        return response


class RequestExtensionController(wsgi.Controller):

    def __init__(self, application):
        self.application = application
        self.handlers = []

    def add_handler(self, handler):
        self.handlers.append(handler)

    def process(self, request, *args, **kwargs):
        res = request.get_response(self.application)
        # currently request handlers are un-ordered
        for handler in self.handlers:
            response = handler(request, res)
        return response


class ExtensionController(wsgi.Controller):

    def __init__(self, extension_manager):
        self.extension_manager = extension_manager

    @staticmethod
    def _translate(ext):
        ext_data = {}
        ext_data['name'] = ext.get_name()
        ext_data['alias'] = ext.get_alias()
        ext_data['description'] = ext.get_description()
        ext_data['updated'] = ext.get_updated()
        ext_data['links'] = []  # TODO(dprince): implement extension links
        return ext_data

    def index(self, request):
        extensions = []
        for _alias, ext in self.extension_manager.extensions.items():
            extensions.append(self._translate(ext))
        return dict(extensions=extensions)

    def show(self, request, id):
        # NOTE(dprince): the extensions alias is used as the 'id' for show
        ext = self.extension_manager.extensions.get(id, None)
        if not ext:
            raise webob.exc.HTTPNotFound(
                _("Extension with alias %s does not exist") % id)
        return dict(extension=self._translate(ext))

    def delete(self, request, id):
        msg = _('Resource not found.')
        raise webob.exc.HTTPNotFound(msg)

    def create(self, request):
        msg = _('Resource not found.')
        raise webob.exc.HTTPNotFound(msg)


class ExtensionMiddleware(base.ConfigurableMiddleware):
    """Extensions middleware for WSGI."""

    def __init__(self, application,
                 ext_mgr=None):
        self.ext_mgr = (ext_mgr or
                        ExtensionManager(get_extensions_path()))
        mapper = routes.Mapper()

        # extended resources
        for resource in self.ext_mgr.get_resources():
            path_prefix = resource.path_prefix
            if resource.parent:
                path_prefix = (resource.path_prefix +
                               "/%s/{%s_id}" %
                               (resource.parent["collection_name"],
                                resource.parent["member_name"]))

            LOG.debug('Extended resource: %s',
                      resource.collection)
            for action, method in resource.collection_actions.items():
                conditions = dict(method=[method])
                path = "/%s/%s" % (resource.collection, action)
                with mapper.submapper(controller=resource.controller,
                                      action=action,
                                      path_prefix=path_prefix,
                                      conditions=conditions) as submap:
                    submap.connect(path_prefix + path, path)
                    submap.connect(path_prefix + path + "_format",
                                   "%s.:(format)" % path)

            for action, method in resource.collection_methods.items():
                conditions = dict(method=[method])
                path = "/%s" % resource.collection
                with mapper.submapper(controller=resource.controller,
                                      action=action,
                                      path_prefix=path_prefix,
                                      conditions=conditions) as submap:
                    submap.connect(path_prefix + path, path)
                    submap.connect(path_prefix + path + "_format",
                                   "%s.:(format)" % path)

            mapper.resource(resource.collection, resource.collection,
                            controller=resource.controller,
                            member=resource.member_actions,
                            parent_resource=resource.parent,
                            path_prefix=path_prefix)

        # extended actions
        action_controllers = self._action_ext_controllers(application,
                                                          self.ext_mgr, mapper)
        for action in self.ext_mgr.get_actions():
            LOG.debug('Extended action: %s', action.action_name)
            controller = action_controllers[action.collection]
            controller.add_action(action.action_name, action.handler)

        # extended requests
        req_controllers = self._request_ext_controllers(application,
                                                        self.ext_mgr, mapper)
        for request_ext in self.ext_mgr.get_request_extensions():
            LOG.debug('Extended request: %s', request_ext.key)
            controller = req_controllers[request_ext.key]
            controller.add_handler(request_ext.handler)

        # NOTE(slaweq): It seems that using singleton=True in conjunction
        # with eventlet monkey patching of the threading library doesn't work
        # well and there is memory leak. See
        # https://bugs.launchpad.net/neutron/+bug/1942179 for details
        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          mapper,
                                                          singleton=False)
        super(ExtensionMiddleware, self).__init__(application)

    @classmethod
    def factory(cls, global_config, **local_config):
        """Paste factory."""
        def _factory(app):
            return cls(app, global_config, **local_config)
        return _factory

    def _action_ext_controllers(self, application, ext_mgr, mapper):
        """Return a dict of ActionExtensionController-s by collection."""
        action_controllers = {}
        for action in ext_mgr.get_actions():
            if action.collection not in action_controllers.keys():
                controller = ActionExtensionController(application)
                mapper.connect("/%s/:(id)/action.:(format)" %
                               action.collection,
                               action='action',
                               controller=controller,
                               conditions=dict(method=['POST']))
                mapper.connect("/%s/:(id)/action" % action.collection,
                               action='action',
                               controller=controller,
                               conditions=dict(method=['POST']))
                action_controllers[action.collection] = controller

        return action_controllers

    def _request_ext_controllers(self, application, ext_mgr, mapper):
        """Returns a dict of RequestExtensionController-s by collection."""
        request_ext_controllers = {}
        for req_ext in ext_mgr.get_request_extensions():
            if req_ext.key not in request_ext_controllers.keys():
                controller = RequestExtensionController(application)
                mapper.connect(req_ext.url_route + '.:(format)',
                               action='process',
                               controller=controller,
                               conditions=req_ext.conditions)

                mapper.connect(req_ext.url_route,
                               action='process',
                               controller=controller,
                               conditions=req_ext.conditions)
                request_ext_controllers[req_ext.key] = controller

        return request_ext_controllers

    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def __call__(self, req):
        """Route the incoming request with router."""
        req.environ['extended.app'] = self.application
        return self._router

    @staticmethod
    @webob.dec.wsgify(RequestClass=wsgi.Request)
    def _dispatch(req):
        """Dispatch the request.

        Returns the routed WSGI app's response or defers to the extended
        application.
        """
        match = req.environ['wsgiorg.routing_args'][1]
        if not match:
            return req.environ['extended.app']
        app = match['controller']
        return app


def plugin_aware_extension_middleware_factory(global_config, **local_config):
    """Paste factory."""
    def _factory(app):
        ext_mgr = PluginAwareExtensionManager.get_instance()
        return ExtensionMiddleware(app, ext_mgr=ext_mgr)
    return _factory


class ExtensionManager(object):
    """Load extensions from the configured extension path.

    See tests/unit/extensions/foxinsocks.py for an
    example extension implementation.
    """

    def __init__(self, path):
        LOG.info('Initializing extension manager.')
        self.path = path
        self.extensions = {}
        self._load_all_extensions()

    def get_resources(self):
        """Returns a list of ResourceExtension objects."""
        resources = []
        resources.append(ResourceExtension('extensions',
                                           ExtensionController(self)))
        for ext in self.extensions.values():
            resources.extend(ext.get_resources())
        return resources

    def get_pecan_resources(self):
        """Returns a list of PecanResourceExtension objects."""
        resources = []
        for ext in self.extensions.values():
            resources.extend(ext.get_pecan_resources())
        return resources

    def get_actions(self):
        """Returns a list of ActionExtension objects."""
        actions = []
        for ext in self.extensions.values():
            actions.extend(ext.get_actions())
        return actions

    def get_request_extensions(self):
        """Returns a list of RequestExtension objects."""
        request_exts = []
        for ext in self.extensions.values():
            request_exts.extend(ext.get_request_extensions())
        return request_exts

    def extend_resources(self, version, attr_map):
        """Extend resources with additional resources or attributes.

        :param attr_map: the existing mapping from resource name to
        attrs definition.

        After this function, we will extend the attr_map if an extension
        wants to extend this map.
        """
        processed_exts = {}
        exts_to_process = self.extensions.copy()
        check_optionals = True
        # Iterate until there are unprocessed extensions or if no progress
        # is made in a whole iteration
        while exts_to_process:
            processed_ext_count = len(processed_exts)
            for ext_name, ext in list(exts_to_process.items()):
                # Process extension only if all required extensions
                # have been processed already
                required_exts_set = set(ext.get_required_extensions())
                if required_exts_set - set(processed_exts):
                    continue
                optional_exts_set = set(ext.get_optional_extensions())
                if check_optionals and optional_exts_set - set(processed_exts):
                    continue
                extended_attrs = ext.get_extended_resources(version)
                for res, resource_attrs in extended_attrs.items():
                    res_to_update = attr_map.setdefault(res, {})
                    if self._is_sub_resource(res_to_update):
                        # in the case of an existing sub-resource, we need to
                        # update the parameters content rather than overwrite
                        # it, and also keep the description of the parent
                        # resource unmodified
                        res_to_update['parameters'].update(
                            resource_attrs['parameters'])
                    else:
                        res_to_update.update(resource_attrs)
                processed_exts[ext_name] = ext
                del exts_to_process[ext_name]
            if len(processed_exts) == processed_ext_count:
                # if we hit here, it means there are unsatisfied
                # dependencies. try again without optionals since optionals
                # are only necessary to set order if they are present.
                if check_optionals:
                    check_optionals = False
                    continue
                # Exit loop as no progress was made
                break
        if exts_to_process:
            unloadable_extensions = set(exts_to_process.keys())
            LOG.error("Unable to process extensions (%s) because "
                      "the configured plugins do not satisfy "
                      "their requirements. Some features will not "
                      "work as expected.",
                      ', '.join(unloadable_extensions))
            self._check_faulty_extensions(unloadable_extensions)
        # Extending extensions' attributes map.
        for ext in processed_exts.values():
            ext.update_attributes_map(attr_map)

    def _is_sub_resource(self, resource):
        return ('parent' in resource and
                isinstance(resource['parent'], dict) and
                'member_name' in resource['parent'] and
                'parameters' in resource)

    def _check_faulty_extensions(self, faulty_extensions):
        """Raise for non-default faulty extensions.

        Gracefully fail for defective default extensions, which will be
        removed from the list of loaded extensions.
        """
        default_extensions = set(const.DEFAULT_SERVICE_PLUGINS.values())
        if not faulty_extensions <= default_extensions:
            raise exceptions.ExtensionsNotFound(
                extensions=list(faulty_extensions))
        # Remove the faulty extensions so that they do not show during
        # ext-list
        for ext in faulty_extensions:
            try:
                del self.extensions[ext]
            except KeyError:
                pass

    def _check_extension(self, extension):
        """Checks for required methods in extension objects."""
        try:
            LOG.debug('Ext name="%(name)s" alias="%(alias)s" '
                      'description="%(desc)s" updated="%(updated)s"',
                      {'name': extension.get_name(),
                       'alias': extension.get_alias(),
                       'desc': extension.get_description(),
                       'updated': extension.get_updated()})
        except AttributeError:
            LOG.exception("Exception loading extension")
            return False
        return isinstance(extension, api_extensions.ExtensionDescriptor)

    def _load_all_extensions(self):
        """Load extensions from the configured path.

        The extension name is constructed from the module_name. If your
        extension module is named widgets.py, the extension class within that
        module should be 'Widgets'.

        See tests/unit/extensions/foxinsocks.py for an example extension
        implementation.
        """

        for path in self.path.split(':'):
            if os.path.exists(path):
                self._load_all_extensions_from_path(path)
            else:
                LOG.error("Extension path '%s' doesn't exist!", path)

    def _load_all_extensions_from_path(self, path):
        # Sorting the extension list makes the order in which they
        # are loaded predictable across a cluster of load-balanced
        # Neutron Servers
        for f in sorted(os.listdir(path)):
            try:
                LOG.debug('Loading extension file: %s', f)
                mod_name, file_ext = os.path.splitext(os.path.split(f)[-1])
                ext_path = os.path.join(path, f)
                if file_ext.lower() == '.py' and not mod_name.startswith('_'):
                    mod = imp.load_source(mod_name, ext_path)
                    ext_name = mod_name.capitalize()
                    new_ext_class = getattr(mod, ext_name, None)
                    if not new_ext_class:
                        LOG.warning('Did not find expected name '
                                    '"%(ext_name)s" in %(file)s',
                                    {'ext_name': ext_name,
                                     'file': ext_path})
                        continue
                    new_ext = new_ext_class()
                    self.add_extension(new_ext)
            except Exception as exception:
                LOG.warning("Extension file %(f)s wasn't loaded due to "
                            "%(exception)s",
                            {'f': f, 'exception': exception})

    def add_extension(self, ext):
        # Do nothing if the extension doesn't check out
        if not self._check_extension(ext):
            return

        alias = ext.get_alias()
        LOG.info('Loaded extension: %s', alias)

        if alias in self.extensions:
            raise exceptions.DuplicatedExtension(alias=alias)
        self.extensions[alias] = ext


class PluginAwareExtensionManager(ExtensionManager):

    _instance = None

    def __init__(self, path, plugins):
        self.plugins = plugins
        super(PluginAwareExtensionManager, self).__init__(path)
        self.check_if_plugin_extensions_loaded()

    def _check_extension(self, extension):
        """Check if an extension is supported by any plugin."""
        extension_is_valid = super(PluginAwareExtensionManager,
                                   self)._check_extension(extension)
        if not extension_is_valid:
            return False

        alias = extension.get_alias()
        if alias in EXTENSION_SUPPORTED_CHECK_MAP:
            return EXTENSION_SUPPORTED_CHECK_MAP[alias]()

        return (self._plugins_support(extension) and
                self._plugins_implement_interface(extension))

    def _plugins_support(self, extension):
        alias = extension.get_alias()
        supports_extension = alias in self.get_supported_extension_aliases()
        if not supports_extension:
            LOG.info("Extension %s not supported by any of loaded "
                     "plugins", alias)
        return supports_extension

    def _plugins_implement_interface(self, extension):
        if extension.get_plugin_interface() is None:
            return True
        for plugin in self.plugins.values():
            if isinstance(plugin, extension.get_plugin_interface()):
                return True
        LOG.warning("Loaded plugins do not implement extension "
                    "%s interface",
                    extension.get_alias())
        return False

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            service_plugins = directory.get_plugins()
            cls._instance = cls(get_extensions_path(service_plugins),
                                service_plugins)
        return cls._instance

    def get_plugin_supported_extension_aliases(self, plugin):
        """Return extension aliases supported by a given plugin"""
        aliases = set()
        # we also check all classes that the plugins inherit to see if they
        # directly provide support for an extension
        for item in [plugin] + plugin.__class__.mro():
            try:
                aliases |= set(
                    getattr(item, "supported_extension_aliases", []))
            except TypeError:
                # we land here if a class has a @property decorator for
                # supported extension aliases. They only work on objects.
                pass
        return aliases

    def get_supported_extension_aliases(self):
        """Gets extension aliases supported by all plugins."""
        aliases = set()
        for plugin in self.plugins.values():
            aliases |= self.get_plugin_supported_extension_aliases(plugin)
        aliases |= {
            alias
            for alias, func in EXTENSION_SUPPORTED_CHECK_MAP.items()
            if func()
        }
        return aliases

    @classmethod
    def clear_instance(cls):
        cls._instance = None

    def check_if_plugin_extensions_loaded(self):
        """Check if an extension supported by a plugin has been loaded."""
        plugin_extensions = self.get_supported_extension_aliases()
        missing_aliases = plugin_extensions - set(self.extensions)
        missing_aliases -= _PLUGIN_AGNOSTIC_EXTENSIONS
        if missing_aliases:
            raise exceptions.ExtensionsNotFound(
                extensions=list(missing_aliases))


class RequestExtension(object):
    """Extend requests and responses of core Neutron OpenStack API controllers.

    Provide a way to add data to responses and handle custom request data
    that is sent to core Neutron OpenStack API controllers.
    """

    def __init__(self, method, url_route, handler):
        self.url_route = url_route
        self.handler = handler
        self.conditions = dict(method=[method])
        self.key = "%s-%s" % (method, url_route)


class ActionExtension(object):
    """Add custom actions to core Neutron OpenStack API controllers."""

    def __init__(self, collection, action_name, handler):
        self.collection = collection
        self.action_name = action_name
        self.handler = handler


class ResourceExtension(object):
    """Add top level resources to the OpenStack API in Neutron."""

    def __init__(self, collection, controller, parent=None, path_prefix="",
                 collection_actions=None, member_actions=None, attr_map=None,
                 collection_methods=None):
        collection_actions = collection_actions or {}
        collection_methods = collection_methods or {}
        member_actions = member_actions or {}
        attr_map = attr_map or {}
        self.collection = collection
        self.controller = controller
        self.parent = parent
        self.collection_actions = collection_actions
        self.collection_methods = collection_methods
        self.member_actions = member_actions
        self.path_prefix = path_prefix
        self.attr_map = attr_map


# Returns the extension paths from a config entry and the __path__
# of neutron.extensions
def get_extensions_path(service_plugins=None):
    paths = collections.OrderedDict()

    # Add Neutron core extensions
    paths[core_extensions.__path__[0]] = 1
    if service_plugins:
        # Add Neutron *-aas extensions
        for plugin in service_plugins.values():
            neutron_mod = provider_configuration.NeutronModule(
                plugin.__module__.split('.')[0])
            try:
                paths[neutron_mod.module().extensions.__path__[0]] = 1
            except AttributeError:
                # Occurs normally if module has no extensions sub-module
                pass

    # Add external/other plugins extensions
    if cfg.CONF.api_extensions_path:
        for path in cfg.CONF.api_extensions_path.split(":"):
            paths[path] = 1

    LOG.debug("get_extension_paths = %s", paths)

    # Re-build the extension string
    path = ':'.join(paths)
    return path


def append_api_extensions_path(paths):
    paths = list(set([cfg.CONF.api_extensions_path] + paths))
    cfg.CONF.set_override('api_extensions_path',
                          ':'.join([p for p in paths if p]))


class ProjectIdMiddleware(base.ConfigurableMiddleware):

    @webob.dec.wsgify
    def __call__(self, req):
        # NOTE(ralonsoh): this method uses Nova Keystone user to retrieve the
        # project because (1) it is allowed to retrieve the projects and (2)
        # Neutron avoids adding another user section in the configuration
        # (Nova user will be always used).
        global _NOVA_CONNECTION
        project = req.params.get('project_id') or req.params.get('tenant_id')
        if project:
            if not _NOVA_CONNECTION:
                auth = ks_loading.load_auth_from_conf_options(cfg.CONF, 'nova')
                keystone_session = ks_loading.load_session_from_conf_options(
                    cfg.CONF, 'nova', auth=auth)
                _NOVA_CONNECTION = connection.Connection(
                    session=keystone_session, oslo_conf=cfg.CONF,
                    connect_retries=cfg.CONF.http_retries)
            if not _NOVA_CONNECTION.get_project(project):
                return webob.exc.HTTPNotFound(
                    comment='Project %s does not exist' % project)

        return req.get_response(self.application)
