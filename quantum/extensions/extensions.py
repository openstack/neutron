
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# Copyright 2011 Justin Santa Barbara
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

from abc import ABCMeta
import imp
import logging
import os

import routes
import webob.dec
import webob.exc

from quantum.common import exceptions
import quantum.extensions
from quantum.manager import QuantumManager
from quantum import wsgi


LOG = logging.getLogger('quantum.api.extensions')


class PluginInterface(object):
    __metaclass__ = ABCMeta

    @classmethod
    def __subclasshook__(cls, klass):
        """
        The __subclasshook__ method is a class method
        that will be called everytime a class is tested
        using issubclass(klass, PluginInterface).
        In that case, it will check that every method
        marked with the abstractmethod decorator is
        provided by the plugin class.
        """
        for method in cls.__abstractmethods__:
            if any(method in base.__dict__ for base in klass.__mro__):
                continue
            return NotImplemented
        return True


class ExtensionDescriptor(object):
    """Base class that defines the contract for extensions.

    Note that you don't have to derive from this class to have a valid
    extension; it is purely a convenience.

    """

    def get_name(self):
        """The name of the extension.

        e.g. 'Fox In Socks'

        """
        raise NotImplementedError()

    def get_alias(self):
        """The alias for the extension.

        e.g. 'FOXNSOX'

        """
        raise NotImplementedError()

    def get_description(self):
        """Friendly description for the extension.

        e.g. 'The Fox In Socks Extension'

        """
        raise NotImplementedError()

    def get_namespace(self):
        """The XML namespace for the extension.

        e.g. 'http://www.fox.in.socks/api/ext/pie/v1.0'

        """
        raise NotImplementedError()

    def get_updated(self):
        """The timestamp when the extension was last updated.

        e.g. '2011-01-22T13:25:27-06:00'

        """
        # NOTE(justinsb): Not sure of the purpose of this is, vs the XML NS
        raise NotImplementedError()

    def get_resources(self):
        """List of extensions.ResourceExtension extension objects.

        Resources define new nouns, and are accessible through URLs.

        """
        resources = []
        return resources

    def get_actions(self):
        """List of extensions.ActionExtension extension objects.

        Actions are verbs callable from the API.

        """
        actions = []
        return actions

    def get_request_extensions(self):
        """List of extensions.RequestException extension objects.

        Request extensions are used to handle custom request data.

        """
        request_exts = []
        return request_exts

    def get_plugin_interface(self):
        """
        Returns an abstract class which defines contract for the plugin.
        The abstract class should inherit from extesnions.PluginInterface,
        Methods in this abstract class  should be decorated as abstractmethod
        """
        return None


class ActionExtensionController(wsgi.Controller):

    def __init__(self, application):

        self.application = application
        self.action_handlers = {}

    def add_action(self, action_name, handler):
        self.action_handlers[action_name] = handler

    def action(self, request, id):

        input_dict = self._deserialize(request.body,
                                       request.get_content_type())
        for action_name, handler in self.action_handlers.iteritems():
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

    def _translate(self, ext):
        ext_data = {}
        ext_data['name'] = ext.get_name()
        ext_data['alias'] = ext.get_alias()
        ext_data['description'] = ext.get_description()
        ext_data['namespace'] = ext.get_namespace()
        ext_data['updated'] = ext.get_updated()
        ext_data['links'] = []  # TODO(dprince): implement extension links
        return ext_data

    def index(self, request):
        extensions = []
        for _alias, ext in self.extension_manager.extensions.iteritems():
            extensions.append(self._translate(ext))
        return dict(extensions=extensions)

    def show(self, request, id):
        # NOTE(dprince): the extensions alias is used as the 'id' for show
        ext = self.extension_manager.extensions.get(id, None)
        if not ext:
            raise webob.exc.HTTPNotFound(
                _("Extension with alias %s does not exist") % id)
        return self._translate(ext)

    def delete(self, request, id):
        raise webob.exc.HTTPNotFound()

    def create(self, request):
        raise webob.exc.HTTPNotFound()


class ExtensionMiddleware(wsgi.Middleware):
    """Extensions middleware for WSGI."""
    def __init__(self, application, config_params,
                 ext_mgr=None):

        self.ext_mgr = (ext_mgr
                        or ExtensionManager(
                        get_extensions_path(config_params)))
        mapper = routes.Mapper()

        # extended resources
        for resource in self.ext_mgr.get_resources():
            LOG.debug(_('Extended resource: %s'),
                        resource.collection)
            for action, method in resource.collection_actions.iteritems():
                path_prefix = ""
                parent = resource.parent
                conditions = dict(method=[method])
                path = "/%s/%s" % (resource.collection, action)
                if parent:
                    path_prefix = "/%s/{%s_id}" % (parent["collection_name"],
                                                   parent["member_name"])
                with mapper.submapper(controller=resource.controller,
                                      action=action,
                                      path_prefix=path_prefix,
                                      conditions=conditions) as submap:
                    submap.connect(path)
                    submap.connect("%s.:(format)" % path)
            mapper.resource(resource.collection, resource.collection,
                            controller=resource.controller,
                            member=resource.member_actions,
                            parent_resource=resource.parent)

        # extended actions
        action_controllers = self._action_ext_controllers(application,
                                                          self.ext_mgr, mapper)
        for action in self.ext_mgr.get_actions():
            LOG.debug(_('Extended action: %s'), action.action_name)
            controller = action_controllers[action.collection]
            controller.add_action(action.action_name, action.handler)

        # extended requests
        req_controllers = self._request_ext_controllers(application,
                                                        self.ext_mgr, mapper)
        for request_ext in self.ext_mgr.get_request_extensions():
            LOG.debug(_('Extended request: %s'), request_ext.key)
            controller = req_controllers[request_ext.key]
            controller.add_handler(request_ext.handler)

        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          mapper)

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
            if not action.collection in action_controllers.keys():
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
            if not req_ext.key in request_ext_controllers.keys():
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
        extensions_path = get_extensions_path(global_config)
        ext_mgr = PluginAwareExtensionManager(extensions_path,
                                              QuantumManager.get_plugin())
        return ExtensionMiddleware(app, global_config, ext_mgr=ext_mgr)
    return _factory


class ExtensionManager(object):
    """Load extensions from the configured extension path.

    See tests/unit/extensions/foxinsocks.py for an
    example extension implementation.

    """
    def __init__(self, path):
        LOG.info(_('Initializing extension manager.'))
        self.path = path
        self.extensions = {}
        self._load_all_extensions()

    def get_resources(self):
        """Returns a list of ResourceExtension objects."""
        resources = []
        resources.append(ResourceExtension('extensions',
                                           ExtensionController(self)))
        for ext in self.extensions.itervalues():
            try:
                resources.extend(ext.get_resources())
            except AttributeError:
                # NOTE(dprince): Extension aren't required to have resource
                # extensions
                pass
        return resources

    def get_actions(self):
        """Returns a list of ActionExtension objects."""
        actions = []
        for ext in self.extensions.itervalues():
            try:
                actions.extend(ext.get_actions())
            except AttributeError:
                # NOTE(dprince): Extension aren't required to have action
                # extensions
                pass
        return actions

    def get_request_extensions(self):
        """Returns a list of RequestExtension objects."""
        request_exts = []
        for ext in self.extensions.itervalues():
            try:
                request_exts.extend(ext.get_request_extensions())
            except AttributeError:
                # NOTE(dprince): Extension aren't required to have request
                # extensions
                pass
        return request_exts

    def _check_extension(self, extension):
        """Checks for required methods in extension objects."""
        try:
            LOG.debug(_('Ext name: %s'), extension.get_name())
            LOG.debug(_('Ext alias: %s'), extension.get_alias())
            LOG.debug(_('Ext description: %s'), extension.get_description())
            LOG.debug(_('Ext namespace: %s'), extension.get_namespace())
            LOG.debug(_('Ext updated: %s'), extension.get_updated())
        except AttributeError as ex:
            LOG.exception(_("Exception loading extension: %s"), unicode(ex))
            return False
        return True

    def _load_all_extensions(self):
        """Load extensions from the configured path.

        Load extensions from the configured path. The extension name is
        constructed from the module_name. If your extension module was named
        widgets.py the extension class within that module should be
        'Widgets'.

        See tests/unit/extensions/foxinsocks.py for an example
        extension implementation.

        """
        for path in self.path.split(':'):
            if os.path.exists(path):
                self._load_all_extensions_from_path(path)
            else:
                LOG.error("Extension path \"%s\" doesn't exist!" % path)

    def _load_all_extensions_from_path(self, path):
        for f in os.listdir(path):
            try:
                LOG.info(_('Loading extension file: %s'), f)
                mod_name, file_ext = os.path.splitext(os.path.split(f)[-1])
                ext_path = os.path.join(path, f)
                if file_ext.lower() == '.py' and not mod_name.startswith('_'):
                    mod = imp.load_source(mod_name, ext_path)
                    ext_name = mod_name[0].upper() + mod_name[1:]
                    new_ext_class = getattr(mod, ext_name, None)
                    if not new_ext_class:
                        LOG.warn(_('Did not find expected name '
                                   '"%(ext_name)s" in %(file)s'),
                                 {'ext_name': ext_name,
                                  'file': ext_path})
                        continue
                    new_ext = new_ext_class()
                    self.add_extension(new_ext)
            except Exception as exception:
                LOG.warn("extension file %s wasnt loaded due to %s",
                         f, exception)

    def add_extension(self, ext):
        # Do nothing if the extension doesn't check out
        if not self._check_extension(ext):
            return

        alias = ext.get_alias()
        LOG.warn(_('Loaded extension: %s'), alias)

        if alias in self.extensions:
            raise exceptions.Error("Found duplicate extension: %s"
                                         % alias)
        self.extensions[alias] = ext


class PluginAwareExtensionManager(ExtensionManager):

    def __init__(self, path, plugin):
        self.plugin = plugin
        super(PluginAwareExtensionManager, self).__init__(path)

    def _check_extension(self, extension):
        """Checks if plugin supports extension and implements the
        extension contract."""
        extension_is_valid = super(PluginAwareExtensionManager,
                                self)._check_extension(extension)
        return (extension_is_valid and
                self._plugin_supports(extension) and
                self._plugin_implements_interface(extension))

    def _plugin_supports(self, extension):
        alias = extension.get_alias()
        supports_extension = (hasattr(self.plugin,
                                      "supported_extension_aliases") and
                              alias in self.plugin.supported_extension_aliases)
        if not supports_extension:
            LOG.warn("extension %s not supported by plugin %s",
                     alias, self.plugin)
        return supports_extension

    def _plugin_implements_interface(self, extension):
        if(not hasattr(extension, "get_plugin_interface") or
           extension.get_plugin_interface() is None):
            return True
        plugin_has_interface = isinstance(self.plugin,
                                          extension.get_plugin_interface())
        if not plugin_has_interface:
            LOG.warn("plugin %s does not implement extension's"
                     "plugin interface %s" % (self.plugin,
                                              extension.get_alias()))
        return plugin_has_interface


class RequestExtension(object):
    """Extend requests and responses of core Quantum OpenStack API controllers.

    Provide a way to add data to responses and handle custom request data
    that is sent to core Quantum OpenStack API controllers.

    """
    def __init__(self, method, url_route, handler):
        self.url_route = url_route
        self.handler = handler
        self.conditions = dict(method=[method])
        self.key = "%s-%s" % (method, url_route)


class ActionExtension(object):
    """Add custom actions to core Quantum OpenStack API controllers."""

    def __init__(self, collection, action_name, handler):
        self.collection = collection
        self.action_name = action_name
        self.handler = handler


class ResourceExtension(object):
    """Add top level resources to the OpenStack API in Quantum."""

    def __init__(self, collection, controller, parent=None,
                 collection_actions={}, member_actions={}):
        self.collection = collection
        self.controller = controller
        self.parent = parent
        self.collection_actions = collection_actions
        self.member_actions = member_actions


# Returns the extention paths from a config entry and the __path__
# of quantum.extensions
def get_extensions_path(config=None):
    paths = ':'.join(quantum.extensions.__path__)
    if config:
        paths = ':'.join([config.get('api_extensions_path', ''), paths])

    return paths
