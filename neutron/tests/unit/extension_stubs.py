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

import abc

from neutron.api import extensions
from neutron import wsgi


class StubExtension(object):

    def __init__(self, alias="stub_extension"):
        self.alias = alias

    def get_name(self):
        return "Stub Extension"

    def get_alias(self):
        return self.alias

    def get_description(self):
        return ""

    def get_namespace(self):
        return ""

    def get_updated(self):
        return ""


class StubPlugin(object):

    def __init__(self, supported_extensions=[]):
        self.supported_extension_aliases = supported_extensions


class ExtensionExpectingPluginInterface(StubExtension):
    """Expect plugin to implement all methods in StubPluginInterface.

    This extension expects plugin to implement all the methods defined
    in StubPluginInterface.
    """

    def get_plugin_interface(self):
        return StubPluginInterface


class StubPluginInterface(extensions.PluginInterface):

    @abc.abstractmethod
    def get_foo(self, bar=None):
        pass


class StubBaseAppController(wsgi.Controller):

    def index(self, request):
        return "base app index"

    def show(self, request, id):
        return {'fort': 'knox'}

    def update(self, request, id):
        return {'uneditable': 'original_value'}
