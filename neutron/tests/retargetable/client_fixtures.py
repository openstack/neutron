# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""
This module defines client fixtures that can be used to target the
Neutron API via different methods.
"""

import abc

import fixtures
import six

from neutron.common import exceptions as q_exc
from neutron import context
from neutron import manager
from neutron.tests import base
from neutron.tests.unit import testlib_api


@six.add_metaclass(abc.ABCMeta)
class AbstractClientFixture(fixtures.Fixture):
    """
    Base class for a client that can interact the neutron api in some
    manner.
    """

    @abc.abstractproperty
    def NotFound(self):
        """The exception that indicates a resource could not be found.

        Tests can use this property to assert for a missing resource
        in a client-agnostic way.
        """

    @abc.abstractmethod
    def create_network(self, **kwargs):
        pass

    @abc.abstractmethod
    def update_network(self, id_, **kwargs):
        pass

    @abc.abstractmethod
    def get_network(self, id_, fields=None):
        pass

    @abc.abstractmethod
    def get_networks(self, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def delete_network(self, id_):
        pass


class PluginClientFixture(AbstractClientFixture):
    """Targets the Neutron API via the plugin API"""

    def __init__(self, plugin_conf):
        self.plugin_conf = plugin_conf

    def setUp(self):
        super(PluginClientFixture, self).setUp()
        self.useFixture(testlib_api.SqlFixture())
        self.useFixture(self.plugin_conf)
        self.useFixture(base.PluginFixture(self.plugin_conf.plugin_name))

    @property
    def ctx(self):
        if not hasattr(self, '_ctx'):
            self._ctx = context.Context('', 'test-tenant')
        return self._ctx

    @property
    def plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def NotFound(self):
        return q_exc.NetworkNotFound

    def create_network(self, **kwargs):
        # Supply defaults that are expected to be set by the api
        # framwork
        kwargs.setdefault('admin_state_up', True)
        kwargs.setdefault('shared', False)
        data = dict(network=kwargs)
        result = self.plugin.create_network(self.ctx, data)
        return base.AttributeDict(result)

    def update_network(self, id_, **kwargs):
        data = dict(network=kwargs)
        result = self.plugin.update_network(self.ctx, id_, data)
        return base.AttributeDict(result)

    def get_network(self, *args, **kwargs):
        result = self.plugin.get_network(self.ctx, *args, **kwargs)
        return base.AttributeDict(result)

    def get_networks(self, *args, **kwargs):
        result = self.plugin.get_networks(self.ctx, *args, **kwargs)
        return [base.AttributeDict(x) for x in result]

    def delete_network(self, id_):
        self.plugin.delete_network(self.ctx, id_)
