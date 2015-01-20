# Copyright 2014, Red Hat Inc.
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

"""
This module defines functional tests for the Neutron V2 API in the
BaseTestApi class.  The intention is that the class will be overridden
and configured for use with testscenarios as follows:

 - A subclass should override the 'scenarios' class member with a
   list of tuple pairs, e.g.

   scenarios = [('scenario_id', dict(client=Client())]

   The first element of each scenario tuple is a user-defined textual
   id, and the second element is a dictionary whose client parameter
   should be a subclass of BaseNeutronClient.

 - The module containing the test class should defines a 'load_tests'
   variable as follows:

   load_tests = testscenarios.load_tests_apply_scenarios

Examples of use include:

   neutron.tests.functional.api.test_v2_plugin - targets the plugin api
                                                 for each configured plugin

   neutron.tests.api.test_v2_rest_client - targets neutron server
                                           via the tempest rest client

   The tests in neutron.tests.api depend on Neutron and Tempest being
   deployed (e.g. with Devstack) and are intended to be run in advisory
   check jobs.

Reference: https://pypi.python.org/pypi/testscenarios/
"""

import abc

import six
import testtools

from neutron.tests import sub_base


class AttributeDict(dict):

    """
    Provide attribute access (dict.key) to dictionary values.
    """

    def __getattr__(self, name):
        """Allow attribute access for all keys in the dict."""
        if name in self:
            return self[name]
        raise AttributeError(_("Unknown attribute '%s'.") % name)


@six.add_metaclass(abc.ABCMeta)
class BaseNeutronClient(object):
    """
    Base class for a client that can interact the neutron api in some
    manner.

    Reference: :file:`neutron/neutron_plugin_base_v2.py`
    """

    def setUp(self, test_case):
        """Configure the api for use with a test case

        :param test_case: The test case that will exercise the api
        """
        self.test_case = test_case

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


class BaseTestApi(sub_base.SubBaseTestCase):

    scenarios = ()

    def setUp(self, setup_parent=True):
        # Calling the parent setUp is optional - the subclass may be
        # calling it already via a different ancestor.
        if setup_parent:
            super(BaseTestApi, self).setUp()
        self.client.setUp(self)

    def test_network_lifecycle(self):
        net = self.client.create_network(name=sub_base.get_rand_name())
        listed_networks = dict((x.id, x.name)
                               for x in self.client.get_networks())
        self.assertIn(net.id, listed_networks)
        self.assertEqual(listed_networks[net.id], net.name,
                         'Listed network name is not as expected.')
        updated_name = 'new %s' % net.name
        updated_net = self.client.update_network(net.id, name=updated_name)
        self.assertEqual(updated_name, updated_net.name,
                         'Updated network name is not as expected.')
        self.client.delete_network(net.id)
        with testtools.ExpectedException(self.client.NotFound,
                                         msg='Network was not deleted'):
            self.client.get_network(net.id)
