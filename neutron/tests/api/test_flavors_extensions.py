# Copyright 2015 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_log import log as logging

from neutron.tests.api import base
from neutron.tests.tempest import test


LOG = logging.getLogger(__name__)


class TestFlavorsJson(base.BaseAdminNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        List, Show, Create, Update, Delete Flavors
        List, Show, Create, Update, Delete service profiles
    """

    @classmethod
    def resource_setup(cls):
        super(TestFlavorsJson, cls).resource_setup()
        if not test.is_extension_enabled('flavors', 'network'):
            msg = "flavors extension not enabled."
            raise cls.skipException(msg)
        service_type = "LOADBALANCER"
        description_flavor = "flavor is created by tempest"
        name_flavor = "Best flavor created by tempest"
        cls.flavor = cls.create_flavor(name_flavor, description_flavor,
                                       service_type)
        description_sp = "service profile created by tempest"
        # Future TODO(madhu_ak): Right now the dummy driver is loaded. Will
        # make changes as soon I get to know the flavor supported drivers
        driver = ""
        metainfo = '{"data": "value"}'
        cls.service_profile = cls.create_service_profile(
            description=description_sp, metainfo=metainfo, driver=driver)

    def _delete_service_profile(self, service_profile_id):
        # Deletes a service profile and verifies if it is deleted or not
        self.admin_client.delete_service_profile(service_profile_id)
        # Asserting that service profile is not found in list after deletion
        labels = self.admin_client.list_service_profiles(id=service_profile_id)
        self.assertEqual(len(labels['service_profiles']), 0)

    @test.attr(type='smoke')
    @test.idempotent_id('ec8e15ff-95d0-433b-b8a6-b466bddb1e50')
    def test_create_update_delete_service_profile(self):
        # Creates a service profile
        description = "service_profile created by tempest"
        driver = ""
        metainfo = '{"data": "value"}'
        body = self.admin_client.create_service_profile(
            description=description, driver=driver, metainfo=metainfo)
        service_profile = body['service_profile']
        # Updates a service profile
        self.admin_client.update_service_profile(service_profile['id'],
                                                 enabled=False)
        self.assertTrue(service_profile['enabled'])
        # Deletes a service profile
        self.addCleanup(self._delete_service_profile,
                        service_profile['id'])
        # Assert whether created service profiles are found in service profile
        # lists or fail if created service profiles are not found in service
        # profiles list
        labels = (self.admin_client.list_service_profiles(
                  id=service_profile['id']))
        self.assertEqual(len(labels['service_profiles']), 1)

    @test.attr(type='smoke')
    @test.idempotent_id('ec8e15ff-95d0-433b-b8a6-b466bddb1e50')
    def test_create_update_delete_flavor(self):
        # Creates a flavor
        description = "flavor created by tempest"
        service = "LOADBALANCERS"
        name = "Best flavor created by tempest"
        body = self.admin_client.create_flavor(name=name, service_type=service,
                                               description=description)
        flavor = body['flavor']
        # Updates a flavor
        self.admin_client.update_flavor(flavor['id'], enabled=False)
        self.assertTrue(flavor['enabled'])
        # Deletes a flavor
        self.addCleanup(self._delete_flavor, flavor['id'])
        # Assert whether created flavors are found in flavor lists or fail
        # if created flavors are not found in flavors list
        labels = (self.admin_client.list_flavors(id=flavor['id']))
        self.assertEqual(len(labels['flavors']), 1)

    @test.attr(type='smoke')
    @test.idempotent_id('30abb445-0eea-472e-bd02-8649f54a5968')
    def test_show_service_profile(self):
        # Verifies the details of a service profile
        body = self.admin_client.show_service_profile(
            self.service_profile['id'])
        service_profile = body['service_profile']
        self.assertEqual(self.service_profile['id'], service_profile['id'])
        self.assertEqual(self.service_profile['description'],
                         service_profile['description'])
        self.assertEqual(self.service_profile['metainfo'],
                         service_profile['metainfo'])
        self.assertEqual(True, service_profile['enabled'])

    @test.attr(type='smoke')
    @test.idempotent_id('30abb445-0eea-472e-bd02-8649f54a5968')
    def test_show_flavor(self):
        # Verifies the details of a flavor
        body = self.admin_client.show_flavor(self.flavor['id'])
        flavor = body['flavor']
        self.assertEqual(self.flavor['id'], flavor['id'])
        self.assertEqual(self.flavor['description'], flavor['description'])
        self.assertEqual(self.flavor['name'], flavor['name'])
        self.assertEqual(True, flavor['enabled'])

    @test.attr(type='smoke')
    @test.idempotent_id('e2fb2f8c-45bf-429a-9f17-171c70444612')
    def test_list_flavors(self):
        # Verify flavor lists
        body = self.admin_client.list_flavors(id=33)
        flavors = body['flavors']
        self.assertEqual(0, len(flavors))

    @test.attr(type='smoke')
    @test.idempotent_id('e2fb2f8c-45bf-429a-9f17-171c70444612')
    def test_list_service_profiles(self):
        # Verify service profiles lists
        body = self.admin_client.list_service_profiles(id=33)
        service_profiles = body['service_profiles']
        self.assertEqual(0, len(service_profiles))

    def _delete_flavor(self, flavor_id):
        # Deletes a flavor and verifies if it is deleted or not
        self.admin_client.delete_flavor(flavor_id)
        # Asserting that the flavor is not found in list after deletion
        labels = self.admin_client.list_flavors(id=flavor_id)
        self.assertEqual(len(labels['flavors']), 0)


class TestFlavorsIpV6TestJSON(TestFlavorsJson):
    _ip_version = 6
