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

from tempest.lib import decorators
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base


class TestFlavorsJson(base.BaseAdminNetworkTest):

    """
    Tests the following operations in the Neutron API using the REST client for
    Neutron:

        List, Show, Create, Update, Delete Flavors
        List, Show, Create, Update, Delete service profiles
    """

    required_extensions = ['flavors']

    @classmethod
    def resource_setup(cls):
        super(TestFlavorsJson, cls).resource_setup()

        # Use flavors service type as know this is loaded
        service_type = "FLAVORS"
        description_flavor = "flavor is created by tempest"
        name_flavor = "Best flavor created by tempest"

        # The check above will pass if api_extensions=all, which does
        # not mean flavors extension itself is present.
        try:
            cls.flavor = cls.create_flavor(name_flavor, description_flavor,
                                           service_type)
        except lib_exc.NotFound:
            msg = "flavors plugin not enabled."
            raise cls.skipException(msg)

        description_sp = "service profile created by tempest"
        # Drivers are supported as is an empty driver field.  Use an
        # empty field for now since otherwise driver is validated against the
        # servicetype configuration which may differ in test scenarios.
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

    @decorators.idempotent_id('b12a9487-b6a2-4cff-a69a-fe2a0b64fae6')
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

    @decorators.idempotent_id('136bcf09-00af-4da7-9b7f-174735d4aebd')
    def test_create_update_delete_flavor(self):
        # Creates a flavor
        description = "flavor created by tempest"
        service = "FLAVORS"
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

    @decorators.idempotent_id('30abb445-0eea-472e-bd02-8649f54a5968')
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
        self.assertTrue(service_profile['enabled'])

    @decorators.idempotent_id('362f9658-164b-44dd-8356-151bc9b7be72')
    def test_show_flavor(self):
        # Verifies the details of a flavor
        body = self.admin_client.show_flavor(self.flavor['id'])
        flavor = body['flavor']
        self.assertEqual(self.flavor['id'], flavor['id'])
        self.assertEqual(self.flavor['description'], flavor['description'])
        self.assertEqual(self.flavor['name'], flavor['name'])
        self.assertTrue(flavor['enabled'])

    @decorators.idempotent_id('eb3dd12e-6dfd-45f4-8393-46e0fa19860e')
    def test_list_flavors(self):
        # Verify flavor lists
        body = self.admin_client.list_flavors(id=33)
        flavors = body['flavors']
        self.assertEqual(0, len(flavors))

    @decorators.idempotent_id('e2fb2f8c-45bf-429a-9f17-171c70444612')
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
