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
#


import copy
import fixtures
import mock

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron import context
from neutron.db import api as dbapi
from neutron.db import flavors_db
from neutron.extensions import flavors
from neutron import manager
from neutron.plugins.common import constants
from neutron.tests import base
from neutron.tests.unit.api.v2 import test_base
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import base as extension

_uuid = uuidutils.generate_uuid
_get_path = test_base._get_path


class FlavorExtensionTestCase(extension.ExtensionTestCase):

    def setUp(self):
        super(FlavorExtensionTestCase, self).setUp()
        self._setUpExtension(
            'neutron.db.flavors_db.FlavorManager',
            constants.FLAVORS, flavors.RESOURCE_ATTRIBUTE_MAP,
            flavors.Flavors, '', supported_extension_aliases='flavors')

    def test_create_flavor(self):
        tenant_id = uuidutils.generate_uuid()
        data = {'flavor': {'name': 'GOLD',
                           'service_type': constants.LOADBALANCER,
                           'description': 'the best flavor',
                           'tenant_id': tenant_id,
                           'enabled': True}}

        expected = copy.deepcopy(data)
        expected['flavor']['service_profiles'] = []

        instance = self.plugin.return_value
        instance.create_flavor.return_value = expected['flavor']
        res = self.api.post(_get_path('flavors', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        instance.create_flavor.assert_called_with(mock.ANY,
                                                  flavor=expected)
        res = self.deserialize(res)
        self.assertIn('flavor', res)
        self.assertEqual(expected, res)

    def test_update_flavor(self):
        flavor_id = 'fake_id'
        data = {'flavor': {'name': 'GOLD',
                           'description': 'the best flavor',
                           'enabled': True}}
        expected = copy.copy(data)
        expected['flavor']['service_profiles'] = []

        instance = self.plugin.return_value
        instance.update_flavor.return_value = expected['flavor']
        res = self.api.put(_get_path('flavors', id=flavor_id, fmt=self.fmt),
                           self.serialize(data),
                           content_type='application/%s' % self.fmt)

        instance.update_flavor.assert_called_with(mock.ANY,
                                                  flavor_id,
                                                  flavor=expected)
        res = self.deserialize(res)
        self.assertIn('flavor', res)
        self.assertEqual(expected, res)

    def test_delete_flavor(self):
        flavor_id = 'fake_id'
        instance = self.plugin.return_value
        self.api.delete(_get_path('flavors', id=flavor_id, fmt=self.fmt),
                        content_type='application/%s' % self.fmt)

        instance.delete_flavor.assert_called_with(mock.ANY,
                                                  flavor_id)

    def test_show_flavor(self):
        flavor_id = 'fake_id'
        expected = {'flavor': {'id': flavor_id,
                               'name': 'GOLD',
                               'description': 'the best flavor',
                               'enabled': True,
                               'service_profiles': ['profile-1']}}
        instance = self.plugin.return_value
        instance.get_flavor.return_value = expected['flavor']
        res = self.api.get(_get_path('flavors', id=flavor_id, fmt=self.fmt))
        instance.get_flavor.assert_called_with(mock.ANY,
                                               flavor_id,
                                               fields=mock.ANY)
        res = self.deserialize(res)
        self.assertEqual(expected, res)

    def test_get_flavors(self):
        data = {'flavors': [{'id': 'id1',
                             'name': 'GOLD',
                             'description': 'the best flavor',
                             'enabled': True,
                             'service_profiles': ['profile-1']},
                            {'id': 'id2',
                             'name': 'GOLD',
                             'description': 'the best flavor',
                             'enabled': True,
                             'service_profiles': ['profile-2', 'profile-1']}]}
        instance = self.plugin.return_value
        instance.get_flavors.return_value = data['flavors']
        res = self.api.get(_get_path('flavors', fmt=self.fmt))
        instance.get_flavors.assert_called_with(mock.ANY,
                                                fields=mock.ANY,
                                                filters=mock.ANY)
        res = self.deserialize(res)
        self.assertEqual(data, res)

    def test_create_service_profile(self):
        tenant_id = uuidutils.generate_uuid()
        expected = {'service_profile': {'description': 'the best sp',
                                        'driver': '',
                                        'tenant_id': tenant_id,
                                        'enabled': True,
                                        'metainfo': '{"data": "value"}'}}

        instance = self.plugin.return_value
        instance.create_service_profile.return_value = (
            expected['service_profile'])
        res = self.api.post(_get_path('service_profiles', fmt=self.fmt),
                            self.serialize(expected),
                            content_type='application/%s' % self.fmt)
        instance.create_service_profile.assert_called_with(
            mock.ANY,
            service_profile=expected)
        res = self.deserialize(res)
        self.assertIn('service_profile', res)
        self.assertEqual(expected, res)

    def test_update_service_profile(self):
        sp_id = "fake_id"
        expected = {'service_profile': {'description': 'the best sp',
                                        'enabled': False,
                                        'metainfo': '{"data1": "value3"}'}}

        instance = self.plugin.return_value
        instance.update_service_profile.return_value = (
            expected['service_profile'])
        res = self.api.put(_get_path('service_profiles',
                                     id=sp_id, fmt=self.fmt),
                           self.serialize(expected),
                           content_type='application/%s' % self.fmt)

        instance.update_service_profile.assert_called_with(
            mock.ANY,
            sp_id,
            service_profile=expected)
        res = self.deserialize(res)
        self.assertIn('service_profile', res)
        self.assertEqual(expected, res)

    def test_delete_service_profile(self):
        sp_id = 'fake_id'
        instance = self.plugin.return_value
        self.api.delete(_get_path('service_profiles', id=sp_id, fmt=self.fmt),
                        content_type='application/%s' % self.fmt)
        instance.delete_service_profile.assert_called_with(mock.ANY,
                                                           sp_id)

    def test_show_service_profile(self):
        sp_id = 'fake_id'
        expected = {'service_profile': {'id': 'id1',
                                        'driver': 'entrypoint1',
                                        'description': 'desc',
                                        'metainfo': '{}',
                                        'enabled': True}}
        instance = self.plugin.return_value
        instance.get_service_profile.return_value = (
            expected['service_profile'])
        res = self.api.get(_get_path('service_profiles',
                                     id=sp_id, fmt=self.fmt))
        instance.get_service_profile.assert_called_with(mock.ANY,
                                                        sp_id,
                                                        fields=mock.ANY)
        res = self.deserialize(res)
        self.assertEqual(expected, res)

    def test_get_service_profiles(self):
        expected = {'service_profiles': [{'id': 'id1',
                                          'driver': 'entrypoint1',
                                          'description': 'desc',
                                          'metainfo': '{}',
                                          'enabled': True},
                                         {'id': 'id2',
                                          'driver': 'entrypoint2',
                                          'description': 'desc',
                                          'metainfo': '{}',
                                          'enabled': True}]}
        instance = self.plugin.return_value
        instance.get_service_profiles.return_value = (
            expected['service_profiles'])
        res = self.api.get(_get_path('service_profiles', fmt=self.fmt))
        instance.get_service_profiles.assert_called_with(mock.ANY,
                                                         fields=mock.ANY,
                                                         filters=mock.ANY)
        res = self.deserialize(res)
        self.assertEqual(expected, res)

    def test_associate_service_profile_with_flavor(self):
        expected = {'service_profile': {'id': _uuid()}}
        instance = self.plugin.return_value
        instance.create_flavor_service_profile.return_value = (
            expected['service_profile'])
        res = self.api.post('/flavors/fl_id/service_profiles',
                            self.serialize(expected),
                            content_type='application/%s' % self.fmt)
        instance.create_flavor_service_profile.assert_called_with(
            mock.ANY, service_profile=expected, flavor_id='fl_id')
        res = self.deserialize(res)
        self.assertEqual(expected, res)

    def test_disassociate_service_profile_with_flavor(self):
        instance = self.plugin.return_value
        instance.delete_flavor_service_profile.return_value = None
        self.api.delete('/flavors/fl_id/service_profiles/%s' % 'fake_spid',
                        content_type='application/%s' % self.fmt)
        instance.delete_flavor_service_profile.assert_called_with(
            mock.ANY,
            'fake_spid',
            flavor_id='fl_id')


class DummyCorePlugin(object):
    pass


class DummyServicePlugin(object):

    def driver_loaded(self, driver, service_profile):
        pass

    def get_plugin_type(self):
        return constants.DUMMY

    def get_plugin_description(self):
        return "Dummy service plugin, aware of flavors"


class DummyServiceDriver(object):

    @staticmethod
    def get_service_type():
        return constants.DUMMY

    def __init__(self, plugin):
        pass


class FlavorManagerTestCase(test_db_base_plugin_v2.NeutronDbPluginV2TestCase,
                            base.PluginFixture):
    def setUp(self):
        super(FlavorManagerTestCase, self).setUp()

        self.config_parse()
        cfg.CONF.set_override(
            'core_plugin',
            'neutron.tests.unit.extensions.test_flavors.DummyCorePlugin')
        cfg.CONF.set_override(
            'service_plugins',
            ['neutron.tests.unit.extensions.test_flavors.DummyServicePlugin'])

        self.useFixture(
            fixtures.MonkeyPatch('neutron.manager.NeutronManager._instance'))

        self.plugin = flavors_db.FlavorManager(
            manager.NeutronManager().get_instance())
        self.ctx = context.get_admin_context()
        dbapi.get_engine()

    def _create_flavor(self, description=None):
        flavor = {'flavor': {'name': 'GOLD',
                             'service_type': constants.LOADBALANCER,
                             'description': description or 'the best flavor',
                             'enabled': True}}
        return self.plugin.create_flavor(self.ctx, flavor), flavor

    def test_create_flavor(self):
        self._create_flavor()
        res = self.ctx.session.query(flavors_db.Flavor).all()
        self.assertEqual(1, len(res))
        self.assertEqual('GOLD', res[0]['name'])

    def test_update_flavor(self):
        fl, flavor = self._create_flavor()
        flavor = {'flavor': {'name': 'Silver',
                             'enabled': False}}
        self.plugin.update_flavor(self.ctx, fl['id'], flavor)
        res = (self.ctx.session.query(flavors_db.Flavor).
               filter_by(id=fl['id']).one())
        self.assertEqual('Silver', res['name'])
        self.assertFalse(res['enabled'])

    def test_delete_flavor(self):
        fl, data = self._create_flavor()
        self.plugin.delete_flavor(self.ctx, fl['id'])
        res = (self.ctx.session.query(flavors_db.Flavor).all())
        self.assertFalse(res)

    def test_show_flavor(self):
        fl, data = self._create_flavor()
        show_fl = self.plugin.get_flavor(self.ctx, fl['id'])
        self.assertEqual(fl, show_fl)

    def test_get_flavors(self):
        fl, flavor = self._create_flavor()
        flavor['flavor']['name'] = 'SILVER'
        self.plugin.create_flavor(self.ctx, flavor)
        show_fl = self.plugin.get_flavors(self.ctx)
        self.assertEqual(2, len(show_fl))

    def _create_service_profile(self, description=None):
        data = {'service_profile':
                {'description': description or 'the best sp',
                 'driver':
                     ('neutron.tests.unit.extensions.test_flavors.'
                      'DummyServiceDriver'),
                 'enabled': True,
                 'metainfo': '{"data": "value"}'}}
        sp = self.plugin.unit_create_service_profile(self.ctx,
                                                     data)
        return sp, data

    def test_create_service_profile(self):
        sp, data = self._create_service_profile()
        res = (self.ctx.session.query(flavors_db.ServiceProfile).
               filter_by(id=sp['id']).one())
        self.assertEqual(data['service_profile']['driver'], res['driver'])
        self.assertEqual(data['service_profile']['metainfo'], res['metainfo'])

    def test_update_service_profile(self):
        sp, data = self._create_service_profile()
        data['service_profile']['metainfo'] = '{"data": "value1"}'
        sp = self.plugin.update_service_profile(self.ctx, sp['id'],
                                                data)
        res = (self.ctx.session.query(flavors_db.ServiceProfile).
               filter_by(id=sp['id']).one())
        self.assertEqual(data['service_profile']['metainfo'], res['metainfo'])

    def test_delete_service_profile(self):
        sp, data = self._create_service_profile()
        self.plugin.delete_service_profile(self.ctx, sp['id'])
        res = self.ctx.session.query(flavors_db.ServiceProfile).all()
        self.assertFalse(res)

    def test_show_service_profile(self):
        sp, data = self._create_service_profile()
        sp_show = self.plugin.get_service_profile(self.ctx, sp['id'])
        self.assertEqual(sp, sp_show)

    def test_get_service_profiles(self):
        self._create_service_profile()
        self._create_service_profile(description='another sp')
        self.assertEqual(2, len(self.plugin.get_service_profiles(self.ctx)))

    def test_associate_service_profile_with_flavor(self):
        sp, data = self._create_service_profile()
        fl, data = self._create_flavor()
        self.plugin.create_flavor_service_profile(
            self.ctx,
            {'service_profile': {'id': sp['id']}},
            fl['id'])
        binding = (
            self.ctx.session.query(flavors_db.FlavorServiceProfileBinding).
            first())
        self.assertEqual(fl['id'], binding['flavor_id'])
        self.assertEqual(sp['id'], binding['service_profile_id'])

        res = self.plugin.get_flavor(self.ctx, fl['id'])
        self.assertEqual(1, len(res['service_profiles']))
        self.assertEqual(sp['id'], res['service_profiles'][0])

        res = self.plugin.get_service_profile(self.ctx, sp['id'])
        self.assertEqual(1, len(res['flavors']))
        self.assertEqual(fl['id'], res['flavors'][0])

    def test_autodelete_flavor_associations(self):
        sp, data = self._create_service_profile()
        fl, data = self._create_flavor()
        self.plugin.create_flavor_service_profile(
            self.ctx,
            {'service_profile': {'id': sp['id']}},
            fl['id'])
        self.plugin.delete_flavor(self.ctx, fl['id'])
        binding = (
            self.ctx.session.query(flavors_db.FlavorServiceProfileBinding).
            first())
        self.assertIsNone(binding)

    def test_associate_service_profile_with_flavor_exists(self):
        sp, data = self._create_service_profile()
        fl, data = self._create_flavor()
        self.plugin.create_flavor_service_profile(
            self.ctx,
            {'service_profile': {'id': sp['id']}},
            fl['id'])
        self.assertRaises(flavors_db.FlavorServiceProfileBindingExists,
                          self.plugin.create_flavor_service_profile,
                          self.ctx,
                          {'service_profile': {'id': sp['id']}},
                          fl['id'])

    def test_disassociate_service_profile_with_flavor(self):
        sp, data = self._create_service_profile()
        fl, data = self._create_flavor()
        self.plugin.create_flavor_service_profile(
            self.ctx,
            {'service_profile': {'id': sp['id']}},
            fl['id'])
        self.plugin.delete_flavor_service_profile(
            self.ctx, sp['id'], fl['id'])
        binding = (
            self.ctx.session.query(flavors_db.FlavorServiceProfileBinding).
            first())
        self.assertIsNone(binding)

        self.assertRaises(
            flavors_db.FlavorServiceProfileBindingNotFound,
            self.plugin.delete_flavor_service_profile,
            self.ctx, sp['id'], fl['id'])

    def test_delete_service_profile_in_use(self):
        sp, data = self._create_service_profile()
        fl, data = self._create_flavor()
        self.plugin.create_flavor_service_profile(
            self.ctx,
            {'service_profile': {'id': sp['id']}},
            fl['id'])
        self.assertRaises(
            flavors_db.ServiceProfileInUse,
            self.plugin.delete_service_profile,
            self.ctx,
            sp['id'])
