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
import copy
import itertools
import netaddr
import random

import mock
from neutron_lib import exceptions as n_exc
from oslo_db import exception as obj_exc
from oslo_utils import timeutils
from oslo_utils import uuidutils
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields
from oslo_versionedobjects import fixture
import testtools

from neutron.common import constants
from neutron.common import utils as common_utils
from neutron import context
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db import segments_db
from neutron.objects import base
from neutron.objects import common_types
from neutron.objects.db import api as obj_db_api
from neutron.objects import subnet
from neutron.tests import base as test_base
from neutron.tests import tools
from neutron.tests.unit.db import test_db_base_plugin_v2


SQLALCHEMY_COMMIT = 'sqlalchemy.engine.Connection._commit_impl'
OBJECTS_BASE_OBJ_FROM_PRIMITIVE = ('oslo_versionedobjects.base.'
                                   'VersionedObject.obj_from_primitive')
TIMESTAMP_FIELDS = ['created_at', 'updated_at', 'revision_number']


class FakeModel(object):
    def __init__(self, *args, **kwargs):
        pass


class ObjectFieldsModel(object):
    def __init__(self, *args, **kwargs):
        pass


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeSmallNeutronObject(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ObjectFieldsModel

    primary_keys = ['field1']

    foreign_keys = {
        'FakeNeutronObjectCompositePrimaryKeyWithId': {'field1': 'id'},
        'FakeNeutronDbObject': {'field2': 'id'},
        'FakeNeutronObjectUniqueKey': {'field3': 'id'},
    }

    fields = {
        'field1': obj_fields.UUIDField(),
        'field2': obj_fields.UUIDField(),
        'field3': obj_fields.UUIDField(),
    }


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeSmallNeutronObjectWithMultipleParents(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ObjectFieldsModel

    primary_keys = ['field1', 'field2']

    foreign_keys = {
        'FakeParent': {'field1': 'id'},
        'FakeParent2': {'field2': 'id'},
    }

    fields = {
        'field1': obj_fields.UUIDField(),
        'field2': obj_fields.StringField(),
    }


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeParent(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ObjectFieldsModel

    primary_keys = ['field1', 'field2']

    fields = {
        'id': obj_fields.UUIDField(),
        'children': obj_fields.ListOfObjectsField(
            'FakeSmallNeutronObjectWithMultipleParents',
            nullable=True)
    }

    synthetic_fields = ['children']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeWeirdKeySmallNeutronObject(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ObjectFieldsModel

    primary_keys = ['field1']

    foreign_keys = {
        'FakeNeutronObjectNonStandardPrimaryKey': {'field1': 'weird_key'},
        'FakeNeutronObjectCompositePrimaryKey': {'field2': 'weird_key'},
    }

    fields = {
        'field1': obj_fields.UUIDField(),
        'field2': obj_fields.StringField(),
    }


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronDbObject(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    fields = {
        'id': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'obj_field': obj_fields.ObjectField('FakeSmallNeutronObject',
                                            nullable=True)
    }

    primary_keys = ['id']

    fields_no_update = ['field1']

    synthetic_fields = ['obj_field']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectNonStandardPrimaryKey(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['weird_key']

    fields = {
        'weird_key': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'obj_field': obj_fields.ListOfObjectsField(
            'FakeWeirdKeySmallNeutronObject'),
        'field2': obj_fields.StringField()
    }

    synthetic_fields = ['obj_field', 'field2']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectCompositePrimaryKey(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['weird_key', 'field1']

    fields = {
        'weird_key': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'obj_field': obj_fields.ListOfObjectsField(
            'FakeWeirdKeySmallNeutronObject')
    }

    synthetic_fields = ['obj_field']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectUniqueKey(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['id', 'id2']
    unique_keys = [['unique_key'], ['id2']]

    fields = {
        'id': obj_fields.UUIDField(),
        'id2': obj_fields.UUIDField(),
        'unique_key': obj_fields.StringField(),
        'field1': obj_fields.StringField(),
        'obj_field': obj_fields.ObjectField('FakeSmallNeutronObject',
                                            nullable=True)
    }

    synthetic_fields = ['obj_field']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectRenamedField(base.NeutronDbObject):
    """
    Testing renaming the parameter from DB to NeutronDbObject
    For tests:
        - db fields: id, field_db, field2
        - object: id, field_ovo, field2
    """
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['id']

    fields = {
        'id': obj_fields.UUIDField(),
        'field_ovo': obj_fields.StringField(),
        'field2': obj_fields.StringField()
    }

    synthetic_fields = ['field2']

    fields_need_translation = {'field_ovo': 'field_db'}


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectCompositePrimaryKeyWithId(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    primary_keys = ['id', 'field1']

    fields = {
        'id': obj_fields.UUIDField(),
        'field1': obj_fields.StringField(),
        'obj_field': obj_fields.ListOfObjectsField('FakeSmallNeutronObject')
    }

    synthetic_fields = ['obj_field']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectMultipleForeignKeys(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = ObjectFieldsModel

    foreign_keys = {
        'FakeNeutronObjectSyntheticField': {'field1': 'id', 'field2': 'id'},
    }

    fields = {
        'field1': obj_fields.UUIDField(),
        'field2': obj_fields.UUIDField(),
    }


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectSyntheticField(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    fields = {
        'id': obj_fields.UUIDField(),
        'obj_field': obj_fields.ListOfObjectsField(
            'FakeNeutronObjectMultipleForeignKeys')
    }

    synthetic_fields = ['obj_field']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectSyntheticField2(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    fields = {
        'id': obj_fields.UUIDField(),
        'obj_field': obj_fields.ObjectField('FakeSmallNeutronObject')
    }

    synthetic_fields = ['obj_field']


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObjectWithProjectId(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    db_model = FakeModel

    fields = {
        'id': obj_fields.UUIDField(),
        'project_id': obj_fields.StringField(),
        'field2': obj_fields.UUIDField(),
    }


@obj_base.VersionedObjectRegistry.register_if(False)
class FakeNeutronObject(base.NeutronObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    fields = {
        'id': obj_fields.UUIDField(),
        'project_id': obj_fields.StringField(),
        'field2': obj_fields.UUIDField(),
    }

    @classmethod
    def get_object(cls, context, **kwargs):
        if not hasattr(cls, '_obj'):
            cls._obj = FakeNeutronObject(id=uuidutils.generate_uuid(),
                                         project_id='fake-id',
                                         field2=uuidutils.generate_uuid())
        return cls._obj

    @classmethod
    def get_objects(cls, context, _pager=None, count=1, **kwargs):
        return [
            cls.get_object(context, **kwargs)
            for i in range(count)
        ]


def get_random_dscp_mark():
    return random.choice(constants.VALID_DSCP_MARKS)


def get_random_direction():
    return random.choice(constants.VALID_DIRECTIONS)


def get_list_of_random_networks(num=10):
    for i in range(5):
        res = [tools.get_random_ip_network() for i in range(num)]
        # make sure there are no duplicates
        if len(set(res)) == num:
            return res
    raise Exception('Failed to generate unique networks')


FIELD_TYPE_VALUE_GENERATOR_MAP = {
    obj_fields.BooleanField: tools.get_random_boolean,
    obj_fields.IntegerField: tools.get_random_integer,
    obj_fields.StringField: tools.get_random_string,
    obj_fields.UUIDField: uuidutils.generate_uuid,
    obj_fields.ObjectField: lambda: None,
    obj_fields.ListOfObjectsField: lambda: [],
    common_types.DscpMarkField: get_random_dscp_mark,
    common_types.FlowDirectionEnumField: get_random_direction,
    obj_fields.IPNetworkField: tools.get_random_ip_network,
    common_types.IPNetworkField: tools.get_random_ip_network,
    common_types.IPNetworkPrefixLenField: tools.get_random_prefixlen,
    common_types.ListOfIPNetworksField: get_list_of_random_networks,
    common_types.IPVersionEnumField: tools.get_random_ip_version,
    obj_fields.DateTimeField: timeutils.utcnow,
    obj_fields.IPAddressField: tools.get_random_ip_address,
    common_types.MACAddressField: tools.get_random_EUI,
    common_types.IPV6ModeEnumField: tools.get_random_ipv6_mode,
    common_types.FlowDirectionEnumField: tools.get_random_flow_direction,
    common_types.EtherTypeEnumField: tools.get_random_ether_type,
    common_types.IpProtocolEnumField: tools.get_random_ip_protocol,
    common_types.PortRangeField: tools.get_random_port,
}


def get_obj_db_fields(obj):
    return {field: getattr(obj, field) for field in obj.fields
            if field not in obj.synthetic_fields}


def get_value(generator, version):
    if 'version' in generator.__code__.co_varnames:
        return generator(version=version)
    return generator()


def remove_timestamps_from_fields(obj_fields):
    return {field: value for field, value in obj_fields.items()
            if field not in TIMESTAMP_FIELDS}


def get_non_synthetic_fields(objclass, obj_fields):
    return {field: value for field, value in obj_fields.items()
            if not objclass.is_synthetic(field)}


class _BaseObjectTestCase(object):

    _test_class = FakeNeutronDbObject

    CORE_PLUGIN = 'neutron.db.db_base_plugin_v2.NeutronDbPluginV2'

    def setUp(self):
        super(_BaseObjectTestCase, self).setUp()
        # TODO(ihrachys): revisit plugin setup once we decouple
        # neutron.objects.db.api from core plugin instance
        self.setup_coreplugin(self.CORE_PLUGIN)
        self.context = context.get_admin_context()
        self.db_objs = list(self.get_random_fields() for _ in range(3))
        self.db_obj = self.db_objs[0]

        self.obj_fields = [self._test_class.modify_fields_from_db(db_obj)
                           for db_obj in self.db_objs]

        valid_field = [f for f in self._test_class.fields
                       if f not in self._test_class.synthetic_fields][0]
        self.valid_field_filter = {valid_field:
                                   self.obj_fields[0][valid_field]}
        self.obj_registry = self.useFixture(
            fixture.VersionedObjectRegistryFixture())
        self.obj_registry.register(FakeSmallNeutronObject)
        self.obj_registry.register(FakeWeirdKeySmallNeutronObject)
        self.obj_registry.register(FakeNeutronObjectMultipleForeignKeys)
        synthetic_obj_fields = self.get_random_fields(FakeSmallNeutronObject)
        self.model_map = {
            self._test_class.db_model: self.db_objs,
            ObjectFieldsModel: [synthetic_obj_fields]}

    @classmethod
    def get_random_fields(cls, obj_cls=None):
        obj_cls = obj_cls or cls._test_class
        fields = {}
        ip_version = tools.get_random_ip_version()
        for field, field_obj in obj_cls.fields.items():
            if field not in obj_cls.synthetic_fields:
                generator = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]
                fields[field] = get_value(generator, ip_version)
        return obj_cls.modify_fields_to_db(fields)

    @classmethod
    def generate_object_keys(cls, obj_cls, field_names=None):
        if field_names is None:
            field_names = obj_cls.primary_keys
        keys = {}
        for field in field_names:
            field_obj = obj_cls.fields[field]
            generator = FIELD_TYPE_VALUE_GENERATOR_MAP[type(field_obj)]
            keys[field] = generator()
        return keys

    def get_updatable_fields(self, fields):
        return base.get_updatable_fields(self._test_class, fields)

    @classmethod
    def _is_test_class(cls, obj):
        return isinstance(obj, cls._test_class)

    def fake_get_objects(self, context, model, **kwargs):
        return self.model_map[model]

    def _get_object_synthetic_fields(self, objclass):
        return [field for field in objclass.synthetic_fields
                if objclass.is_object_field(field)]

    def _get_ovo_object_class(self, objclass, field):
        try:
            name = objclass.fields[field].objname
            return obj_base.VersionedObjectRegistry.obj_classes().get(name)[0]
        except TypeError:
            # NOTE(korzen) some synthetic fields are not handled by
            # this method, for example the ones that have subclasses, see
            # QosRule
            return


class BaseObjectIfaceTestCase(_BaseObjectTestCase, test_base.BaseTestCase):

    def setUp(self):
        super(BaseObjectIfaceTestCase, self).setUp()
        self.model_map = collections.defaultdict(list)
        self.model_map[self._test_class.db_model] = self.db_objs
        self.pager_map = collections.defaultdict(lambda: None)

    def test_get_object(self):
        with mock.patch.object(obj_db_api, 'get_object',
                               return_value=self.db_obj) as get_object_mock:
            with mock.patch.object(obj_db_api, 'get_objects',
                                   side_effect=self.fake_get_objects):
                obj_keys = self.generate_object_keys(self._test_class)
                obj = self._test_class.get_object(self.context, **obj_keys)
                self.assertTrue(self._is_test_class(obj))
                self.assertEqual(self.obj_fields[0], get_obj_db_fields(obj))
                get_object_mock.assert_called_once_with(
                    self.context, self._test_class.db_model,
                    **self._test_class.modify_fields_to_db(obj_keys))

    def test_get_object_missing_object(self):
        with mock.patch.object(obj_db_api, 'get_object', return_value=None):
            obj_keys = self.generate_object_keys(self._test_class)
            obj = self._test_class.get_object(self.context, **obj_keys)
            self.assertIsNone(obj)

    def test_get_object_missing_primary_key(self):
        non_unique_fields = (set(self._test_class.fields.keys()) -
                             set(self._test_class.primary_keys) -
                             set(itertools.chain.from_iterable(
                                 self._test_class.unique_keys)))
        obj_keys = self.generate_object_keys(self._test_class,
                                             non_unique_fields)
        self.assertRaises(base.NeutronPrimaryKeyMissing,
                          self._test_class.get_object,
                          self.context, **obj_keys)

    def test_get_object_unique_key(self):
        if not self._test_class.unique_keys:
            self.skipTest('No unique keys found in test class %r' %
                          self._test_class)

        for unique_keys in self._test_class.unique_keys:
            with mock.patch.object(obj_db_api, 'get_object',
                                   return_value=self.db_obj) \
                    as get_object_mock:
                with mock.patch.object(obj_db_api, 'get_objects',
                                       side_effect=self.fake_get_objects):
                    obj_keys = self.generate_object_keys(self._test_class,
                                                         unique_keys)
                    obj = self._test_class.get_object(self.context,
                                                      **obj_keys)
                    self.assertTrue(self._is_test_class(obj))
                    self.assertEqual(self.obj_fields[0],
                                     get_obj_db_fields(obj))
                    get_object_mock.assert_called_once_with(
                        self.context, self._test_class.db_model,
                        **self._test_class.modify_fields_to_db(obj_keys))

    def _get_synthetic_fields_get_objects_calls(self, db_objs):
        mock_calls = []
        for db_obj in db_objs:
            for field in self._test_class.synthetic_fields:
                if self._test_class.is_object_field(field):
                    obj_class = self._get_ovo_object_class(self._test_class,
                                                           field)
                    foreign_keys = obj_class.foreign_keys.get(
                        self._test_class.__name__)
                    mock_calls.append(
                        mock.call(
                            self.context, obj_class.db_model,
                            _pager=self.pager_map[obj_class.obj_name()],
                            **{k: db_obj[v]
                            for k, v in foreign_keys.items()}))
        return mock_calls

    def test_get_objects(self):
        with mock.patch.object(
                obj_db_api, 'get_objects',
                side_effect=self.fake_get_objects) as get_objects_mock:
            objs = self._test_class.get_objects(self.context)
            self._validate_objects(self.db_objs, objs)
        mock_calls = [
            mock.call(self.context, self._test_class.db_model,
                      _pager=self.pager_map[self._test_class.obj_name()])
        ]
        mock_calls.extend(self._get_synthetic_fields_get_objects_calls(
            self.db_objs))
        get_objects_mock.assert_has_calls(mock_calls)

    def test_get_objects_valid_fields(self):
        with mock.patch.object(
            obj_db_api, 'get_objects',
            side_effect=self.fake_get_objects) as get_objects_mock:

            objs = self._test_class.get_objects(self.context,
                                                **self.valid_field_filter)
            self._validate_objects(self.db_objs, objs)
        mock_calls = [
            mock.call(
                self.context, self._test_class.db_model,
                _pager=self.pager_map[self._test_class.obj_name()],
                **self._test_class.modify_fields_to_db(self.valid_field_filter)
            )
        ]
        mock_calls.extend(self._get_synthetic_fields_get_objects_calls(
            [self.db_obj]))
        get_objects_mock.assert_has_calls(mock_calls)

    def test_get_objects_mixed_fields(self):
        synthetic_fields = (
            set(self._test_class.synthetic_fields) -
            self._test_class.extra_filter_names
        )
        if not synthetic_fields:
            self.skipTest('No synthetic fields that are not extra filters '
                          'found in test class %r' %
                          self._test_class)

        filters = copy.copy(self.valid_field_filter)
        filters[synthetic_fields.pop()] = 'xxx'

        with mock.patch.object(obj_db_api, 'get_objects',
                               return_value=self.db_objs):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              **filters)

    def test_get_objects_synthetic_fields_not_extra_filters(self):
        synthetic_fields = (
            set(self._test_class.synthetic_fields) -
            self._test_class.extra_filter_names
        )
        if not synthetic_fields:
            self.skipTest('No synthetic fields that are not extra filters '
                          'found in test class %r' %
                          self._test_class)

        with mock.patch.object(obj_db_api, 'get_objects',
                               side_effect=self.fake_get_objects):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              **{synthetic_fields.pop(): 'xxx'})

    def test_get_objects_invalid_fields(self):
        with mock.patch.object(obj_db_api, 'get_objects',
                               side_effect=self.fake_get_objects):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.get_objects, self.context,
                              fake_field='xxx')

    def test_count(self):
        if not isinstance(self._test_class, base.NeutronDbObject):
            self.skipTest('Class %s does not inherit from NeutronDbObject' %
                          self._test_class)
        expected = 10
        with mock.patch.object(obj_db_api, 'count', return_value=expected):
            self.assertEqual(expected, self._test_class.count(self.context))

    def test_count_invalid_fields(self):
            self.assertRaises(base.exceptions.InvalidInput,
                              self._test_class.count, self.context,
                              fake_field='xxx')

    def _validate_objects(self, expected, observed):
        self.assertTrue(all(self._is_test_class(obj) for obj in observed))
        self.assertEqual(
            sorted([self._test_class.modify_fields_from_db(db_obj)
                    for db_obj in expected],
                   key=common_utils.safe_sort_key),
            sorted([get_obj_db_fields(obj) for obj in observed],
                   key=common_utils.safe_sort_key))

    def _check_equal(self, obj, db_obj):
        self.assertEqual(
            sorted(db_obj),
            sorted(get_obj_db_fields(obj)))

    def test_create(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               return_value=self.db_obj) as create_mock:
            with mock.patch.object(obj_db_api, 'get_objects',
                  side_effect=self.fake_get_objects):
                obj = self._test_class(self.context, **self.obj_fields[0])
                self._check_equal(obj, self.obj_fields[0])
                obj.create()
                self._check_equal(obj, self.obj_fields[0])
                create_mock.assert_called_once_with(
                    self.context, self._test_class.db_model, self.db_obj)

    def test_create_updates_from_db_object(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               return_value=self.db_obj):
            with mock.patch.object(obj_db_api, 'get_objects',
                  side_effect=self.fake_get_objects):
                obj = self._test_class(self.context, **self.obj_fields[1])
                self._check_equal(obj, self.obj_fields[1])
                obj.create()
                self._check_equal(obj, self.obj_fields[0])

    def test_create_duplicates(self):
        with mock.patch.object(obj_db_api, 'create_object',
                               side_effect=obj_exc.DBDuplicateEntry):
            obj = self._test_class(self.context, **self.obj_fields[0])
            self.assertRaises(base.NeutronDbObjectDuplicateEntry, obj.create)

    def test_update_fields(self):
        if not self._test_class.primary_keys:
            self.skipTest(
                'Test class %r has no primary keys' % self._test_class)

        with mock.patch.object(obj_base.VersionedObject, 'obj_reset_changes'):
            expected = self._test_class(self.context, **self.obj_fields[0])
            for key, val in self.obj_fields[1].items():
                if key not in expected.fields_no_update:
                    setattr(expected, key, val)
            observed = self._test_class(self.context, **self.obj_fields[0])
            observed.update_fields(self.obj_fields[1], reset_changes=True)
            self.assertEqual(expected, observed)
            self.assertTrue(observed.obj_reset_changes.called)

        with mock.patch.object(obj_base.VersionedObject, 'obj_reset_changes'):
            obj = self._test_class(self.context, **self.obj_fields[0])
            obj.update_fields(self.obj_fields[1])
            self.assertFalse(obj.obj_reset_changes.called)

    def test_extra_fields(self):
        if not len(self._test_class.obj_extra_fields):
            self.skipTest(
                'Test class %r has no obj_extra_fields' % self._test_class)
        obj = self._test_class(self.context, **self.obj_fields[0])
        for field in self._test_class.obj_extra_fields:
            # field is accessible and cannot be set by any value
            getattr(obj, field)
            self.assertTrue(field in obj.to_dict().keys())
            self.assertRaises(AttributeError, setattr, obj, field, "1")

    def test_fields_no_update(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        for field in self._test_class.fields_no_update:
            self.assertTrue(hasattr(obj, field))

    def test_get_tenant_id(self):
        if not hasattr(self._test_class, 'project_id'):
            self.skipTest(
                'Test class %r has no project_id field' % self._test_class)
        obj = self._test_class(self.context, **self.obj_fields[0])
        project_id = self.obj_fields[0]['project_id']
        self.assertEqual(project_id, obj.tenant_id)

    @mock.patch.object(obj_db_api, 'update_object')
    def test_update_no_changes(self, update_mock):
        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value={}):
            obj_keys = self.generate_object_keys(self._test_class)
            obj = self._test_class(self.context, **obj_keys)
            obj.update()
            self.assertFalse(update_mock.called)

    @mock.patch.object(obj_db_api, 'update_object')
    def test_update_changes(self, update_mock):
        fields_to_update = self.get_updatable_fields(
            self._test_class.modify_fields_from_db(self.db_obj))
        if not fields_to_update:
            self.skipTest('No updatable fields found in test class %r' %
                          self._test_class)

        with mock.patch.object(base.NeutronDbObject,
                               '_get_changed_persistent_fields',
                               return_value=fields_to_update):
            with mock.patch.object(obj_db_api, 'get_objects',
                side_effect=self.fake_get_objects):
                obj = self._test_class(self.context, **self.obj_fields[0])
                # get new values and fix keys
                update_mock.return_value = self.db_objs[1].copy()
                fixed_keys = self._test_class.modify_fields_to_db(
                    obj._get_composite_keys())
                for key, value in fixed_keys.items():
                    update_mock.return_value[key] = value
                obj.update()
                update_mock.assert_called_once_with(
                    self.context, self._test_class.db_model,
                    self._test_class.modify_fields_to_db(fields_to_update),
                    **fixed_keys)

    @mock.patch.object(base.NeutronDbObject,
                       '_get_changed_persistent_fields',
                       return_value={'a': 'a', 'b': 'b', 'c': 'c'})
    def test_update_changes_forbidden(self, *mocks):
        with mock.patch.object(
            self._test_class,
            'fields_no_update',
            new_callable=mock.PropertyMock(return_value=['a', 'c']),
            create=True):
            obj = self._test_class(self.context, **self.obj_fields[0])
            self.assertRaises(base.NeutronObjectUpdateForbidden, obj.update)

    def test_update_updates_from_db_object(self):
        with mock.patch.object(obj_db_api, 'update_object',
                               return_value=self.db_obj):
            with mock.patch.object(obj_db_api, 'get_objects',
                  side_effect=self.fake_get_objects):
                obj = self._test_class(self.context, **self.obj_fields[1])
                fields_to_update = self.get_updatable_fields(
                    self.obj_fields[1])
                if not fields_to_update:
                    self.skipTest('No updatable fields found in test '
                                  'class %r' % self._test_class)
                with mock.patch.object(base.NeutronDbObject,
                                       '_get_changed_persistent_fields',
                                       return_value=fields_to_update):
                    with mock.patch.object(
                        obj_db_api, 'get_objects',
                        side_effect=self.fake_get_objects):
                        obj.update()
                self._check_equal(obj, self.obj_fields[0])

    @mock.patch.object(obj_db_api, 'delete_object')
    def test_delete(self, delete_mock):
        obj = self._test_class(self.context, **self.obj_fields[0])
        self._check_equal(obj, self.obj_fields[0])
        obj.delete()
        self._check_equal(obj, self.obj_fields[0])
        delete_mock.assert_called_once_with(
            self.context, self._test_class.db_model,
            **self._test_class.modify_fields_to_db(obj._get_composite_keys()))

    @mock.patch(OBJECTS_BASE_OBJ_FROM_PRIMITIVE)
    def test_clean_obj_from_primitive(self, get_prim_m):
        expected_obj = get_prim_m.return_value
        observed_obj = self._test_class.clean_obj_from_primitive('foo', 'bar')
        self.assertIs(expected_obj, observed_obj)
        self.assertTrue(observed_obj.obj_reset_changes.called)

    def test_update_primary_key_forbidden_fail(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.obj_reset_changes()

        if not self._test_class.primary_keys:
            self.skipTest(
                'All non-updatable fields found in test class %r '
                'are primary keys' % self._test_class)

        for key, val in self.obj_fields[0].items():
            if key in self._test_class.primary_keys:
                setattr(obj, key, val)

        self.assertRaises(base.NeutronObjectUpdateForbidden, obj.update)

    def test_to_dict_synthetic_fields(self):
        cls_ = self._test_class
        object_fields = self._get_object_synthetic_fields(cls_)
        if not object_fields:
            self.skipTest(
                'No object fields found in test class %r' % cls_)

        for field in object_fields:
            obj = cls_(self.context, **self.obj_fields[0])
            objclass = self._get_ovo_object_class(cls_, field)
            if not objclass:
                continue

            child = objclass(
                self.context, **objclass.modify_fields_from_db(
                    self.get_random_fields(obj_cls=objclass))
            )
            child_dict = child.to_dict()
            if isinstance(cls_.fields[field], obj_fields.ListOfObjectsField):
                setattr(obj, field, [child])
                dict_ = obj.to_dict()
                self.assertEqual([child_dict], dict_[field])
            else:
                setattr(obj, field, child)
                dict_ = obj.to_dict()
                self.assertEqual(child_dict, dict_[field])

    def test_get_objects_pager_is_passed_through(self):
        with mock.patch.object(obj_db_api, 'get_objects') as get_objects:
            pager = base.Pager()
            self._test_class.get_objects(self.context, _pager=pager)
            get_objects.assert_called_once_with(
                mock.ANY, self._test_class.db_model, _pager=pager)


class BaseDbObjectNonStandardPrimaryKeyTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectNonStandardPrimaryKey


class BaseDbObjectCompositePrimaryKeyTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectCompositePrimaryKey


class BaseDbObjectUniqueKeysTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectUniqueKey


class UniqueKeysTestCase(test_base.BaseTestCase):

    def test_class_creation(self):
        m_get_unique_keys = mock.patch.object(model_base, 'get_unique_keys')
        with m_get_unique_keys as get_unique_keys:
            get_unique_keys.return_value = [['field1'],
                                            ['field2', 'db_field3']]

            @obj_base.VersionedObjectRegistry.register_if(False)
            class UniqueKeysTestObject(base.NeutronDbObject):
                # Version 1.0: Initial version
                VERSION = '1.0'

                db_model = FakeModel

                primary_keys = ['id']

                fields = {
                    'id': obj_fields.UUIDField(),
                    'field1': obj_fields.UUIDField(),
                    'field2': obj_fields.UUIDField(),
                    'field3': obj_fields.UUIDField(),
                }

                fields_need_translation = {'field3': 'db_field3'}
        expected = {('field1',), ('field2', 'field3')}
        observed = {tuple(sorted(key))
                    for key in UniqueKeysTestObject.unique_keys}
        self.assertEqual(expected, observed)


class NeutronObjectCountTestCase(test_base.BaseTestCase):

    def test_count(self):
        expected = 10
        self.assertEqual(
            expected, FakeNeutronObject.count(None, count=expected))


class BaseDbObjectCompositePrimaryKeyWithIdTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectCompositePrimaryKeyWithId


class BaseDbObjectRenamedFieldTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectRenamedField


class BaseObjectIfaceWithProjectIdTestCase(BaseObjectIfaceTestCase):

    _test_class = FakeNeutronObjectWithProjectId

    def test_update_fields_using_tenant_id(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        obj.obj_reset_changes()

        tenant_id = obj['tenant_id']
        new_obj_fields = dict()
        new_obj_fields['tenant_id'] = uuidutils.generate_uuid()
        new_obj_fields['field2'] = uuidutils.generate_uuid()

        obj.update_fields(new_obj_fields)
        self.assertEqual(set(['field2']), obj.obj_what_changed())
        self.assertEqual(tenant_id, obj.project_id)


class BaseDbObjectMultipleForeignKeysTestCase(_BaseObjectTestCase,
                                              test_base.BaseTestCase):

    _test_class = FakeNeutronObjectSyntheticField

    def test_load_synthetic_db_fields_with_multiple_foreign_keys(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        self.assertRaises(base.NeutronSyntheticFieldMultipleForeignKeys,
                          obj.load_synthetic_db_fields)


class BaseDbObjectForeignKeysNotFoundTestCase(_BaseObjectTestCase,
                                              test_base.BaseTestCase):

    _test_class = FakeNeutronObjectSyntheticField2

    def test_load_foreign_keys_not_belong_class(self):
        obj = self._test_class(self.context, **self.obj_fields[0])
        self.assertRaises(base.NeutronSyntheticFieldsForeignKeysNotFound,
                          obj.load_synthetic_db_fields)


class BaseDbObjectMultipleParentsForForeignKeysTestCase(
        _BaseObjectTestCase,
        test_base.BaseTestCase):

    _test_class = FakeParent

    def test_load_synthetic_db_fields_with_multiple_parents(self):
        child_cls = FakeSmallNeutronObjectWithMultipleParents
        self.obj_registry.register(child_cls)
        self.obj_registry.register(FakeParent)
        obj = self._test_class(self.context, **self.obj_fields[0])
        fake_children = [
            child_cls(
                self.context, **child_cls.modify_fields_from_db(
                    self.get_random_fields(obj_cls=child_cls))
            )
            for _ in range(5)
        ]
        with mock.patch.object(child_cls, 'get_objects',
                               return_value=fake_children) as get_objects:
            obj.load_synthetic_db_fields()
        get_objects.assert_called_once_with(self.context, field1=obj.id)
        self.assertEqual(fake_children, obj.children)


class BaseDbObjectTestCase(_BaseObjectTestCase,
                           test_db_base_plugin_v2.DbOperationBoundMixin):
    def setUp(self):
        super(BaseDbObjectTestCase, self).setUp()
        self.useFixture(tools.CommonDbMixinHooksFixture())
        synthetic_fields = self._get_object_synthetic_fields(self._test_class)
        for synth_field in synthetic_fields:
            objclass = self._get_ovo_object_class(self._test_class,
                                                  synth_field)
            if not objclass:
                continue
            for db_obj in self.db_objs:
                objclass_fields = self.get_random_fields(objclass)
                db_obj[synth_field] = [objclass_fields]

    def _create_test_network(self):
        # TODO(ihrachys): replace with network.create() once we get an object
        # implementation for networks
        self._network = obj_db_api.create_object(self.context,
                                                 models_v2.Network,
                                                 {'name': 'test-network1'})

    def _create_network(self):
        name = "test-network-%s" % tools.get_random_string(4)
        return obj_db_api.create_object(self.context,
                                        models_v2.Network,
                                        {'name': name})

    def _create_test_subnet(self, network):
        test_subnet = {
            'project_id': uuidutils.generate_uuid(),
            'name': 'test-subnet1',
            'network_id': network['id'],
            'ip_version': 4,
            'cidr': netaddr.IPNetwork('10.0.0.0/24'),
            'gateway_ip': '10.0.0.1',
            'enable_dhcp': 1,
            'ipv6_ra_mode': None,
            'ipv6_address_mode': None
        }
        self._subnet = subnet.Subnet(self.context, **test_subnet)
        self._subnet.create()

    def _create_port(self, **port_attrs):
        if not hasattr(self, '_mac_address_generator'):
            self._mac_address_generator = (":".join(["%02x" % i] * 6)
                                           for i in itertools.count())

        if not hasattr(self, '_port_name_generator'):
            self._port_name_generator = ("test-port%d" % i
                                         for i in itertools.count(1))

        attrs = {'tenant_id': 'fake_tenant_id',
                 'admin_state_up': True,
                 'status': 'ACTIVE',
                 'device_id': 'fake_device',
                 'device_owner': 'fake_owner'}
        attrs.update(port_attrs)

        if 'name' not in attrs:
            attrs['name'] = next(self._port_name_generator)
        if 'mac_address' not in attrs:
            attrs['mac_address'] = next(self._mac_address_generator)

        # TODO(ihrachys): replace with port.create() once we get an object
        # implementation for ports
        return obj_db_api.create_object(self.context, models_v2.Port, attrs)

    def _create_test_segment(self, network):
        test_segment = {
            'network_id': network['id'],
            'network_type': 'vxlan',
        }
        # TODO(korzen): replace with segment.create() once we get an object
        # implementation for segments
        self._segment = obj_db_api.create_object(self.context,
                                                 segments_db.NetworkSegment,
                                                 test_segment)

    def _create_test_port(self, network):
        self._port = self._create_port(network_id=network['id'])

    def _make_object(self, fields):
        fields = get_non_synthetic_fields(self._test_class, fields)
        return self._test_class(
            self.context, **remove_timestamps_from_fields(fields))

    def test_get_object_create_update_delete(self):
        # Timestamps can't be initialized and multiple objects may use standard
        # attributes so we need to remove timestamps when creating objects
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        new = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        self.assertEqual(obj, new)

        obj = new

        for key, val in self.get_updatable_fields(self.obj_fields[1]).items():
            setattr(obj, key, val)
        obj.update()

        new = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        self.assertEqual(obj, new)

        obj = new
        new.delete()

        new = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        self.assertIsNone(new)

    def test_update_non_existent_object_raises_not_found(self):
        obj = self._make_object(self.obj_fields[0])
        obj.obj_reset_changes()

        fields_to_update = self.get_updatable_fields(self.obj_fields[0])
        if not fields_to_update:
            self.skipTest('No updatable fields found in test class %r' %
                          self._test_class)
        for key, val in fields_to_update.items():
            setattr(obj, key, val)

        self.assertRaises(n_exc.ObjectNotFound, obj.update)

    def test_delete_non_existent_object_raises_not_found(self):
        obj = self._make_object(self.obj_fields[0])
        self.assertRaises(n_exc.ObjectNotFound, obj.delete)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_create_single_transaction(self, mock_commit):
        obj = self._make_object(self.obj_fields[0])
        obj.create()
        self.assertEqual(1, mock_commit.call_count)

    def test_update_single_transaction(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        fields_to_update = self.get_updatable_fields(self.obj_fields[1])
        if not fields_to_update:
            self.skipTest('No updatable fields found in test class %r' %
                          self._test_class)
        for key, val in fields_to_update.items():
            setattr(obj, key, val)

        with mock.patch(SQLALCHEMY_COMMIT) as mock_commit:
            obj.update()
        self.assertEqual(1, mock_commit.call_count)

    def test_delete_single_transaction(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        with mock.patch(SQLALCHEMY_COMMIT) as mock_commit:
            obj.delete()
        self.assertEqual(1, mock_commit.call_count)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_get_objects_single_transaction(self, mock_commit):
        self._test_class.get_objects(self.context)
        self.assertEqual(1, mock_commit.call_count)

    @mock.patch(SQLALCHEMY_COMMIT)
    def test_get_object_single_transaction(self, mock_commit):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        obj = self._test_class.get_object(self.context,
                                          **obj._get_composite_keys())
        self.assertEqual(2, mock_commit.call_count)

    def test_get_objects_supports_extra_filtername(self):
        self.filtered_args = None

        def foo_filter(query, filters):
            self.filtered_args = filters
            return query

        self.obj_registry.register(self._test_class)
        db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
            self._test_class.db_model,
            'foo_filter',
            None,
            None,
            foo_filter)
        base.register_filter_hook_on_model(self._test_class.db_model, 'foo')

        self._test_class.get_objects(self.context, foo=42)
        self.assertEqual({'foo': [42]}, self.filtered_args)

    def test_filtering_by_fields(self):
        obj = self._make_object(self.obj_fields[0])
        obj.create()

        for field in remove_timestamps_from_fields(self.obj_fields[0]):
            filters = {field: [self.obj_fields[0][field]]}
            new = self._test_class.get_objects(self.context, **filters)
            self.assertEqual([obj], new, 'Filtering by %s failed.' % field)

    def _get_non_synth_fields(self, objclass, db_attrs):
        fields = objclass.modify_fields_from_db(db_attrs)
        fields = remove_timestamps_from_fields(fields)
        fields = get_non_synthetic_fields(objclass, fields)
        return fields

    def _create_object_with_synthetic_fields(self, db_obj):
        cls_ = self._test_class
        object_fields = self._get_object_synthetic_fields(cls_)

        # create base object
        obj = cls_(self.context, **self._get_non_synth_fields(cls_, db_obj))
        obj.create()

        # create objects that are going to be loaded into the base object
        # through synthetic fields
        for field in object_fields:
            objclass = self._get_ovo_object_class(cls_, field)
            if not objclass:
                continue
            objclass_fields = self._get_non_synth_fields(objclass,
                                                         db_obj[field][0])

            # make sure children point to the base object
            foreign_keys = objclass.foreign_keys.get(obj.__class__.__name__)
            for local_field, foreign_key in foreign_keys.items():
                objclass_fields[local_field] = obj.get(foreign_key)

            synth_field_obj = objclass(self.context, **objclass_fields)
            synth_field_obj.create()

            # populate the base object synthetic fields with created children
            if isinstance(cls_.fields[field], obj_fields.ObjectField):
                setattr(obj, field, synth_field_obj)
            else:
                setattr(obj, field, [synth_field_obj])

            # reset the object so that we can compare it to other clean objects
            obj.obj_reset_changes([field])
        return obj

    def test_get_object_with_synthetic_fields(self):
        object_fields = self._get_object_synthetic_fields(self._test_class)
        if not object_fields:
            self.skipTest(
                'No synthetic object fields found '
                'in test class %r' % self._test_class
            )
        obj = self._create_object_with_synthetic_fields(self.db_objs[0])
        listed_obj = self._test_class.get_object(
            self.context, **obj._get_composite_keys())
        self.assertTrue(listed_obj)
        self.assertEqual(obj, listed_obj)

    # NOTE(korzen) _list method is used in neutron.tests.db.unit.db.
    # test_db_base_plugin_v2.DbOperationBoundMixin in _list_and_count_queries()
    # This is used in test_subnet for asserting that number of queries is
    # constant. It can be used also for port and network objects when ready.
    def _list(self, resource, neutron_context):
        cls_ = resource
        return cls_.get_objects(neutron_context)

    def test_get_objects_queries_constant(self):
        iter_db_obj = iter(self.db_objs)

        def _create():
            self._create_object_with_synthetic_fields(next(iter_db_obj))

        self._assert_object_list_queries_constant(_create, self._test_class)

    def test_count(self):
        for fields in self.obj_fields:
            self._make_object(fields).create()
        self.assertEqual(
            len(self.obj_fields), self._test_class.count(self.context))


class UniqueObjectBase(test_base.BaseTestCase):
    def setUp(self):
        super(UniqueObjectBase, self).setUp()
        obj_registry = self.useFixture(
            fixture.VersionedObjectRegistryFixture())
        self.db_model = FakeModel

        class RegisteredObject(base.NeutronDbObject):
            db_model = self.db_model

        self.registered_object = RegisteredObject
        obj_registry.register(self.registered_object)


class GetObjectClassByModelTestCase(UniqueObjectBase):
    def setUp(self):
        super(GetObjectClassByModelTestCase, self).setUp()
        self.not_registered_object = FakeSmallNeutronObject

    def test_object_found_by_model(self):
        found_obj = base.get_object_class_by_model(
            self.registered_object.db_model)
        self.assertIs(self.registered_object, found_obj)

    def test_not_registed_object_raises_exception(self):
        with testtools.ExpectedException(base.NeutronDbObjectNotFoundByModel):
            base.get_object_class_by_model(self.not_registered_object.db_model)


class RegisterFilterHookOnModelTestCase(UniqueObjectBase):
    def test_filtername_is_added(self):
        filter_name = 'foo'
        self.assertNotIn(
            filter_name, self.registered_object.extra_filter_names)
        base.register_filter_hook_on_model(
            FakeNeutronDbObject.db_model, filter_name)
        self.assertIn(filter_name, self.registered_object.extra_filter_names)


class PagerTestCase(test_base.BaseTestCase):
    def test_comparison(self):
        pager = base.Pager(sorts=[('order', True)])
        pager2 = base.Pager(sorts=[('order', True)])
        self.assertEqual(pager, pager2)

        pager3 = base.Pager()
        self.assertNotEqual(pager, pager3)
