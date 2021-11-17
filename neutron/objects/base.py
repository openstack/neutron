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
import collections
from collections import abc as collections_abc
import copy
import functools
import itertools

from neutron_lib.db import api as db_api
from neutron_lib.db import standard_attr
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import exceptions as o_exc
from neutron_lib.objects.extensions import standardattributes
from oslo_db import exception as obj_exc
from oslo_db.sqlalchemy import enginefacade
from oslo_db.sqlalchemy import utils as db_utils
from oslo_log import log as logging
from oslo_serialization import jsonutils
from oslo_utils import versionutils
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import exception as obj_exception
from oslo_versionedobjects import fields as obj_fields
from sqlalchemy import orm
from sqlalchemy.orm import query as sqla_query

from neutron._i18n import _
from neutron.objects.db import api as obj_db_api


LOG = logging.getLogger(__name__)

_NO_DB_MODEL = object()


def get_object_class_by_model(model):
    for obj_class in NeutronObjectRegistry.obj_classes().values():
        obj_class = obj_class[0]
        if getattr(obj_class, 'db_model', _NO_DB_MODEL) is model:
            return obj_class
    raise o_exc.NeutronDbObjectNotFoundByModel(model=model.__name__)


def register_filter_hook_on_model(model, filter_name):
    obj_class = get_object_class_by_model(model)
    obj_class.add_extra_filter_name(filter_name)


class LazyQueryIterator(object):
    def __init__(self, obj_class, lazy_query):
        self.obj_class = obj_class
        self.context = None
        self.query = lazy_query

    def __iter__(self):
        self.results = self.query.all()
        self.i = 0
        return self

    def __next__(self):
        if self.i >= len(self.results):
            raise StopIteration()
        item = self.obj_class._load_object(self.context, self.results[self.i])
        self.i += 1
        return item


class Pager(object):
    '''Pager class

    This class represents a pager object. It is consumed by get_objects to
    specify sorting and pagination criteria.
    '''
    def __init__(self, sorts=None, limit=None, page_reverse=None, marker=None):
        '''Initialize

        :param sorts: A list of (key, direction) tuples.
                      direction: True == ASC, False == DESC
        :param limit: maximum number of items to return
        :param page_reverse: True if sort direction is reversed.
        :param marker: the last item of the previous page; when used, returns
                       next results after the marker resource.
        '''

        self.sorts = sorts
        self.limit = limit
        self.page_reverse = page_reverse
        self.marker = marker

    def to_kwargs(self, context, obj_cls):
        res = {
            attr: getattr(self, attr)
            for attr in ('sorts', 'limit', 'page_reverse')
            if getattr(self, attr) is not None
        }
        if self.marker and self.limit:
            res['marker_obj'] = obj_db_api.get_object(
                obj_cls, context, id=self.marker)
        return res

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


class NeutronObjectRegistry(obj_base.VersionedObjectRegistry):

    _registry = None

    def __new__(cls, *args, **kwargs):
        # TODO(slaweq): this should be moved back to oslo.versionedobjects
        # lib as soon as bug https://bugs.launchpad.net/neutron/+bug/1731948
        # will be fixed and OVO's registry class will support defining custom
        # registries for objects.

        # NOTE(slaweq): it is overridden method
        # oslo_versionedobjects.base.VersionedObjectRegistry.__new__
        # We need to overwrite it to use separate registry for Neutron's
        # objects.
        # This is necessary to avoid clash in naming objects between Neutron
        # and e.g. os-vif (for example Route or Subnet objects are used in
        # both)
        if not NeutronObjectRegistry._registry:
            NeutronObjectRegistry._registry = object.__new__(
                NeutronObjectRegistry, *args, **kwargs)
            NeutronObjectRegistry._registry._obj_classes = \
                collections.defaultdict(list)
        self = object.__new__(cls, *args, **kwargs)
        self._obj_classes = (
            NeutronObjectRegistry._registry._obj_classes)
        return self


class NeutronObject(obj_base.VersionedObject,
                    obj_base.VersionedObjectDictCompat,
                    obj_base.ComparableVersionedObject,
                    metaclass=abc.ABCMeta):

    synthetic_fields = []
    extra_filter_names = set()

    # To use lazy queries for child objects, you must set the ORM
    # relationship in the db model to 'dynamic'. By default, all
    # children are eager loaded.
    lazy_fields = set()

    def __init__(self, context=None, **kwargs):
        super(NeutronObject, self).__init__(context, **kwargs)
        self._load_synthetic_fields = True
        self.obj_set_defaults()

    def _synthetic_fields_items(self):
        for field in self.synthetic_fields:
            if field in self:
                yield field, getattr(self, field)

    def to_dict(self):
        dict_ = {}
        # not using obj_to_primitive because it skips extra fields
        for name, value in self.items():
            # we have to check if item is in fields because obj_extra_fields
            # is included in self.items()
            if name in self.fields and name not in self.synthetic_fields:
                value = self.fields[name].to_primitive(self, name, value)
            # TODO(ralonsoh): remove once bp/keystone-v3 migration finishes.
            if name == 'tenant_id':
                if ('project_id' in self.fields and
                        not self.obj_attr_is_set('project_id')):
                    continue
            dict_[name] = value
        for field_name, value in self._synthetic_fields_items():
            field = self.fields[field_name]
            if isinstance(field, obj_fields.ListOfObjectsField):
                dict_[field_name] = [obj.to_dict() for obj in value]
            elif isinstance(field, obj_fields.ObjectField):
                dict_[field_name] = (
                    dict_[field_name].to_dict() if value else None)
            else:
                dict_[field_name] = field.to_primitive(self, field_name, value)
        return dict_

    @classmethod
    def is_synthetic(cls, field):
        return field in cls.synthetic_fields

    @classmethod
    def is_object_field(cls, field):
        return (isinstance(cls.fields[field], obj_fields.ListOfObjectsField) or
                isinstance(cls.fields[field], obj_fields.ObjectField))

    @classmethod
    def obj_class_from_name(cls, objname, objver):
        """Returns a class from the registry based on a name and version."""
        # NOTE(slaweq): it is override method
        # oslo_versionedobjects.base.VersionedObject.obj_class_from_name
        # We need to override it to use Neutron's objects registry class
        # (NeutronObjectRegistry) instead of original VersionedObjectRegistry
        # class from oslo_versionedobjects
        # This is necessary to avoid clash in naming objects between Neutron
        # and e.g. os-vif (for example Route or Subnet objects are used in
        # both)
        if objname not in NeutronObjectRegistry.obj_classes():
            LOG.error('Unable to instantiate unregistered object type '
                      '%(objtype)s', dict(objtype=objname))
            raise obj_exception.UnsupportedObjectError(objtype=objname)

        # NOTE(comstud): If there's not an exact match, return the highest
        # compatible version. The objects stored in the class are sorted
        # such that highest version is first, so only set compatible_match
        # once below.
        compatible_match = None

        for objclass in NeutronObjectRegistry.obj_classes()[objname]:
            if objclass.VERSION == objver:
                return objclass
            if (not compatible_match and
                    versionutils.is_compatible(objver, objclass.VERSION)):
                compatible_match = objclass

        if compatible_match:
            return compatible_match

        # As mentioned above, latest version is always first in the list.
        latest_ver = (
            NeutronObjectRegistry.obj_classes()[objname][0].VERSION)
        raise obj_exception.IncompatibleObjectVersion(objname=objname,
                                                      objver=objver,
                                                      supported=latest_ver)

    @classmethod
    def clean_obj_from_primitive(cls, primitive, context=None):
        obj = cls.obj_from_primitive(primitive, context)
        obj.obj_reset_changes()
        return obj

    @classmethod
    def get_object(cls, context, fields=None, **kwargs):
        raise NotImplementedError()

    @classmethod
    def add_extra_filter_name(cls, filter_name):
        """Register filter passed from API layer.

        :param filter_name: Name of the filter passed in the URL

        Filter names are validated in validate_filters() method which by
        default allows filters based on fields' names.  Extensions can create
        new filter names.  Such names must be registered to particular object
        with this method.
        """
        cls.extra_filter_names.add(filter_name)

    @classmethod
    def validate_filters(cls, **kwargs):
        bad_filters = {key for key in kwargs
                       if key not in cls.fields or cls.is_synthetic(key)}
        bad_filters.difference_update(cls.extra_filter_names)
        if bad_filters:
            bad_filters = ', '.join(bad_filters)
            msg = _("'%s' is not supported for filtering") % bad_filters
            raise n_exc.InvalidInput(error_message=msg)

    @classmethod
    @abc.abstractmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    fields=None, **kwargs):
        raise NotImplementedError()

    @classmethod
    def get_values(cls, context, field, validate_filters=True, **kwargs):
        raise NotImplementedError()

    @classmethod
    def _update_objects(cls, objects, values):
        if not isinstance(objects, collections_abc.Sequence):
            objects = (objects, )

        for obj in objects:
            for k, v in values.items():
                setattr(obj, k, v)
            obj.update()
        return len(objects)

    @classmethod
    def update_object(cls, context, values, validate_filters=True, **kwargs):
        obj = cls.get_object(
            context, validate_filters=validate_filters, **kwargs)
        if obj:
            cls._update_objects(obj, values)
            return obj

    @classmethod
    def update_objects(cls, context, values, validate_filters=True, **kwargs):
        objs = cls.get_objects(
            context, validate_filters=validate_filters, **kwargs)
        return cls._update_objects(objs, values)

    @classmethod
    def delete_objects(cls, context, validate_filters=True, **kwargs):
        objs = cls.get_objects(
            context, validate_filters=validate_filters, **kwargs)
        for obj in objs:
            obj.delete()
        return len(objs)

    def create(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    @classmethod
    def count(cls, context, validate_filters=True, **kwargs):
        '''Count the number of objects matching filtering criteria.'''
        return len(
            cls.get_objects(
                context, validate_filters=validate_filters, **kwargs))


def _guarantee_rw_subtransaction(func):
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        with self.db_context_writer(self.obj_context):
            return func(self, *args, **kwargs)
    return decorator


class DeclarativeObject(abc.ABCMeta):

    def __init__(cls, name, bases, dct):
        super(DeclarativeObject, cls).__init__(name, bases, dct)
        # TODO(ralonsoh): remove once bp/keystone-v3 migration finishes.
        if 'project_id' in cls.fields:
            obj_extra_fields_set = set(cls.obj_extra_fields)
            obj_extra_fields_set.add('tenant_id')
            cls.obj_extra_fields = list(obj_extra_fields_set)
            setattr(cls, 'tenant_id',
                    property(lambda x: x.get('project_id', None)))

        fields_no_update_set = set(cls.fields_no_update)
        for base in itertools.chain([cls], bases):
            keys_set = set()
            if hasattr(base, 'primary_keys'):
                keys_set.update(base.primary_keys)
            if hasattr(base, 'obj_extra_fields'):
                keys_set.update(base.obj_extra_fields)
            for key in keys_set:
                if key in cls.fields or key in cls.obj_extra_fields:
                    fields_no_update_set.add(key)
        cls.fields_no_update = list(fields_no_update_set)

        model = getattr(cls, 'db_model', None)
        if model:
            # generate unique_keys from the model
            if not getattr(cls, 'unique_keys', None):
                cls.unique_keys = []
                obj_field_names = set(cls.fields.keys())
                model_to_obj_translation = {
                    v: k for (k, v) in cls.fields_need_translation.items()}

                keys = db_utils.get_unique_keys(model) or []
                for model_unique_key in keys:
                    obj_unique_key = [model_to_obj_translation.get(key, key)
                                      for key in model_unique_key]
                    if obj_field_names.issuperset(obj_unique_key):
                        cls.unique_keys.append(obj_unique_key)
            cls.create = _guarantee_rw_subtransaction(cls.create)
            cls.update = _guarantee_rw_subtransaction(cls.update)

        if (hasattr(cls, 'has_standard_attributes') and
                cls.has_standard_attributes()):
            setattr(cls, 'standard_attr_id',
                    property(lambda x: x.db_obj.standard_attr_id
                             if x.db_obj else None))
            standardattributes.add_standard_attributes(cls)
            standardattributes.add_tag_filter_names(cls)
        # Instantiate extra filters per class
        cls.extra_filter_names = set(cls.extra_filter_names)
        # TODO(ralonsoh): remove once bp/keystone-v3 migration finishes.
        # add tenant_id filter for objects that have project_id
        if 'project_id' in cls.fields and 'tenant_id' not in cls.fields:
            cls.extra_filter_names.add('tenant_id')

        invalid_fields = [f for f in cls.synthetic_fields
                          if f not in cls.fields]
        if invalid_fields:
            raise o_exc.NeutronObjectValidatorException(fields=invalid_fields)


class NeutronDbObject(NeutronObject, metaclass=DeclarativeObject):

    # should be overridden for all persistent objects
    db_model = None

    # should be overridden for all rbac aware objects
    rbac_db_cls = None

    primary_keys = ['id']

    # 'unique_keys' is a list of unique keys that can be used with get_object
    # instead of 'primary_keys' (e.g. [['key1'], ['key2a', 'key2b']]).
    # By default 'unique_keys' will be inherited from the 'db_model'
    unique_keys = []

    # this is a dict to store the association between the foreign key and the
    # corresponding key in the main table for a synthetic field of a specific
    # class, e.g. port extension has 'port_id' as foreign key, that is
    # associated with the key 'id' of the table Port for the synthetic
    # field of class Port. So foreign_keys = {'Port': {'port_id': 'id'}}.
    # The assumption is the association is the same for all object fields.
    # E.g. all the port extension will use 'port_id' as key.
    foreign_keys = {}

    fields_no_update = []

    # dict with name mapping: {'field_name_in_object': 'field_name_in_db'}
    # It can be used also as DB relationship mapping to synthetic fields name.
    # It is needed to load synthetic fields with one SQL query using side
    # loaded entities.
    # Examples: {'synthetic_field_name': 'relationship_name_in_model'}
    #           {'field_name_in_object': 'field_name_in_db'}
    fields_need_translation = {}

    # obj_extra_fields defines properties that are not part of the model
    # but we want to expose them for easier usage of the object.
    # Handling of obj_extra_fields is in oslo.versionedobjects.
    # The extra fields can be accessed as read only property and are exposed
    # in to_dict()
    # obj_extra_fields = []

    def __init__(self, *args, **kwargs):
        super(NeutronDbObject, self).__init__(*args, **kwargs)
        self._captured_db_model = None

    @property
    def db_obj(self):
        '''Return a database model that persists object data.'''
        return self._captured_db_model

    def _set_lazy_contexts(self, fields, context):
        for field in self.lazy_fields.intersection(fields):
            if isinstance(fields[field], LazyQueryIterator):
                fields[field].context = context

    def from_db_object(self, db_obj):
        fields = self.modify_fields_from_db(db_obj)
        if self.lazy_fields:
            self._set_lazy_contexts(fields, self.obj_context)
        for field in self.fields:
            if field in fields and not self.is_synthetic(field):
                setattr(self, field, fields[field])
        if self._load_synthetic_fields:
            self.load_synthetic_db_fields(db_obj)
        self._captured_db_model = db_obj
        self.obj_reset_changes()

    @classmethod
    def has_standard_attributes(cls):
        return bool(cls.db_model and
                    issubclass(cls.db_model,
                               standard_attr.HasStandardAttributes))

    @classmethod
    def modify_fields_to_db(cls, fields):
        """Modify the fields before data is inserted into DB.

        This method enables to modify the fields and its
        content before data is inserted into DB.

         It uses the fields_need_translation dict with structure:
        {
            'field_name_in_object': 'field_name_in_db'
        }

        :param fields: dict of fields from NeutronDbObject
        :return: modified dict of fields
        """
        for k, v in fields.items():
            if isinstance(v, LazyQueryIterator):
                fields[k] = list(v)
        result = copy.deepcopy(dict(fields))
        for field, field_db in cls.fields_need_translation.items():
            if field in result:
                result[field_db] = result.pop(field)
        return result

    @classmethod
    def _get_lazy_iterator(cls, field, appender_query):
        if field not in cls.lazy_fields:
            raise KeyError(_('Field %s is not a lazy query field') % field)
        n_obj_classes = NeutronObjectRegistry.obj_classes()
        n_obj = n_obj_classes.get(cls.fields[field].objname)
        return LazyQueryIterator(n_obj[0], appender_query)

    @classmethod
    def modify_fields_from_db(cls, db_obj):
        """Modify the fields after data were fetched from DB.

        It uses the fields_need_translation dict with structure:
        {
            'field_name_in_object': 'field_name_in_db'
        }

        :param db_obj: model fetched from database
        :return: modified dict of DB values
        """
        # db models can have declarative proxies that are not exposed into
        # db.keys() so we must fetch data based on object fields definition
        potential_fields = (list(cls.fields.keys()) +
                            list(cls.fields_need_translation.values()))
        # NOTE(ralonsoh): fields dynamically loaded will be represented as
        # ``sqla_query.Query``, because the value is load when needed executing
        # a query to the DB.
        result = {
            field: db_obj[field] for field in potential_fields
            if (db_obj.get(field) is not None and
                not issubclass(db_obj.get(field).__class__, sqla_query.Query))
        }
        for field, field_db in cls.fields_need_translation.items():
            if field_db in result:
                result[field] = result.pop(field_db)
        for k, v in result.items():
            # don't allow sqlalchemy lists to propagate outside
            if isinstance(v, orm.collections.InstrumentedList):
                result[k] = list(v)
            if isinstance(v, orm.dynamic.AppenderQuery):
                result[k] = cls._get_lazy_iterator(k, v)
        return result

    @classmethod
    def _load_object(cls, context, db_obj, fields=None):
        obj = cls(context)

        if fields is not None and len(fields) != 0:
            if len(set(fields).intersection(set(cls.synthetic_fields))) == 0:
                obj._load_synthetic_fields = False

        obj.from_db_object(db_obj)
        return obj

    def obj_load_attr(self, attrname):
        """Set None for nullable fields that has unknown value.

        In case model attribute is not present in database, value stored under
        ``attrname'' field will be unknown. In such cases if the field
        ``attrname'' is a nullable Field return None
        """
        try:
            is_attr_nullable = self.fields[attrname].nullable
        except KeyError:
            return super(NeutronDbObject, self).obj_load_attr(attrname)
        if is_attr_nullable:
            self[attrname] = None

    # TODO(ihrachys) remove once we switch plugin code to enginefacade
    @staticmethod
    def _use_db_facade(context):
        try:
            enginefacade._transaction_ctx_for_context(context)
        except obj_exc.NoEngineContextEstablished:
            return False
        return True

    @classmethod
    def db_context_writer(cls, context):
        """Return read-write session activation decorator."""
        return db_api.CONTEXT_WRITER.using(context)

    @classmethod
    def db_context_reader(cls, context):
        """Return read-only session activation decorator."""
        return db_api.CONTEXT_READER.using(context)

    @classmethod
    def get_object(cls, context, fields=None, **kwargs):
        """Fetch a single object

        Return the first result of given context or None if the result doesn't
        contain any row. Next, convert it to a versioned object.

        :param context:
        :param fields: indicate which fields the caller is interested in
                       using. Note that currently this is limited to
                       avoid loading synthetic fields when possible, and
                       does not affect db queries. Default is None, which
                       is the same as []. Example: ['id', 'name']
        :param kwargs: multiple keys defined by key=value pairs
        :return: single object of NeutronDbObject class or None
        """
        lookup_keys = set(kwargs.keys())
        all_keys = itertools.chain([cls.primary_keys], cls.unique_keys)
        if not any(lookup_keys.issuperset(keys) for keys in all_keys):
            missing_keys = set(cls.primary_keys).difference(lookup_keys)
            raise o_exc.NeutronPrimaryKeyMissing(object_class=cls,
                                                 missing_keys=missing_keys)

        with cls.db_context_reader(context):
            db_obj = obj_db_api.get_object(
                cls, context, **cls.modify_fields_to_db(kwargs))
            if db_obj:
                return cls._load_object(context, db_obj, fields=fields)

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    fields=None, return_db_obj=False, **kwargs):
        """Fetch a list of objects

        Fetch all results from DB and convert them to versioned objects.

        :param context:
        :param _pager: a Pager object representing advanced sorting/pagination
                       criteria
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param fields: indicate which fields the caller is interested in
                       using. Note that currently this is limited to
                       avoid loading synthetic fields when possible, and
                       does not affect db queries. Default is None, which
                       is the same as []. Example: ['id', 'name']
        :param return_db_obj: if 'True', the DB object is returned instead of
                              the OVO, saving the conversion time.
        :param kwargs: multiple keys defined by key=value pairs
        :return: list of objects of NeutronDbObject class or empty list
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        with cls.db_context_reader(context):
            db_objs = obj_db_api.get_objects(
                cls, context, _pager=_pager, **cls.modify_fields_to_db(kwargs))
            if return_db_obj:
                return db_objs

            return [cls._load_object(context, db_obj, fields=fields)
                    for db_obj in db_objs]

    @classmethod
    def get_values(cls, context, field, validate_filters=True, **kwargs):
        """Fetch a list of values of a specific object's field

        Fetch a specific column from DB.

        :param context:
        :param field: a specific field of the object
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: list of objects of NeutronDbObject class or empty list
        """
        cls._validate_field(field)
        db_field = cls.fields_need_translation.get(field, field)
        if validate_filters:
            cls.validate_filters(**kwargs)
        with cls.db_context_reader(context):
            db_values = obj_db_api.get_values(
                cls, context, db_field, **cls.modify_fields_to_db(kwargs))
            obj = cls(context)
            values = []
            for db_value in db_values:
                value = cls.modify_fields_from_db({
                    db_field: db_value}).get(field)
                value = cls.fields[field].coerce(obj, field, value)
                values.append(value)

            return values

    @classmethod
    def _validate_field(cls, field):
        if field not in cls.fields or cls.is_synthetic(field):
            msg = _("Get value of field '%(field)s' is not supported by "
                    "object '%(object)s'.") % {'field': field, 'object': cls}
            raise n_exc.InvalidInput(error_message=msg)

    @classmethod
    def update_object(cls, context, values, validate_filters=True, **kwargs):
        """Update an object that match filtering criteria from DB.

        :param context:
        :param values: multiple keys to update in matching objects
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: The updated version of the object
        """
        if validate_filters:
            cls.validate_filters(**kwargs)

        # if we have standard attributes, we will need to fetch records to
        # update revision numbers
        db_obj = None
        if cls.has_standard_attributes():
            return super(NeutronDbObject, cls).update_object(
                context, values, validate_filters=False, **kwargs)
        else:
            with cls.db_context_writer(context):
                db_obj = obj_db_api.update_object(
                    cls, context,
                    cls.modify_fields_to_db(values),
                    **cls.modify_fields_to_db(kwargs))
                return cls._load_object(context, db_obj)

    @classmethod
    def update_objects(cls, context, values, validate_filters=True, **kwargs):
        """Update objects that match filtering criteria from DB.

        :param context:
        :param values: multiple keys to update in matching objects
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: Number of entries updated
        """
        if validate_filters:
            cls.validate_filters(**kwargs)

        with cls.db_context_writer(context):
            # if we have standard attributes, we will need to fetch records to
            # update revision numbers
            if cls.has_standard_attributes():
                return super(NeutronDbObject, cls).update_objects(
                    context, values, validate_filters=False, **kwargs)
            return obj_db_api.update_objects(
                cls, context,
                cls.modify_fields_to_db(values),
                **cls.modify_fields_to_db(kwargs))

    @classmethod
    def delete_objects(cls, context, validate_filters=True, **kwargs):
        """Delete objects that match filtering criteria from DB.

        :param context:
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: Number of entries deleted
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        with cls.db_context_writer(context):
            return obj_db_api.delete_objects(
                cls, context, **cls.modify_fields_to_db(kwargs))

    @classmethod
    def is_accessible(cls, context, db_obj):
        return (context.is_admin or
                context.project_id == db_obj.project_id)

    @staticmethod
    def filter_to_str(value):
        if isinstance(value, list):
            return [str(val) for val in value]
        return str(value)

    @staticmethod
    def filter_to_json_str(value, default=None):
        def _dict_to_json(v):
            return (
                jsonutils.dumps(
                    collections.OrderedDict(
                        sorted(v.items(), key=lambda t: t[0])
                    )
                ) if v else default
            )

        if isinstance(value, list):
            return [_dict_to_json(val) for val in value]
        v = _dict_to_json(value)
        return v

    @staticmethod
    def load_json_from_str(field, default=None):
        value = field or default
        if value:
            value = jsonutils.loads(value)
        return value

    def _get_changed_persistent_fields(self):
        fields = self.obj_get_changes()
        for field in self.synthetic_fields:
            if field in fields:
                del fields[field]
        return fields

    def _validate_changed_fields(self, fields):
        fields = fields.copy()
        forbidden_updates = set(self.fields_no_update) & set(fields.keys())
        if forbidden_updates:
            raise o_exc.NeutronObjectUpdateForbidden(fields=forbidden_updates)

        return fields

    def load_synthetic_db_fields(self, db_obj=None):
        """Load synthetic DB fields

        Load the synthetic fields that are stored in a different table from the
        main object.

        This method doesn't take care of loading synthetic fields that aren't
        stored in the DB, e.g. 'shared' in RBAC policy.
        """
        clsname = self.__class__.__name__

        # TODO(rossella_s) Find a way to handle ObjectFields with
        # subclasses=True
        for field in self.synthetic_fields:
            try:
                field_def = self.fields[field]
                objclasses = NeutronObjectRegistry.obj_classes(
                ).get(field_def.objname)
            except AttributeError:
                # NOTE(rossella_s) this is probably because this field is not
                # an ObjectField
                continue
            if not objclasses:
                # NOTE(rossella_s) some synthetic fields are not handled by
                # this method, for example the ones that have subclasses, see
                # QosRule
                continue
            objclass = objclasses[0]
            foreign_keys = objclass.foreign_keys.get(clsname)
            if not foreign_keys:
                raise o_exc.NeutronSyntheticFieldsForeignKeysNotFound(
                    parent=clsname, child=objclass.__name__)
            if len(foreign_keys.keys()) > 1:
                raise o_exc.NeutronSyntheticFieldMultipleForeignKeys(
                        field=field)

            synthetic_field_db_name = (
                self.fields_need_translation.get(field, field))

            # synth_db_objs can be list, empty list or None, that is why
            # we need 'is not None', because [] is valid case for 'True'
            if isinstance(field_def, obj_fields.ListOfObjectsField):
                synth_db_objs = (db_obj.get(synthetic_field_db_name, None)
                                 if db_obj else None)
                if synth_db_objs is not None:
                    synth_objs = [objclass._load_object(self.obj_context, obj)
                                  for obj in synth_db_objs]
                else:
                    synth_objs = objclass.get_objects(
                        self.obj_context, **{
                            k: getattr(self, v) if v in self else db_obj.get(v)
                            for k, v in foreign_keys.items()})
                setattr(self, field, synth_objs)
            else:
                synth_db_obj = (db_obj.get(synthetic_field_db_name, None)
                                if db_obj else None)
                if synth_db_obj:
                    synth_db_obj = objclass._load_object(self.obj_context,
                                                         synth_db_obj)
                setattr(self, field, synth_db_obj)
            self.obj_reset_changes([field])

    def create(self):
        fields = self._get_changed_persistent_fields()
        with self.db_context_writer(self.obj_context):
            try:
                db_obj = obj_db_api.create_object(
                    self, self.obj_context, self.modify_fields_to_db(fields))
            except obj_exc.DBDuplicateEntry as db_exc:
                raise o_exc.NeutronDbObjectDuplicateEntry(
                    object_class=self.__class__, db_exception=db_exc)

            self.from_db_object(db_obj)

    def _get_composite_keys(self):
        keys = {}
        for key in self.primary_keys:
            keys[key] = getattr(self, key)
        return keys

    def update_fields(self, obj_data, reset_changes=False):
        """Updates fields of an object that are not forbidden to be updated.

        :param obj_data: the full set of object data
        :type obj_data: dict
        :param reset_changes: indicates whether the object's current set of
                              changed fields should be cleared
        :type reset_changes: boolean

        :returns: None
        """
        if reset_changes:
            self.obj_reset_changes()
        for k, v in obj_data.items():
            if k not in self.fields_no_update:
                setattr(self, k, v)

    def update(self):
        updates = self._get_changed_persistent_fields()
        updates = self._validate_changed_fields(updates)

        with self.db_context_writer(self.obj_context):
            db_obj = obj_db_api.update_object(
                self, self.obj_context,
                self.modify_fields_to_db(updates),
                **self.modify_fields_to_db(
                    self._get_composite_keys()))
            self.from_db_object(db_obj)

    def delete(self):
        obj_db_api.delete_object(self, self.obj_context,
                                 **self.modify_fields_to_db(
                                     self._get_composite_keys()))
        self._captured_db_model = None

    @classmethod
    def count(cls, context, validate_filters=True, **kwargs):
        """Count the number of objects matching filtering criteria.

        :param context:
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: number of matching objects
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        return obj_db_api.count(
            cls, context, **cls.modify_fields_to_db(kwargs)
        )

    @classmethod
    def objects_exist(cls, context, validate_filters=True, **kwargs):
        """Check if objects are present in DB.

        :param context:
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: boolean. True if object is present.
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        # Succeed if at least a single object matches; no need to fetch more
        return bool(obj_db_api.count(
            cls, context, query_limit=1, **cls.modify_fields_to_db(kwargs))
        )
