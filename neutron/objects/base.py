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
import copy
import functools
import itertools

from neutron_lib import exceptions as n_exc
from oslo_db import exception as obj_exc
from oslo_db.sqlalchemy import utils as db_utils
from oslo_serialization import jsonutils
from oslo_versionedobjects import base as obj_base
from oslo_versionedobjects import fields as obj_fields
import six

from neutron._i18n import _
from neutron.db import api as db_api
from neutron.db import standard_attr
from neutron.objects.db import api as obj_db_api
from neutron.objects import exceptions as o_exc
from neutron.objects.extensions import standardattributes

_NO_DB_MODEL = object()


def get_updatable_fields(cls, fields):
    fields = fields.copy()
    for field in cls.fields_no_update:
        if field in fields:
            del fields[field]
    return fields


def get_object_class_by_model(model):
    for obj_class in obj_base.VersionedObjectRegistry.obj_classes().values():
        obj_class = obj_class[0]
        if getattr(obj_class, 'db_model', _NO_DB_MODEL) is model:
            return obj_class
    raise o_exc.NeutronDbObjectNotFoundByModel(model=model.__name__)


def register_filter_hook_on_model(model, filter_name):
    obj_class = get_object_class_by_model(model)
    obj_class.add_extra_filter_name(filter_name)


class Pager(object):
    '''
    This class represents a pager object. It is consumed by get_objects to
    specify sorting and pagination criteria.
    '''
    def __init__(self, sorts=None, limit=None, page_reverse=None, marker=None):
        '''
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

    def to_kwargs(self, context, model):
        res = {
            attr: getattr(self, attr)
            for attr in ('sorts', 'limit', 'page_reverse')
            if getattr(self, attr) is not None
        }
        if self.marker and self.limit:
            res['marker_obj'] = obj_db_api.get_object(
                context, model, id=self.marker)
        return res

    def __str__(self):
        return str(self.__dict__)

    def __eq__(self, other):
        return self.__dict__ == other.__dict__


@six.add_metaclass(abc.ABCMeta)
class NeutronObject(obj_base.VersionedObject,
                    obj_base.VersionedObjectDictCompat,
                    obj_base.ComparableVersionedObject):

    synthetic_fields = []
    extra_filter_names = set()

    def __init__(self, context=None, **kwargs):
        super(NeutronObject, self).__init__(context, **kwargs)
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
    def clean_obj_from_primitive(cls, primitive, context=None):
        obj = cls.obj_from_primitive(primitive, context)
        obj.obj_reset_changes()
        return obj

    @classmethod
    def get_object(cls, context, **kwargs):
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
                    **kwargs):
        raise NotImplementedError()

    @classmethod
    def update_objects(cls, context, values, validate_filters=True, **kwargs):
        objs = cls.get_objects(
            context, validate_filters=validate_filters, **kwargs)
        for obj in objs:
            for k, v in values.items():
                setattr(obj, k, v)
            obj.update()
        return len(objs)

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


def _detach_db_obj(func):
    """Decorator to detach db_obj from the session."""
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        synthetic_changed = bool(self._get_changed_synthetic_fields())
        res = func(self, *args, **kwargs)
        # some relationship based fields may be changed since we
        # captured the model, let's refresh it for the latest database
        # state
        if synthetic_changed:
            # TODO(ihrachys) consider refreshing just changed attributes
            self.obj_context.session.refresh(self.db_obj)
        # detach the model so that consequent fetches don't reuse it
        self.obj_context.session.expunge(self.db_obj)
        return res
    return decorator


class DeclarativeObject(abc.ABCMeta):

    def __init__(cls, name, bases, dct):
        super(DeclarativeObject, cls).__init__(name, bases, dct)
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
            # detach db_obj right after object is loaded from the model
            cls.create = _detach_db_obj(cls.create)
            cls.update = _detach_db_obj(cls.update)

        if (hasattr(cls, 'has_standard_attributes') and
                cls.has_standard_attributes()):
            setattr(cls, 'standard_attr_id',
                    property(lambda x: x.db_obj.standard_attr_id
                             if x.db_obj else None))
            standardattributes.add_standard_attributes(cls)
            standardattributes.add_tag_filter_names(cls)
        # Instantiate extra filters per class
        cls.extra_filter_names = set(cls.extra_filter_names)
        # add tenant_id filter for objects that have project_id
        if 'project_id' in cls.fields and 'tenant_id' not in cls.fields:
            cls.extra_filter_names.add('tenant_id')


@six.add_metaclass(DeclarativeObject)
class NeutronDbObject(NeutronObject):

    # should be overridden for all persistent objects
    db_model = None

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

    def from_db_object(self, db_obj):
        fields = self.modify_fields_from_db(db_obj)
        for field in self.fields:
            if field in fields and not self.is_synthetic(field):
                setattr(self, field, fields[field])
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
        """
        This method enables to modify the fields and its
        content before data is inserted into DB.

         It uses the fields_need_translation dict with structure:
        {
            'field_name_in_object': 'field_name_in_db'
        }

        :param fields: dict of fields from NeutronDbObject
        :return: modified dict of fields
        """
        result = copy.deepcopy(dict(fields))
        for field, field_db in cls.fields_need_translation.items():
            if field in result:
                result[field_db] = result.pop(field)
        return result

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
        result = {field: db_obj[field] for field in potential_fields
                  if db_obj.get(field) is not None}
        for field, field_db in cls.fields_need_translation.items():
            if field_db in result:
                result[field] = result.pop(field_db)
        return result

    @classmethod
    def _load_object(cls, context, db_obj):
        obj = cls(context)
        obj.from_db_object(db_obj)
        # detach the model so that consequent fetches don't reuse it
        context.session.expunge(obj.db_obj)
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

    @classmethod
    def get_object(cls, context, **kwargs):
        """
        Return the first result of given context or None if the result doesn't
        contain any row. Next, convert it to a versioned object.

        :param context:
        :param kwargs: multiple keys defined by key=value pairs
        :return: single object of NeutronDbObject class or None
        """
        lookup_keys = set(kwargs.keys())
        all_keys = itertools.chain([cls.primary_keys], cls.unique_keys)
        if not any(lookup_keys.issuperset(keys) for keys in all_keys):
            missing_keys = set(cls.primary_keys).difference(lookup_keys)
            raise o_exc.NeutronPrimaryKeyMissing(object_class=cls.__name__,
                                                 missing_keys=missing_keys)

        with context.session.begin(subtransactions=True):
            db_obj = obj_db_api.get_object(
                context, cls.db_model,
                **cls.modify_fields_to_db(kwargs)
            )
            if db_obj:
                return cls._load_object(context, db_obj)

    @classmethod
    def get_objects(cls, context, _pager=None, validate_filters=True,
                    **kwargs):
        """
        Fetch all results from DB and convert them to versioned objects.

        :param context:
        :param _pager: a Pager object representing advanced sorting/pagination
                       criteria
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: list of objects of NeutronDbObject class or empty list
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        with context.session.begin(subtransactions=True):
            db_objs = obj_db_api.get_objects(
                context, cls.db_model, _pager=_pager,
                **cls.modify_fields_to_db(kwargs)
            )
            return [cls._load_object(context, db_obj) for db_obj in db_objs]

    @classmethod
    def update_objects(cls, context, values, validate_filters=True, **kwargs):
        """
        Update objects that match filtering criteria from DB.

        :param context:
        :param values: multiple keys to update in matching objects
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: Number of entries updated
        """
        if validate_filters:
            cls.validate_filters(**kwargs)

        # if we have standard attributes, we will need to fetch records to
        # update revision numbers
        if cls.has_standard_attributes():
            return super(NeutronDbObject, cls).update_objects(
                context, values, validate_filters=False, **kwargs)

        with db_api.autonested_transaction(context.session):
            return obj_db_api.update_objects(
                context, cls.db_model,
                cls.modify_fields_to_db(values),
                **cls.modify_fields_to_db(kwargs))

    @classmethod
    def delete_objects(cls, context, validate_filters=True, **kwargs):
        """
        Delete objects that match filtering criteria from DB.

        :param context:
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: Number of entries deleted
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        with context.session.begin(subtransactions=True):
            return obj_db_api.delete_objects(
                context, cls.db_model, **cls.modify_fields_to_db(kwargs))

    @classmethod
    def is_accessible(cls, context, db_obj):
        return (context.is_admin or
                context.tenant_id == db_obj.tenant_id)

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

    def _get_changed_synthetic_fields(self):
        fields = self.obj_get_changes()
        for field in self._get_changed_persistent_fields():
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
        """
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
                objclasses = obj_base.VersionedObjectRegistry.obj_classes(
                ).get(self.fields[field].objname)
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
            synth_db_objs = (db_obj.get(synthetic_field_db_name, None)
                             if db_obj else None)

            # synth_db_objs can be list, empty list or None, that is why
            # we need 'is not None', because [] is valid case for 'True'
            if synth_db_objs is not None:
                if not isinstance(synth_db_objs, list):
                    synth_db_objs = [synth_db_objs]
                synth_objs = [objclass._load_object(self.obj_context, obj)
                              for obj in synth_db_objs]
            else:
                synth_objs = objclass.get_objects(
                    self.obj_context, **{
                        k: getattr(self, v) if v in self else db_obj.get(v)
                        for k, v in foreign_keys.items()})
            if isinstance(self.fields[field], obj_fields.ObjectField):
                setattr(self, field, synth_objs[0] if synth_objs else None)
            else:
                setattr(self, field, synth_objs)
            self.obj_reset_changes([field])

    def create(self):
        fields = self._get_changed_persistent_fields()
        with db_api.autonested_transaction(self.obj_context.session):
            try:
                db_obj = obj_db_api.create_object(
                    self.obj_context, self.db_model,
                    self.modify_fields_to_db(fields))
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

        with db_api.autonested_transaction(self.obj_context.session):
            db_obj = obj_db_api.update_object(
                self.obj_context, self.db_model,
                self.modify_fields_to_db(updates),
                **self.modify_fields_to_db(
                    self._get_composite_keys()))
            self.from_db_object(db_obj)

    def delete(self):
        obj_db_api.delete_object(self.obj_context, self.db_model,
                                 **self.modify_fields_to_db(
                                     self._get_composite_keys()))
        self._captured_db_model = None

    @classmethod
    def count(cls, context, validate_filters=True, **kwargs):
        """
        Count the number of objects matching filtering criteria.

        :param context:
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: number of matching objects
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        return obj_db_api.count(
            context, cls.db_model, **cls.modify_fields_to_db(kwargs)
        )

    @classmethod
    def objects_exist(cls, context, validate_filters=True, **kwargs):
        """
        Check if objects are present in DB.

        :param context:
        :param validate_filters: Raises an error in case of passing an unknown
                                 filter
        :param kwargs: multiple keys defined by key=value pairs
        :return: boolean. True if object is present.
        """
        if validate_filters:
            cls.validate_filters(**kwargs)
        # Succeed if at least a single object matches; no need to fetch more
        return bool(obj_db_api.get_object(
            context, cls.db_model, **cls.modify_fields_to_db(kwargs))
        )
