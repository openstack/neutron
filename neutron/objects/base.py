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
import copy
import itertools

from neutron_lib import exceptions
from oslo_db import exception as obj_exc
from oslo_utils import reflection
from oslo_versionedobjects import base as obj_base
import six

from neutron._i18n import _
from neutron.objects.db import api as obj_db_api


class NeutronObjectUpdateForbidden(exceptions.NeutronException):
    message = _("Unable to update the following object fields: %(fields)s")


class NeutronDbObjectDuplicateEntry(exceptions.Conflict):
    message = _("Failed to create a duplicate %(object_type)s: "
                "for attribute(s) %(attributes)s with value(s) %(values)s")

    def __init__(self, object_class, db_exception):
        super(NeutronDbObjectDuplicateEntry, self).__init__(
            object_type=reflection.get_class_name(object_class,
                                                  fully_qualified=False),
            attributes=db_exception.columns,
            values=db_exception.value)


class NeutronPrimaryKeyMissing(exceptions.BadRequest):
    message = _("For class %(object_type)s missing primary keys: "
                "%(missing_keys)s")

    def __init__(self, object_class, missing_keys):
        super(NeutronPrimaryKeyMissing, self).__init__(
            object_type=reflection.get_class_name(object_class,
                                                  fully_qualified=False),
            missing_keys=missing_keys
        )


def get_updatable_fields(cls, fields):
    fields = fields.copy()
    for field in cls.fields_no_update:
        if field in fields:
            del fields[field]
    return fields


@six.add_metaclass(abc.ABCMeta)
class NeutronObject(obj_base.VersionedObject,
                    obj_base.VersionedObjectDictCompat,
                    obj_base.ComparableVersionedObject):

    synthetic_fields = []

    def __init__(self, context=None, **kwargs):
        super(NeutronObject, self).__init__(context, **kwargs)
        self.obj_set_defaults()

    def to_dict(self):
        return dict(self.items())

    @classmethod
    def clean_obj_from_primitive(cls, primitive, context=None):
        obj = cls.obj_from_primitive(primitive, context)
        obj.obj_reset_changes()
        return obj

    @classmethod
    def get_object(cls, context, **kwargs):
        raise NotImplementedError()

    @classmethod
    def validate_filters(cls, **kwargs):
        bad_filters = [key for key in kwargs
                       if key not in cls.fields or key in cls.synthetic_fields]
        if bad_filters:
            bad_filters = ', '.join(bad_filters)
            msg = _("'%s' is not supported for filtering") % bad_filters
            raise exceptions.InvalidInput(error_message=msg)

    @classmethod
    @abc.abstractmethod
    def get_objects(cls, context, **kwargs):
        raise NotImplementedError()

    def create(self):
        raise NotImplementedError()

    def update(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()


class DeclarativeObject(abc.ABCMeta):

    def __init__(cls, name, bases, dct):
        super(DeclarativeObject, cls).__init__(name, bases, dct)
        for base in itertools.chain([cls], bases):
            if hasattr(base, 'primary_keys'):
                cls.fields_no_update += base.primary_keys
        # avoid duplicate entries
        cls.fields_no_update = list(set(cls.fields_no_update))


@six.add_metaclass(DeclarativeObject)
class NeutronDbObject(NeutronObject):

    # should be overridden for all persistent objects
    db_model = None

    primary_keys = ['id']

    fields_no_update = []

    # dict with name mapping: {'field_name_in_object': 'field_name_in_db'}
    fields_need_translation = {}

    def from_db_object(self, *objs):
        db_objs = [self.modify_fields_from_db(db_obj) for db_obj in objs]
        for field in self.fields:
            for db_obj in db_objs:
                if field in db_obj:
                    setattr(self, field, db_obj[field])
                break
        self.obj_reset_changes()

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
        """
        This method enables to modify the fields and its
        content after data was fetched from DB.

        It uses the fields_need_translation dict with structure:
        {
            'field_name_in_object': 'field_name_in_db'
        }

        :param db_obj: dict of object fetched from database
        :return: modified dict of DB values
        """
        result = dict(db_obj)
        for field, field_db in cls.fields_need_translation.items():
            if field_db in result:
                result[field] = result.pop(field_db)
        return result

    @classmethod
    def get_object(cls, context, **kwargs):
        """
        This method fetches object from DB and convert it to versioned
        object.

        :param context:
        :param kwargs: multiple primary keys defined key=value pairs
        :return: single object of NeutronDbObject class
        """
        missing_keys = set(cls.primary_keys).difference(kwargs.keys())
        if missing_keys:
            raise NeutronPrimaryKeyMissing(object_class=cls.__class__,
                                           missing_keys=missing_keys)

        db_obj = obj_db_api.get_object(context, cls.db_model, **kwargs)
        if db_obj:
            obj = cls(context, **cls.modify_fields_from_db(db_obj))
            obj.obj_reset_changes()
            return obj

    @classmethod
    def get_objects(cls, context, **kwargs):
        cls.validate_filters(**kwargs)
        db_objs = obj_db_api.get_objects(context, cls.db_model, **kwargs)
        result = []
        for db_obj in db_objs:
            obj = cls(context, **cls.modify_fields_from_db(db_obj))
            obj.obj_reset_changes()
            result.append(obj)
        return result

    @classmethod
    def is_accessible(cls, context, db_obj):
        return (context.is_admin or
                context.tenant_id == db_obj.tenant_id)

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
            raise NeutronObjectUpdateForbidden(fields=forbidden_updates)

        return fields

    def create(self):
        fields = self._get_changed_persistent_fields()
        try:
            db_obj = obj_db_api.create_object(self._context, self.db_model,
                                              self.modify_fields_to_db(fields))
        except obj_exc.DBDuplicateEntry as db_exc:
            raise NeutronDbObjectDuplicateEntry(object_class=self.__class__,
                                                db_exception=db_exc)
        self.from_db_object(db_obj)

    def _get_composite_keys(self):
        keys = {}
        for key in self.primary_keys:
            keys[key] = getattr(self, key)
        return self.modify_fields_to_db(keys)

    def update(self):
        updates = self._get_changed_persistent_fields()
        updates = self._validate_changed_fields(updates)

        if updates:
            db_obj = obj_db_api.update_object(self._context, self.db_model,
                                            self.modify_fields_to_db(updates),
                                            **self._get_composite_keys())
            self.from_db_object(self, db_obj)

    def delete(self):
        obj_db_api.delete_object(self._context, self.db_model,
                                 **self._get_composite_keys())
