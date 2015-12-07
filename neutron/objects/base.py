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

from oslo_db import exception as obj_exc
from oslo_utils import reflection
from oslo_versionedobjects import base as obj_base
import six

from neutron._i18n import _
from neutron.common import exceptions
from neutron.db import api as db_api


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
    def get_by_id(cls, context, id):
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


class NeutronDbObject(NeutronObject):

    # should be overridden for all persistent objects
    db_model = None

    fields_no_update = []

    def from_db_object(self, *objs):
        for field in self.fields:
            for db_obj in objs:
                if field in db_obj:
                    setattr(self, field, db_obj[field])
                break
        self.obj_reset_changes()

    @classmethod
    def get_by_id(cls, context, id):
        db_obj = db_api.get_object(context, cls.db_model, id=id)
        if db_obj:
            obj = cls(context, **db_obj)
            obj.obj_reset_changes()
            return obj

    @classmethod
    def get_objects(cls, context, **kwargs):
        cls.validate_filters(**kwargs)
        db_objs = db_api.get_objects(context, cls.db_model, **kwargs)
        objs = [cls(context, **db_obj) for db_obj in db_objs]
        for obj in objs:
            obj.obj_reset_changes()
        return objs

    def _get_changed_persistent_fields(self):
        fields = self.obj_get_changes()
        for field in self.synthetic_fields:
            if field in fields:
                del fields[field]
        return fields

    def _validate_changed_fields(self, fields):
        fields = fields.copy()
        # We won't allow id update anyway, so let's pop it out not to trigger
        # update on id field touched by the consumer
        fields.pop('id', None)

        forbidden_updates = set(self.fields_no_update) & set(fields.keys())
        if forbidden_updates:
            raise NeutronObjectUpdateForbidden(fields=forbidden_updates)

        return fields

    def create(self):
        fields = self._get_changed_persistent_fields()
        try:
            db_obj = db_api.create_object(self._context, self.db_model, fields)
        except obj_exc.DBDuplicateEntry as db_exc:
            raise NeutronDbObjectDuplicateEntry(object_class=self.__class__,
                                                db_exception=db_exc)

        self.from_db_object(db_obj)

    def update(self):
        updates = self._get_changed_persistent_fields()
        updates = self._validate_changed_fields(updates)

        if updates:
            db_obj = db_api.update_object(self._context, self.db_model,
                                          self.id, updates)
            self.from_db_object(self, db_obj)

    def delete(self):
        db_api.delete_object(self._context, self.db_model, self.id)
