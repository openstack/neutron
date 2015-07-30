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

from oslo_versionedobjects import base as obj_base
import six

from neutron.db import api as db_api


@six.add_metaclass(abc.ABCMeta)
class NeutronObject(obj_base.VersionedObject,
                    obj_base.VersionedObjectDictCompat,
                    obj_base.ComparableVersionedObject):

    def __init__(self, context=None, **kwargs):
        super(NeutronObject, self).__init__(context, **kwargs)
        self.obj_set_defaults()

    def to_dict(self):
        return dict(self.items())

    @classmethod
    def get_by_id(cls, context, id):
        raise NotImplementedError()

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

    # fields that are not allowed to update
    fields_no_update = []

    synthetic_fields = []

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

    def create(self):
        fields = self._get_changed_persistent_fields()
        db_obj = db_api.create_object(self._context, self.db_model, fields)
        self.from_db_object(db_obj)

    def update(self):
        updates = self._get_changed_persistent_fields()
        if updates:
            db_obj = db_api.update_object(self._context, self.db_model,
                                          self.id, updates)
            self.from_db_object(self, db_obj)

    def delete(self):
        db_api.delete_object(self._context, self.db_model, self.id)
