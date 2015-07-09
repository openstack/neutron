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


# TODO(QoS): revisit dict compatibility and how we can isolate dict behavior


@six.add_metaclass(abc.ABCMeta)
class NeutronObject(obj_base.VersionedObject,
                    obj_base.VersionedObjectDictCompat,
                    obj_base.ComparableVersionedObject):

    # should be overridden for all persistent objects
    db_model = None

    # fields that are not allowed to update
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
        db_obj = db_api.get_object(context, cls.db_model, id)
        if db_obj:
            obj = cls(context, **db_obj)
            obj.obj_reset_changes()
            return obj

    @classmethod
    def get_objects(cls, context):
        db_objs = db_api.get_objects(context, cls.db_model)
        objs = [cls(context, **db_obj) for db_obj in db_objs]
        for obj in objs:
            obj.obj_reset_changes()
        return objs

    def create(self):
        fields = self.obj_get_changes()
        db_obj = db_api.create_object(self._context, self.db_model, fields)
        self.from_db_object(db_obj)

    def update(self):
        # TODO(QoS): enforce fields_no_update
        updates = self.obj_get_changes()
        if updates:
            db_obj = db_api.update_object(self._context, self.db_model,
                                          self.id, updates)
            self.from_db_object(self, db_obj)

    def delete(self):
        db_api.delete_object(self._context, self.db_model, self.id)
