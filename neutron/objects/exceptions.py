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


from neutron._i18n import _
from neutron_lib import exceptions
from oslo_utils import reflection


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


class NeutronDbObjectNotFoundByModel(exceptions.NotFound):
    message = _("NeutronDbObject not found by model %(model)s.")


class NeutronPrimaryKeyMissing(exceptions.BadRequest):
    message = _("For class %(object_type)s missing primary keys: "
                "%(missing_keys)s")

    def __init__(self, object_class, missing_keys):
        super(NeutronPrimaryKeyMissing, self).__init__(
            object_type=reflection.get_class_name(object_class,
                                                  fully_qualified=False),
            missing_keys=missing_keys
        )


class NeutronRangeConstrainedIntegerInvalidLimit(exceptions.NeutronException):
    message = _("Incorrect range limits specified: "
                "start = %(start)s, end = %(end)s")


class NeutronSyntheticFieldMultipleForeignKeys(exceptions.NeutronException):
    message = _("Synthetic field %(field)s shouldn't have more than one "
                "foreign key")


class NeutronSyntheticFieldsForeignKeysNotFound(exceptions.NeutronException):
    message = _("%(child)s does not define a foreign key for %(parent)s")
