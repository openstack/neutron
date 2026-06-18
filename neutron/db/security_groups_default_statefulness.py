# Copyright (c) 2026 Red Hat, Inc.
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

from neutron_lib.api.definitions import \
    security_groups_default_statefulness as apidef
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as n_exc

from neutron._i18n import _
from neutron.objects import base as base_obj
from neutron.objects import security_groups_default_statefulness as sg_ds_obj


class SecurityGroupDefaultStatefulnessNotFound(n_exc.NotFound):
    message = _("Security group default statefulness %(id)s could not "
                "be found.")


class SecurityGroupDefaultStatefulnessAlreadyExists(n_exc.Conflict):
    message = _("A security group default statefulness setting already "
                "exists for project '%(project_id)s'.")


class SecurityGroupDefaultStatefulnessMixin:
    """Mixin class for security group default statefulness CRUD."""

    @staticmethod
    def _make_sg_default_statefulness_dict(sg_ds, fields=None):
        res = {'id': sg_ds['id'],
               'project_id': sg_ds['project_id'],
               'stateful': sg_ds['stateful']}
        return db_utils.resource_fields(res, fields)

    def _get_sg_default_statefulness(self, context, id):
        obj = sg_ds_obj.SecurityGroupDefaultStatefulness.get_object(
            context, id=id)
        if obj is None:
            raise SecurityGroupDefaultStatefulnessNotFound(id=id)
        return obj

    def create_security_groups_default_statefulness(
            self, context, security_groups_default_statefulness):
        fields = security_groups_default_statefulness[
            apidef.RESOURCE_NAME]
        project_id = fields.get('project_id')
        existing = sg_ds_obj.SecurityGroupDefaultStatefulness.get_object(
            context.elevated(), project_id=project_id)
        if existing:
            raise SecurityGroupDefaultStatefulnessAlreadyExists(
                project_id=project_id or 'system-wide')

        sg_ds = sg_ds_obj.SecurityGroupDefaultStatefulness(
            context,
            project_id=project_id,
            stateful=fields['stateful'])
        sg_ds.create()
        return self._make_sg_default_statefulness_dict(sg_ds)

    def update_security_groups_default_statefulness(
            self, context, id, security_groups_default_statefulness):
        fields = security_groups_default_statefulness[
            apidef.RESOURCE_NAME]
        sg_ds = self._get_sg_default_statefulness(context, id)
        sg_ds.update_fields(fields)
        sg_ds.update()
        return self._make_sg_default_statefulness_dict(sg_ds)

    def get_security_groups_default_statefulness(
            self, context, id=None, filters=None, fields=None,
            sorts=None, limit=None, marker=None, page_reverse=False):
        if id is not None:
            sg_ds = self._get_sg_default_statefulness(context, id)
            return self._make_sg_default_statefulness_dict(sg_ds, fields)

        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        objs = sg_ds_obj.SecurityGroupDefaultStatefulness.get_objects(
            context, _pager=pager, **filters)
        return [
            self._make_sg_default_statefulness_dict(obj, fields)
            for obj in objs
        ]

    def delete_security_groups_default_statefulness(self, context, id):
        sg_ds = self._get_sg_default_statefulness(context, id)
        sg_ds.delete()

    def get_default_stateful_for_project(self, context, project_id):
        """Return the effective default 'stateful' value for a project.

        Looks for a project-specific setting first, then a system-wide
        setting. Returns True (the built-in default) if neither exists.
        """
        obj = sg_ds_obj.SecurityGroupDefaultStatefulness.get_object(
            context, project_id=project_id)
        if obj:
            return obj.stateful

        obj = sg_ds_obj.SecurityGroupDefaultStatefulness.get_object(
            context, project_id=None)
        if obj:
            return obj.stateful

        # Return the default static value defined for this API, that is 'True'.
        return True
