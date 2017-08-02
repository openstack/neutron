# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
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

import abc

from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
import sqlalchemy as sa
from sqlalchemy.ext import declarative
from sqlalchemy.orm import validates

from neutron._i18n import _


ACCESS_SHARED = 'access_as_shared'
ACCESS_EXTERNAL = 'access_as_external'


class InvalidActionForType(n_exc.InvalidInput):
    message = _("Invalid action '%(action)s' for object type "
                "'%(object_type)s'. Valid actions: %(valid_actions)s")


class RBACColumns(model_base.HasId, model_base.HasProject):
    """Mixin that object-specific RBAC tables should inherit.

    All RBAC tables should inherit directly from this one because
    the RBAC code uses the __subclasses__() method to discover the
    RBAC types.
    """

    # the target_tenant is the subject that the policy will affect. this may
    # also be a wildcard '*' to indicate all tenants or it may be a role if
    # neutron gets better integration with keystone
    target_tenant = sa.Column(sa.String(db_const.PROJECT_ID_FIELD_SIZE),
                              nullable=False)

    action = sa.Column(sa.String(255), nullable=False)

    @abc.abstractproperty
    def object_type(self):
        # this determines the name that users will use in the API
        # to reference the type. sub-classes should set their own
        pass

    @declarative.declared_attr
    def __table_args__(cls):
        return (
            sa.UniqueConstraint('target_tenant', 'object_id', 'action'),
            model_base.BASEV2.__table_args__
        )

    @validates('action')
    def _validate_action(self, key, action):
        if action not in self.get_valid_actions():
            raise InvalidActionForType(
                action=action, object_type=self.object_type,
                valid_actions=self.get_valid_actions())
        return action

    @abc.abstractmethod
    def get_valid_actions(self):
        # object table needs to override this to return an interable
        # with the valid actions rbac entries
        pass


def get_type_model_map():
    return {table.object_type: table for table in RBACColumns.__subclasses__()}


def _object_id_column(foreign_key):
    return sa.Column(sa.String(36),
                     sa.ForeignKey(foreign_key, ondelete="CASCADE"),
                     nullable=False)


class NetworkRBAC(RBACColumns, model_base.BASEV2):
    """RBAC table for networks."""

    object_id = _object_id_column('networks.id')
    object_type = 'network'
    revises_on_change = ('network', )

    def get_valid_actions(self):
        actions = (ACCESS_SHARED,)
        pl = directory.get_plugin()
        if 'external-net' in pl.supported_extension_aliases:
            actions += (ACCESS_EXTERNAL,)
        return actions


class QosPolicyRBAC(RBACColumns, model_base.BASEV2):
    """RBAC table for qos policies."""

    object_id = _object_id_column('qos_policies.id')
    object_type = 'qos_policy'

    def get_valid_actions(self):
        return (ACCESS_SHARED,)
