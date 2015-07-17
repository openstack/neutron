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

import sqlalchemy as sa
from sqlalchemy.orm import validates

from neutron.common import exceptions as n_exc
from neutron.db import model_base
from neutron.db import models_v2


class InvalidActionForType(n_exc.InvalidInput):
    message = _("Invalid action '%(action)s' for object type "
                "'%(object_type)s'. Valid actions: %(valid_actions)s")


class RBACColumns(models_v2.HasId, models_v2.HasTenant):
    """Mixin that object-specific RBAC tables should inherit.

    All RBAC tables should inherit directly from this one because
    the RBAC code uses the __subclasses__() method to discover the
    RBAC types.
    """

    # the target_tenant is the subject that the policy will affect. this may
    # also be a wildcard '*' to indicate all tenants or it may be a role if
    # neutron gets better integration with keystone
    target_tenant = sa.Column(sa.String(255), nullable=False)

    action = sa.Column(sa.String(255), nullable=False)

    @abc.abstractproperty
    def object_type(self):
        # this determines the name that users will use in the API
        # to reference the type. sub-classes should set their own
        pass

    __table_args__ = (
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


class NetworkRBAC(RBACColumns, model_base.BASEV2):
    """RBAC table for networks."""

    object_id = sa.Column(sa.String(36),
                          sa.ForeignKey('networks.id', ondelete="CASCADE"),
                          nullable=False)
    object_type = 'network'

    def get_valid_actions(self):
        return ('access_as_shared',)
