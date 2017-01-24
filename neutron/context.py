# Copyright 2012 OpenStack Foundation.
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

"""Context: context for security/db session."""

import copy
import datetime

from oslo_context import context as oslo_context
from oslo_db.sqlalchemy import enginefacade

from neutron.db import api as db_api
from neutron import policy


class ContextBase(oslo_context.RequestContext):
    """Security context and request information.

    Represents the user taking a given action within the system.

    """

    def __init__(self, user_id=None, tenant_id=None, is_admin=None,
                 timestamp=None, tenant_name=None, user_name=None,
                 is_advsvc=None, **kwargs):
        """Object initialization.

        :param overwrite: Set to False to ensure that the greenthread local
            copy of the index is not overwritten.
        """
        # NOTE(jamielennox): We maintain these arguments in order for tests
        # that pass arguments positionally.
        kwargs.setdefault('user', user_id)
        kwargs.setdefault('tenant', tenant_id)
        super(ContextBase, self).__init__(is_admin=is_admin, **kwargs)

        self.user_name = user_name
        # NOTE(sdague): tenant* is a deprecated set of names from
        # keystone, and is no longer set in modern keystone middleware
        # code, as such this is almost always going to be None.
        self.tenant_name = tenant_name

        if not timestamp:
            timestamp = datetime.datetime.utcnow()
        self.timestamp = timestamp
        self.is_advsvc = is_advsvc
        if self.is_advsvc is None:
            self.is_advsvc = self.is_admin or policy.check_is_advsvc(self)
        if self.is_admin is None:
            self.is_admin = policy.check_is_admin(self)

    @property
    def project_id(self):
        return self.tenant

    @property
    def tenant_id(self):
        return self.tenant

    @tenant_id.setter
    def tenant_id(self, tenant_id):
        self.tenant = tenant_id

    @property
    def user_id(self):
        return self.user

    @user_id.setter
    def user_id(self, user_id):
        self.user = user_id

    def to_dict(self):
        context = super(ContextBase, self).to_dict()
        context.update({
            'user_id': self.user_id,
            'tenant_id': self.tenant_id,
            'project_id': self.project_id,
            'timestamp': str(self.timestamp),
            # prefer project_name, as that's what's going to be set by
            # keystone. Fall back if for some reason it's blank.
            'tenant_name': self.project_name or self.tenant_name,
            'project_name': self.project_name or self.tenant_name,
            'user_name': self.user_name,
        })
        return context

    def to_policy_values(self):
        values = super(ContextBase, self).to_policy_values()
        values['tenant_id'] = self.tenant_id
        values['is_admin'] = self.is_admin

        # NOTE(jamielennox): These are almost certainly unused and non-standard
        # but kept for backwards compatibility. Remove them in Pike
        # (oslo.context from Ocata release already issues deprecation warnings
        # for non-standard keys).
        values['user'] = self.user
        values['tenant'] = self.tenant
        values['domain'] = self.domain
        values['user_domain'] = self.user_domain
        values['project_domain'] = self.project_domain
        # prefer project_name, as that's what's going to be set by
        # keystone. Fall back if for some reason it's blank.
        values['tenant_name'] = self.project_name or self.tenant_name
        values['project_name'] = self.project_name or self.tenant_name
        values['user_name'] = self.user_name

        return values

    @classmethod
    def from_dict(cls, values):
        return cls(user_id=values.get('user_id', values.get('user')),
                   tenant_id=values.get('tenant_id', values.get('project_id')),
                   is_admin=values.get('is_admin'),
                   roles=values.get('roles'),
                   timestamp=values.get('timestamp'),
                   request_id=values.get('request_id'),
                   tenant_name=values.get('tenant_name'),
                   user_name=values.get('user_name'),
                   auth_token=values.get('auth_token'))

    def elevated(self):
        """Return a version of this context with admin flag set."""
        context = copy.copy(self)
        context.is_admin = True

        if 'admin' not in [x.lower() for x in context.roles]:
            context.roles = context.roles + ["admin"]

        return context


@enginefacade.transaction_context_provider
class ContextBaseWithSession(ContextBase):
    pass


class Context(ContextBaseWithSession):
    def __init__(self, *args, **kwargs):
        super(Context, self).__init__(*args, **kwargs)
        self._session = None

    @property
    def session(self):
        # TODO(akamyshnikova): checking for session attribute won't be needed
        # when reader and writer will be used
        if hasattr(super(Context, self), 'session'):
            return super(Context, self).session
        if self._session is None:
            self._session = db_api.get_writer_session()
        return self._session


def get_admin_context():
    return Context(user_id=None,
                   tenant_id=None,
                   is_admin=True,
                   overwrite=False)


def get_admin_context_without_session():
    return ContextBase(user_id=None,
                       tenant_id=None,
                       is_admin=True)
