# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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
import logging

from datetime import datetime

from quantum.db import api as db_api

LOG = logging.getLogger(__name__)


class Context(object):
    """Security context and request information.

    Represents the user taking a given action within the system.

    """

    def __init__(self, user_id, tenant_id, is_admin=None, read_deleted="no",
                 roles=None, timestamp=None, **kwargs):
        """
        :param read_deleted: 'no' indicates deleted records are hidden, 'yes'
            indicates deleted records are visible, 'only' indicates that
            *only* deleted records are visible.
        """
        if kwargs:
            LOG.warn(_('Arguments dropped when creating context: %s') %
                    str(kwargs))

        self.user_id = user_id
        self.tenant_id = tenant_id
        self.roles = roles or []
        self.is_admin = is_admin
        if self.is_admin is None:
            self.is_admin = 'admin' in [x.lower() for x in self.roles]
        elif self.is_admin and 'admin' not in [x.lower() for x in self.roles]:
            self.roles.append('admin')
        self.read_deleted = read_deleted
        if not timestamp:
            timestamp = datetime.utcnow()
        self.timestamp = timestamp
        self._session = None

    def _get_read_deleted(self):
        return self._read_deleted

    def _set_read_deleted(self, read_deleted):
        if read_deleted not in ('no', 'yes', 'only'):
            raise ValueError(_("read_deleted can only be one of 'no', "
                               "'yes' or 'only', not %r") % read_deleted)
        self._read_deleted = read_deleted

    def _del_read_deleted(self):
        del self._read_deleted

    read_deleted = property(_get_read_deleted, _set_read_deleted,
                            _del_read_deleted)

    @property
    def session(self):
        if self._session is None:
            self._session = db_api.get_session()
        return self._session

    def to_dict(self):
        return {'user_id': self.user_id,
                'tenant_id': self.tenant_id,
                'is_admin': self.is_admin,
                'read_deleted': self.read_deleted,
                'roles': self.roles,
                'timestamp': str(self.timestamp)}

    @classmethod
    def from_dict(cls, values):
        return cls(**values)

    def elevated(self, read_deleted=None):
        """Return a version of this context with admin flag set."""
        context = copy.copy(self)
        context.is_admin = True

        if 'admin' not in [x.lower() for x in context.roles]:
            context.roles.append('admin')

        if read_deleted is not None:
            context.read_deleted = read_deleted

        return context


def get_admin_context(read_deleted="no"):
    return Context(user_id=None,
                   tenant_id=None,
                   is_admin=True,
                   read_deleted=read_deleted)
