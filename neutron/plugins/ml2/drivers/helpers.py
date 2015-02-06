# Copyright (c) 2014 Thales Services SAS
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

from oslo_db import exception as db_exc

from neutron.common import exceptions as exc
from neutron.i18n import _LW
from neutron.openstack.common import log
from neutron.plugins.ml2 import driver_api as api


# Number of attempts to find a valid segment candidate and allocate it
DB_MAX_ATTEMPTS = 10


LOG = log.getLogger(__name__)


class TypeDriverHelper(api.TypeDriver):
    """TypeDriver Helper for segment allocation.

    Provide methods helping to perform segment allocation fully or partially
    specified.
    """

    def __init__(self, model):
        self.model = model
        self.primary_keys = set(dict(model.__table__.columns))
        self.primary_keys.remove("allocated")

    def allocate_fully_specified_segment(self, session, **raw_segment):
        """Allocate segment fully specified by raw_segment.

        If segment exists, then try to allocate it and return db object
        If segment does not exists, then try to create it and return db object
        If allocation/creation failed, then return None
        """

        network_type = self.get_type()
        try:
            with session.begin(subtransactions=True):
                alloc = (session.query(self.model).filter_by(**raw_segment).
                         first())
                if alloc:
                    if alloc.allocated:
                        # Segment already allocated
                        return
                    else:
                        # Segment not allocated
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "started ",
                                  {"type": network_type,
                                   "segment": raw_segment})
                        count = (session.query(self.model).
                                 filter_by(allocated=False, **raw_segment).
                                 update({"allocated": True}))
                        if count:
                            LOG.debug("%(type)s segment %(segment)s allocate "
                                      "done ",
                                  {"type": network_type,
                                   "segment": raw_segment})
                            return alloc

                        # Segment allocated or deleted since select
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "failed: segment has been allocated or "
                                  "deleted",
                                  {"type": network_type,
                                   "segment": raw_segment})

                # Segment to create or already allocated
                LOG.debug("%(type)s segment %(segment)s create started",
                          {"type": network_type, "segment": raw_segment})
                alloc = self.model(allocated=True, **raw_segment)
                alloc.save(session)
                LOG.debug("%(type)s segment %(segment)s create done",
                          {"type": network_type, "segment": raw_segment})

        except db_exc.DBDuplicateEntry:
            # Segment already allocated (insert failure)
            alloc = None
            LOG.debug("%(type)s segment %(segment)s create failed",
                      {"type": network_type, "segment": raw_segment})

        return alloc

    def allocate_partially_specified_segment(self, session, **filters):
        """Allocate model segment from pool partially specified by filters.

        Return allocated db object or None.
        """

        network_type = self.get_type()
        with session.begin(subtransactions=True):
            select = (session.query(self.model).
                      filter_by(allocated=False, **filters))

            # Selected segment can be allocated before update by someone else,
            # We retry until update success or DB_MAX_ATTEMPTS attempts
            for attempt in range(1, DB_MAX_ATTEMPTS + 1):
                alloc = select.first()

                if not alloc:
                    # No resource available
                    return

                raw_segment = dict((k, alloc[k]) for k in self.primary_keys)
                LOG.debug("%(type)s segment allocate from pool, attempt "
                          "%(attempt)s started with %(segment)s ",
                          {"type": network_type, "attempt": attempt,
                           "segment": raw_segment})
                count = (session.query(self.model).
                         filter_by(allocated=False, **raw_segment).
                         update({"allocated": True}))
                if count:
                    LOG.debug("%(type)s segment allocate from pool, attempt "
                              "%(attempt)s success with %(segment)s ",
                              {"type": network_type, "attempt": attempt,
                               "segment": raw_segment})
                    return alloc

                # Segment allocated since select
                LOG.debug("Allocate %(type)s segment from pool, "
                          "attempt %(attempt)s failed with segment "
                          "%(segment)s",
                          {"type": network_type, "attempt": attempt,
                           "segment": raw_segment})

        LOG.warning(_LW("Allocate %(type)s segment from pool failed "
                        "after %(number)s failed attempts"),
                    {"type": network_type, "number": DB_MAX_ATTEMPTS})
        raise exc.NoNetworkFoundInMaximumAllowedAttempts()
