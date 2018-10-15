# Copyright 2015 IBM Corporation
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

import os

from oslo_log import log as logging

from neutron._i18n import _

LOG = logging.getLogger(__name__)


class ItemAllocator(object):
    """Manages allocation of items from a pool

    Some of the allocations such as link local addresses used for routing
    inside the fip namespaces need to persist across agent restarts to maintain
    consistency. Persisting such allocations in the neutron database is
    unnecessary and would degrade performance. ItemAllocator utilizes local
    file system to track allocations made for objects of a given class.

    The persistent datastore is a file. The records are one per line of
    the format: key<delimiter>value.  For example if the delimiter is a ','
    (the default value) then the records will be: key,value (one per line)
    """

    def __init__(self, state_file, ItemClass, item_pool, delimiter=','):
        """Read the file with previous allocations recorded.

        See the note in the allocate method for more detail.
        """
        self.ItemClass = ItemClass
        self.state_file = state_file

        self.allocations = {}

        self.remembered = {}
        self.pool = item_pool

        read_error = False
        for line in self._read():
            try:
                key, saved_value = line.strip().split(delimiter)
                self.remembered[key] = self.ItemClass(saved_value)
            except ValueError:
                read_error = True
                LOG.warning("Invalid line in %(file)s, "
                            "ignoring: %(line)s",
                            {'file': state_file, 'line': line})

        self.pool.difference_update(self.remembered.values())
        if read_error:
            LOG.debug("Re-writing file %s due to read error", state_file)
            self._write_allocations()

    def lookup(self, key):
        """Try to lookup an item of ItemClass type.

        See if there are any current or remembered allocations for the key.
        """
        if key in self.allocations:
            return self.allocations[key]

        if key in self.remembered:
            self.allocations[key] = self.remembered.pop(key)
            return self.allocations[key]

    def allocate(self, key):
        """Try to allocate an item of ItemClass type.

        I expect this to work in all cases because I expect the pool size to be
        large enough for any situation.  Nonetheless, there is some defensive
        programming in here.

        Since the allocations are persisted, there is the chance to leak
        allocations which should have been released but were not.  This leak
        could eventually exhaust the pool.

        So, if a new allocation is needed, the code first checks to see if
        there are any remembered allocations for the key.  If not, it checks
        the free pool.  If the free pool is empty then it dumps the remembered
        allocations to free the pool.  This final desperate step will not
        happen often in practice.
        """
        entry = self.lookup(key)
        if entry:
            return entry

        if not self.pool:
            # Desperate times.  Try to get more in the pool.
            self.pool.update(self.remembered.values())
            self.remembered.clear()
            if not self.pool:
                # The number of address pairs allocated from the
                # pool depends upon the prefix length specified
                # in DVR_FIP_LL_CIDR
                raise RuntimeError(_("Cannot allocate item of type: "
                                     "%(class)s from pool using file %(file)s")
                                   % {'class': self.ItemClass,
                                      'file': self.state_file})

        self.allocations[key] = self.pool.pop()
        self._write_allocations()
        return self.allocations[key]

    def release(self, key):
        if self.lookup(key):
            self.pool.add(self.allocations.pop(key))
            self._write_allocations()

    def _write_allocations(self):
        current = ["%s,%s\n" % (k, v) for k, v in self.allocations.items()]
        remembered = ["%s,%s\n" % (k, v) for k, v in self.remembered.items()]
        current.extend(remembered)
        self._write(current)

    def _write(self, lines):
        with open(self.state_file, "w") as f:
            f.writelines(lines)

    def _read(self):
        if not os.path.exists(self.state_file):
            return []
        with open(self.state_file) as f:
            return f.readlines()
