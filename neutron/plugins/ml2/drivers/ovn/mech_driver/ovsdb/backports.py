# Copyright 2021 Red Hat, Inc.
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
#
# We don't technically require ovsdbapp that has these fixes so
# just include them here for stable releases
try:
    from ovsdbapp.backend.ovs_idl import idlutils
    frozen_row = idlutils.frozen_row
except AttributeError:
    def frozen_row(row):
        return row._table.rows.IndexEntry(
            uuid=row.uuid,
            **{col: getattr(row, col)
                for col in row._table.columns if hasattr(row, col)})

try:
    from ovsdbapp.backend.ovs_idl import event as row_event
    from ovsdbapp import event as ovsdb_event

    RowEventHandler = row_event.RowEventHandler
except AttributeError:
    class RowEventHandler(ovsdb_event.RowEventHandler):
        def notify(self, event, row, updates=None):
            row = frozen_row(row)
            super().notify(event, row, updates)
