# Copyright 2011 OpenStack Foundation.
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

from debtcollector import removals
from neutron_lib.db import utils as db_utils
from oslo_db.sqlalchemy import utils as sa_utils


@removals.remove(version='newton', removal_version='ocata',
                 message='Use  ' + sa_utils.__name__ + '.' +
                         sa_utils.paginate_query.__name__ + '() instead, '
                         'but note that the arguments differ')
def paginate_query(query, model, limit, sorts, marker_obj=None):
    if not sorts:
        return query

    sort_keys = db_utils.get_and_validate_sort_keys(sorts, model)
    sort_dirs = ['asc' if s[1] else 'desc' for s in sorts]
    return sa_utils.paginate_query(query, model, limit, marker=marker_obj,
                                   sort_keys=sort_keys, sort_dirs=sort_dirs)
