# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron_lib.db import model_base as lib_mb
import sqlalchemy as sa

from neutron.common import _deprecate


_deprecate._moved_global('HasTenant', new_module=lib_mb, new_name='HasProject')


def get_unique_keys(model):
    try:
        constraints = model.__table__.constraints
    except AttributeError:
        constraints = []
    return [[c.name for c in constraint.columns]
            for constraint in constraints
            if isinstance(constraint, sa.UniqueConstraint)]

# This shim is used to deprecate the old contents.
_deprecate._MovedGlobals(lib_mb)
