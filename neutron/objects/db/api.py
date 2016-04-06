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

from neutron_lib import exceptions as n_exc
from oslo_utils import uuidutils

from neutron.db import common_db_mixin


# Common database operation implementations
def get_object(context, model, **kwargs):
    with context.session.begin(subtransactions=True):
        return (common_db_mixin.model_query(context, model)
                .filter_by(**kwargs)
                .first())


def get_objects(context, model, **kwargs):
    with context.session.begin(subtransactions=True):
        return (common_db_mixin.model_query(context, model)
                .filter_by(**kwargs)
                .all())


def create_object(context, model, values):
    with context.session.begin(subtransactions=True):
        if 'id' not in values and hasattr(model, 'id'):
            values['id'] = uuidutils.generate_uuid()
        db_obj = model(**values)
        context.session.add(db_obj)
    return db_obj


def _safe_get_object(context, model, **kwargs):
    db_obj = get_object(context, model, **kwargs)

    if db_obj is None:
        key = "".join(['%s:: %s ' % (key, value) for (key, value)
                       in kwargs.items()])
        raise n_exc.ObjectNotFound(id=key)
    return db_obj


def update_object(context, model, values, **kwargs):
    with context.session.begin(subtransactions=True):
        db_obj = _safe_get_object(context, model, **kwargs)
        db_obj.update(values)
        db_obj.save(session=context.session)
    return db_obj


def delete_object(context, model, **kwargs):
    with context.session.begin(subtransactions=True):
        db_obj = _safe_get_object(context, model, **kwargs)
        context.session.delete(db_obj)
