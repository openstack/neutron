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

# TODO(ihrachys): cover the module with functional tests targeting supported
# backends

from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_utils import uuidutils


# Common database operation implementations
def _get_filter_query(context, model, **kwargs):
    # TODO(jlibosva): decompose _get_collection_query from plugin instance
    plugin = directory.get_plugin()
    with context.session.begin(subtransactions=True):
        filters = _kwargs_to_filters(**kwargs)
        query = plugin._get_collection_query(context, model, filters)
        return query


def get_object(context, model, **kwargs):
    return _get_filter_query(context, model, **kwargs).first()


def count(context, model, **kwargs):
    return _get_filter_query(context, model, **kwargs).count()


def _kwargs_to_filters(**kwargs):
    return {k: v if isinstance(v, list) else [v]
            for k, v in kwargs.items()}


def get_objects(context, model, _pager=None, **kwargs):
    with context.session.begin(subtransactions=True):
        filters = _kwargs_to_filters(**kwargs)
        # TODO(ihrachys): decompose _get_collection from plugin instance
        plugin = directory.get_plugin()
        return plugin._get_collection(
            context, model,
            # TODO(ihrachys): avoid this no-op call per model found
            lambda obj, fields: obj,
            filters=filters,
            **(_pager.to_kwargs(context, model) if _pager else {}))


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
        key = ", ".join(['%s=%s' % (key, value) for (key, value)
                         in kwargs.items()])
        raise n_exc.ObjectNotFound(id="%s(%s)" % (model.__name__, key))
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


def delete_objects(context, model, **kwargs):
    '''Delete matching objects, if any. Return number of deleted objects.

    This function does not raise exceptions if nothing matches.

    :param model: SQL model
    :param kwargs: multiple filters defined by key=value pairs
    :return: Number of entries deleted
    '''
    with context.session.begin(subtransactions=True):
        db_objs = get_objects(context, model, **kwargs)
        for db_obj in db_objs:
            context.session.delete(db_obj)
        return len(db_objs)
