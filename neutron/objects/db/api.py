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

from neutron_lib.db import model_query
from neutron_lib import exceptions as n_exc
from neutron_lib.objects import utils as obj_utils
from oslo_utils import uuidutils


# Common database operation implementations
def _get_filter_query(obj_cls, context, **kwargs):
    with obj_cls.db_context_reader(context):
        filters = _kwargs_to_filters(**kwargs)
        query = model_query.get_collection_query(
            context, obj_cls.db_model, filters)
        return query


def get_object(obj_cls, context, **kwargs):
    return _get_filter_query(obj_cls, context, **kwargs).first()


def count(obj_cls, context, **kwargs):
    return _get_filter_query(obj_cls, context, **kwargs).count()


def _kwargs_to_filters(**kwargs):
    retain_classes = (list, set, obj_utils.FilterObj)
    return {k: v if isinstance(v, retain_classes) else [v]
            for k, v in kwargs.items()}


def get_objects(obj_cls, context, _pager=None, **kwargs):
    with obj_cls.db_context_reader(context):
        filters = _kwargs_to_filters(**kwargs)
        return model_query.get_collection(
            context, obj_cls.db_model,
            dict_func=None,  # return all the data
            filters=filters,
            **(_pager.to_kwargs(context, obj_cls) if _pager else {}))


def get_values(obj_cls, context, field, **kwargs):
    with obj_cls.db_context_reader(context):
        filters = _kwargs_to_filters(**kwargs)
        return model_query.get_values(
            context, obj_cls.db_model, field, filters=filters)


def create_object(obj_cls, context, values, populate_id=True):
    with obj_cls.db_context_writer(context):
        if (populate_id and
                'id' not in values and
                hasattr(obj_cls.db_model, 'id')):
            values['id'] = uuidutils.generate_uuid()
        db_obj = obj_cls.db_model(**values)
        context.session.add(db_obj)
    return db_obj


def _safe_get_object(obj_cls, context, **kwargs):
    db_obj = get_object(obj_cls, context, **kwargs)

    if db_obj is None:
        key = ", ".join(['%s=%s' % (key, value) for (key, value)
                         in kwargs.items()])
        raise n_exc.ObjectNotFound(
            id="%s(%s)" % (obj_cls.db_model.__name__, key))
    return db_obj


def update_object(obj_cls, context, values, **kwargs):
    with obj_cls.db_context_writer(context):
        db_obj = _safe_get_object(obj_cls, context, **kwargs)
        db_obj.update(values)
        db_obj.save(session=context.session)
    return db_obj


def delete_object(obj_cls, context, **kwargs):
    with obj_cls.db_context_writer(context):
        db_obj = _safe_get_object(obj_cls, context, **kwargs)
        context.session.delete(db_obj)


def update_objects(obj_cls, context, values, **kwargs):
    '''Update matching objects, if any. Return number of updated objects.

    This function does not raise exceptions if nothing matches.

    :param obj_cls: Object class
    :param values: values to update in matching objects
    :param kwargs: multiple filters defined by key=value pairs
    :return: Number of entries updated
    '''
    with obj_cls.db_context_writer(context):
        if not values:
            return count(obj_cls, context, **kwargs)
        q = _get_filter_query(obj_cls, context, **kwargs)
        return q.update(values, synchronize_session=False)


def delete_objects(obj_cls, context, **kwargs):
    '''Delete matching objects, if any. Return number of deleted objects.

    This function does not raise exceptions if nothing matches.

    :param obj_cls: Object class
    :param kwargs: multiple filters defined by key=value pairs
    :return: Number of entries deleted
    '''
    with obj_cls.db_context_writer(context):
        db_objs = get_objects(obj_cls, context, **kwargs)
        for db_obj in db_objs:
            context.session.delete(db_obj)
        return len(db_objs)
