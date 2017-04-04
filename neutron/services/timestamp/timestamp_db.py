# Copyright 2015 HuaWei Technologies.
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

from neutron_lib import exceptions as n_exc
from oslo_utils import timeutils
from sqlalchemy.orm import session as se

from neutron.db import _model_query as model_query
from neutron.db import _resource_extend as resource_extend
from neutron.db import api as db_api
from neutron.db import standard_attr

CHANGED_SINCE = 'changed_since'
TIME_FORMAT_WHOLE_SECONDS = '%Y-%m-%dT%H:%M:%S'


def _change_since_result_filter_hook(query, filters):
    # this block is for change_since query
    # we get the changed_since string from filters.
    # And translate it from string to datetime type.
    # Then compare with the timestamp in db which has
    # datetime type.
    values = filters and filters.get(CHANGED_SINCE, [])
    if not values:
        return query
    data = filters[CHANGED_SINCE][0]
    try:
        changed_since_string = timeutils.parse_isotime(data)
    except Exception:
        msg = ("The input %s must be in the "
               "following format: YYYY-MM-DDTHH:MM:SSZ") % CHANGED_SINCE
        raise n_exc.InvalidInput(error_message=msg)
    changed_since = (timeutils.
                     normalize_time(changed_since_string))
    target_model_class = query.column_descriptions[0]['type']
    query = query.join(standard_attr.StandardAttribute,
                       target_model_class.standard_attr_id ==
                       standard_attr.StandardAttribute.id).filter(
                       standard_attr.StandardAttribute.updated_at
                       >= changed_since)
    return query


def _update_timestamp(session, context, instances):
    objs_list = session.new.union(session.dirty)

    while objs_list:
        obj = objs_list.pop()
        if (isinstance(obj, standard_attr.HasStandardAttributes)
            and obj.standard_attr_id):
            obj.updated_at = timeutils.utcnow()


def _format_timestamp(resource_db, result):
    result['created_at'] = (resource_db.created_at.
                            strftime(TIME_FORMAT_WHOLE_SECONDS)) + 'Z'
    result['updated_at'] = (resource_db.updated_at.
                            strftime(TIME_FORMAT_WHOLE_SECONDS)) + 'Z'


def _add_timestamp(mapper, _conn, target):
    if not target.created_at and not target.updated_at:
        time = timeutils.utcnow()
        for field in ['created_at', 'updated_at']:
            setattr(target, field, time)
    return target


@resource_extend.has_resource_extenders
class TimeStamp_db_mixin(object):
    """Mixin class to add Time Stamp methods."""

    def __new__(cls, *args, **kwargs):
        rs_model_maps = standard_attr.get_standard_attr_resource_model_map()
        for model in rs_model_maps.values():
            model_query.register_hook(
                model,
                "change_since_query",
                query_hook=None,
                filter_hook=None,
                result_filters=_change_since_result_filter_hook)
        return super(TimeStamp_db_mixin, cls).__new__(cls, *args, **kwargs)

    def register_db_events(self):
        listen = db_api.sqla_listen
        listen(standard_attr.StandardAttribute, 'before_insert',
               _add_timestamp)
        listen(se.Session, 'before_flush', _update_timestamp)

    @staticmethod
    @resource_extend.extends(
        list(standard_attr.get_standard_attr_resource_model_map()))
    def _extend_resource_dict_timestamp(resource_res, resource_db):
        if (resource_db and resource_db.created_at and
                resource_db.updated_at):
            _format_timestamp(resource_db, resource_res)
