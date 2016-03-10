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

import datetime
import time

from oslo_log import log
from oslo_utils import timeutils
from sqlalchemy import event
from sqlalchemy import exc as sql_exc
from sqlalchemy.orm import session as se

from neutron._i18n import _LW
from neutron.common import exceptions as n_exc
from neutron.db import model_base

LOG = log.getLogger(__name__)


class TimeStamp_db_mixin(object):
    """Mixin class to add Time Stamp methods."""

    ISO8601_TIME_FORMAT = '%Y-%m-%dT%H:%M:%S'

    def _change_since_result_filter_hook(self, query, filters):
        # this block is for change_since query
        # we get the changed_since string from filters.
        # And translate it from string to datetime type.
        # Then compare with the timestamp in db which has
        # datetime type.
        values = filters and filters.get('changed_since', [])
        if not values:
            return query
        data = filters['changed_since'][0]
        try:
            # this block checks queried timestamp format.
            datetime.datetime.fromtimestamp(time.mktime(
                time.strptime(data,
                              self.ISO8601_TIME_FORMAT)))
        except Exception:
            msg = _LW("The input changed_since must be in the "
                      "following format: YYYY-MM-DDTHH:MM:SS")
            raise n_exc.InvalidInput(error_message=msg)
        changed_since_string = timeutils.parse_isotime(data)
        changed_since = (timeutils.
                         normalize_time(changed_since_string))
        target_model_class = list(query._mapper_adapter_map.keys())[0]
        query = query.join(model_base.StandardAttribute,
                           target_model_class.standard_attr_id ==
                           model_base.StandardAttribute.id).filter(
                           model_base.StandardAttribute.updated_at
                           >= changed_since)
        return query

    def update_timestamp(self, session, context, instances):
        objs_list = session.new.union(session.dirty)

        while objs_list:
            obj = objs_list.pop()
            if (isinstance(obj, model_base.HasStandardAttributes)
                and obj.standard_attr_id):
                obj.standard_attr.updated_at = timeutils.utcnow()

    def register_db_events(self):
        event.listen(model_base.StandardAttribute, 'before_insert',
                     self._add_timestamp)
        event.listen(se.Session, 'before_flush', self.update_timestamp)

    def unregister_db_events(self):
        self._unregister_db_event(model_base.StandardAttribute,
                                  'before_insert', self._add_timestamp)
        self._unregister_db_event(se.Session, 'before_flush',
                                  self.update_timestamp)

    def _unregister_db_event(self, listen_obj, listened_event, listen_hander):
        try:
            event.remove(listen_obj, listened_event, listen_hander)
        except sql_exc.InvalidRequestError:
            LOG.warning(_LW("No sqlalchemy event for resource %s found"),
                        listen_obj)

    def _format_timestamp(self, resource_db, result):
        result['created_at'] = (resource_db.standard_attr.created_at.
                                strftime(self.ISO8601_TIME_FORMAT))
        result['updated_at'] = (resource_db.standard_attr.updated_at.
                                strftime(self.ISO8601_TIME_FORMAT))

    def extend_resource_dict_timestamp(self, plugin_obj,
                                       resource_res, resource_db):
        if (resource_db and resource_db.standard_attr.created_at and
                resource_db.standard_attr.updated_at):
            self._format_timestamp(resource_db, resource_res)

    def _add_timestamp(self, mapper, _conn, target):
        if not target.created_at and not target.updated_at:
            time = timeutils.utcnow()
            for field in ['created_at', 'updated_at']:
                setattr(target, field, time)
        return target
