# Copyright (c) 2014 OpenStack Foundation.
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

from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils


# TODO(HenryG): Deprecate and schedule for removal
class CommonDbMixin(object):
    """Deprecated."""

    @staticmethod
    def _model_query(context, model):
        return model_query.query_with_hooks(context, model)

    @staticmethod
    def _fields(resource, fields):
        return db_utils.resource_fields(resource, fields)

    @staticmethod
    def _get_by_id(context, model, id):
        return model_query.get_by_id(context, model, id)

    @staticmethod
    def _get_collection_query(context, model,
                              filters=None, sorts=None,
                              limit=None, marker_obj=None,
                              page_reverse=False):
        return model_query.get_collection_query(context, model,
                                                filters, sorts,
                                                limit, marker_obj,
                                                page_reverse)

    @staticmethod
    def _get_collection(context, model, dict_func,
                        filters=None, fields=None, sorts=None,
                        limit=None, marker_obj=None,
                        page_reverse=False):
        return model_query.get_collection(context, model, dict_func,
                                          filters, fields, sorts,
                                          limit, marker_obj,
                                          page_reverse)

    @staticmethod
    def _get_collection_count(context, model, filters=None):
        return model_query.get_collection_count(context, model, filters)

    # TODO(HenryG): Remove this when available in neutron-lib
    def _get_marker_obj(self, context, resource, limit, marker):
        return db_utils.get_marker_obj(self, context, resource, limit, marker)
