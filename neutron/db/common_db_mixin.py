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

from neutron_lib.db import utils as db_utils

from neutron.db import _model_query
from neutron.db import _resource_extend


# TODO(HenryG): Deprecate and schedule for removal
class CommonDbMixin(object):
    """Deprecated."""

    @staticmethod
    def register_model_query_hook(model, name, query_hook, filter_hook,
                                  result_filters=None):
        _model_query.register_hook(
            model, name, query_hook, filter_hook,
            result_filters=result_filters)

    @staticmethod
    def register_dict_extend_funcs(resource, funcs):
        _resource_extend.register_funcs(resource, funcs)

    @staticmethod
    def _model_query(context, model):
        return _model_query.query_with_hooks(context, model)

    @staticmethod
    def _fields(resource, fields):
        return db_utils.resource_fields(resource, fields)

    @staticmethod
    def _get_by_id(context, model, id):
        return _model_query.get_by_id(context, model, id)

    @staticmethod
    def _apply_filters_to_query(query, model, filters, context=None):
        return _model_query.apply_filters(query, model, filters, context)

    @staticmethod
    def _apply_dict_extend_functions(resource_type, response, db_object):
        _resource_extend.apply_funcs(resource_type, response, db_object)

    @staticmethod
    def _get_collection_query(context, model,
                              filters=None, sorts=None,
                              limit=None, marker_obj=None,
                              page_reverse=False):
        return _model_query.get_collection_query(context, model,
                                                 filters, sorts,
                                                 limit, marker_obj,
                                                 page_reverse)

    @staticmethod
    def _get_collection(context, model, dict_func,
                        filters=None, fields=None, sorts=None,
                        limit=None, marker_obj=None,
                        page_reverse=False):
        return _model_query.get_collection(context, model, dict_func,
                                           filters, fields, sorts,
                                           limit, marker_obj,
                                           page_reverse)

    @staticmethod
    def _get_collection_count(context, model, filters=None):
        return _model_query.get_collection_count(context, model, filters)

    # TODO(HenryG): Remove this when available in neutron-lib
    def _get_marker_obj(self, context, resource, limit, marker):
        return db_utils.get_marker_obj(self, context, resource, limit, marker)

    @staticmethod
    def _filter_non_model_columns(data, model):
        return db_utils.filter_non_model_columns(data, model)
