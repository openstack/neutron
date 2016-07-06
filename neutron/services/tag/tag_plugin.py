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

import functools

from oslo_db import api as oslo_db_api
from oslo_db import exception as db_exc
from oslo_log import helpers as log_helpers
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db import models_v2
from neutron.db import tag_db as tag_model
from neutron.extensions import tag as tag_ext


resource_model_map = {
    attributes.NETWORKS: models_v2.Network,
    # other resources can be added
}


def _extend_tags_dict(plugin, response_data, db_data):
    tags = [tag_db.tag for tag_db in db_data.standard_attr.tags]
    response_data['tags'] = tags


class TagPlugin(common_db_mixin.CommonDbMixin, tag_ext.TagPluginBase):
    """Implementation of the Neutron Tag Service Plugin."""

    supported_extension_aliases = ['tag']

    def _get_resource(self, context, resource, resource_id):
        model = resource_model_map[resource]
        try:
            return self._get_by_id(context, model, resource_id)
        except exc.NoResultFound:
            raise tag_ext.TagResourceNotFound(resource=resource,
                                              resource_id=resource_id)

    @log_helpers.log_method_call
    def get_tags(self, context, resource, resource_id):
        res = self._get_resource(context, resource, resource_id)
        tags = [tag_db.tag for tag_db in res.standard_attr.tags]
        return dict(tags=tags)

    @log_helpers.log_method_call
    def get_tag(self, context, resource, resource_id, tag):
        res = self._get_resource(context, resource, resource_id)
        if not any(tag == tag_db.tag for tag_db in res.standard_attr.tags):
            raise tag_ext.TagNotFound(tag=tag)

    @log_helpers.log_method_call
    @oslo_db_api.wrap_db_retry(
        max_retries=db_api.MAX_RETRIES,
        exception_checker=lambda e: isinstance(e, db_exc.DBDuplicateEntry))
    def update_tags(self, context, resource, resource_id, body):
        res = self._get_resource(context, resource, resource_id)
        new_tags = set(body['tags'])
        old_tags = {tag_db.tag for tag_db in res.standard_attr.tags}
        tags_added = new_tags - old_tags
        tags_removed = old_tags - new_tags
        with context.session.begin(subtransactions=True):
            for tag_db in res.standard_attr.tags:
                if tag_db.tag in tags_removed:
                    context.session.delete(tag_db)
            for tag in tags_added:
                tag_db = tag_model.Tag(standard_attr_id=res.standard_attr_id,
                                       tag=tag)
                context.session.add(tag_db)
        return body

    @log_helpers.log_method_call
    def update_tag(self, context, resource, resource_id, tag):
        res = self._get_resource(context, resource, resource_id)
        if any(tag == tag_db.tag for tag_db in res.standard_attr.tags):
            return
        try:
            with context.session.begin(subtransactions=True):
                tag_db = tag_model.Tag(standard_attr_id=res.standard_attr_id,
                                       tag=tag)
                context.session.add(tag_db)
        except db_exc.DBDuplicateEntry:
            pass

    @log_helpers.log_method_call
    def delete_tags(self, context, resource, resource_id):
        res = self._get_resource(context, resource, resource_id)
        with context.session.begin(subtransactions=True):
            query = context.session.query(tag_model.Tag)
            query = query.filter_by(standard_attr_id=res.standard_attr_id)
            query.delete()

    @log_helpers.log_method_call
    def delete_tag(self, context, resource, resource_id, tag):
        res = self._get_resource(context, resource, resource_id)
        with context.session.begin(subtransactions=True):
            query = context.session.query(tag_model.Tag)
            query = query.filter_by(tag=tag,
                                    standard_attr_id=res.standard_attr_id)
            if not query.delete():
                raise tag_ext.TagNotFound(tag=tag)

    # support only _apply_dict_extend_functions supported resources
    # at the moment.
    for resource, model in resource_model_map.items():
        common_db_mixin.CommonDbMixin.register_dict_extend_funcs(
            resource, [_extend_tags_dict])
        common_db_mixin.CommonDbMixin.register_model_query_hook(
            model, "tag", None, None,
            functools.partial(tag_model.apply_tag_filters, model))
