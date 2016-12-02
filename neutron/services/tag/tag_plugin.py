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

from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.db import _model_query as model_query
from neutron.db import _resource_extend as resource_extend
from neutron.db import api as db_api
from neutron.db import common_db_mixin
from neutron.db.models import l3 as l3_model
from neutron.db import models_v2
from neutron.db import tag_db as tag_methods
from neutron.extensions import l3 as l3_ext
from neutron.extensions import tag as tag_ext
from neutron.objects import exceptions as obj_exc
from neutron.objects import tag as tag_obj


# Taggable resources
resource_model_map = {
    # When we'll add other resources, we must add new extension for them
    # if we don't have better discovery mechanism instead of it.
    attributes.NETWORKS: models_v2.Network,
    attributes.SUBNETS: models_v2.Subnet,
    attributes.PORTS: models_v2.Port,
    attributes.SUBNETPOOLS: models_v2.SubnetPool,
    l3_ext.ROUTERS: l3_model.Router,
}


def _extend_tags_dict(plugin, response_data, db_data):
    if not directory.get_plugin(tag_ext.TAG_PLUGIN_TYPE):
        return
    tags = [tag_db.tag for tag_db in db_data.standard_attr.tags]
    response_data['tags'] = tags


class TagPlugin(common_db_mixin.CommonDbMixin, tag_ext.TagPluginBase):
    """Implementation of the Neutron Tag Service Plugin."""

    supported_extension_aliases = ['tag', 'tag-ext']

    def __new__(cls, *args, **kwargs):
        inst = super(TagPlugin, cls).__new__(cls, *args, **kwargs)
        inst._filter_methods = []  # prevent GC of our partial functions
        for resource, model in resource_model_map.items():
            resource_extend.register_funcs(resource, [_extend_tags_dict])
            method = functools.partial(tag_methods.apply_tag_filters, model)
            inst._filter_methods.append(method)
            model_query.register_hook(model, "tag",
                                      query_hook=None,
                                      filter_hook=None,
                                      result_filters=method)
        return inst

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
    @db_api.retry_if_session_inactive()
    def update_tags(self, context, resource, resource_id, body):
        with db_api.context_manager.writer.using(context):
            # We get and do all operations with objects in one session
            res = self._get_resource(context, resource, resource_id)
            new_tags = set(body['tags'])
            old_tags = {tag_db.tag for tag_db in res.standard_attr.tags}
            tags_added = new_tags - old_tags
            tags_removed = old_tags - new_tags
            if tags_removed:
                tag_obj.Tag.delete_objects(
                    context,
                    standard_attr_id=res.standard_attr_id,
                    tag=[
                        tag_db.tag
                        for tag_db in res.standard_attr.tags
                        if tag_db.tag in tags_removed
                    ]
                )
            for tag in tags_added:
                tag_obj.Tag(context, standard_attr_id=res.standard_attr_id,
                            tag=tag).create()
        return body

    @log_helpers.log_method_call
    def update_tag(self, context, resource, resource_id, tag):
        res = self._get_resource(context, resource, resource_id)
        if any(tag == tag_db.tag for tag_db in res.standard_attr.tags):
            return
        try:
            tag_obj.Tag(context, standard_attr_id=res.standard_attr_id,
                tag=tag).create()
        except obj_exc.NeutronDbObjectDuplicateEntry:
            pass

    @log_helpers.log_method_call
    def delete_tags(self, context, resource, resource_id):
        res = self._get_resource(context, resource, resource_id)
        tag_obj.Tag.delete_objects(context,
                                   standard_attr_id=res.standard_attr_id)

    @log_helpers.log_method_call
    def delete_tag(self, context, resource, resource_id, tag):
        res = self._get_resource(context, resource, resource_id)
        if not tag_obj.Tag.delete_objects(context,
            tag=tag, standard_attr_id=res.standard_attr_id):
            raise tag_ext.TagNotFound(tag=tag)
