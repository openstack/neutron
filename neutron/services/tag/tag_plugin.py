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

from neutron_lib.api.definitions import tag_creation
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib.db import standard_attr
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from sqlalchemy.orm import exc

from neutron.extensions import tagging
from neutron.objects import tag as tag_obj


# Taggable resources
resource_model_map = standard_attr.get_standard_attr_resource_model_map()


@resource_extend.has_resource_extenders
class TagPlugin(tagging.TagPluginBase):
    """Implementation of the Neutron Tag Service Plugin."""

    supported_extension_aliases = ['standard-attr-tag',
                                   tag_creation.ALIAS,
                                   ]

    __filter_validation_support = True

    def __new__(cls, *args, **kwargs):
        inst = super().__new__(cls, *args, **kwargs)
        tag_obj.register_tag_hooks()
        return inst

    @staticmethod
    @resource_extend.extends(list(resource_model_map))
    def _extend_tags_dict(response_data, db_data):
        if not directory.get_plugin(tagging.TAG_PLUGIN_TYPE):
            return
        response_data['tags'] = [
            tag_db.tag for tag_db in db_data.standard_attr.tags
        ]

    @db_api.CONTEXT_READER
    def _get_resource(self, context, resource, resource_id):
        model = resource_model_map[resource]
        try:
            return model_query.get_by_id(context, model, resource_id)
        except exc.NoResultFound:
            raise tagging.TagResourceNotFound(resource=resource,
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
            raise tagging.TagNotFound(tag=tag)

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
    @db_api.CONTEXT_WRITER
    def create_tags(self, context, resource, resource_id, body):
        """Create new tags for a resource

        This method will create the non-existent tags of a resource. If
        present, the tags will be omitted. This method is idempotent.
        """
        res = self._get_resource(context, resource, resource_id)
        new_tags = set(body['tags'])
        old_tags = {tag_db.tag for tag_db in res.standard_attr.tags}
        tags_added = new_tags - old_tags
        self.add_tags(context, res.standard_attr_id, tags_added)
        return body

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
    def update_tags(self, context, resource, resource_id, body):
        with db_api.CONTEXT_WRITER.using(context):
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
            self.add_tags(context, res.standard_attr_id, tags_added)
        return body

    def add_tags(self, context, standard_attr_id, tags):
        for tag in tags:
            tag_obj.Tag(context, standard_attr_id=standard_attr_id,
                        tag=tag).create()

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
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
    @db_api.retry_if_session_inactive()
    def delete_tags(self, context, resource, resource_id):
        res = self._get_resource(context, resource, resource_id)
        tag_obj.Tag.delete_objects(context,
                                   standard_attr_id=res.standard_attr_id)

    @log_helpers.log_method_call
    @db_api.retry_if_session_inactive()
    def delete_tag(self, context, resource, resource_id, tag):
        res = self._get_resource(context, resource, resource_id)
        if not tag_obj.Tag.delete_objects(
                context, tag=tag, standard_attr_id=res.standard_attr_id):
            raise tagging.TagNotFound(tag=tag)
