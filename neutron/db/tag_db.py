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

from sqlalchemy.orm import aliased

from neutron.db.models import tag as tag_model


def _get_tag_list(tag_strings):
    tags = set()
    for tag_str in tag_strings:
        tags |= set(tag_str.split(','))
    return list(tags)


def apply_tag_filters(model, query, filters):
    """Apply tag filters

    There are four types of filter:
    `tags` -- One or more strings that will be used to filter results
            in an AND expression: T1 AND T2

    `tags-any` -- One or more strings that will be used to filter results
            in an OR expression: T1 OR T2

    `not-tags` -- One or more strings that will be used to filter results
            in a NOT AND expression: NOT (T1 AND T2)

    `not-tags-any` -- One or more strings that will be used to filter results
            in a NOT OR expression: NOT (T1 OR T2)

    Note: tag values can be specified comma separated string.
          for example,
          'GET /v2.0/networks?tags-any=red,blue' is equivalent to
          'GET /v2.0/networks?tags-any=red&tags-any=blue'
          it means 'red' or 'blue'.
    """

    if 'tags' in filters:
        tags = _get_tag_list(filters.pop('tags'))
        first_tag = tags.pop(0)
        query = query.join(tag_model.Tag,
            model.standard_attr_id == tag_model.Tag.standard_attr_id)
        query = query.filter(tag_model.Tag.tag == first_tag)

        for tag in tags:
            tag_alias = aliased(tag_model.Tag)
            query = query.join(tag_alias,
                model.standard_attr_id == tag_alias.standard_attr_id)
            query = query.filter(tag_alias.tag == tag)

    if 'tags-any' in filters:
        tags = _get_tag_list(filters.pop('tags-any'))
        query = query.join(tag_model.Tag,
            model.standard_attr_id == tag_model.Tag.standard_attr_id)
        query = query.filter(tag_model.Tag.tag.in_(tags))

    if 'not-tags' in filters:
        tags = _get_tag_list(filters.pop('not-tags'))
        first_tag = tags.pop(0)
        subq = query.session.query(tag_model.Tag.standard_attr_id)
        subq = subq.filter(tag_model.Tag.tag == first_tag)

        for tag in tags:
            tag_alias = aliased(tag_model.Tag)
            subq = subq.join(tag_alias,
                tag_model.Tag.standard_attr_id == tag_alias.standard_attr_id)
            subq = subq.filter(tag_alias.tag == tag)

        query = query.filter(~model.standard_attr_id.in_(subq))

    if 'not-tags-any' in filters:
        tags = _get_tag_list(filters.pop('not-tags-any'))
        subq = query.session.query(tag_model.Tag.standard_attr_id)
        subq = subq.filter(tag_model.Tag.tag.in_(tags))
        query = query.filter(~model.standard_attr_id.in_(subq))

    return query
