# Copyright 2017 Red Hat, Inc.
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

import datetime

from neutron_lib.db import api as db_api
from neutron_lib.db import standard_attr
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
import sqlalchemy as sa
from sqlalchemy.orm import exc

from neutron.common.ovn import utils as ovn_utils
from neutron.db.models import l3  # noqa
from neutron.db.models import ovn as ovn_models
from neutron.db.models import securitygroup  # noqa
from neutron.db import models_v2  # noqa

LOG = log.getLogger(__name__)
CONF = cfg.CONF

STD_ATTR_MAP = standard_attr.get_standard_attr_resource_model_map()

# NOTE(ralonsoh): to be moved to neutron-lib
TYPE_NETWORKS = 'networks'
TYPE_PORTS = 'ports'
TYPE_SECURITY_GROUP_RULES = 'security_group_rules'
TYPE_ROUTERS = 'routers'
TYPE_ROUTER_PORTS = 'router_ports'
TYPE_SECURITY_GROUPS = 'security_groups'
TYPE_FLOATINGIPS = 'floatingips'
TYPE_SUBNETS = 'subnets'

_TYPES_PRIORITY_ORDER = (
    TYPE_NETWORKS,
    TYPE_SECURITY_GROUPS,
    TYPE_SUBNETS,
    TYPE_ROUTERS,
    TYPE_PORTS,
    TYPE_ROUTER_PORTS,
    TYPE_FLOATINGIPS,
    TYPE_SECURITY_GROUP_RULES)

# The order in which the resources should be created or updated by the
# maintenance task: Root ones first and leafs at the end.
MAINTENANCE_CREATE_UPDATE_TYPE_ORDER = [
    (ovn_models.OVNRevisionNumbers.resource_type == resource_type, idx)
    for idx, resource_type in enumerate(_TYPES_PRIORITY_ORDER, 1)
]

# The order in which the resources should be deleted by the maintenance
# task: Leaf ones first and roots at the end.
MAINTENANCE_DELETE_TYPE_ORDER = [
    (ovn_models.OVNRevisionNumbers.resource_type == resource_type, idx)
    for idx, resource_type in enumerate(reversed(_TYPES_PRIORITY_ORDER), 1)
]

INITIAL_REV_NUM = -1

# Time (in seconds) used to identify if an entry is new before considering
# it an inconsistency
INCONSISTENCIES_OLDER_THAN = 60


# 1:2 mapping for OVN, neutron router ports are simple ports, but
# for OVN we handle LSP & LRP objects
if STD_ATTR_MAP:
    STD_ATTR_MAP[TYPE_ROUTER_PORTS] = STD_ATTR_MAP[TYPE_PORTS]


# NOTE(ralonsoh): to be moved to neutron-lib
class StandardAttributeIDNotFound(n_exc.NeutronException):
    message = 'Standard attribute ID not found for %(resource_uuid)s'


# NOTE(ralonsoh): to be moved to neutron-lib
class UnknownResourceType(n_exc.NeutronException):
    message = 'Uknown resource type: %(resource_type)s'


def _get_standard_attr_id(context, resource_uuid, resource_type):
    try:
        row = context.session.query(STD_ATTR_MAP[resource_type]).filter_by(
            id=resource_uuid).one()
        return row.standard_attr_id
    except exc.NoResultFound:
        raise StandardAttributeIDNotFound(resource_uuid=resource_uuid)


@db_api.retry_if_session_inactive()
def create_initial_revision(context, resource_uuid, resource_type,
                            revision_number=INITIAL_REV_NUM,
                            may_exist=False, std_attr_id=None):
    LOG.debug('create_initial_revision uuid=%s, type=%s, rev=%s',
              resource_uuid, resource_type, revision_number)
    db_func = context.session.merge if may_exist else context.session.add
    with db_api.CONTEXT_WRITER.using(context):
        std_attr_id = std_attr_id or _get_standard_attr_id(
            context, resource_uuid, resource_type)
        row = ovn_models.OVNRevisionNumbers(
            resource_uuid=resource_uuid, resource_type=resource_type,
            standard_attr_id=std_attr_id, revision_number=revision_number)
        db_func(row)


@db_api.retry_if_session_inactive()
def delete_revision(context, resource_uuid, resource_type):
    LOG.debug('delete_revision(%s)', resource_uuid)
    with db_api.CONTEXT_WRITER.using(context):
        row = context.session.query(ovn_models.OVNRevisionNumbers).filter_by(
            resource_uuid=resource_uuid,
            resource_type=resource_type).one_or_none()
        if row:
            context.session.delete(row)


def _ensure_revision_row_exist(context, resource, resource_type, std_attr_id):
    """Ensure the revision row exists.

    Ensure the revision row exist before we try to bump its revision
    number. This method is part of the migration plan to deal with
    resources that have been created prior to the database sync work
    getting merged.
    """
    # TODO(lucasagomes): As the docstring says, this method was created to
    # deal with objects that already existed before the sync work. I believe
    # that we can remove this method after few development cycles. Or,
    # if we decide to make a migration script as well.
    if context.session.query(ovn_models.OVNRevisionNumbers).filter_by(
            resource_uuid=resource['id'],
            resource_type=resource_type).one_or_none():
        return

    LOG.warning(
        'No revision row found for %(res_uuid)s (type: '
        '%(res_type)s) when bumping the revision number. '
        'Creating one.', {'res_uuid': resource['id'],
                          'res_type': resource_type})
    create_initial_revision(context, resource['id'], resource_type,
                            std_attr_id=std_attr_id)


@db_api.retry_if_session_inactive()
def get_revision_row(context, resource_uuid):
    try:
        with db_api.CONTEXT_READER.using(context):
            return context.session.query(
                ovn_models.OVNRevisionNumbers).filter_by(
                    resource_uuid=resource_uuid).one()
    except exc.NoResultFound:
        pass


@db_api.retry_if_session_inactive()
def bump_revision(context, resource, resource_type):
    revision_number = ovn_utils.get_revision_number(resource, resource_type)
    with db_api.CONTEXT_WRITER.using(context):
        std_attr_id = _get_standard_attr_id(context, resource['id'],
                                            resource_type)
        _ensure_revision_row_exist(context, resource, resource_type,
                                   std_attr_id)
        row = context.session.merge(ovn_models.OVNRevisionNumbers(
            standard_attr_id=std_attr_id, resource_uuid=resource['id'],
            resource_type=resource_type))
        if revision_number < row.revision_number:
            LOG.debug(
                'Skip bumping the revision number for %(res_uuid)s (type: '
                '%(res_type)s) to %(rev_num)d. A higher version is already '
                'registered in the database (%(new_rev)d)',
                {'res_type': resource_type, 'res_uuid': resource['id'],
                 'rev_num': revision_number, 'new_rev': row.revision_number})
            return
        row.revision_number = revision_number
        context.session.merge(row)
    LOG.info('Successfully bumped revision number for resource '
             '%(res_uuid)s (type: %(res_type)s) to %(rev_num)d',
             {'res_uuid': resource['id'], 'res_type': resource_type,
              'rev_num': revision_number})


def get_inconsistent_resources(context):
    """Get a list of inconsistent resources.

    :returns: A list of objects which the revision number from the
              ovn_revision_number and standardattributes tables differs.
    """
    sort_order = sa.case(*MAINTENANCE_CREATE_UPDATE_TYPE_ORDER)
    time_ = (timeutils.utcnow() -
             datetime.timedelta(seconds=INCONSISTENCIES_OLDER_THAN))
    with db_api.CONTEXT_READER.using(context):
        query = context.session.query(ovn_models.OVNRevisionNumbers).join(
            standard_attr.StandardAttribute,
            ovn_models.OVNRevisionNumbers.standard_attr_id ==
            standard_attr.StandardAttribute.id)
        # Filter out new entries
        query = query.filter(
            standard_attr.StandardAttribute.created_at < time_)
        # Filter for resources which revision_number differs
        query = query.filter(
            ovn_models.OVNRevisionNumbers.revision_number !=
            standard_attr.StandardAttribute.revision_number)
        return query.order_by(sort_order).all()


def get_deleted_resources(context):
    """Get a list of resources that failed to be deleted in OVN.

    Get a list of resources that have been deleted from neutron but not
    in OVN. Once a resource is deleted in Neutron the ``standard_attr_id``
    foreign key in the ovn_revision_numbers table will be set to NULL.

    Upon successfully deleting the resource in OVN the entry in the
    ovn_revision_number should also be deleted but if something fails
    the entry will be kept and returned in this list so the maintenance
    thread can later fix it.
    """
    sort_order = sa.case(*MAINTENANCE_DELETE_TYPE_ORDER)
    with db_api.CONTEXT_READER.using(context):
        return context.session.query(ovn_models.OVNRevisionNumbers).filter_by(
            standard_attr_id=None).order_by(sort_order).all()
