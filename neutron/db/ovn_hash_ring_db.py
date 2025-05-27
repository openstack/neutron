# Copyright 2019 Red Hat, Inc.
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
from oslo_config import cfg
from oslo_log import log
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.db.models import ovn as ovn_models

CONF = cfg.CONF
LOG = log.getLogger(__name__)


# NOTE(ralonsoh): this was migrated from networking-ovn to neutron and should
#                 be refactored to be integrated in a OVO.
@db_api.retry_if_session_inactive()
def add_node(context, group_name, node_uuid=None, created_at=None):
    if node_uuid is None:
        node_uuid = uuidutils.generate_uuid()

    with db_api.CONTEXT_WRITER.using(context):
        kwargs = {'node_uuid': node_uuid,
                  'hostname': CONF.host,
                  'group_name': group_name}
        if created_at:
            kwargs['created_at'] = created_at
        context.session.add(ovn_models.OVNHashRing(**kwargs))
    LOG.info('Node %s from host "%s" and group "%s" added to the Hash Ring',
             node_uuid, CONF.host, group_name)
    return node_uuid


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_READER
def get_nodes(context, group_name, created_at=None):
    query = context.session.query(ovn_models.OVNHashRing).filter(
        ovn_models.OVNHashRing.group_name == group_name)
    if created_at:
        query = query.filter(
            ovn_models.OVNHashRing.created_at == created_at)
    return query.all()


@db_api.retry_if_session_inactive()
def remove_nodes_from_host(context, group_name, created_at=None):
    with (db_api.CONTEXT_WRITER.using(context)):
        query = context.session.query(ovn_models.OVNHashRing).filter(
            ovn_models.OVNHashRing.hostname == CONF.host,
            ovn_models.OVNHashRing.group_name == group_name)
        if created_at:
            query = query.filter(
                ovn_models.OVNHashRing.created_at != created_at)
        query.delete()
    msg = ('Nodes from host "%s" and group "%s" removed from the Hash Ring' %
           (CONF.host, group_name))
    if created_at:
        msg += ' created at %s' % str(created_at)
    LOG.info(msg)


@db_api.retry_if_session_inactive()
def remove_node_by_uuid(context, node_uuid):
    with db_api.CONTEXT_WRITER.using(context):
        context.session.query(ovn_models.OVNHashRing).filter(
            ovn_models.OVNHashRing.node_uuid == node_uuid).delete()
    LOG.info('Node "%s" removed from the Hash Ring', node_uuid)


@db_api.retry_if_session_inactive()
def cleanup_old_nodes(context, days):
    age = timeutils.utcnow() - datetime.timedelta(days=days)
    with db_api.CONTEXT_WRITER.using(context):
        context.session.query(ovn_models.OVNHashRing).filter(
            ovn_models.OVNHashRing.updated_at < age).delete()
    LOG.info('Cleaned up Hash Ring nodes older than %d days', days)


@db_api.retry_if_session_inactive()
def _touch(context, updated_at=None, **filter_args):
    if updated_at is None:
        updated_at = timeutils.utcnow()
    with db_api.CONTEXT_WRITER.using(context):
        context.session.query(ovn_models.OVNHashRing).filter_by(
            **filter_args).update({'updated_at': updated_at})


def touch_nodes_from_host(context, group_name):
    _touch(context, hostname=CONF.host, group_name=group_name)


def touch_node(context, node_uuid):
    _touch(context, node_uuid=node_uuid)


def _get_nodes_query(context, interval, group_name, offline=False,
                     from_host=False):
    limit = timeutils.utcnow() - datetime.timedelta(seconds=interval)
    query = context.session.query(ovn_models.OVNHashRing).filter(
        ovn_models.OVNHashRing.group_name == group_name)

    if offline:
        query = query.filter(ovn_models.OVNHashRing.updated_at < limit)
    else:
        query = query.filter(ovn_models.OVNHashRing.updated_at >= limit)

    if from_host:
        query = query.filter_by(hostname=CONF.host)

    return query


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_READER
def get_active_nodes(context, interval, group_name, from_host=False):
    query = _get_nodes_query(context, interval, group_name,
                             from_host=from_host)
    return query.all()


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_READER
def count_offline_nodes(context, interval, group_name):
    query = _get_nodes_query(context, interval, group_name, offline=True)
    return query.count()


@db_api.retry_if_session_inactive()
@db_api.CONTEXT_READER
def count_nodes_from_host(context, group_name):
    query = context.session.query(ovn_models.OVNHashRing).filter(
        ovn_models.OVNHashRing.group_name == group_name,
        ovn_models.OVNHashRing.hostname == CONF.host)
    return query.count()
