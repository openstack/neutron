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
from oslo_utils import timeutils
from oslo_utils import uuidutils

from neutron.db.models import ovn as ovn_models

CONF = cfg.CONF


# NOTE(ralonsoh): this was migrated from networking-ovn to neutron and should
#                 be refactored to be integrated in a OVO.
def add_node(context, group_name, node_uuid=None):
    if node_uuid is None:
        node_uuid = uuidutils.generate_uuid()

    with db_api.CONTEXT_WRITER.using(context):
        context.session.add(ovn_models.OVNHashRing(
            node_uuid=node_uuid, hostname=CONF.host, group_name=group_name))
    return node_uuid


def remove_nodes_from_host(context, group_name):
    with db_api.CONTEXT_WRITER.using(context):
        context.session.query(ovn_models.OVNHashRing).filter(
            ovn_models.OVNHashRing.hostname == CONF.host,
            ovn_models.OVNHashRing.group_name == group_name).delete()


def _touch(context, **filter_args):
    with db_api.CONTEXT_WRITER.using(context):
        context.session.query(ovn_models.OVNHashRing).filter_by(
            **filter_args).update({'updated_at': timeutils.utcnow()})


def touch_nodes_from_host(context, group_name):
    _touch(context, hostname=CONF.host, group_name=group_name)


def touch_node(context, node_uuid):
    _touch(context, node_uuid=node_uuid)


def get_active_nodes(context, interval, group_name, from_host=False):
    limit = timeutils.utcnow() - datetime.timedelta(seconds=interval)
    with db_api.CONTEXT_READER.using(context):
        query = context.session.query(ovn_models.OVNHashRing).filter(
            ovn_models.OVNHashRing.updated_at >= limit,
            ovn_models.OVNHashRing.group_name == group_name)
        if from_host:
            query = query.filter_by(hostname=CONF.host)
        return query.all()
