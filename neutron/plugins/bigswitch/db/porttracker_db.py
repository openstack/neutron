# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013, Big Switch Networks
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

import sqlalchemy as sa

from neutron.api.v2 import attributes
from neutron.db import model_base
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class PortLocation(model_base.BASEV2):
    port_id = sa.Column(sa.String(255), primary_key=True)
    host_id = sa.Column(sa.String(255), nullable=False)


def get_port_hostid(context, port_id):
    with context.session.begin(subtransactions=True):
        query = context.session.query(PortLocation)
        res = query.filter_by(port_id=port_id).first()
    if not res:
        return False
    return res.host_id


def put_port_hostid(context, port_id, host_id):
    if not attributes.is_attr_set(host_id):
        LOG.warning(_("No host_id in port request to track port location."))
        return
    if port_id == '':
        LOG.warning(_("Received an empty port ID for host '%s'"), host_id)
        return
    with context.session.begin(subtransactions=True):
        location = PortLocation(port_id=port_id, host_id=host_id)
        context.session.add(location)
