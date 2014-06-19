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

from neutron.api.v2 import attributes
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def get_port_hostid(context, port_id):
    # REVISIT(kevinbenton): this is a workaround to avoid portbindings_db
    # relational table generation until one of the functions is called.
    from neutron.db import portbindings_db
    with context.session.begin(subtransactions=True):
        query = context.session.query(portbindings_db.PortBindingPort)
        res = query.filter_by(port_id=port_id).first()
    if not res:
        return False
    return res.host


def put_port_hostid(context, port_id, host):
    # REVISIT(kevinbenton): this is a workaround to avoid portbindings_db
    # relational table generation until one of the functions is called.
    from neutron.db import portbindings_db
    if not attributes.is_attr_set(host):
        LOG.warning(_("No host_id in port request to track port location."))
        return
    if port_id == '':
        LOG.warning(_("Received an empty port ID for host_id '%s'"), host)
        return
    if host == '':
        LOG.debug(_("Received an empty host_id for port '%s'"), port_id)
        return
    LOG.debug(_("Logging port %(port)s on host_id %(host)s"),
              {'port': port_id, 'host': host})
    with context.session.begin(subtransactions=True):
        location = portbindings_db.PortBindingPort(port_id=port_id, host=host)
        context.session.merge(location)
