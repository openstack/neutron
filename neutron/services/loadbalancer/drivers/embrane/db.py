# Copyright 2014 Embrane, Inc.
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

from neutron.db import models_v2 as nmodel
from neutron.services.loadbalancer.drivers.embrane import models


def add_pool_port(context, pool_id, port_id):
    session = context.session
    with session.begin(subtransactions=True):
        pool_port = models.PoolPort()
        pool_port.pool_id = pool_id
        pool_port.port_id = port_id
        session.add(pool_port)


def get_pool_port(context, pool_id):
    return (context.session.query(models.PoolPort).filter_by(pool_id=pool_id).
            first())


def delete_pool_backend(context, pool_id):
    session = context.session
    backend = (session.query(models.PoolPort).filter_by(
        pool_id=pool_id))
    for b in backend:
        delete_pool_port(context, b)


def delete_pool_port(context, backend_port):
    session = context.session
    with session.begin(subtransactions=True):
        port = (session.query(nmodel.Port).filter_by(
            id=backend_port['port_id'])).first()
        if port:
            session.delete(backend_port)
            session.delete(port)
