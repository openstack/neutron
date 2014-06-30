# Copyright 2014 VMware, Inc.
#
# All Rights Reserved
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

from oslo.db import exception as d_exc
from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import orm
from sqlalchemy import String

from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import exceptions as p_exc


LOG = logging.getLogger(__name__)


class LsnPort(models_v2.model_base.BASEV2):

    __tablename__ = 'lsn_port'

    lsn_port_id = Column(String(36), primary_key=True)

    lsn_id = Column(String(36), ForeignKey('lsn.lsn_id', ondelete="CASCADE"),
                    nullable=False)
    sub_id = Column(String(36), nullable=False, unique=True)
    mac_addr = Column(String(32), nullable=False, unique=True)

    def __init__(self, lsn_port_id, subnet_id, mac_address, lsn_id):
        self.lsn_port_id = lsn_port_id
        self.lsn_id = lsn_id
        self.sub_id = subnet_id
        self.mac_addr = mac_address


class Lsn(models_v2.model_base.BASEV2):
    __tablename__ = 'lsn'

    lsn_id = Column(String(36), primary_key=True)
    net_id = Column(String(36), nullable=False)

    def __init__(self, net_id, lsn_id):
        self.net_id = net_id
        self.lsn_id = lsn_id


def lsn_add(context, network_id, lsn_id):
    """Add Logical Service Node information to persistent datastore."""
    with context.session.begin(subtransactions=True):
        lsn = Lsn(network_id, lsn_id)
        context.session.add(lsn)


def lsn_remove(context, lsn_id):
    """Remove Logical Service Node information from datastore given its id."""
    with context.session.begin(subtransactions=True):
        context.session.query(Lsn).filter_by(lsn_id=lsn_id).delete()


def lsn_remove_for_network(context, network_id):
    """Remove information about the Logical Service Node given its network."""
    with context.session.begin(subtransactions=True):
        context.session.query(Lsn).filter_by(net_id=network_id).delete()


def lsn_get_for_network(context, network_id, raise_on_err=True):
    """Retrieve LSN information given its network id."""
    query = context.session.query(Lsn)
    try:
        return query.filter_by(net_id=network_id).one()
    except (orm.exc.NoResultFound, d_exc.DBError):
        logger = raise_on_err and LOG.error or LOG.warn
        logger(_('Unable to find Logical Service Node for '
                 'network %s'), network_id)
        if raise_on_err:
            raise p_exc.LsnNotFound(entity='network',
                                    entity_id=network_id)


def lsn_port_add_for_lsn(context, lsn_port_id, subnet_id, mac, lsn_id):
    """Add Logical Service Node Port information to persistent datastore."""
    with context.session.begin(subtransactions=True):
        lsn_port = LsnPort(lsn_port_id, subnet_id, mac, lsn_id)
        context.session.add(lsn_port)


def lsn_port_get_for_subnet(context, subnet_id, raise_on_err=True):
    """Return Logical Service Node Port information given its subnet id."""
    with context.session.begin(subtransactions=True):
        try:
            return (context.session.query(LsnPort).
                    filter_by(sub_id=subnet_id).one())
        except (orm.exc.NoResultFound, d_exc.DBError):
            if raise_on_err:
                raise p_exc.LsnPortNotFound(lsn_id=None,
                                            entity='subnet',
                                            entity_id=subnet_id)


def lsn_port_get_for_mac(context, mac_address, raise_on_err=True):
    """Return Logical Service Node Port information given its mac address."""
    with context.session.begin(subtransactions=True):
        try:
            return (context.session.query(LsnPort).
                    filter_by(mac_addr=mac_address).one())
        except (orm.exc.NoResultFound, d_exc.DBError):
            if raise_on_err:
                raise p_exc.LsnPortNotFound(lsn_id=None,
                                            entity='mac',
                                            entity_id=mac_address)


def lsn_port_remove(context, lsn_port_id):
    """Remove Logical Service Node port from the given Logical Service Node."""
    with context.session.begin(subtransactions=True):
        (context.session.query(LsnPort).
         filter_by(lsn_port_id=lsn_port_id).delete())
