# Copyright 2012 Isaku Yamahata <yamahata at private email ne jp>
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

from sqlalchemy import exc as sa_exc
from sqlalchemy import func
from sqlalchemy.orm import exc as orm_exc

from neutron.common import exceptions as n_exc
import neutron.db.api as db
from neutron.db import models_v2
from neutron.db import securitygroups_db as sg_db
from neutron.extensions import securitygroup as ext_sg
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.ryu.db import models_v2 as ryu_models_v2


LOG = logging.getLogger(__name__)


def network_all_tenant_list():
    session = db.get_session()
    return session.query(models_v2.Network).all()


def get_port_from_device(port_id):
    LOG.debug(_("get_port_from_device() called:port_id=%s"), port_id)
    session = db.get_session()
    sg_binding_port = sg_db.SecurityGroupPortBinding.port_id

    query = session.query(models_v2.Port,
                          sg_db.SecurityGroupPortBinding.security_group_id)
    query = query.outerjoin(sg_db.SecurityGroupPortBinding,
                            models_v2.Port.id == sg_binding_port)
    query = query.filter(models_v2.Port.id == port_id)
    port_and_sgs = query.all()
    if not port_and_sgs:
        return None
    port = port_and_sgs[0][0]
    plugin = manager.NeutronManager.get_plugin()
    port_dict = plugin._make_port_dict(port)
    port_dict[ext_sg.SECURITYGROUPS] = [
        sg_id for port_, sg_id in port_and_sgs if sg_id]
    port_dict['security_group_rules'] = []
    port_dict['security_group_source_groups'] = []
    port_dict['fixed_ips'] = [ip['ip_address'] for ip in port['fixed_ips']]
    return port_dict


class TunnelKey(object):
    # VLAN: 12 bits
    # GRE, VXLAN: 24bits
    # TODO(yamahata): STT: 64bits
    _KEY_MIN_HARD = 1
    _KEY_MAX_HARD = 0xffffffff

    def __init__(self, key_min=_KEY_MIN_HARD, key_max=_KEY_MAX_HARD):
        self.key_min = key_min
        self.key_max = key_max

        if (key_min < self._KEY_MIN_HARD or key_max > self._KEY_MAX_HARD or
                key_min > key_max):
            raise ValueError(_('Invalid tunnel key options '
                               'tunnel_key_min: %(key_min)d '
                               'tunnel_key_max: %(key_max)d. '
                               'Using default value') % {'key_min': key_min,
                                                         'key_max': key_max})

    def _last_key(self, session):
        try:
            return session.query(ryu_models_v2.TunnelKeyLast).one()
        except orm_exc.MultipleResultsFound:
            max_key = session.query(
                func.max(ryu_models_v2.TunnelKeyLast.last_key))
            if max_key > self.key_max:
                max_key = self.key_min

            session.query(ryu_models_v2.TunnelKeyLast).delete()
            last_key = ryu_models_v2.TunnelKeyLast(last_key=max_key)
        except orm_exc.NoResultFound:
            last_key = ryu_models_v2.TunnelKeyLast(last_key=self.key_min)

        session.add(last_key)
        session.flush()
        return session.query(ryu_models_v2.TunnelKeyLast).one()

    def _find_key(self, session, last_key):
        """Try to find unused tunnel key.

        Trying to find unused tunnel key in TunnelKey table starting
        from last_key + 1.
        When all keys are used, raise sqlalchemy.orm.exc.NoResultFound
        """
        # key 0 is used for special meanings. So don't allocate 0.

        # sqlite doesn't support
        # '(select order by limit) union all (select order by limit) '
        # 'order by limit'
        # So do it manually
        # new_key = session.query("new_key").from_statement(
        #     # If last_key + 1 isn't used, it's the result
        #     'SELECT new_key '
        #     'FROM (SELECT :last_key + 1 AS new_key) q1 '
        #     'WHERE NOT EXISTS '
        #     '(SELECT 1 FROM tunnelkeys WHERE tunnel_key = :last_key + 1) '
        #
        #     'UNION ALL '
        #
        #     # if last_key + 1 used,
        #     # find the least unused key from last_key + 1
        #     '(SELECT t.tunnel_key + 1 AS new_key '
        #     'FROM tunnelkeys t '
        #     'WHERE NOT EXISTS '
        #     '(SELECT 1 FROM tunnelkeys ti '
        #     ' WHERE ti.tunnel_key = t.tunnel_key + 1) '
        #     'AND t.tunnel_key >= :last_key '
        #     'ORDER BY new_key LIMIT 1) '
        #
        #     'ORDER BY new_key LIMIT 1'
        # ).params(last_key=last_key).one()
        try:
            new_key = session.query("new_key").from_statement(
                # If last_key + 1 isn't used, it's the result
                'SELECT new_key '
                'FROM (SELECT :last_key + 1 AS new_key) q1 '
                'WHERE NOT EXISTS '
                '(SELECT 1 FROM tunnelkeys WHERE tunnel_key = :last_key + 1) '
            ).params(last_key=last_key).one()
        except orm_exc.NoResultFound:
            new_key = session.query("new_key").from_statement(
                # if last_key + 1 used,
                # find the least unused key from last_key + 1
                '(SELECT t.tunnel_key + 1 AS new_key '
                'FROM tunnelkeys t '
                'WHERE NOT EXISTS '
                '(SELECT 1 FROM tunnelkeys ti '
                ' WHERE ti.tunnel_key = t.tunnel_key + 1) '
                'AND t.tunnel_key >= :last_key '
                'ORDER BY new_key LIMIT 1) '
            ).params(last_key=last_key).one()

        new_key = new_key[0]  # the result is tuple.
        LOG.debug(_("last_key %(last_key)s new_key %(new_key)s"),
                  {'last_key': last_key, 'new_key': new_key})
        if new_key > self.key_max:
            LOG.debug(_("No key found"))
            raise orm_exc.NoResultFound()
        return new_key

    def _allocate(self, session, network_id):
        last_key = self._last_key(session)
        try:
            new_key = self._find_key(session, last_key.last_key)
        except orm_exc.NoResultFound:
            new_key = self._find_key(session, self.key_min)

        tunnel_key = ryu_models_v2.TunnelKey(network_id=network_id,
                                             tunnel_key=new_key)
        last_key.last_key = new_key
        session.add(tunnel_key)
        return new_key

    _TRANSACTION_RETRY_MAX = 16

    def allocate(self, session, network_id):
        count = 0
        while True:
            session.begin(subtransactions=True)
            try:
                new_key = self._allocate(session, network_id)
                session.commit()
                break
            except sa_exc.SQLAlchemyError:
                session.rollback()

            count += 1
            if count > self._TRANSACTION_RETRY_MAX:
                # if this happens too often, increase _TRANSACTION_RETRY_MAX
                LOG.warn(_("Transaction retry exhausted (%d). "
                           "Abandoned tunnel key allocation."), count)
                raise n_exc.ResourceExhausted()

        return new_key

    def delete(self, session, network_id):
        session.query(ryu_models_v2.TunnelKey).filter_by(
            network_id=network_id).delete()
        session.flush()

    def all_list(self):
        session = db.get_session()
        return session.query(ryu_models_v2.TunnelKey).all()


def set_port_status(session, port_id, status):
    try:
        port = session.query(models_v2.Port).filter_by(id=port_id).one()
        port['status'] = status
        session.merge(port)
        session.flush()
    except orm_exc.NoResultFound:
        raise n_exc.PortNotFound(port_id=port_id)
