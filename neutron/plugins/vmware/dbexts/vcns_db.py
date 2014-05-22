# Copyright 2013 VMware, Inc.
#
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

from sqlalchemy.orm import exc

from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.dbexts import vcns_models
from neutron.plugins.vmware.vshield.common import (
    exceptions as vcns_exc)

LOG = logging.getLogger(__name__)


def add_vcns_router_binding(session, router_id, vse_id, lswitch_id, status):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsRouterBinding(
            router_id=router_id,
            edge_id=vse_id,
            lswitch_id=lswitch_id,
            status=status)
        session.add(binding)
        return binding


def get_vcns_router_binding(session, router_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsRouterBinding).
                filter_by(router_id=router_id).first())


def update_vcns_router_binding(session, router_id, **kwargs):
    with session.begin(subtransactions=True):
        binding = (session.query(vcns_models.VcnsRouterBinding).
                   filter_by(router_id=router_id).one())
        for key, value in kwargs.iteritems():
            binding[key] = value


def delete_vcns_router_binding(session, router_id):
    with session.begin(subtransactions=True):
        binding = (session.query(vcns_models.VcnsRouterBinding).
                   filter_by(router_id=router_id).one())
        session.delete(binding)


#
# Edge Firewall binding methods
#
def add_vcns_edge_firewallrule_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeFirewallRuleBinding(
            rule_id=map_info['rule_id'],
            rule_vseid=map_info['rule_vseid'],
            edge_id=map_info['edge_id'])
        session.add(binding)
        return binding


def delete_vcns_edge_firewallrule_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        if not (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                filter_by(rule_id=id, edge_id=edge_id).delete()):
            msg = _("Rule Resource binding with id:%s not found!") % id
            raise nsx_exc.NsxPluginException(err_msg=msg)


def get_vcns_edge_firewallrule_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                filter_by(rule_id=id, edge_id=edge_id).first())


def get_vcns_edge_firewallrule_binding_by_vseid(
        session, edge_id, rule_vseid):
    with session.begin(subtransactions=True):
        try:
            return (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                    filter_by(edge_id=edge_id, rule_vseid=rule_vseid).one())
        except exc.NoResultFound:
            msg = _("Rule Resource binding not found!")
            raise nsx_exc.NsxPluginException(err_msg=msg)


def cleanup_vcns_edge_firewallrule_binding(session, edge_id):
    with session.begin(subtransactions=True):
        session.query(
            vcns_models.VcnsEdgeFirewallRuleBinding).filter_by(
                edge_id=edge_id).delete()


def add_vcns_edge_vip_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeVipBinding(
            vip_id=map_info['vip_id'],
            edge_id=map_info['edge_id'],
            vip_vseid=map_info['vip_vseid'],
            app_profileid=map_info['app_profileid'])
        session.add(binding)

    return binding


def get_vcns_edge_vip_binding(session, id):
    with session.begin(subtransactions=True):
        try:
            qry = session.query(vcns_models.VcnsEdgeVipBinding)
            return qry.filter_by(vip_id=id).one()
        except exc.NoResultFound:
            msg = _("VIP Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise vcns_exc.VcnsNotFound(
                resource='router_service_binding', msg=msg)


def delete_vcns_edge_vip_binding(session, id):
    with session.begin(subtransactions=True):
        qry = session.query(vcns_models.VcnsEdgeVipBinding)
        if not qry.filter_by(vip_id=id).delete():
            msg = _("VIP Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)


def add_vcns_edge_pool_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgePoolBinding(
            pool_id=map_info['pool_id'],
            edge_id=map_info['edge_id'],
            pool_vseid=map_info['pool_vseid'])
        session.add(binding)

    return binding


def get_vcns_edge_pool_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsEdgePoolBinding).
                filter_by(pool_id=id, edge_id=edge_id).first())


def get_vcns_edge_pool_binding_by_vseid(session, edge_id, pool_vseid):
    with session.begin(subtransactions=True):
        try:
            qry = session.query(vcns_models.VcnsEdgePoolBinding)
            binding = qry.filter_by(edge_id=edge_id,
                                    pool_vseid=pool_vseid).one()
        except exc.NoResultFound:
            msg = (_("Pool Resource binding with edge_id:%(edge_id)s "
                     "pool_vseid:%(pool_vseid)s not found!") %
                   {'edge_id': edge_id, 'pool_vseid': pool_vseid})
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)
        return binding


def delete_vcns_edge_pool_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        qry = session.query(vcns_models.VcnsEdgePoolBinding)
        if not qry.filter_by(pool_id=id, edge_id=edge_id).delete():
            msg = _("Pool Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)


def add_vcns_edge_monitor_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeMonitorBinding(
            monitor_id=map_info['monitor_id'],
            edge_id=map_info['edge_id'],
            monitor_vseid=map_info['monitor_vseid'])
        session.add(binding)

    return binding


def get_vcns_edge_monitor_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        return (session.query(vcns_models.VcnsEdgeMonitorBinding).
                filter_by(monitor_id=id, edge_id=edge_id).first())


def delete_vcns_edge_monitor_binding(session, id, edge_id):
    with session.begin(subtransactions=True):
        qry = session.query(vcns_models.VcnsEdgeMonitorBinding)
        if not qry.filter_by(monitor_id=id, edge_id=edge_id).delete():
            msg = _("Monitor Resource binding with id:%s not found!") % id
            LOG.exception(msg)
            raise nsx_exc.NsxPluginException(err_msg=msg)
