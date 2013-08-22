# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Nicira, Inc.
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

from neutron.plugins.nicira.common import exceptions as nvp_exc
from neutron.plugins.nicira.dbexts import vcns_models


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
def add_vcns_edge_firewallrule_binding(session, map_info):
    with session.begin(subtransactions=True):
        binding = vcns_models.VcnsEdgeFirewallRuleBinding(
            rule_id=map_info['rule_id'],
            rule_vseid=map_info['rule_vseid'],
            edge_id=map_info['edge_id'])
        session.add(binding)
        return binding


def delete_vcns_edge_firewallrule_binding(session, id):
    with session.begin(subtransactions=True):
        if not (session.query(vcns_models.VcnsEdgeFirewallRuleBinding).
                filter_by(rule_id=id).delete()):
            msg = _("Rule Resource binding with id:%s not found!") % id
            raise nvp_exc.NvpServicePluginException(err_msg=msg)


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
            raise nvp_exc.NvpServicePluginException(err_msg=msg)


def cleanup_vcns_edge_firewallrule_binding(session, edge_id):
    with session.begin(subtransactions=True):
        session.query(
            vcns_models.VcnsEdgeFirewallRuleBinding).filter_by(
                edge_id=edge_id).delete()
