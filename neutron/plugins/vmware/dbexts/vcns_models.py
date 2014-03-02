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


import sqlalchemy as sa

from neutron.db import model_base
from neutron.db import models_v2


class VcnsRouterBinding(model_base.BASEV2, models_v2.HasStatusDescription):
    """Represents the mapping between neutron router and vShield Edge."""

    __tablename__ = 'vcns_router_bindings'

    # no ForeignKey to routers.id because for now, a router can be removed
    # from routers when delete_router is executed, but the binding is only
    # removed after the Edge is deleted
    router_id = sa.Column(sa.String(36),
                          primary_key=True)
    edge_id = sa.Column(sa.String(16),
                        nullable=True)
    lswitch_id = sa.Column(sa.String(36),
                           nullable=False)


#
# VCNS Edge FW mapping tables
#
class VcnsEdgeFirewallRuleBinding(model_base.BASEV2):
    """1:1 mapping between firewall rule and edge firewall rule_id."""

    __tablename__ = 'vcns_firewall_rule_bindings'

    rule_id = sa.Column(sa.String(36),
                        sa.ForeignKey("firewall_rules.id"),
                        primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    rule_vseid = sa.Column(sa.String(36))


class VcnsEdgePoolBinding(model_base.BASEV2):
    """Represents the mapping between neutron pool and Edge pool."""

    __tablename__ = 'vcns_edge_pool_bindings'

    pool_id = sa.Column(sa.String(36),
                        sa.ForeignKey("pools.id", ondelete="CASCADE"),
                        primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    pool_vseid = sa.Column(sa.String(36))


class VcnsEdgeVipBinding(model_base.BASEV2):
    """Represents the mapping between neutron vip and Edge vip."""

    __tablename__ = 'vcns_edge_vip_bindings'

    vip_id = sa.Column(sa.String(36),
                       sa.ForeignKey("vips.id", ondelete="CASCADE"),
                       primary_key=True)
    edge_id = sa.Column(sa.String(36))
    vip_vseid = sa.Column(sa.String(36))
    app_profileid = sa.Column(sa.String(36))


class VcnsEdgeMonitorBinding(model_base.BASEV2):
    """Represents the mapping between neutron monitor and Edge monitor."""

    __tablename__ = 'vcns_edge_monitor_bindings'

    monitor_id = sa.Column(sa.String(36),
                           sa.ForeignKey("healthmonitors.id",
                                         ondelete="CASCADE"),
                           primary_key=True)
    edge_id = sa.Column(sa.String(36), primary_key=True)
    monitor_vseid = sa.Column(sa.String(36))
