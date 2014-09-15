# Copyright 2014 OpenStack Foundation
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

"""havana_initial

Revision ID: havana
Revises: None

"""

# revision identifiers, used by Alembic.
revision = 'havana'
down_revision = None


from neutron.db.migration.alembic_migrations import agent_init_ops
from neutron.db.migration.alembic_migrations import brocade_init_ops
from neutron.db.migration.alembic_migrations import cisco_init_ops
from neutron.db.migration.alembic_migrations import core_init_ops
from neutron.db.migration.alembic_migrations import firewall_init_ops
from neutron.db.migration.alembic_migrations import l3_init_ops
from neutron.db.migration.alembic_migrations import lb_init_ops
from neutron.db.migration.alembic_migrations import loadbalancer_init_ops
from neutron.db.migration.alembic_migrations import metering_init_ops
from neutron.db.migration.alembic_migrations import ml2_init_ops
from neutron.db.migration.alembic_migrations import mlnx_init_ops
from neutron.db.migration.alembic_migrations import nec_init_ops
from neutron.db.migration.alembic_migrations import other_extensions_init_ops
from neutron.db.migration.alembic_migrations import other_plugins_init_ops
from neutron.db.migration.alembic_migrations import ovs_init_ops
from neutron.db.migration.alembic_migrations import portsec_init_ops
from neutron.db.migration.alembic_migrations import ryu_init_ops
from neutron.db.migration.alembic_migrations import secgroup_init_ops
from neutron.db.migration.alembic_migrations import vmware_init_ops
from neutron.db.migration.alembic_migrations import vpn_init_ops


def upgrade():
    agent_init_ops.upgrade()
    core_init_ops.upgrade()
    l3_init_ops.upgrade()
    secgroup_init_ops.upgrade()
    portsec_init_ops.upgrade()
    other_extensions_init_ops.upgrade()
    lb_init_ops.upgrade()
    ovs_init_ops.upgrade()
    ml2_init_ops.upgrade()
    firewall_init_ops.upgrade()
    loadbalancer_init_ops.upgrade()
    vpn_init_ops.upgrade()
    metering_init_ops.upgrade()
    brocade_init_ops.upgrade()
    cisco_init_ops.upgrade()
    mlnx_init_ops.upgrade()
    nec_init_ops.upgrade()
    other_plugins_init_ops.upgrade()
    ryu_init_ops.upgrade()
    vmware_init_ops.upgrade()


def downgrade():
    vmware_init_ops.downgrade()
    ryu_init_ops.downgrade()
    other_plugins_init_ops.downgrade()
    nec_init_ops.downgrade()
    mlnx_init_ops.downgrade()
    cisco_init_ops.downgrade()
    brocade_init_ops.downgrade()
    metering_init_ops.downgrade()
    vpn_init_ops.downgrade()
    loadbalancer_init_ops.downgrade()
    firewall_init_ops.downgrade()
    ovs_init_ops.downgrade()
    ml2_init_ops.downgrade()
    lb_init_ops.downgrade()
    other_extensions_init_ops.downgrade()
    portsec_init_ops.downgrade()
    secgroup_init_ops.downgrade()
    l3_init_ops.downgrade()
    core_init_ops.downgrade()
    agent_init_ops.downgrade()
