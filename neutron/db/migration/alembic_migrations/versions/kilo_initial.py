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

"""kilo_initial

Revision ID: kilo
Revises: None

"""

# revision identifiers, used by Alembic.
revision = 'kilo'
down_revision = None


from neutron.db import migration
from neutron.db.migration.alembic_migrations import agent_init_ops
from neutron.db.migration.alembic_migrations import brocade_init_ops
from neutron.db.migration.alembic_migrations import cisco_init_ops
from neutron.db.migration.alembic_migrations import core_init_ops
from neutron.db.migration.alembic_migrations import dvr_init_opts
from neutron.db.migration.alembic_migrations import firewall_init_ops
from neutron.db.migration.alembic_migrations import l3_init_ops
from neutron.db.migration.alembic_migrations import lb_init_ops
from neutron.db.migration.alembic_migrations import loadbalancer_init_ops
from neutron.db.migration.alembic_migrations import metering_init_ops
from neutron.db.migration.alembic_migrations import ml2_init_ops
from neutron.db.migration.alembic_migrations import nec_init_ops
from neutron.db.migration.alembic_migrations import nsxv_initial_opts
from neutron.db.migration.alembic_migrations import nuage_init_opts
from neutron.db.migration.alembic_migrations import other_extensions_init_ops
from neutron.db.migration.alembic_migrations import other_plugins_init_ops
from neutron.db.migration.alembic_migrations import ovs_init_ops
from neutron.db.migration.alembic_migrations import portsec_init_ops
from neutron.db.migration.alembic_migrations import secgroup_init_ops
from neutron.db.migration.alembic_migrations import vmware_init_ops
from neutron.db.migration.alembic_migrations import vpn_init_ops


def upgrade():
    migration.pk_on_alembic_version_table()
    agent_init_ops.upgrade()
    core_init_ops.upgrade()
    l3_init_ops.upgrade()
    secgroup_init_ops.upgrade()
    portsec_init_ops.upgrade()
    other_extensions_init_ops.upgrade()
    lb_init_ops.upgrade()
    ovs_init_ops.upgrade()
    ml2_init_ops.upgrade()
    dvr_init_opts.upgrade()
    firewall_init_ops.upgrade()
    loadbalancer_init_ops.upgrade()
    vpn_init_ops.upgrade()
    metering_init_ops.upgrade()
    brocade_init_ops.upgrade()
    cisco_init_ops.upgrade()
    nec_init_ops.upgrade()
    other_plugins_init_ops.upgrade()
    vmware_init_ops.upgrade()
    nuage_init_opts.upgrade()
    nsxv_initial_opts.upgrade()
