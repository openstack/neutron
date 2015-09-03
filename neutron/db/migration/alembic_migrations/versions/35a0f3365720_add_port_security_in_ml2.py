# Copyright 2015 OpenStack Foundation
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

"""add port-security in ml2

Revision ID: 35a0f3365720
Revises: 341ee8a4ccb5
Create Date: 2014-09-30 09:41:14.146519

"""

# revision identifiers, used by Alembic.
revision = '35a0f3365720'
down_revision = '341ee8a4ccb5'

from alembic import op


def upgrade():
    context = op.get_context()

    if context.bind.dialect.name == 'ibm_db_sa':
        # NOTE(junxie): DB2 stores booleans as 0 and 1.
        op.execute('INSERT INTO networksecuritybindings (network_id, '
                   'port_security_enabled) SELECT id, 1 FROM networks '
                   'WHERE id NOT IN (SELECT network_id FROM '
                   'networksecuritybindings);')

        op.execute('INSERT INTO portsecuritybindings (port_id, '
                   'port_security_enabled) SELECT id, 1 FROM ports '
                   'WHERE id NOT IN (SELECT port_id FROM '
                   'portsecuritybindings);')
    else:
        op.execute('INSERT INTO networksecuritybindings (network_id, '
                   'port_security_enabled) SELECT id, True FROM networks '
                   'WHERE id NOT IN (SELECT network_id FROM '
                   'networksecuritybindings);')

        op.execute('INSERT INTO portsecuritybindings (port_id, '
                   'port_security_enabled) SELECT id, True FROM ports '
                   'WHERE id NOT IN (SELECT port_id FROM '
                   'portsecuritybindings);')
