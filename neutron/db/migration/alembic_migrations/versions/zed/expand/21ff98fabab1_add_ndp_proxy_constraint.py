# Copyright 2022 OpenStack Foundation
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

from alembic import op


"""add ndp proxy constraint

Revision ID: 21ff98fabab1
Revises: 659cbedf30a1
Create Date: 2022-05-22 14:16:24.550155

"""

# revision identifiers, used by Alembic.
revision = '21ff98fabab1'
down_revision = '659cbedf30a1'


def upgrade():
    op.create_unique_constraint(
        'uniq_ndp_proxy0router_id0ip_address',
        'ndp_proxies',
        ['router_id', 'ip_address']
    )
