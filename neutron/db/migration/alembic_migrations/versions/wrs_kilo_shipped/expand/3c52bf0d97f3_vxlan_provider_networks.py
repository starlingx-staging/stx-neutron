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

"""vxlan provider networks

Revision ID: 3c52bf0d97f3
Revises: 428d71c78e01
Create Date: 2015-02-11 17:14:05.190769

"""

# revision identifiers, used by Alembic.
revision = '3c52bf0d97f3'
down_revision = '10b1502ffd1c'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'wrs_vxlan_allocations',
        sa.Column('physical_network',
                  sa.String(length=64), nullable=False),
        sa.Column('vxlan_vni',
                  sa.Integer(), autoincrement=False, nullable=False),
        sa.Column('allocated',
                  sa.Boolean(), server_default='false', nullable=False),
        sa.PrimaryKeyConstraint('physical_network', 'vxlan_vni')
    )
    op.create_table(
        'providernet_range_vxlans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('group', sa.String(length=64), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('ttl', sa.Integer(), nullable=False),
        sa.Column('providernet_range_id',
                  sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['providernet_range_id'],
                                ['providernet_ranges.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.drop_table('providernet_vxlans')
