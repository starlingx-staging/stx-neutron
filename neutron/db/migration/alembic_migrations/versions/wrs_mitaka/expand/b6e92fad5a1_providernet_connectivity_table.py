# Copyright 2016 OpenStack Foundation
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
# Copyright (c) 2016 Wind River Systems, Inc.
#

"""Providernet connectivity table

Revision ID: b6e92fad5a1
Revises: 777864baa973
Create Date: 2016-02-23 17:26:15.718638

"""

# revision identifiers, used by Alembic.
revision = 'b6e92fad5a1'
down_revision = '777864baa973'

from alembic import op
from neutron.common import constants
import sqlalchemy as sa


providernet_connectivity_state = sa.Enum(
    constants.PROVIDERNET_CONNECTIVITY_UNKNOWN,
    constants.PROVIDERNET_CONNECTIVITY_PASS,
    constants.PROVIDERNET_CONNECTIVITY_FAIL,
    name='providernet_connectivity_state_enum'
)


def upgrade():
    op.create_table(
        'providernet_connectivity_states',
        sa.Column('host_id', sa.String(36), nullable=False),
        sa.Column('providernet_id', sa.String(36), nullable=False),
        sa.Column('segmentation_id', sa.String(36),
                  autoincrement=False, nullable=False),
        sa.Column('master_host_id', sa.String(36), nullable=False),
        sa.Column('test_details', sa.String(255), nullable=True),
        sa.Column('master_connectivity_state', providernet_connectivity_state,
                  nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
        sa.Column('audit_uuid', sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['providernet_id'], ['providernets.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['master_host_id'], ['hosts.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('host_id', 'providernet_id',
                                'segmentation_id', 'master_host_id'))


def downgrade():
    op.drop_table('providernet_connectivity_states')
