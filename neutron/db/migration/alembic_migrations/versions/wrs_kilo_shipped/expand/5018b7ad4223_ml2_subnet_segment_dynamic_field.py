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
#
# Copyright (c) 2015 Wind River Systems, Inc.
#

"""ml2 subnet segment new kilo fields

Revision ID: 5018b7ad4223
Revises: 52eb37bd3d77
Create Date: 2015-07-02 12:15:51.341278

"""

# revision identifiers, used by Alembic.
revision = '5018b7ad4223'
down_revision = '230661bb0d02'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'ml2_subnet_segments',
        sa.Column('is_dynamic',
                  sa.Boolean(), server_default='false', nullable=False))
    op.add_column(
        'ml2_subnet_segments',
        sa.Column('segment_index', sa.Integer(), nullable=False,
                  server_default='0'))


def downgrade():
    op.drop_column('ml2_subnet_segments', 'is_dynamic')
    op.drop_column('ml2_subnet_segments', 'segment_index')
