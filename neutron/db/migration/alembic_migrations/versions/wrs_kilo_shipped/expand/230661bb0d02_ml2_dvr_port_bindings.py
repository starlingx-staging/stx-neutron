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

"""ml2_dvr_port_bindings

Revision ID: 230661bb0d02
Revises: 10b1502ffd1c
Create Date: 2015-03-17 20:31:21.124839

"""

# revision identifiers, used by Alembic.
revision = '230661bb0d02'
down_revision = '3c52bf0d97f3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('ml2_dvr_port_bindings',
                  sa.Column('mac_filtering', sa.Boolean(), nullable=True))
    op.add_column('ml2_dvr_port_bindings',
                  sa.Column('mtu', sa.Integer(), nullable=True))
    op.add_column('ml2_dvr_port_bindings',
                  sa.Column('vif_model', sa.String(length=255), nullable=True))


def downgrade():
    op.drop_column('ml2_dvr_port_bindings', 'vif_model')
    op.drop_column('ml2_dvr_port_bindings', 'mtu')
    op.drop_column('ml2_dvr_port_bindings', 'mac_filtering')
