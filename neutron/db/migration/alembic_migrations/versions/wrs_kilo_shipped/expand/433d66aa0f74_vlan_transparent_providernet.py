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

"""vlan_transparent_providernet

Revision ID: 433d66aa0f74
Revises: 5018b7ad4223
Create Date: 2015-07-15 20:31:21.124839

"""

# revision identifiers, used by Alembic.
revision = '433d66aa0f74'
down_revision = '5018b7ad4223'


from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('providernets',
                  sa.Column('vlan_transparent', sa.Boolean(), nullable=True,
                            default=False, server_default=sa.sql.false()))


def downgrade():
    op.drop_column('providernets', 'vlan_transparent')
