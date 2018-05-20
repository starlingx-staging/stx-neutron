# Copyright 2017 OpenStack Foundation
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

"""vxlan mode column

Revision ID: wrs_11a84c4cea76
Revises: 7d32f979895f
Create Date: 2015-07-15 20:31:21.124839

"""

# revision identifiers, used by Alembic.
revision = 'wrs_11a84c4cea76'
down_revision = '7d32f979895f'


from alembic import op
from neutron.common import constants as n_const
import sqlalchemy as sa


def upgrade():
    op.add_column('providernet_range_vxlans',
                  sa.Column('mode', sa.String(8), nullable=False,
                            default=n_const.PROVIDERNET_VXLAN_DYNAMIC,
                            server_default=n_const.PROVIDERNET_VXLAN_DYNAMIC))
    op.alter_column('providernet_range_vxlans', 'group', nullable=True)
