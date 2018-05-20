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
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

"""hosts table primary key fix

Revision ID: 52eb37bd3d77
Revises: juno
Create Date: 2014-12-26 12:15:51.341278

"""

from alembic import op
import sqlalchemy as sa

from neutron.db.migration import cli


# revision identifiers, used by Alembic.
revision = '52eb37bd3d77'
down_revision = 'kilo'
branch_labels = (cli.EXPAND_BRANCH,)


def upgrade():
    op.alter_column('hosts', 'id',
               existing_type=sa.VARCHAR(length=36),
               nullable=False)


def downgrade():
    op.alter_column('hosts', 'id',
               existing_type=sa.VARCHAR(length=36),
               nullable=True)
