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

"""Provider network table updates

Revision ID: ca1fb1471d20
Revises: f3ead3dada66
Create Date: 2016-05-30 00:00:01.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ca1fb1471d20'
down_revision = 'f3ead3dada66'


def upgrade():
    # The original feature code specified the NULL constraint differently on
    # the DB migration and DB model definitions.
    op.alter_column('providernets', 'vlan_transparent',
                    existing_type=sa.Boolean(), nullable=False)

    # The original feature code had a descrepancy between the DB model (which
    # has an index on tenant-id), and the DB migration code which did not have
    # an index defined.  Defining one now after the fact to avoid migration
    # warnings.
    op.create_index('ix_providernet_ranges_tenant_id',
                    'providernet_ranges', ['tenant_id'], unique=False)
