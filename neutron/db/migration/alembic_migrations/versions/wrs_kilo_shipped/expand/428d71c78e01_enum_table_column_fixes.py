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

"""enum table column fixes

Revision ID: 428d71c78e01
Revises: 5018b7ad4223
Create Date: 2014-12-26 12:34:34.210251

"""

# revision identifiers, used by Alembic.
revision = '428d71c78e01'
down_revision = '52eb37bd3d77'

from alembic import op
import sqlalchemy as sa


# The original havana based code used camel case for the enum names (e.g.,
# availabilityEnum, providerNetTypeEnum) and unfortunately postgres does not
# handle camel case well enough for the alembic enum code to work properly.
# This upgrade code renames the types to be lower case only.  Because of a
# different alembic issue the column type cannot be altered with simple
# alembic commands in a postgres environment so it is done with raw sql
# statements (see bug #89)
#
availability = sa.Enum('up', 'down',
                       name='availability_states')
providernet_type = sa.Enum('flat', 'vlan', 'vxlan', 'gre',
                           name='providernet_type')


def upgrade():
    context = op.get_context()
    if context.bind.dialect.name == 'postgresql':
        has_availability_states = context.bind.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_type "
            "WHERE typname='availability_states')").scalar()
        if not has_availability_states:
            op.execute("CREATE TYPE availability_states AS ENUM ('%s', '%s')"
                       % ('up', 'down'))
        op.execute("ALTER TABLE hosts"
                   " ALTER COLUMN availability TYPE availability_states"
                   " USING availability::text::availability_states")
    else:
        op.alter_column('hosts', 'availability', type_=availability)

    if context.bind.dialect.name == 'postgresql':
        has_providernet_types = context.bind.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_type "
            "WHERE typname='providernet_types')").scalar()
        if not has_providernet_types:
            op.execute("CREATE TYPE providernet_types AS "
                       "ENUM ('%s', '%s', '%s', '%s')"
                       % ('flat', 'vlan', 'vxlan', 'gre'))
        op.execute("ALTER TABLE providernets"
                   " ALTER COLUMN type TYPE providernet_types"
                   " USING type::text::providernet_types")
    else:
        op.alter_column('providernets', 'type',
                        type_=providernet_type)


def downgrade():
    # Since the columns are simply being renamed it is not necessary to
    # downgrade them back to the originals
    pass
