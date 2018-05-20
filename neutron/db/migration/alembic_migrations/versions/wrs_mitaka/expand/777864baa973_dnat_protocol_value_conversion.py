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

"""Port forwarding rule protocol conversion

Revision ID: 777864baa973
Revises: ca1fb1471d20
Create Date: 2016-05-30 00:00:01.000000

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = '777864baa973'
down_revision = 'ca1fb1471d20'


def upgrade():
    # The original feature code used 'udp-lite' as the user visible name of the
    # UDP Lite protocol.  At that time there was no upstream definition for
    # this protocol.  As of Liberty upstream now defines UDP lite as "udplite"
    # without a hyphen.  To align with them we need to reformat our data.
    op.execute(
        "UPDATE portforwardingrules "
        "SET protocol = 'udplite' "
        "WHERE protocol = 'udp-lite'")

    # The original feature code had a descrepancy between the DB model (which
    # has an index on tenant-id), and the DB migration code which did not have
    # an index defined.  Defining one now after the fact to avoid migration
    # warnings.
    op.create_index('ix_portforwardingrules_tenant_id',
                    'portforwardingrules', ['tenant_id'], unique=False)
