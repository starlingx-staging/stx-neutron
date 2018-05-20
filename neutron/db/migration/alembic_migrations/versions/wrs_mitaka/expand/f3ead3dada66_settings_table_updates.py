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

"""Settings table updates

Revision ID: f3ead3dada66
Revises: 0e66c5227a8a
Create Date: 2016-05-30 00:00:01.000000

"""

#from alembic import op


# revision identifiers, used by Alembic.
revision = 'f3ead3dada66'
down_revision = '0e66c5227a8a'


def upgrade():
    # The original feature code had a descrepancy between the DB model (which
    # has an index on tenant-id), and the DB migration code which did not have
    # an index defined.  Defining one now after the fact to avoid migration
    # warnings.
    #
    # FIXME(alegacy): For some reason the database coming from 15.12 already
    # has this index created.  It did not exist when the tenant settings code
    # was ported and tested for the Mitaka rebase and so the database migration
    # check code reported a warning saying that the DB schema was inconsistent
    # when compared to the current codebase.  It is possible that the index
    # gets auto-created at runtime based on demand and that the environment
    # used in the rebase just hadn't reached that point yet.  Not sure.
    #
    # Temporarily removing this for now until we can determine if it is at all
    # needed.
    #
    # op.create_index('ix_settings_tenant_id',
    #                 'settings', ['tenant_id'], unique=False)
    return
