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
# Copyright (c) 2016 Wind River Systems, Inc.
#

"""WRS QoS table renaming

Revision ID: 41038c0cd102
Revises: wrs_kilo_shipped
Create Date: 2016-05-27 00:00:01.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '41038c0cd102'
down_revision = 'wrs_kilo_shipped'


# NOTE(alegacy): The original Quality of Service feature was introduced by
# WRS in Havana/Juno.  At that time it was derived based on upstream content
# but it used the same table names.  Now that the QoS feature has been
# officially added to the neutron project we have table conflicts that need to
# be resolved before we can run the upgrade scripts for Liberty.  Otherwise, we
# will collide on the table name and the upgrade will stop.

def upgrade():
    context = op.get_context()
    op.execute(
        'ALTER TABLE qoses RENAME TO wrs_qoses')
    op.execute(
        'ALTER TABLE qos_policies RENAME TO wrs_qos_policies')
    op.execute(
        'ALTER TABLE networkqosmappings RENAME TO wrs_network_qos_mappings')
    op.execute(
        'ALTER TABLE portqosmappings RENAME TO wrs_port_qos_mappings')
    if context.bind.dialect.name == 'postgresql':
        op.execute('ALTER TYPE qos_types RENAME TO wrs_qos_types')
    else:
        # rename the enum qos_types to wrs_qos_types
        op.alter_column('qos_policies', 'type',
                  _type=sa.Enum('dscp', 'ratelimit', 'scheduler',
                                name='wrs_qos_types'),
                  existing_nullable=True)
    op.create_index(
        'ix_wrs_qoses_tenant_id', 'wrs_qoses', ['tenant_id'], unique=False)
