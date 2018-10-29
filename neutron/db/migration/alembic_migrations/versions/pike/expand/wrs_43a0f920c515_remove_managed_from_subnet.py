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
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

"""Remove managed from subnet

Revision ID: wrs_43a0f920c515
Revises: wrs_11a84c4cea76
Create Date: 2017-09-07 18:54:18.641545

"""

# revision identifiers, used by Alembic.
revision = 'wrs_43a0f920c515'
down_revision = 'wrs_11a84c4cea76'

from alembic import op
import sqlalchemy as sa


def upgrade():
    context = op.get_context()
    if context.bind.dialect.name == 'postgresql':
        # The following SQL syntax is not supported by mysql < 10.3.1
        cmd = ("DELETE FROM subnets WHERE id IN"
               " (SELECT s.id FROM subnets AS s LEFT OUTER JOIN ipallocations"
               " AS ia ON ia.subnet_id = s.id WHERE s.managed = false"
               " GROUP BY s.id,ia.ip_address HAVING COUNT(ia.ip_address) = 0);")
    else:
        cmd = ("CREATE TEMPORARY TABLE TEMP_SUBNETS"
               " (SELECT s.id FROM subnets AS s LEFT OUTER JOIN ipallocations"
               " AS ia ON ia.subnet_id = s.id WHERE s.managed = false"
               " GROUP BY s.id,ia.ip_address HAVING COUNT(ia.ip_address) = 0);")
    op.execute(cmd)
    if context.bind.dialect.name == 'postgresql':
        op.drop_column('subnets', 'managed')
    else:
        cmd = ("DELETE FROM subnets WHERE id IN"
               " (SELECT id FROM TEMP_SUBNETS);")
        op.execute(cmd)
        cmd = ("DROP TEMPORARY TABLE TEMP_SUBNETS;")
        op.execute(cmd)
        op.drop_column('subnets', 'managed')
