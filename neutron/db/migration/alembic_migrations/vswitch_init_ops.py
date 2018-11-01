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

# Initial schema operations for vswitch related features.  This file should
# only contain content that was delivered prior to the Kilo release.  Anything
# that happened during Kilo should be in the wrs_kilo/{expand,contract}/*
# directories.
#


from alembic import op
import sqlalchemy as sa


availability = sa.Enum('up', 'down',
                       name='availabilityEnum')
providernet_type = sa.Enum('flat', 'vlan', 'vxlan', 'gre',
                           name='providerNetTypeEnum')


def upgrade():
    op.create_table(
        'hosts',
        sa.Column('id', sa.String(length=36), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('availability', availability, nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'))

    op.create_table(
        'providernets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('mtu', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('type', providernet_type, nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'))

    op.create_table(
        'providernet_vxlans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('first_ip', sa.String(length=64), nullable=False),
        sa.Column('last_ip', sa.String(length=64), nullable=False),
        sa.Column('providernet_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['providernet_id'], ['providernets.id'], ),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'providernet_ranges',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255), nullable=True),
        sa.Column('shared', sa.Boolean(), nullable=False),
        sa.Column('minimum', sa.Integer(), nullable=True),
        sa.Column('maximum', sa.Integer(), nullable=True),
        sa.Column('providernet_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['providernet_id'], ['providernets.id'], ),
        sa.PrimaryKeyConstraint('id'))

    op.create_table(
        'hostprovidernetbindings',
        sa.Column('providernet_id', sa.String(length=36), nullable=False),
        sa.Column('host_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['providernet_id'], ['providernets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('providernet_id', 'host_id'))

    op.add_column(
        'ml2_port_bindings',
        sa.Column('vif_model', sa.String(length=255), nullable=True))

    op.add_column(
        'ml2_port_bindings',
        sa.Column('mtu', sa.Integer(), nullable=True))

    op.create_table(
        'qoses',
        sa.Column('tenant_id', sa.String(length=255), nullable=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'))

    op.create_table(
        'qos_policies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('qos_id', sa.String(length=36), nullable=False),
        sa.Column('type',
                  sa.Enum('dscp', 'ratelimit', 'scheduler', name='qos_types'),
                  nullable=True),
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['qos_id'], ['qoses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', 'qos_id', 'key'))

    op.create_table(
        'networkqosmappings',
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('qos_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'],
                                ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['qos_id'], ['qoses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('network_id', 'qos_id'))

    op.create_table(
        'portqosmappings',
        sa.Column('port_id', sa.String(length=36), nullable=False),
        sa.Column('qos_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['port_id'], ['ports.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['qos_id'], ['qoses.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('port_id', 'qos_id'))

    op.add_column(
        'subnets',
        sa.Column('vlan_id', sa.Integer(), nullable=True))

    op.create_table(
        'ml2_subnet_segments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('subnet_id', sa.String(length=36), nullable=False),
        sa.Column('network_type', sa.String(length=32), nullable=False),
        sa.Column('physical_network', sa.String(length=64), nullable=True),
        sa.Column('segmentation_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['subnet_id'], ['subnets.id'],
                                ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))

    op.add_column(
        'subnets',
        sa.Column('managed', sa.Boolean(), nullable=True))
