# Copyright (c) 2013-2014 OpenStack Foundation
# All Rights Reserved.
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
# Copyright (c) 2015 Wind River Systems, Inc.
#

from neutron_lib.db import model_base
from oslo_log import log as logging
import sqlalchemy as sa
from sqlalchemy import sql

from neutron.common import constants as q_const
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils
from neutron.plugins.wrs.drivers import type_generic

LOG = logging.getLogger(__name__)


class ManagedVxlanAllocation(model_base.BASEV2):
    """
    This class is a refinement of the ML2 VXLAN allocation table.  The ML2
    version of the table does not include the physical network name which we
    require for management of provider networks.  We cannot extend the
    existing table directly because it would break existing unit tests.
    """
    __tablename__ = 'wrs_vxlan_allocations'

    physical_network = sa.Column(sa.String(64), nullable=False,
                                 primary_key=True)
    vxlan_vni = sa.Column(sa.Integer, nullable=False, primary_key=True,
                          autoincrement=False)
    allocated = sa.Column(sa.Boolean, nullable=False, default=False,
                          server_default=sql.false())


class ManagedVxlanTypeDriver(type_generic.GenericRangeTypeDriver):
    """
    This class is a refinement of the default VXLAN type driver.

    Its purpose is to allocate VXLAN segments based on the enhanced provider
    network extension.  The main difference being that VXLAN segments are
    allocated according to the tenant ownership rules defined by the
    administrator rather than treating all possible segments as equal. It also
    adds the physical_network attribute to all VXLAN segmentation id
    allocations to support tracking unique VXLAN instances on a per provider
    network basis.
    """

    def __init__(self):
        super(ManagedVxlanTypeDriver, self).__init__(ManagedVxlanAllocation)
        self.model_key = ManagedVxlanAllocation.vxlan_vni
        self.segmentation_key = "vxlan_vni"

    def allow_dynamic_allocation(self):
        return False

    def get_type(self):
        return p_const.TYPE_VXLAN

    def get_segmentation_key(self):
        return "vxlan_vni"

    def is_valid_segmentation_id(self, value):
        return utils.is_valid_vxlan_vni(value)

    def get_min_id(self):
        return q_const.MIN_VXLAN_VNI

    def get_max_id(self):
        return q_const.MAX_VXLAN_VNI

    def initialize(self):
        self._sync_allocations()
        LOG.info(("ML2 ManagedVxlanTypeDriver initialization complete"))
