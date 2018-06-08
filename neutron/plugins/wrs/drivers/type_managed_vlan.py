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
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#

from oslo_log import log as logging

from neutron.common import constants as q_const
from neutron.plugins.common import constants as p_const
from neutron.plugins.common import utils

from neutron.db.models.plugins.ml2 import vlanallocation as vlan_alloc_model
from neutron.objects.plugins.ml2 import vlanallocation as vlanalloc
from neutron.plugins.ml2.drivers import helpers
from neutron.plugins.wrs.drivers import type_generic

LOG = logging.getLogger(__name__)


class ManagedVlanTypeDriver(type_generic.GenericRangeTypeDriverMixin,
                            helpers.SegmentTypeDriver):
    """The class is a refinement of the default VLAN type driver.

    Its purpose is to allocate VLAN segments based on the enhanced provider
    network extension.  The main difference being that VLAN segments are
    allocated according to the tenant ownership rules defined by the
    administrator rather than treating all possible segments as equal.
    """

    def __init__(self):
        super(ManagedVlanTypeDriver, self).__init__(vlanalloc.VlanAllocation)
        self.model_key = vlan_alloc_model.VlanAllocation.vlan_id
        self.segmentation_key = "vlan_id"

    def allow_dynamic_allocation(self):
        return False

    def get_type(self):
        return p_const.TYPE_VLAN

    def get_segmentation_key(self):
        return "vlan_id"

    def is_valid_segmentation_id(self, value):
        return utils.is_valid_vlan_tag(value)

    def get_min_id(self):
        return q_const.MIN_VLAN_TAG

    def get_max_id(self):
        return q_const.MAX_VLAN_TAG

    def initialize(self):
        self._sync_allocations()
        LOG.info(("ML2 ManagedVlanTypeDriver initialization complete"))
