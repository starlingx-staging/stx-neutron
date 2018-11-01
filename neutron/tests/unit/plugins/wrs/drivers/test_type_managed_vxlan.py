# Copyright 2013 OpenStack Foundation
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

from neutron.common import constants
from neutron.db import qos_db  # noqa
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.wrs.drivers import type_managed_vxlan
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.plugins.wrs.drivers import test_type_managed_vlan

LOG = logging.getLogger(__name__)


VXLAN_PNET1 = {'name': 'vxlan-pnet0',
               'type': constants.PROVIDERNET_VXLAN,
               'mtu': constants.DEFAULT_MTU - constants.VXLAN_MTU_OVERHEAD,
               'description': 'vxlan test provider network'}

VXLAN_PNET1_RANGE1 = {'name': 'vxlan-pnet0-0',
                      'description': 'vxlan range1',
                      'shared': False,
                      'minimum': 10,
                      'maximum': 100,
                      'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID,
                      'group': '239.0.0.1',
                      'port': 8472,
                      'ttl': 1}


class ManagedVxlanTypeDriverTestCase(
        test_type_managed_vlan.ManagedVlanTypeDriverTestCase):

    def setUp(self):
        super(ManagedVxlanTypeDriverTestCase, self).setUp()
        self.driver = type_managed_vxlan.ManagedVxlanTypeDriver()
        self._pnet1 = VXLAN_PNET1
        self._pnet_range1 = VXLAN_PNET1_RANGE1

    def tearDown(self):
        super(ManagedVxlanTypeDriverTestCase, self).tearDown()

    def _get_allocation(self, context, segment):
        session = context.session
        return (session.query(type_managed_vxlan.ManagedVxlanAllocation).
                filter_by(physical_network=segment[api.PHYSICAL_NETWORK],
                          vxlan_vni=segment[api.SEGMENTATION_ID]).first())

    # There are no tests defined here because they are all reused from the
    # parent class
