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

from testtools import matchers

from neutron_lib import context
from neutron_lib import exceptions as exc
from oslo_log import log as logging

from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.db import api as db
from neutron.db.models.plugins.ml2 import vlanallocation as vlan_alloc_model
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.wrs.drivers import type_managed_vlan
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.plugins.wrs import test_extension_pnet as test_pnet
from neutron.tests.unit.plugins.wrs import test_wrs_plugin

LOG = logging.getLogger(__name__)


VLAN_PNET1 = {'name': 'vlan-pnet0',
              'type': constants.PROVIDERNET_VLAN,
              'description': 'vlan test provider network'}

VLAN_PNET1_RANGE1 = {'name': 'vlan-pnet0-0',
                     'description': 'vlan range1',
                     'shared': False,
                     'minimum': 10,
                     'maximum': 100,
                     'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}


class ManagedVlanTypeDriverTestCase(test_pnet.ProvidernetTestCaseMixin,
                                    test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setUp(self):
        super(ManagedVlanTypeDriverTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.driver = type_managed_vlan.ManagedVlanTypeDriver()
        self.session = db.get_session()
        self._pnet1 = VLAN_PNET1
        self._pnet_range1 = VLAN_PNET1_RANGE1

    def tearDown(self):
        super(ManagedVlanTypeDriverTestCase, self).tearDown()

    def _get_allocation(self, context, segment):
        session = context.session
        return session.query(vlan_alloc_model.VlanAllocation).filter_by(
            physical_network=segment[api.PHYSICAL_NETWORK],
            vlan_id=segment[api.SEGMENTATION_ID]).first()

    def test_validate_provider_segment(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: pnet_data['type'],
                       api.PHYSICAL_NETWORK: pnet_data['name'],
                       api.SEGMENTATION_ID: 1}
            self.assertIsNone(self.driver.validate_provider_segment(
                segment, self.context))

    def test_validate_provider_segment_without_segmentation_id(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: pnet_data['type'],
                       api.PHYSICAL_NETWORK: pnet_data['name']}
            self.driver.validate_provider_segment(segment, self.context)

    def test_validate_provider_segment_without_physical_network(self):
        segment = {api.NETWORK_TYPE: self._pnet1['type']}
        self.driver.validate_provider_segment(segment, self.context)

    def test_validate_provider_segment_with_missing_physical_network(self):
        segment = {api.NETWORK_TYPE: self._pnet1['type'],
                   api.SEGMENTATION_ID: 1}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment, self.context)

    def test_validate_provider_segment_with_invalid_physical_network(self):
        with self.pnet(self._pnet1):
            segment = {api.NETWORK_TYPE: self._pnet1['type'],
                       api.PHYSICAL_NETWORK: 'invalid',
                       api.SEGMENTATION_ID: 1}
            self.assertRaises(exc.InvalidInput,
                              self.driver.validate_provider_segment,
                              segment, self.context)

    def test_validate_provider_segment_with_invalid_segmentation_id(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: pnet_data['type'],
                       api.PHYSICAL_NETWORK: pnet_data['name'],
                       api.SEGMENTATION_ID: 2 ** 24}
            self.assertRaises(exc.InvalidInput,
                              self.driver.validate_provider_segment,
                              segment, self.context)

    def test_validate_provider_segment_with_invalid_input(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: pnet_data['type'],
                       api.PHYSICAL_NETWORK: pnet_data['name'],
                       api.SEGMENTATION_ID: 1,
                       'invalid': 1}
            self.assertRaises(exc.InvalidInput,
                              self.driver.validate_provider_segment,
                              segment, self.context)

    def test_reserve_provider_segment(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, self._pnet_range1) as pnet_range:
                data = pnet_range['providernet_range']
                segment = {api.NETWORK_TYPE: pnet_data['type'],
                           api.PHYSICAL_NETWORK: pnet_data['name'],
                           api.SEGMENTATION_ID: data['minimum']}
                alloc = self._get_allocation(self.context, segment)
                self.assertFalse(alloc.allocated)
                observed = self.driver.reserve_provider_segment(
                    self.context, segment, tenant_id=self._tenant_id)
                alloc = self._get_allocation(self.context, observed)
                self.assertTrue(alloc.allocated)
                self.driver.release_segment(self.context, observed)

    def test_reserve_provider_segment_already_allocated(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, self._pnet_range1) as pnet_range:
                data = pnet_range['providernet_range']
                segment = {api.NETWORK_TYPE: pnet_data['type'],
                           api.PHYSICAL_NETWORK: pnet_data['name'],
                           api.SEGMENTATION_ID: data['minimum']}
                observed = self.driver.reserve_provider_segment(
                    self.context, segment, tenant_id=self._tenant_id)
                self.assertRaises(n_exc.SegmentationIdInUse,
                                  self.driver.reserve_provider_segment,
                                  self.context,
                                  observed,
                                  tenant_id=self._tenant_id)
                self.driver.release_segment(self.context, observed)

    def test_reserve_provider_segment_without_segmentation_id(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, self._pnet_range1) as pnet_range:
                data = pnet_range['providernet_range']
                segment = {api.NETWORK_TYPE: pnet_data['type'],
                           api.PHYSICAL_NETWORK: pnet_data['name']}
                observed = self.driver.reserve_provider_segment(
                    self.context, segment, tenant_id=self._tenant_id)
                alloc = self._get_allocation(self.context, observed)
                self.assertTrue(alloc.allocated)
                self.driver.release_segment(self.context, observed)
                vlan_id = observed[api.SEGMENTATION_ID]
                self.assertThat(vlan_id,
                                matchers.GreaterThan(data['minimum'] - 1))
                self.assertThat(vlan_id,
                                matchers.LessThan(data['maximum'] + 1))

    def test_reserve_provider_segment_without_physical_network(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, self._pnet_range1) as pnet_range:
                data = pnet_range['providernet_range']
                segment = {api.NETWORK_TYPE: pnet_data['type']}
                observed = self.driver.reserve_provider_segment(
                    self.context, segment, tenant_id=self._tenant_id)
                alloc = self._get_allocation(self.context, observed)
                self.assertTrue(alloc.allocated)
                vlan_id = observed[api.SEGMENTATION_ID]
                self.assertEqual(alloc.physical_network, pnet_data['name'])
                self.assertThat(vlan_id,
                                matchers.GreaterThan(data['minimum'] - 1))
                self.assertThat(vlan_id,
                                matchers.LessThan(data['maximum'] + 1))
                self.driver.release_segment(self.context, observed)

    def test_reserve_provider_segment_none_available(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: pnet_data['type']}
            self.assertRaises(exc.NoNetworkAvailable,
                              self.driver.reserve_provider_segment,
                              self.context,
                              segment,
                              tenant_id=self._tenant_id)

    def test_reserve_provider_segment_none_created(self):
        segment = {api.NETWORK_TYPE: self._pnet1['type']}
        self.assertRaises(exc.NoNetworkAvailable,
                          self.driver.reserve_provider_segment,
                          self.context,
                          segment,
                          tenant_id=self._tenant_id)
