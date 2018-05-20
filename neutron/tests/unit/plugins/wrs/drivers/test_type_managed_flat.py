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

from neutron_lib import context
from neutron_lib import exceptions as exc
from oslo_log import log as logging

from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc
from neutron.db import api as db
from neutron.db.models.plugins.ml2 import flatallocation
from neutron.db import qos_db  # noqa
from neutron.db import settings_db  # noqa
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.wrs.drivers import type_managed_flat
from neutron.tests.unit.plugins.wrs import test_extension_pnet as test_pnet
from neutron.tests.unit.plugins.wrs import test_wrs_plugin

LOG = logging.getLogger(__name__)


FLAT_PNET1 = {'name': 'flat-pnet0',
              'type': n_const.PROVIDERNET_FLAT,
              'description': 'flat test provider network'}


class ManagedFlatTypeDriverTestCase(test_pnet.ProvidernetTestCaseMixin,
                                    test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setUp(self):
        super(ManagedFlatTypeDriverTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.driver = type_managed_flat.ManagedFlatTypeDriver()
        self.session = db.get_session()
        self._pnet1 = FLAT_PNET1

    def tearDown(self):
        super(ManagedFlatTypeDriverTestCase, self).tearDown()

    def _get_allocation(self, context, segment):
        session = context.session
        return session.query(flatallocation.FlatAllocation).filter_by(
            physical_network=segment[api.PHYSICAL_NETWORK]).first()

    def test_validate_provider_segment(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                       api.PHYSICAL_NETWORK: pnet_data['name']}
            self.driver.validate_provider_segment(segment, self.context)

    def test_validate_provider_segment_with_missing_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment, self.context)

    def test_validate_provider_segment_with_unknown_physical_network(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: 'unknown'}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment, self.context)

    def test_validate_provider_segment_with_unallowed_segmentation_id(self):
        segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                   api.PHYSICAL_NETWORK: self._pnet1['name'],
                   api.SEGMENTATION_ID: 1234}
        self.assertRaises(exc.InvalidInput,
                          self.driver.validate_provider_segment,
                          segment, self.context)

    def test_reserve_provider_segment(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                       api.PHYSICAL_NETWORK: pnet_data['name']}
            observed = self.driver.reserve_provider_segment(
                self.context, segment, tenant_id=self._tenant_id)
            alloc = self._get_allocation(self.context, observed)
            self.assertEqual(segment[api.PHYSICAL_NETWORK],
                             alloc.physical_network)
            self.driver.release_segment(self.context, observed)

    def test_release_segment(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                       api.PHYSICAL_NETWORK: pnet_data['name']}
            observed = self.driver.reserve_provider_segment(
                self.context, segment, tenant_id=self._tenant_id)
            alloc = self._get_allocation(self.context, segment)
            self.assertIsNotNone(alloc)
            self.driver.release_segment(self.context, observed)
            alloc = self._get_allocation(self.context, segment)
            self.assertIsNone(alloc)

    def test_reserve_provider_segment_already_reserved(self):
        with self.pnet(self._pnet1) as pnet:
            pnet_data = pnet['providernet']
            segment = {api.NETWORK_TYPE: p_const.TYPE_FLAT,
                       api.PHYSICAL_NETWORK: pnet_data['name']}
            observed = self.driver.reserve_provider_segment(
                self.context, segment, tenant_id=self._tenant_id)
            self.assertRaises(n_exc.FlatNetworkInUse,
                              self.driver.reserve_provider_segment,
                              self.context, segment, tenant_id=self._tenant_id)
            self.driver.release_segment(self.context, observed)
