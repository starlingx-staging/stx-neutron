# Copyright (c) 2013 OpenStack Foundation
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

import copy
import uuid

import webob.exc

from oslo_log import log as logging

from neutron.common import constants
from neutron.plugins.ml2 import config
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.plugins.wrs import test_extension_host
from neutron.tests.unit.plugins.wrs import test_extension_pnet
from neutron.tests.unit.plugins.wrs import test_wrs_plugin
from neutron_lib import context
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

HOST1 = {'name': 'compute-0',
         'id': '065aa1d1-84ed-4d59-a777-16b0ea8a5640',
         'availability': constants.HOST_DOWN}

HOST2 = {'name': 'compute-1',
         'id': '28c25767-e6e7-49c3-9735-2ef5ff04c4a2',
         'availability': constants.HOST_DOWN}

HOST3 = {'name': 'compute-2',
         'id': 'c947cbd0-f59a-4ab1-b0c6-1e12bd4846ab',
         'availability': constants.HOST_DOWN}

HOST4 = {'name': 'compute-3',
         'id': '5e00774c-d132-4403-aa66-91d97ab6c6e6',
         'availability': constants.HOST_DOWN}

HOST5 = {'name': 'compute-4',
         'id': 'cf82551c-b39f-49e1-8e25-fd946b57c697',
         'availability': constants.HOST_DOWN}

HOSTS = (HOST1, HOST2, HOST3, HOST4, HOST5)

PNET1 = {'name': 'vlan-pnet1',
         'type': constants.PROVIDERNET_VLAN,
         'mtu': constants.DEFAULT_MTU,
         'description': 'vlan test provider network'}

PNET2 = {'name': 'vlan-pnet2',
         'type': constants.PROVIDERNET_VLAN,
         'mtu': constants.DEFAULT_MTU,
         'description': 'vlan test provider network'}

PNET3 = {'name': 'vlan-pnet3',
         'type': constants.PROVIDERNET_VLAN,
         'mtu': constants.DEFAULT_MTU,
         'description': 'vlan test provider network'}

PNET4 = {'name': 'vxlan-pnet1',
         'type': constants.PROVIDERNET_VXLAN,
         'mtu': constants.DEFAULT_MTU,
         'description': 'vxlan test provider network'}

PNET5 = {'name': 'vxlan-pnet2',
         'type': constants.PROVIDERNET_VXLAN,
         'mtu': constants.DEFAULT_MTU,
         'description': 'vxlan test provider network'}

PNET6 = {'name': 'flat-pnet1',
         'type': constants.PROVIDERNET_FLAT,
         'mtu': constants.DEFAULT_MTU,
         'description': 'flat test provider network'}

PNETS = (PNET1, PNET2, PNET3, PNET4, PNET5, PNET6)

PNET1_RANGE1 = {'name': 'vlan-pnet1-0',
                'description': 'vlan range1',
                'shared': False,
                'minimum': 1,
                'maximum': 100,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET2_RANGE1 = {'name': 'vlan-pnet2-0',
                'description': 'vlan range1',
                'shared': False,
                'minimum': 101,
                'maximum': 200,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET3_RANGE1 = {'name': 'vlan-pnet3-0',
                'description': 'vlan range1',
                'shared': False,
                'minimum': 101,
                'maximum': 200,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET4_RANGE1 = {'name': 'vxlan-pnet1-0',
                'description': 'vxlan range1',
                'shared': False,
                'minimum': 1,
                'maximum': 1000,
                'group': '239.0.0.1',
                'port': 4789,
                'ttl': 10,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET5_RANGE1 = {'name': 'vxlan-pnet2-0',
                'description': 'vxlan range1',
                'shared': False,
                'minimum': 10000,
                'maximum': 100010,
                'group': '239.0.0.2',
                'port': 8472,
                'ttl': 1,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET_RANGES = {'vlan-pnet1': [PNET1_RANGE1],
               'vlan-pnet2': [PNET2_RANGE1],
               'vlan-pnet3': [PNET3_RANGE1],
               'vxlan-pnet1': [PNET4_RANGE1],
               'vxlan-petn2': [PNET5_RANGE1]}

PNET_BINDINGS = {'compute-0': ['vlan-pnet1', 'vlan-pnet2', 'vxlan-pnet1'],
                 'compute-1': ['vlan-pnet1', 'vxlan-pnet1'],
                 'compute-2': ['vlan-pnet1', 'vlan-pnet3', 'vxlan-pnet1'],
                 'compute-3': ['flat-pnet1'],
                 'compute-4': ['flat-pnet1']}

INTERFACE1 = {'uuid': str(uuid.uuid4()),
              'mtu': constants.DEFAULT_MTU + constants.VXLAN_MTU_OVERHEAD,
              'vlans': '',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-0'])}

INTERFACE2 = {'uuid': str(uuid.uuid4()),
              'mtu': constants.DEFAULT_MTU + constants.VXLAN_MTU_OVERHEAD,
              'vlans': '4001,,4002, 4003',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-1'])}

INTERFACE3 = {'uuid': str(uuid.uuid4()),
              'mtu': constants.DEFAULT_MTU + constants.VXLAN_MTU_OVERHEAD,
              'vlans': '4001',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-2'])}

INTERFACE4 = {'uuid': str(uuid.uuid4()),
              'mtu': constants.DEFAULT_MTU,
              'vlans': '',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-3'])}

INTERFACE5 = {'uuid': str(uuid.uuid4()),
              'mtu': constants.DEFAULT_MTU,
              'vlans': '',
              'network_type': 'pci-passthrough',
              'providernets': ','.join(PNET_BINDINGS['compute-4'])}

INTERFACES = {'compute-0': INTERFACE1,
              'compute-1': INTERFACE2,
              'compute-2': INTERFACE3,
              'compute-3': INTERFACE4,
              'compute-4': INTERFACE5}


class WrsHostInterfaceTestCase(test_extension_pnet.ProvidernetTestCaseMixin,
                               test_extension_host.HostTestCaseMixin,
                               test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setup_config(self):
        super(WrsHostInterfaceTestCase, self).setup_config()
        # Instantiate a fake host driver to allow us to control the host to
        # provider network mappings
        config.cfg.CONF.set_override('host_driver',
                                     'neutron.tests.unit.plugins.wrs.'
                                     'test_host_driver.TestHostDriver')

    def setUp(self, plugin=None, ext_mgr=None):
        self._hosts = {}
        self._interfaces = {}
        self._pnets = {}
        self._pnet_ranges = {}
        super(WrsHostInterfaceTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._l3_plugin = directory.get_plugin(plugin_constants.L3)
        self._host_driver = self._plugin.host_driver
        self._prepare_test_dependencies(hosts=HOSTS,
                                        providernets=PNETS,
                                        providernet_ranges=PNET_RANGES,
                                        interfaces=INTERFACES)

    def tearDown(self):
        self._cleanup_test_dependencies()
        super(WrsHostInterfaceTestCase, self).tearDown()

    def test_create_interface(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        data = self._make_interface(HOST1['id'], interface_data)
        self.assertEqual(data['interface']['uuid'], interface_data['uuid'])
        self.assertEqual(data['interface']['mtu'], interface_data['mtu'])

    def test_create_interface_duplicate_providernet(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': PNET5['name'] + ',' + PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        data = self._make_interface(HOST1['id'], interface_data)
        self.assertEqual(data['interface']['uuid'], interface_data['uuid'])
        self.assertEqual(data['interface']['mtu'], interface_data['mtu'])

    def test_update_vxlan_providernet_matches_link_mtu(self):
        link_mtu = INTERFACE1['mtu']
        link_mtu -= constants.VXLAN_MTU_OVERHEAD
        data = {'providernet': {'mtu': link_mtu}}
        pnet = self._get_pnet(PNET4['name'])
        request = self.new_update_request('wrs-provider/providernets',
                                          data, pnet['id'])
        response = request.get_response(self.ext_api)
        self.assertEqual(response.status_int, 200)
        body = self.deserialize(self.fmt, response)
        self.assertEqual(body['providernet']['mtu'], link_mtu)

    def test_update_vxlan_providernet_exceeds_link_mtu(self):
        data = {'mtu': INTERFACE1['mtu'] + 1}
        pnet = self._get_pnet(PNET4['name'])
        self.assertRaises(webob.exc.HTTPClientError,
                          self._update_pnet,
                          pnet['id'], data)

    def test_update_vlan_providernet_matches_link_mtu(self):
        link_mtu = INTERFACE1['mtu']
        data = {'providernet': {'mtu': link_mtu}}
        pnet = self._get_pnet(PNET1['name'])
        request = self.new_update_request('wrs-provider/providernets',
                                          data, pnet['id'])
        response = request.get_response(self.ext_api)
        self.assertEqual(response.status_int, 200)
        body = self.deserialize(self.fmt, response)
        self.assertEqual(body['providernet']['mtu'], link_mtu)

    def test_update_vlan_providernet_exceeds_link_mtu(self):
        data = {'mtu': INTERFACE1['mtu'] + 1}
        pnet = self._get_pnet(PNET1['name'])
        self.assertRaises(webob.exc.HTTPClientError,
                          self._update_pnet,
                          pnet['id'], data)

    def test_create_interface_invalid_mtu(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': 'invalid',
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_small_mtu(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': 1,
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_large_mtu(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': 99999,
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_unknown_host(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        host_id = str(uuid.uuid4())
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          host_id, interface_data)

    def test_create_interface_invalid_host(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': ''}
        host_id = 'invalid'
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          host_id, interface_data)

    def test_create_interface_unknown_providernet(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': 'unknown',
                          'network_type': 'data',
                          'vlans': ''}
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_invalid_vlans(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': 'invalid,invalid'}
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_out_of_range_vlans(self):
        interface_data = {'uuid': str(uuid.uuid4()),
                          'mtu': (constants.DEFAULT_MTU +
                                  constants.VXLAN_MTU_OVERHEAD),
                          'providernets': PNET5['name'],
                          'network_type': 'data',
                          'vlans': '0,5000'}
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)


class WrsHostInterfaceProviderNetSemanticTestCase(WrsHostInterfaceTestCase):

    def test_create_range_no_overlap(self):
        range_data = {'name': 'no-overlap',
                      'shared': True,
                      'minimum': 2000,
                      'maximum': 2010,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET1['name'])
        with self.pnet_range(pnet, range_data) as pnet_range:
            data = pnet_range['providernet_range']
            self.assertEqual(data['name'], range_data['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['shared'], range_data['shared'])

    def test_create_range_overlap_self(self):
        range_data = {'name': 'self-overlap',
                      'shared': True,
                      'minimum': 20,
                      'maximum': 30,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET1['name'])
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet_range,
                          pnet, range_data)

    def test_create_range_overlap_same_interface(self):
        range_data = {'name': 'peer-overlap',
                      'shared': True,
                      'minimum': 120,
                      'maximum': 130,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET1['name'])
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet_range,
                          pnet, range_data)

    def test_create_range_no_overlap_different_interface(self):
        range_data = {'name': 'no-overlap',
                      'shared': True,
                      'minimum': 220,
                      'maximum': 230,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET2['name'])
        with self.pnet_range(pnet, range_data) as pnet_range:
            data = pnet_range['providernet_range']
            self.assertEqual(data['name'], range_data['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['shared'], range_data['shared'])

    def test_create_range_overlap_different_type(self):
        range_data = {'name': 'overlap',
                      'shared': True,
                      'minimum': 900,
                      'maximum': 1000,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET1['name'])
        with self.pnet_range(pnet, range_data) as pnet_range:
            data = pnet_range['providernet_range']
            self.assertEqual(data['name'], range_data['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['shared'], range_data['shared'])

    def test_create_range_overlap_system_vlans(self):
        range_data = {'name': 'overlap',
                      'shared': True,
                      'minimum': 4000,
                      'maximum': 4010,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET1['name'])
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet_range,
                          pnet, range_data)

    def test_create_range_no_overlap_system_vlans(self):
        range_data = {'name': 'overlap',
                      'shared': True,
                      'minimum': 4000,
                      'maximum': 4010,
                      'tenant_id': self._tenant_id}
        ctxt = context.get_admin_context()
        pnet = self._plugin.get_providernet_by_name(ctxt, PNET2['name'])
        with self.pnet_range(pnet, range_data) as pnet_range:
            data = pnet_range['providernet_range']
            self.assertEqual(data['name'], range_data['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['shared'], range_data['shared'])

    def test_create_interface_peer_overlap(self):
        interface_data = copy.deepcopy(INTERFACE1)
        interface_data['providernets'] += ',' + PNET3['name']
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_incompatible_providernets(self):
        interface_data = copy.deepcopy(INTERFACE1)
        interface_data['providernets'] += ',' + PNET6['name']
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_incompatible_pci_providernets(self):
        interface_data = copy.deepcopy(INTERFACE5)
        interface_data['providernets'] = PNET4['name']
        interface_data['mtu'] = PNET4['mtu'] + constants.VXLAN_MTU_OVERHEAD
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST5['id'], interface_data)

    def test_create_interface_system_vlan_overlap(self):
        interface_data = copy.deepcopy(INTERFACE1)
        interface_data['vlans'] = '1'
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST1['id'], interface_data)

    def test_create_interface_incompatible_flat_mtu(self):
        interface_data = copy.deepcopy(INTERFACE4)
        interface_data['mtu'] = PNET6['mtu'] - 1
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST4['id'], interface_data)

    def test_create_interface_incompatible_vxlan_mtu(self):
        interface_data = copy.deepcopy(INTERFACE2)
        interface_data['mtu'] = PNET4['mtu']
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_interface,
                          HOST2['id'], interface_data)
