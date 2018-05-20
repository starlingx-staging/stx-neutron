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

import contextlib
import copy
import uuid

import webob.exc

import mock
from oslo_log import log as logging

from neutron.api.rpc.agentnotifiers import pnet_connectivity_rpc_agent_api
from neutron.api.rpc.handlers import pnet_connectivity_rpc
from neutron.common import constants as n_const
from neutron.common import rpc as n_rpc
from neutron.extensions import wrs_provider as ext_pnet
from neutron.plugins.ml2 import config
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.plugins.wrs import test_wrs_plugin
from neutron_lib import context
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

TENANT_1 = "test-tenant"

HOST_1 = 'test-host'

AUDIT_1 = '43b12c0b-3c17-4661-86d2-52c5a3b83c2f'

FLAT_PNET1 = {'name': 'flat-pnet0',
              'type': n_const.PROVIDERNET_FLAT,
              'description': 'flat test provider network'}

VLAN_PNET1 = {'name': 'vlan-pnet0',
              'type': n_const.PROVIDERNET_VLAN,
              'description': 'vlan test provider network'}

VLAN_PNET1_RANGE1 = {'name': 'vlan-pnet0-0',
                     'description': 'vlan range1',
                     'shared': False,
                     'minimum': 10,
                     'maximum': 100,
                     'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

VLAN_PNET2 = {'name': 'vlan-pnet1',
              'type': n_const.PROVIDERNET_VLAN,
              'description': 'vlan test provider network'}

VLAN_PNET2_RANGE1 = {'name': 'vlan-pnet1-0',
                     'description': 'vlan range1',
                     'shared': True,
                     'minimum': 1,
                     'maximum': 100,
                     'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

VXLAN_PNET1 = {'name': 'vxlan-pnet0',
               'type': n_const.PROVIDERNET_VXLAN,
               'mtu': n_const.DEFAULT_MTU - n_const.VXLAN_MTU_OVERHEAD,
               'description': 'vxlan test provider network'}

VXLAN_PNET1_RANGE1 = {'name': 'vxlan-pnet0-0',
                      'description': 'vxlan range1',
                      'shared': False,
                      'minimum': 10,
                      'maximum': 100,
                      'group': '239.0.0.1',
                      'port': 8472,
                      'ttl': 1,
                      'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

VXLAN_PNET1_RANGE2 = {'name': 'vxlan-pnet0-1',
                      'description': 'vxlan range2',
                      'shared': False,
                      'minimum': 1000,
                      'maximum': 9999,
                      'group': 'ff0e::239.0.0.1',
                      'port': 4789,
                      'ttl': 10,
                      'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

VXLAN_PNET2 = {'name': 'vxlan-pnet1',
               'type': n_const.PROVIDERNET_VXLAN,
               'mtu': n_const.DEFAULT_MTU - n_const.VXLAN_MTU_OVERHEAD,
               'description': 'vxlan test provider network',
               'vlan_transparent': True}

VXLAN_PNET2_RANGE1 = {'name': 'vxlan-pnet1-0',
                      'description': 'vxlan range1',
                      'shared': False,
                      'minimum': 101,
                      'maximum': 200,
                      'group': '239.0.0.2',
                      'port': 4789,
                      'ttl': 10,
                      'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}


class ProvidernetTestCaseMixin(object):

    @contextlib.contextmanager
    def network(self, name='net1',
                admin_state_up=True,
                fmt=None,
                **kwargs):
        # This is being overriden from the test_db_plugin version because that
        # version does not automatically cleanup the network upon exiting the
        # context manager context.
        network = self._make_network(fmt or self.fmt, name,
                                     admin_state_up, **kwargs)
        try:
            yield network
        finally:
            self._delete('networks', network['network']['id'])

    def _update_pnet(self, id, body):
        data = {'providernet': body}
        request = self.new_update_request('wrs-provider/providernets',
                                          data, id)
        response = request.get_response(self.ext_api)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    def _create_pnet(self, pnet):
        data = {'providernet': {'name': pnet['name'],
                                'tenant_id': self._tenant_id}}
        for arg in ('name', 'type', 'mtu', 'description', 'vlan_transparent'):
            if arg in pnet:
                data['providernet'][arg] = pnet[arg]
        request = self.new_create_request('wrs-provider/providernets', data)
        return request.get_response(self.ext_api)

    def _make_pnet(self, data):
        response = self._create_pnet(data)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    @contextlib.contextmanager
    def pnet(self, data, no_delete=False):
        obj = self._make_pnet(data)
        try:
            yield obj
        finally:
            if not no_delete:
                self._delete('wrs-provider/providernets',
                             obj['providernet']['id'])

    def _update_pnet_range(self, id, body):
        data = {'providernet_range': body}
        request = self.new_update_request('wrs-provider/providernet_range',
                                          data, id)
        response = request.get_response(self.ext_api)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    def _create_pnet_range(self, pnet, pnet_range):
        data = {'providernet_range': {'providernet_id': pnet['id']}}
        for arg in ('name', 'description', 'shared',
                    'minimum', 'maximum', 'tenant_id',
                    'group', 'port', 'ttl'):
            if arg in pnet_range:
                data['providernet_range'][arg] = pnet_range[arg]
        request = self.new_create_request('wrs-provider/providernet-ranges',
                                          data)
        return request.get_response(self.ext_api)

    def _make_pnet_range(self, pnet, data):
        response = self._create_pnet_range(pnet, data)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    @contextlib.contextmanager
    def pnet_range(self, pnet, data, no_delete=False):
        obj = self._make_pnet_range(pnet, data)
        try:
            yield obj
        finally:
            if not no_delete:
                self._delete('wrs-provider/providernet-ranges',
                             obj['providernet_range']['id'])

    def assertReturnsApiError(self, expected_type, function, *args, **kwargs):
        response = function(*args, **kwargs)
        body = response.json_body
        actual_type = body['NeutronError']['type']
        self.assertEqual(expected_type, actual_type)

    def _create_pnet_connectivity_state(self, data):
        request = self.new_create_request(
            'wrs-provider/providernet-connectivity-tests', data
        )
        return request.get_response(self.ext_api)

    def _make_pnet_connectivity_state(self, data):
        response = self._create_pnet_connectivity_state(data)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    @contextlib.contextmanager
    def pnet_connectivity_state(self, providernet_id=None, host_name=None):
        data = {'providernet_connectivity_test': {
                    'providernet_id': providernet_id,
                    'host_name': host_name,
                    'tenant_id': TENANT_1
                }}
        obj = self._make_pnet_connectivity_state(data)
        try:
            yield obj
        finally:
            pass


class ProvidernetTestCase(ProvidernetTestCaseMixin,
                          test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setup_config(self):
        super(ProvidernetTestCase, self).setup_config()
        # Instantiate a fake host driver to allow us to control the host to
        # provider network mappings
        config.cfg.CONF.set_override('host_driver',
                                     'neutron.tests.unit.plugins.wrs.'
                                     'test_host_driver.TestHostDriver')
        config.cfg.CONF.set_override('vlan_transparent', True)

    def setUp(self):
        super(ProvidernetTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._host_driver = self._plugin.host_driver

    def tearDown(self):
        super(ProvidernetTestCase, self).tearDown()

    def test_create_vlan_providernet(self):
        with self.pnet(VLAN_PNET1) as pnet:
            data = pnet['providernet']
            self.assertEqual(data['name'], VLAN_PNET1['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['type'], n_const.PROVIDERNET_VLAN)

    def test_create_providernet_invalid_name(self):
        pnet = copy.deepcopy(VLAN_PNET1)
        pnet['name'] = "   "
        self.assertReturnsApiError("HTTPBadRequest", self._create_pnet, pnet)

    def test_create_providernet_invalid_mtu(self):
        pnet = copy.deepcopy(VLAN_PNET1)
        pnet['mtu'] = 12345678
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet, pnet)

    def test_create_providernet_invalid_type(self):
        pnet = copy.deepcopy(VLAN_PNET1)
        pnet['type'] = 'invalid'
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet, pnet)

    def test_create_providernet_unsupported(self):
        pnet = copy.deepcopy(VLAN_PNET1)
        pnet['type'] = 'gre'
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet, pnet)

    def test_create_providernet_minimum_mtu(self):
        pnet = copy.deepcopy(VLAN_PNET1)
        pnet['mtu'] = n_const.MINIMUM_TTL - 1
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet, pnet)

    def test_create_providernet_maximum_mtu(self):
        pnet = copy.deepcopy(VLAN_PNET1)
        pnet['mtu'] = n_const.MAXIMUM_TTL + 1
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet, pnet)

    def test_create_vxlan_providernet(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            data = pnet['providernet']
            self.assertEqual(data['name'], VXLAN_PNET1['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['type'], n_const.PROVIDERNET_VXLAN)

    def test_update_vlan_providernet(self):
        with self.pnet(VLAN_PNET1) as pnet:
            data = {'providernet': {'mtu': 1234}}
            request = self.new_update_request('wrs-provider/providernets',
                                              data, pnet['providernet']['id'])
            response = request.get_response(self.ext_api)
            self.assertEqual(response.status_int, 200)
            body = self.deserialize(self.fmt, response)
            self.assertEqual(body['providernet']['mtu'], 1234)

    def test_update_vlan_providernet_minimum_mtu(self):
        with self.pnet(VLAN_PNET1) as pnet:
            data = {'providernet': {'mtu': n_const.MINIMUM_MTU}}
            request = self.new_update_request('wrs-provider/providernets',
                                              data, pnet['providernet']['id'])
            response = request.get_response(self.ext_api)
            self.assertEqual(response.status_int, 200)
            body = self.deserialize(self.fmt, response)
            self.assertEqual(body['providernet']['mtu'], n_const.MINIMUM_MTU)

    def test_update_vlan_providernet_below_minimum_mtu(self):
        with self.pnet(VLAN_PNET1) as pnet:
            body = {'mtu': n_const.MINIMUM_MTU - 1}
            self.assertRaises(webob.exc.HTTPClientError,
                              self._update_pnet,
                              pnet['providernet']['id'], body)

    def test_update_vxlan_providernet(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            data = {'providernet': {'mtu': 1234}}
            request = self.new_update_request('wrs-provider/providernets',
                                              data, pnet['providernet']['id'])
            response = request.get_response(self.ext_api)
            self.assertEqual(response.status_int, 200)
            body = self.deserialize(self.fmt, response)
            self.assertEqual(body['providernet']['mtu'], 1234)

    def test_update_vxlan_providernet_minimum_mtu(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            data = {'providernet': {'mtu': n_const.MINIMUM_MTU}}
            request = self.new_update_request('wrs-provider/providernets',
                                              data, pnet['providernet']['id'])
            response = request.get_response(self.ext_api)
            self.assertEqual(response.status_int, 200)
            body = self.deserialize(self.fmt, response)
            self.assertEqual(body['providernet']['mtu'], n_const.MINIMUM_MTU)

    def test_update_vxlan_providernet_below_minimum_mtu(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            body = {'mtu': n_const.MINIMUM_MTU - 1}
            self.assertRaises(webob.exc.HTTPClientError,
                              self._update_pnet,
                              pnet['providernet']['id'], body)

    def test_create_vlan_tenant_net(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1):
                with self.network() as net:
                    data = net['network']
                    self.assertEqual(data['provider:physical_network'],
                                     VLAN_PNET1['name'])
                    self.assertEqual(data['provider:network_type'],
                                     VLAN_PNET1['type'])
                    self.assertIsNotNone(data['provider:segmentation_id'])
                    self.assertEqual(data['mtu'], pnet_data['mtu'])

    def test_create_vlan_tenant_subnet(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1):
                with self.network() as net:
                    data = net['network']
                    self.assertEqual(data['provider:physical_network'],
                                     VLAN_PNET1['name'])
                    self.assertEqual(data['provider:network_type'],
                                     VLAN_PNET1['type'])
                    self.assertIsNotNone(data['provider:segmentation_id'])
                    self.assertEqual(data['mtu'], pnet_data['mtu'])
                    with self.subnet(net, cidr='1.2.3.0/24') as subnet:
                        sdata = subnet['subnet']
                        self.assertEqual(sdata[ext_pnet.PHYSICAL_NETWORK],
                                         data['provider:physical_network'])
                        self.assertEqual(sdata[ext_pnet.NETWORK_TYPE],
                                         data['provider:network_type'])
                        self.assertEqual(sdata[ext_pnet.SEGMENTATION_ID],
                                         data['provider:segmentation_id'])

    def test_create_vxlan_tenant_net(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1):
                with self.network() as net:
                    data = net['network']
                    self.assertEqual(data['provider:physical_network'],
                                     VXLAN_PNET1['name'])
                    self.assertEqual(data['provider:network_type'],
                                     VXLAN_PNET1['type'])
                    self.assertIsNotNone(data['provider:segmentation_id'])
                    self.assertEqual(data['mtu'], pnet_data['mtu'])

    def test_create_vxlan_tenant_subnet(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1):
                with self.network() as net:
                    data = net['network']
                    self.assertEqual(data['provider:physical_network'],
                                     VXLAN_PNET1['name'])
                    self.assertEqual(data['provider:network_type'],
                                     VXLAN_PNET1['type'])
                    self.assertIsNotNone(data['provider:segmentation_id'])
                    self.assertEqual(data['mtu'], pnet_data['mtu'])
                    with self.subnet(net, cidr='1.2.3.0/24') as subnet:
                        sdata = subnet['subnet']
                        self.assertEqual(sdata[ext_pnet.PHYSICAL_NETWORK],
                                         data['provider:physical_network'])
                        self.assertEqual(sdata[ext_pnet.NETWORK_TYPE],
                                         data['provider:network_type'])
                        self.assertEqual(sdata[ext_pnet.SEGMENTATION_ID],
                                         data['provider:segmentation_id'])

    def test_create_vxlan_tenant_vlan_transparent_network(self):
        with self.pnet(VXLAN_PNET1) as pnet1, \
                self.pnet(VXLAN_PNET2) as pnet2:
            pnet1_data = pnet1['providernet']
            pnet2_data = pnet2['providernet']
            with self.pnet_range(pnet1_data, VXLAN_PNET1_RANGE1), \
                    self.pnet_range(pnet2_data, VXLAN_PNET2_RANGE1):
                with self.network(
                        arg_list=('vlan_transparent', ),
                        vlan_transparent=True) as net:
                    data = net['network']
                    self.assertTrue(data['vlan_transparent'])
                    self.assertEqual(data['provider:physical_network'],
                                     VXLAN_PNET2['name'])
                    self.assertEqual(data['provider:network_type'],
                                     VXLAN_PNET2['type'])
                    self.assertIsNotNone(data['provider:segmentation_id'])
                    self.assertEqual(data['mtu'], pnet2_data['mtu'])

    def test_create_vxlan_tenant_vlan_network_no_transparent_pnet(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1):
                self.assertReturnsApiError("NoNetworkAvailable",
                                           self._create_network,
                                           self.fmt, 'net1', True,
                                           arg_list=('vlan_transparent',),
                                           vlan_transparent=True)

    def test_create_flat_tenant_net(self):
        with self.pnet(FLAT_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.network(arg_list=('provider__physical_network',
                                        'provider__network_type',),
                              provider__physical_network=pnet_data['name'],
                              provider__network_type='flat') as net:
                data = net['network']
                self.assertEqual(data['provider:physical_network'],
                                 FLAT_PNET1['name'])
                self.assertEqual(data['provider:network_type'],
                                 FLAT_PNET1['type'])
                self.assertIsNone(data['provider:segmentation_id'])
                self.assertEqual(data['mtu'], pnet_data['mtu'])

    def test_create_flat_tenant_subnet(self):
        with self.pnet(FLAT_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.network(arg_list=('provider__physical_network',
                                        'provider__network_type',),
                              provider__physical_network=pnet_data['name'],
                              provider__network_type='flat') as net:
                data = net['network']
                self.assertEqual(data['provider:physical_network'],
                                 FLAT_PNET1['name'])
                self.assertEqual(data['provider:network_type'],
                                 FLAT_PNET1['type'])
                self.assertIsNone(data['provider:segmentation_id'])
                self.assertEqual(data['mtu'], pnet_data['mtu'])
                with self.subnet(net, cidr='1.2.3.0/24') as subnet:
                    sdata = subnet['subnet']
                    self.assertEqual(sdata[ext_pnet.PHYSICAL_NETWORK],
                                     data['provider:physical_network'])
                    self.assertEqual(sdata[ext_pnet.NETWORK_TYPE],
                                     data['provider:network_type'])
                    self.assertEqual(sdata[ext_pnet.SEGMENTATION_ID],
                                     data['provider:segmentation_id'])

    def test_create_vlan_tenant_net_with_out_of_range_vlan(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1):
                self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_network,
                                  self.fmt, 'net1', True,
                                  arg_list=('provider__physical_network',
                                            'provider__network_type',
                                            'provider__segmentation_id'),
                                  provider__physical_network=pnet_data['name'],
                                  provider__network_type='vlan',
                                  provider__segmentation_id='999')

    def test_create_vxlan_tenant_net_with_out_of_range_vxlan(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1):
                self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_network,
                                  self.fmt, 'net1', True,
                                  arg_list=('provider__physical_network',
                                            'provider__network_type',
                                            'provider__segmentation_id'),
                                  provider__physical_network=pnet_data['name'],
                                  provider__network_type='vxlan',
                                  provider__segmentation_id='999')

    def test_create_flat_tenant_net_on_vlan_pnet(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_network,
                              self.fmt, 'net1', True,
                              arg_list=('provider__physical_network',
                                        'provider__network_type',),
                              provider__physical_network=pnet_data['name'],
                              provider__network_type='flat')

    def test_create_flat_tenant_net_on_vxlan_pnet(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_network,
                              self.fmt, 'net1', True,
                              arg_list=('provider__physical_network',
                                        'provider__network_type',),
                              provider__physical_network=pnet_data['name'],
                              provider__network_type='flat')

    def test_create_vlan_tenant_net_on_flat_pnet(self):
        with self.pnet(FLAT_PNET1) as pnet:
            pnet_data = pnet['providernet']
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_network,
                              self.fmt, 'net1', True,
                              arg_list=('provider__physical_network',
                                        'provider__network_type',),
                              provider__physical_network=pnet_data['name'],
                              provider__network_type='vlan')

    def test_create_vlan_tenant_net_with_no_providernets(self):
        with self.pnet(VLAN_PNET1):
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_network,
                              self.fmt, 'net1', True)

    def test_create_flat_providernet(self):
        with self.pnet(FLAT_PNET1) as pnet:
            data = pnet['providernet']
            self.assertEqual(data['name'], FLAT_PNET1['name'])
            self.assertIsNotNone(data['id'])
            self.assertEqual(data['type'], n_const.PROVIDERNET_FLAT)
            ctxt = context.get_admin_context()
            result = self._plugin.get_providernet_segment_details(
                ctxt, n_const.PROVIDERNET_FLAT,
                data['name'], None)
            self.assertEqual(data['name'], result['name'])
            self.assertEqual(n_const.PROVIDERNET_FLAT, result['type'])
            self.assertFalse(result['vlan_transparent'])


class ProvidernetRangeTestCase(ProvidernetTestCaseMixin,
                               test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setup_config(self):
        super(ProvidernetRangeTestCase, self).setup_config()
        # Instantiate a fake host driver to allow us to control the host to
        # provider network mappings
        config.cfg.CONF.set_override('host_driver',
                                     'neutron.tests.unit.plugins.wrs.'
                                     'test_host_driver.TestHostDriver')

    def setUp(self, plugin=None, ext_mgr=None):
        super(ProvidernetRangeTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._host_driver = self._plugin.host_driver

    def tearDown(self):
        super(ProvidernetRangeTestCase, self).tearDown()

    def test_create_vlan_providernet_range(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                self.assertEqual(data['name'], VLAN_PNET1_RANGE1['name'])
                self.assertEqual(data['providernet_id'], pnet_data['id'])
                self.assertIsNotNone(data['id'])
                self.assertEqual(data['shared'], VLAN_PNET1_RANGE1['shared'])
                self.assertEqual(data['tenant_id'],
                                 VLAN_PNET1_RANGE1['tenant_id'])
                ctxt = context.get_admin_context()
                result = self._plugin.get_providernet_segment_details(
                    ctxt, n_const.PROVIDERNET_VLAN,
                    VLAN_PNET1['name'], VLAN_PNET1_RANGE1['minimum'])
                self.assertEqual(VLAN_PNET1['name'], result['name'])
                self.assertEqual(n_const.PROVIDERNET_VLAN, result['type'])
                self.assertFalse(result['vlan_transparent'])

    def test_create_vlan_providernet_range_overlap_all(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                range_data = copy.deepcopy(data)
                range_data['name'] = 'overlap'
                range_data['minimum'] -= 1
                range_data['maximum'] += 1
                self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_pnet_range,
                                  pnet_data, range_data)

    def test_create_vlan_providernet_range_overlap_bottom(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                range_data = copy.deepcopy(data)
                range_data['name'] = 'overlap'
                range_data['minimum'] -= 1
                range_data['maximum'] -= 1
                self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_pnet_range,
                                  pnet_data, range_data)

    def test_create_vlan_providernet_range_overlap_top(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                range_data = copy.deepcopy(data)
                range_data['name'] = 'overlap'
                range_data['minimum'] += 1
                range_data['maximum'] += 1
                self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_pnet_range,
                                  pnet_data, range_data)

    def test_create_vlan_providernet_range_overlap_inside(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                range_data = copy.deepcopy(data)
                range_data['name'] = 'overlap'
                range_data['minimum'] += 1
                range_data['maximum'] -= 1
                self.assertRaises(webob.exc.HTTPClientError,
                                  self._make_pnet_range,
                                  pnet_data, range_data)

    def test_create_vlan_providernet_range_no_overlap_below(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                range_data = copy.deepcopy(data)
                range_data['name'] = 'overlap'
                range_data['minimum'] -= 5
                range_data['maximum'] = range_data['minimum'] + 2
                with self.pnet_range(pnet_data, range_data) as pnet_range2:
                    data = pnet_range2['providernet_range']
                    self.assertEqual(data['name'], range_data['name'])

    def test_create_vlan_providernet_range_no_overlap_above(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                range_data = copy.deepcopy(data)
                range_data['name'] = 'overlap'
                range_data['maximum'] += 50
                range_data['minimum'] = range_data['maximum'] - 2
                with self.pnet_range(pnet_data, range_data) as pnet_range2:
                    data = pnet_range2['providernet_range']
                    self.assertEqual(data['name'], range_data['name'])

    def test_create_vlan_providernet_range_minimum_id(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VLAN_PNET1_RANGE1)
            range_data['minimum'] = 0
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vlan_providernet_range_maximum_id(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VLAN_PNET1_RANGE1)
            range_data['maximum'] = 16384
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vlan_providernet_range_shared(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = VLAN_PNET1_RANGE1
            range_data['shared'] = True
            with self.pnet_range(pnet_data, range_data) as pnet_range:
                data = pnet_range['providernet_range']
                self.assertEqual(data['name'], range_data['name'])
                self.assertEqual(data['providernet_id'], pnet_data['id'])
                self.assertIsNotNone(data['id'])
                self.assertTrue(data['shared'])

    def test_create_vlan_providernet_range_invalid_pnet(self):
        pnet = VLAN_PNET1
        pnet['id'] = str(uuid.uuid4())
        self.assertRaises(webob.exc.HTTPClientError,
                          self._make_pnet_range,
                          pnet, VLAN_PNET1_RANGE1)

    def test_create_vxlan_providernet_range(self):
        with self.pnet(VXLAN_PNET2) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET2_RANGE1) as pnet_range:
                data = pnet_range['providernet_range']
                self.assertEqual(data['name'], VXLAN_PNET2_RANGE1['name'])
                self.assertEqual(data['providernet_id'], pnet_data['id'])
                self.assertIsNotNone(data['id'])
                vxlan = data['vxlan']
                self.assertEqual(vxlan['group'], VXLAN_PNET2_RANGE1['group'])
                self.assertEqual(vxlan['port'], VXLAN_PNET2_RANGE1['port'])
                self.assertEqual(vxlan['ttl'], VXLAN_PNET2_RANGE1['ttl'])
                ctxt = context.get_admin_context()
                result = self._plugin.get_providernet_segment_details(
                    ctxt, n_const.PROVIDERNET_VXLAN,
                    VXLAN_PNET2['name'], VXLAN_PNET2_RANGE1['minimum'])
                self.assertEqual(VXLAN_PNET2['name'], result['name'])
                self.assertEqual(n_const.PROVIDERNET_VXLAN, result['type'])
                self.assertEqual(VXLAN_PNET2_RANGE1['group'],
                                 result['vxlan']['group'])
                self.assertTrue(result['vlan_transparent'])

    def test_create_vxlan_multiple_providernet_range(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1):
                with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE2):
                    ctxt = context.get_admin_context()
                    # Check that get_providernet_segment_details returns the
                    # range data for the first range.
                    result1 = self._plugin.get_providernet_segment_details(
                        ctxt, n_const.PROVIDERNET_VXLAN,
                        VXLAN_PNET1['name'], VXLAN_PNET1_RANGE1['minimum'])
                    self.assertEqual(VXLAN_PNET1['name'], result1['name'])
                    self.assertEqual(n_const.PROVIDERNET_VXLAN,
                                     result1['type'])
                    self.assertEqual(VXLAN_PNET1_RANGE1['group'],
                                     result1['vxlan']['group'])
                    self.assertFalse(result1['vlan_transparent'])
                    # Check that get_providernet_segment_details returns the
                    # range data for the second range.
                    result2 = self._plugin.get_providernet_segment_details(
                        ctxt, n_const.PROVIDERNET_VXLAN,
                        VXLAN_PNET1['name'], VXLAN_PNET1_RANGE2['minimum'])
                    self.assertEqual(VXLAN_PNET1['name'], result2['name'])
                    self.assertEqual(n_const.PROVIDERNET_VXLAN,
                                     result2['type'])
                    self.assertEqual(VXLAN_PNET1_RANGE2['group'],
                                     result2['vxlan']['group'])
                    self.assertFalse(result2['vlan_transparent'])

    def test_create_vxlan_providernet_range_minimum_ttl(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE2)
            range_data['ttl'] = n_const.MINIMUM_TTL
            with self.pnet_range(pnet_data, range_data) as pnet_range:
                data = pnet_range['providernet_range']
                self.assertEqual(data['name'], VXLAN_PNET1_RANGE2['name'])
                self.assertEqual(data['providernet_id'], pnet_data['id'])
                self.assertIsNotNone(data['id'])
                vxlan = data['vxlan']
                self.assertEqual(vxlan['group'], VXLAN_PNET1_RANGE2['group'])
                self.assertEqual(vxlan['port'], VXLAN_PNET1_RANGE2['port'])
                self.assertEqual(vxlan['ttl'], range_data['ttl'])

    def test_create_vxlan_providernet_range_maximum_ttl(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE2)
            range_data['ttl'] = n_const.MAXIMUM_TTL
            with self.pnet_range(pnet_data, range_data) as pnet_range:
                data = pnet_range['providernet_range']
                self.assertEqual(data['name'], VXLAN_PNET1_RANGE2['name'])
                self.assertEqual(data['providernet_id'], pnet_data['id'])
                self.assertIsNotNone(data['id'])
                vxlan = data['vxlan']
                self.assertEqual(vxlan['group'], VXLAN_PNET1_RANGE2['group'])
                self.assertEqual(vxlan['port'], VXLAN_PNET1_RANGE2['port'])
                self.assertEqual(vxlan['ttl'], range_data['ttl'])

    def test_create_vxlan_providernet_range_invalid_port(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['port'] = 1234
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_below_minimum_ttl(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['ttl'] = n_const.MINIMUM_TTL - 1
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_above_maximum_ttl(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['ttl'] = n_const.MAXIMUM_TTL + 1
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_missing_ttl(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            del range_data['ttl']
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_invalid_group(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['group'] = 'invalid'
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_missing_group(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            del range_data['group']
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_unicast_group(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['group'] = '1.2.3.4'
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_unicast_ipv6_group(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['group'] = 'fd10::1'
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_minimum_id(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['minimum'] = 0
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_maximum_id(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['maximum'] = (2 ** 24)
            self.assertRaises(webob.exc.HTTPClientError,
                              self._make_pnet_range,
                              pnet_data, range_data)

    def test_create_vxlan_providernet_range_shared(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            range_data = copy.deepcopy(VXLAN_PNET1_RANGE1)
            range_data['shared'] = True
            with self.pnet_range(pnet_data, range_data) as pnet_range:
                data = pnet_range['providernet_range']
                self.assertEqual(data['name'], range_data['name'])
                self.assertEqual(data['providernet_id'], pnet_data['id'])
                self.assertIsNotNone(data['id'])
                self.assertTrue(data['shared'])


class ProvidernetRangeUpdateTestCase(ProvidernetTestCaseMixin,
                                     test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setup_config(self):
        super(ProvidernetRangeUpdateTestCase, self).setup_config()
        # Instantiate a fake host driver to allow us to control the host to
        # provider network mappings
        config.cfg.CONF.set_override('host_driver',
                                     'neutron.tests.unit.plugins.wrs.'
                                     'test_host_driver.TestHostDriver')

    def setUp(self, plugin=None, ext_mgr=None):
        super(ProvidernetRangeUpdateTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._host_driver = self._plugin.host_driver

    def tearDown(self):
        super(ProvidernetRangeUpdateTestCase, self).tearDown()

    def test_update_vlan_range_with_larger_range_no_orphans(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VLAN_PNET1_RANGE1['minimum'] - 1,
                             'maximum': VLAN_PNET1_RANGE1['maximum'] + 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)
                    body = self.deserialize(self.fmt, response)
                    self.assertEqual(body['providernet_range']['minimum'],
                                     data['providernet_range']['minimum'])
                    self.assertEqual(body['providernet_range']['maximum'],
                                     data['providernet_range']['maximum'])

    def test_update_vlan_range_with_smaller_range_no_orphans(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VLAN_PNET1_RANGE1['minimum'],
                             'maximum': VLAN_PNET1_RANGE1['maximum'] - 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)
                    body = self.deserialize(self.fmt, response)
                    self.assertEqual(body['providernet_range']['minimum'],
                                     data['providernet_range']['minimum'])
                    self.assertEqual(body['providernet_range']['maximum'],
                                     data['providernet_range']['maximum'])

    def test_update_vlan_range_with_orphans_above(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VLAN_PNET1_RANGE1['maximum'] + 1,
                             'maximum': VLAN_PNET1_RANGE1['maximum'] + 2}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vlan_range_with_orphans_below(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VLAN_PNET1_RANGE1['minimum'] - 2,
                             'maximum': VLAN_PNET1_RANGE1['minimum'] - 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vlan_range_with_no_orphans_bottom(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VLAN_PNET1_RANGE1['minimum'] - 2,
                             'maximum': VLAN_PNET1_RANGE1['minimum'] + 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)
                    body = self.deserialize(self.fmt, response)
                    self.assertEqual(body['providernet_range']['minimum'],
                                     data['providernet_range']['minimum'])
                    self.assertEqual(body['providernet_range']['maximum'],
                                     data['providernet_range']['maximum'])

    def test_update_vlan_range_with_orphans_top(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VLAN_PNET1_RANGE1['maximum'] - 2,
                             'maximum': VLAN_PNET1_RANGE1['maximum'] + 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vlan_range_with_orphans_inside(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network() as net:
                    net_data = net['network']
                    segmentation_id = net_data['provider:segmentation_id']
                    data = {'providernet_range':
                            {'minimum': segmentation_id + 1,
                             'maximum': VLAN_PNET1_RANGE1['maximum']}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vlan_range_with_no_orphans_used(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network() as net:
                    net_data = net['network']
                    segmentation_id = net_data['provider:segmentation_id']
                    data = {'providernet_range':
                            {'minimum': segmentation_id,
                             'maximum': segmentation_id}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)

    def test_update_vlan_range_with_invalid_minimum(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                data = {'providernet_range': {'minimum': 0,
                                              'maximum': 10}}
                request = self.new_update_request(
                    'wrs-provider/providernet-ranges',
                    data, range_data['id'])
                response = request.get_response(self.ext_api)
                self.assertEqual(response.status_int, 500)

    def test_update_vlan_range_with_invalid_maximum(self):
        with self.pnet(VLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                data = {'providernet_range': {'minimum': 1,
                                              'maximum': (2 ** 24)}}
                request = self.new_update_request(
                    'wrs-provider/providernet-ranges',
                    data, range_data['id'])
                response = request.get_response(self.ext_api)
                self.assertEqual(response.status_int, 500)

    def test_update_vxlan_range_with_larger_range_no_orphans(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VXLAN_PNET1_RANGE1['minimum'] - 1,
                             'maximum': VXLAN_PNET1_RANGE1['maximum'] + 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)
                    body = self.deserialize(self.fmt, response)
                    self.assertEqual(body['providernet_range']['minimum'],
                                     data['providernet_range']['minimum'])
                    self.assertEqual(body['providernet_range']['maximum'],
                                     data['providernet_range']['maximum'])

    def test_update_vxlan_range_with_smaller_range_no_orphans(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VXLAN_PNET1_RANGE1['minimum'],
                             'maximum': VXLAN_PNET1_RANGE1['maximum'] - 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)
                    body = self.deserialize(self.fmt, response)
                    self.assertEqual(body['providernet_range']['minimum'],
                                     data['providernet_range']['minimum'])
                    self.assertEqual(body['providernet_range']['maximum'],
                                     data['providernet_range']['maximum'])

    def test_update_vxlan_range_with_orphans_above(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VXLAN_PNET1_RANGE1['maximum'] + 1,
                             'maximum': VXLAN_PNET1_RANGE1['maximum'] + 2}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vxlan_range_with_orphans_below(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VXLAN_PNET1_RANGE1['minimum'] - 2,
                             'maximum': VXLAN_PNET1_RANGE1['minimum'] - 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vxlan_range_with_no_orphans_bottom(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VXLAN_PNET1_RANGE1['minimum'] - 2,
                             'maximum': VXLAN_PNET1_RANGE1['minimum'] + 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)
                    body = self.deserialize(self.fmt, response)
                    self.assertEqual(body['providernet_range']['minimum'],
                                     data['providernet_range']['minimum'])
                    self.assertEqual(body['providernet_range']['maximum'],
                                     data['providernet_range']['maximum'])

    def test_update_vxlan_range_with_orphans_top(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network():
                    data = {'providernet_range':
                            {'minimum': VXLAN_PNET1_RANGE1['maximum'] - 2,
                             'maximum': VXLAN_PNET1_RANGE1['maximum'] + 1}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vxlan_range_with_orphans_inside(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network() as net:
                    net_data = net['network']
                    segmentation_id = net_data['provider:segmentation_id']
                    data = {'providernet_range':
                            {'minimum': segmentation_id + 1,
                             'maximum': VXLAN_PNET1_RANGE1['maximum']}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 500)

    def test_update_vxlan_range_with_no_orphans_used(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                with self.network() as net:
                    net_data = net['network']
                    segmentation_id = net_data['provider:segmentation_id']
                    data = {'providernet_range':
                            {'minimum': segmentation_id,
                             'maximum': segmentation_id}}
                    request = self.new_update_request(
                        'wrs-provider/providernet-ranges',
                        data, range_data['id'])
                    response = request.get_response(self.ext_api)
                    self.assertEqual(response.status_int, 200)

    def test_update_vxlan_range_with_invalid_minimum(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                data = {'providernet_range': {'minimum': 0,
                                              'maximum': 10}}
                request = self.new_update_request(
                    'wrs-provider/providernet-ranges',
                    data, range_data['id'])
                response = request.get_response(self.ext_api)
                self.assertEqual(response.status_int, 500)

    def test_update_vxlan_range_with_invalid_maximum(self):
        with self.pnet(VXLAN_PNET1) as pnet:
            pnet_data = pnet['providernet']
            with self.pnet_range(pnet_data, VXLAN_PNET1_RANGE1) as pnet_range:
                range_data = pnet_range['providernet_range']
                data = {'providernet_range': {'minimum': 1,
                                              'maximum': (2 ** 24)}}
                request = self.new_update_request(
                              'wrs-provider/providernet-ranges',
                              data, range_data['id'])
                response = request.get_response(self.ext_api)
                self.assertEqual(response.status_int, 500)


class ProvidernetConnectivityTestCase(ProvidernetTestCaseMixin,
                                      test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setup_config(self):
        super(ProvidernetConnectivityTestCase, self).setup_config()
        # Instantiate a fake host driver to allow us to control the host to
        # provider network mappings
        config.cfg.CONF.set_override('host_driver',
                                     'neutron.tests.unit.plugins.wrs.'
                                     'test_host_driver.TestHostDriver')

    def setUp(self, plugin=None, ext_mgr=None):
        super(ProvidernetConnectivityTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._host_driver = self._plugin.host_driver
        self.client = mock.patch.object(n_rpc, "get_client").start()
        self.rpc = pnet_connectivity_rpc.PnetConnectivityRpcApi('fake_topic')
        self.mock_cctxt = self.rpc.client.prepare.return_value
        self.ctxt = mock.ANY
        self.notifier = pnet_connectivity_rpc_agent_api.\
            PnetConnectivityAgentNotifyAPI(topic='fake-topic')

    def test_notify_schedule_providernet_audit_generic(self):
        with self.pnet_connectivity_state():
            pass

    def test_setup_connectivity_audit_rpc(self):
        self.notifier.setup_connectivity_audit(self.ctxt,
                                               hostname=HOST_1,
                                               audit_uuid=AUDIT_1,
                                               providernet=VLAN_PNET1,
                                               segments=[],
                                               extra_data={})
        self.mock_cctxt.call.assert_called_with(self.ctxt,
                                                'setup_connectivity_audit',
                                                audit_uuid=AUDIT_1,
                                                providernet=VLAN_PNET1,
                                                segments=[],
                                                extra_data={})

    def test_start_connectivity_audit_rpc(self):
        self.notifier.start_connectivity_audit(self.ctxt,
                                               audit_uuid=AUDIT_1,
                                               masters=[],
                                               hosts=[],
                                               providernet=VLAN_PNET1,
                                               segments=[],
                                               extra_data={})
        self.mock_cctxt.cast.assert_called_with(self.ctxt,
                                                'start_connectivity_audit',
                                                audit_uuid=AUDIT_1,
                                                masters=[],
                                                hosts=[],
                                                providernet=VLAN_PNET1,
                                                segments=[],
                                                extra_data={})

    def test_report_connectivity_results_rpc(self):
        self.rpc.report_connectivity_results(self.ctxt,
                                             audit_results=[],
                                             audit_uuid=AUDIT_1)
        self.mock_cctxt.cast.assert_called_with(self.ctxt,
                                                'report_connectivity_results',
                                                audit_results=[],
                                                audit_uuid=AUDIT_1)

    def test_teardown_connectivity_audit_rpc(self):
        self.notifier.teardown_connectivity_audit(self.ctxt,
                                                  hostname=HOST_1,
                                                  audit_uuid=AUDIT_1)
        self.mock_cctxt.call.assert_called_with(self.ctxt,
                                                'teardown_connectivity_audit',
                                                audit_uuid=AUDIT_1)
