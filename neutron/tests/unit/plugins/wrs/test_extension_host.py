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
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

import contextlib
import copy

import six
import webob.exc

from neutron_lib.utils import helpers as lib_helpers
from oslo_log import log as logging

from neutron.common import constants
from neutron.tests.common import helpers
from neutron.tests.unit.plugins.wrs import test_wrs_plugin

LOG = logging.getLogger(__name__)


HOST1 = {'name': 'compute-0',
         'id': '065aa1d1-84ed-4d59-a777-16b0ea8a5640',
         'availability': constants.HOST_UP}

HOST2 = {'name': 'compute-1',
         'id': '31df579d-d9ea-4623-a5a6-1bb0ccad22ef',
         'availability': constants.HOST_DOWN}


class HostTestCaseMixin(object):

    def _update_host(self, id, body):
        data = {'host': body}
        request = self.new_update_request('hosts', data, id)
        response = request.get_response(self.ext_api)
        return self.deserialize(self.fmt, response)

    def _bind_interface(self, id, body):
        data = {'interface': body}
        request = self.new_action_request('hosts', data, id,
                                          'bind_interface')
        return request.get_response(self.ext_api)

    def _unbind_interface(self, id, body):
        data = {'interface': body}
        request = self.new_action_request('hosts', data, id,
                                          'unbind_interface')
        return request.get_response(self.ext_api)

    def _create_host(self, host):
        data = {'host': {'name': host['name'],
                         'tenant_id': self._tenant_id}}
        for arg in ('id', 'availability'):
            data['host'][arg] = host[arg]
        request = self.new_create_request('hosts', data)
        return request.get_response(self.ext_api)

    def _make_host(self, host):
        response = self._create_host(host)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    def _make_interface(self, id, interface):
        response = self._bind_interface(id, interface)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    def _delete_interface(self, id, interface):
        response = self._unbind_interface(id, interface)
        if response.status_int >= 400:
            raise webob.exc.HTTPClientError(code=response.status_int)
        return self.deserialize(self.fmt, response)

    @contextlib.contextmanager
    def host(self, host, no_delete=False):
        host = self._make_host(host)
        try:
            yield host
        finally:
            if not no_delete:
                self._delete('hosts', host['host']['id'])

    def _create_test_interfaces(self, interfaces):
        self._interfaces = copy.deepcopy(interfaces)
        for name, host in six.iteritems(self._hosts):
            interface = self._interfaces.get(host['name'])
            if not interface:
                continue
            # Add to "sysinv" first
            self._host_driver.add_interface(host['name'], interface)
            # Then, add to the plugin
            self._make_interface(host['id'], interface)

    def _delete_test_interfaces(self):
        for name, host in six.iteritems(self._hosts):
            interface = self._interfaces.get(host['name'])
            if not interface:
                continue
            self._delete_interface(host['id'], interface)

    def _create_test_hosts(self, hosts):
        for host in hosts:
            data = self._make_host(host)
            self._hosts[host['name']] = data['host']
            self._host_driver.add_host(data['host'])

    def _delete_test_hosts(self):
        for name, host in six.iteritems(self._hosts):
            self._delete('hosts', host['id'])
        self._hosts = []

    def _get_pnet(self, name):
        return self._pnets.get(name, None)

    def _create_test_providernets(self, pnets, pnet_ranges):
        for pnet in pnets:
            data = self._make_pnet(pnet)
            self._pnets[pnet['name']] = data['providernet']
            # create segmentation ranges for each provider network
            pnet_ranges.setdefault(pnet['name'], [])
            for pnet_range in pnet_ranges[pnet['name']]:
                data = self._make_pnet_range(data['providernet'], pnet_range)
                self._pnet_ranges[pnet_range['name']] = data

    def _delete_test_providernets(self):
        for name, pnet in six.iteritems(self._pnets):
            self._delete('wrs-provider/providernets', pnet['id'])
        self._pnets = []

    def _register_avs_agent(self, host=None, mappings=None):
        agent = helpers._get_l2_agent_dict(
            host, constants.AGENT_TYPE_WRS_VSWITCH,
            'neutron-avs-agent')
        agent['configurations']['mappings'] = mappings
        return helpers._register_agent(agent, self._plugin)

    def _create_l2_agents(self):
        for name, host in six.iteritems(self._hosts):
            iface = self._interfaces[name]
            mappings = ['%s:%s' % (p, iface['uuid'])
                        for p in iface['providernets'].split(',')]
            mappings_dict = lib_helpers.parse_mappings(mappings,
                                                       unique_values=False)
            self._register_avs_agent(
                host=name, mappings=mappings_dict)

    def _update_host_states(self):
        for name, host in six.iteritems(self._hosts):
            updates = {'availability': constants.HOST_UP}
            data = self._update_host(host['id'], updates)
            self._hosts[name] = data['host']

    def _prepare_test_dependencies(self, hosts, providernets,
                                   providernet_ranges, interfaces):
        self._create_test_hosts(hosts)
        self._create_test_providernets(providernets, providernet_ranges)
        self._create_test_interfaces(interfaces)
        self._create_l2_agents()
        self._update_host_states()

    def _cleanup_test_dependencies(self):
        self._delete_test_interfaces()
        self._delete_test_hosts()
        self._delete_test_providernets()


class HostTestCase(HostTestCaseMixin,
                   test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setUp(self, plugin=None, ext_mgr=None):
        self.host1 = HOST1
        self.host2 = HOST2
        super(HostTestCase, self).setUp()

    def tearDown(self):
        super(HostTestCase, self).tearDown()

    def test_create_host(self):
        with self.host(self.host1) as host:
            self.assertEqual(host['host']['name'], self.host1['name'])
            self.assertIsNotNone(host['host']['id'])

    def test_update_host(self):
        with self.host(self.host1) as host:
            self.assertEqual(host['host']['availability'],
                             constants.HOST_UP)
            data = {'host': {'availability': constants.HOST_DOWN}}
            request = self.new_update_request('hosts', data,
                                              host['host']['id'])
            response = request.get_response(self.ext_api)
            self.assertEqual(response.status_int, 200)
            body = self.deserialize(self.fmt, response)
            self.assertEqual(body['host']['availability'],
                             constants.HOST_DOWN)
