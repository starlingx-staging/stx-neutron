# Copyright 2017 NEC India
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
from oslo_utils import uuidutils

from neutron.tests.fullstack import base
from neutron.tests.fullstack.resources import environment
from neutron.tests.unit import testlib_api

load_tests = testlib_api.module_load_tests


class MTUNetworkTestSetup(base.BaseFullStackTestCase):
    of_interface = None
    ovsdb_interface = None
    number_of_hosts = 1

    def setUp(self):
        host_desc = [
            environment.HostDescription(
                l3_agent=False,
                of_interface=self.of_interface,
                ovsdb_interface=self.ovsdb_interface,
                l2_agent_type=self.l2_agent_type
            ) for _ in range(self.number_of_hosts)]
        env_desc = environment.EnvironmentDescription()
        env = environment.Environment(env_desc, host_desc)
        super(MTUNetworkTestSetup, self).setUp(env)

        self.tenant_id = uuidutils.generate_uuid()
        self.subnet = self.safe_client.create_subnet(
            self.tenant_id, self.network['id'],
            cidr='10.0.0.0/24',
            gateway_ip='10.0.0.1',
            name='subnet-test',
            enable_dhcp=False)

    def _restart_neutron_server(self):
        env_desc = environment.EnvironmentDescription(global_mtu=9000)
        env = environment.Environment(env_desc, self.host_desc)
        env.test_name = self.get_name()
        self.useFixture(env)
        env.neutron_server.restart()

    def _create_network(self, mtu):
        return self.safe_client.create_network(self.tenant_id,
                                               mtu=mtu, name='test-network')

    def _update_network(self, mtu):
        return self.safe_client.update_network(self.tenant_id,
                                               mtu=mtu, name='test-network')

    def _delete_network(self):
        return self.safe_client.delete_network(self.tenant_id)


class TestMTUScenarios(MTUNetworkTestSetup, base.BaseFullStackTestCase):

    def test_mtu_success_scenario(self):
        self._create_network(1450)
        self._update_network(9000)
        res = self._delete_network()
        self.assertEqual(0, res)

    def test_mtu_failure_scenario(self):
        self._create_network(9000)
        self.assertRaises(self.exception, self._update_network, 1450)
        self._restart_neutron_server()
        res = self._delete_network()
        self.assertEqual(0, res)
