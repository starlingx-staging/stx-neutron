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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

import collections
import copy
import datetime
import math
import uuid

import six


from neutron_lib import constants
from oslo_log import log as logging
from oslo_utils import timeutils

from neutron.common import constants as n_const
from neutron.common import topics
from neutron.db import agents_db
from neutron.extensions import wrs_net
from neutron.plugins.ml2 import config
from neutron.tests.unit.db import test_db_base_plugin_v2
from neutron.tests.unit.extensions import test_agent
from neutron.tests.unit.extensions import test_l3
from neutron.tests.unit.plugins.wrs import test_extension_host
from neutron.tests.unit.plugins.wrs import test_extension_pnet
from neutron.tests.unit.plugins.wrs import test_wrs_plugin
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

HOST1 = {'name': 'compute-0',
         'id': '065aa1d1-84ed-4d59-a777-16b0ea8a5640',
         'availability': n_const.HOST_DOWN}

HOST2 = {'name': 'compute-1',
         'id': '28c25767-e6e7-49c3-9735-2ef5ff04c4a2',
         'availability': n_const.HOST_DOWN}

HOST3 = {'name': 'compute-2',
         'id': 'c947cbd0-f59a-4ab1-b0c6-1e12bd4846ab',
         'availability': n_const.HOST_DOWN}

HOST4 = {'name': 'compute-3',
         'id': '89bfbe7a-c416-4c32-ae65-bc390fa0a908',
         'availability': n_const.HOST_DOWN}

HOST5 = {'name': 'compute-4',
         'id': '81c8fbd6-4512-4d83-9b86-c1ab90bbb587',
         'availability': n_const.HOST_DOWN}

HOSTS = (HOST1, HOST2, HOST3, HOST4, HOST5)

PNET1 = {'name': 'vlan-pnet0',
         'type': n_const.PROVIDERNET_VLAN,
         'description': 'vlan test provider network'}

PNET2 = {'name': 'vlan-pnet1',
         'type': n_const.PROVIDERNET_VLAN,
         'description': 'vlan test provider network'}

PNET3 = {'name': 'flat-pnet0',
         'type': n_const.PROVIDERNET_FLAT,
         'description': 'flat test provider network'}

# PNET4 should not be bound to a compute node
PNET4 = {'name': 'flat-pnet1',
         'type': n_const.PROVIDERNET_FLAT,
         'description': 'flat test provider network'}

PNET5 = {'name': 'flat-sriov-pnet1',
         'type': n_const.PROVIDERNET_FLAT,
         'description': 'flat test provider network for sriov networks'}

PNET6 = {'name': 'flat-pnet2',
         'type': n_const.PROVIDERNET_FLAT,
         'description': 'flat test provider network'}

PNETS = (PNET1, PNET2, PNET3, PNET4, PNET5, PNET6)

PNET1_RANGE1 = {'name': 'vlan-pnet0-0',
                'description': 'vlan range1',
                'shared': False,
                'minimum': 1,
                'maximum': 100,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET2_RANGE1 = {'name': 'vlan-pnet1-0',
                'description': 'vlan range1',
                'shared': False,
                'minimum': 101,
                'maximum': 200,
                'tenant_id': test_db_base_plugin_v2.TEST_TENANT_ID}

PNET_RANGES = {'vlan-pnet0': [PNET1_RANGE1],
               'vlan-pnet1': [PNET2_RANGE1]}

PNET_BINDINGS = {'compute-0': ['vlan-pnet0', 'vlan-pnet1', 'flat-pnet0'],
                 'compute-1': ['vlan-pnet0', 'vlan-pnet1', 'flat-pnet0'],
                 'compute-2': ['vlan-pnet0', 'vlan-pnet1'],
                 'compute-3': ['flat-sriov-pnet1'],
                 'compute-4': ['flat-pnet2']}

INTERFACE1 = {'uuid': str(uuid.uuid4()),
              'mtu': n_const.DEFAULT_MTU,
              'vlans': '',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-0'])}

INTERFACE2 = {'uuid': str(uuid.uuid4()),
              'mtu': n_const.DEFAULT_MTU,
              'vlans': '4001,,4002, 4003',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-1'])}

INTERFACE3 = {'uuid': str(uuid.uuid4()),
              'mtu': n_const.DEFAULT_MTU,
              'vlans': '4001',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-2'])}

INTERFACE4 = {'uuid': str(uuid.uuid4()),
              'mtu': n_const.DEFAULT_MTU,
              'vlans': '4001',
              'network_type': 'pci-sriov',
              'providernets': ','.join(PNET_BINDINGS['compute-3'])}

INTERFACE5 = {'uuid': str(uuid.uuid4()),
              'mtu': n_const.DEFAULT_MTU,
              'vlans': '4001',
              'network_type': 'data',
              'providernets': ','.join(PNET_BINDINGS['compute-4'])}

INTERFACES = {'compute-0': INTERFACE1,
              'compute-1': INTERFACE2,
              'compute-2': INTERFACE3,
              'compute-3': INTERFACE4,
              'compute-4': INTERFACE5}

NET1 = {'name': 'tenant-net0',
        'provider__physical_network': 'vlan-pnet0',
        'provider__network_type': n_const.PROVIDERNET_VLAN}

NET2 = {'name': 'tenant-net1',
        'provider__physical_network': 'vlan-pnet1',
        'provider__network_type': n_const.PROVIDERNET_VLAN}

NET3 = {'name': 'external-net0',
        'router__external': True,
        'provider__physical_network': 'flat-pnet0',
        'provider__network_type': n_const.PROVIDERNET_FLAT}

NET4 = {'name': 'tenant-net2',
        'provider__physical_network': 'flat-pnet1',
        'provider__network_type': n_const.PROVIDERNET_FLAT}

NET5 = {'name': 'tenant-net3',
        'provider__physical_network': 'flat-sriov-pnet1',
        'provider__network_type': n_const.PROVIDERNET_FLAT}

NET6 = {'name': 'tenant-net4',
        'provider__physical_network': 'flat-pnet2',
        'provider__network_type': n_const.PROVIDERNET_FLAT}

NET7 = {'name': 'tenant-net5',
        'provider__physical_network': 'vlan-pnet0',
        'provider__network_type': n_const.PROVIDERNET_VLAN}

NETS = (NET1, NET2, NET3, NET4, NET5, NET6, NET7)

SUBNET1 = {'name': 'tenant-subnet0',
           'cidr': '192.168.1.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.1.1'}

SUBNET2 = {'name': 'tenant-subnet1',
           'cidr': '192.168.2.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.2.1'}

SUBNET3 = {'name': 'external-subnet0',
           'cidr': '192.168.3.0/24',
           'shared': True,
           'enable_dhcp': False,
           'gateway': '192.168.3.1'}

SUBNET4 = {'name': 'tenant-subnet3',
           'cidr': '192.168.4.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.4.1'}

SUBNET5 = {'name': 'tenant-subnet4',
           'cidr': '192.168.5.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.5.1'}

SUBNET6 = {'name': 'tenant-subnet5',
           'cidr': '192.168.6.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.6.1'}

SUBNET7 = {'name': 'tenant-subnet6',
           'cidr': '192.168.7.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.7.1'}

SUBNET8 = {'name': 'tenant-subnet7',
           'cidr': '192.168.8.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.8.1'}

SUBNET9 = {'name': 'tenant-subnet8',
           'cidr': '192.168.9.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.9.1'}

SUBNET10 = {'name': 'tenant-subnet9',
           'cidr': '192.168.10.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.10.1'}

SUBNET11 = {'name': 'tenant-subnet10',
           'cidr': '192.168.11.0/24',
           'shared': False,
           'enable_dhcp': True,
           'gateway': '192.168.11.1'}


SUBNETS = {'tenant-net0': [SUBNET1],
           'tenant-net1': [SUBNET2],
           'external-net0': [SUBNET3],
           'tenant-net2': [SUBNET4],
           'tenant-net3': [SUBNET5],
           'tenant-net4': [SUBNET6],
           'tenant-net5': [SUBNET7, SUBNET8, SUBNET9, SUBNET10]}

L3_AGENT_TEMPLATE = {
    'binary': 'neutron-l3-agent',
    'host': 'TBD',
    'topic': topics.L3_AGENT,
    'admin_state_up': True,
    'configurations': {'use_namespaces': True,
                       'router_id': None,
                       'handle_internal_only_routers': True,
                       'gateway_external_network_id': None,
                       'interface_driver': 'interface_driver',
                       },
    'agent_type': constants.AGENT_TYPE_L3}

DHCP_AGENT_TEMPLATE = {
    'binary': 'neutron-dhcp-agent',
    'host': 'TBD',
    'topic': topics.DHCP_AGENT,
    'admin_state_up': True,
    'configurations': {'dhcp_driver': 'dhcp_driver',
                       'use_namespaces': True,
                       },
    'agent_type': constants.AGENT_TYPE_DHCP}


class FakeAgent(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __getitem__(self, k):
        return self.__dict__.get(k)


class WrsAgentSchedulerTestCase(test_extension_pnet.ProvidernetTestCaseMixin,
                                test_extension_host.HostTestCaseMixin,
                                test_l3.L3NatTestCaseMixin,
                                test_agent.AgentDBTestMixIn,
                                test_wrs_plugin.WrsMl2PluginV2TestCase):

    def setup_config(self):
        super(WrsAgentSchedulerTestCase, self).setup_config()
        # Instantiate a fake host driver to allow us to control the host to
        # provider network mappings
        config.cfg.CONF.set_override('host_driver',
                                     'neutron.tests.unit.plugins.wrs.'
                                     'test_host_driver.TestHostDriver')

    def setUp(self, plugin=None, ext_mgr=None):
        self._hosts = {}
        self._pnets = {}
        self._pnet_ranges = {}
        self._nets = {}
        self._subnets = {}
        self._dhcp_agents = {}
        self._l3_agents = {}
        super(WrsAgentSchedulerTestCase, self).setUp()
        self._plugin = directory.get_plugin()
        self._l3_plugin = directory.get_plugin(plugin_constants.L3)
        self._l3_scheduler = self._l3_plugin.router_scheduler
        self._dhcp_scheduler = self._plugin.network_scheduler
        self._host_driver = self._plugin.host_driver
        self._l3_plugin.agent_notifiers = {}
        self._plugin.agent_notifiers = {}
        self._prepare_test_dependencies(hosts=HOSTS,
                                        providernets=PNETS,
                                        providernet_ranges=PNET_RANGES,
                                        interfaces=INTERFACES,
                                        networks=NETS,
                                        subnets=SUBNETS)

    def tearDown(self):
        self._cleanup_test_dependencies()
        super(WrsAgentSchedulerTestCase, self).tearDown()

    def _get_subnet_id(self, name):
        return self._subnets[name]['id']

    def _get_net_id(self, name):
        return self._nets[name]['id']

    def _get_network(self, name):
        return self._nets[name]

    def _get_host_id(self, name):
        return self._hosts[name]['id']

    def _lock_test_host(self, id):
        body = {'availability': n_const.HOST_DOWN}
        data = self._update_host(id, body)
        self.assertEqual(data['host']['availability'],
                         n_const.HOST_DOWN)

    def _lock_test_hosts(self, hosts=HOSTS):
        for host in hosts:
            self._lock_test_host(host['id'])

    def _query_router_host(self, id):
        router = self._l3_plugin.get_router(self.adminContext, id)
        self.assertIsNotNone(router)
        return router[wrs_net.HOST]

    def _create_subnets_for_network(self, data, subnets):
        network = data['network']
        for subnet in subnets[network['name']]:
            arg_list = ('enable_dhcp', 'arg_list')
            args = dict((k, v) for k, v in six.iteritems(subnet)
                        if k in arg_list)
            subnet_data = self._make_subnet(self.fmt, data,
                                            subnet['gateway'],
                                            subnet['cidr'], **args)
            self._subnets[subnet['name']] = subnet_data['subnet']

    def _create_test_networks(self, networks, subnets):
        for net in networks:
            arg_list = ('provider__physical_network',
                        'provider__network_type',
                        'provider__segmentation_id',
                        'router__external')
            args = dict((k, v) for k, v in six.iteritems(net)
                        if k in arg_list)
            data = self._make_network(self.fmt,
                                      name=net['name'],
                                      admin_state_up=True,
                                      arg_list=arg_list,
                                      **args)
            self._nets[net['name']] = data['network']
            self._create_subnets_for_network(data, subnets)

    def _delete_test_networks(self):
        for name, data in six.iteritems(self._nets):
            self._delete('networks', data['id'])
        self._nets = []

    def _register_dhcp_agent(self, hostname):
        agent = copy.deepcopy(DHCP_AGENT_TEMPLATE)
        agent['host'] = hostname
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': agent},
                              time=timeutils.utcnow().isoformat())
        self._dhcp_agents[hostname] = FakeAgent(**agent)

    def _register_dhcp_agents(self, hosts):
        for host in HOSTS:
            self._register_dhcp_agent(host['name'])

    def _register_l3_agent(self, hostname):
        agent = copy.deepcopy(L3_AGENT_TEMPLATE)
        agent['host'] = hostname
        callback = agents_db.AgentExtRpcCallback()
        callback.report_state(self.adminContext,
                              agent_state={'agent_state': agent},
                              time=timeutils.utcnow().isoformat())
        self._l3_agents[hostname] = FakeAgent(**agent)

    def _register_l3_agents(self, hosts):
        for host in HOSTS:
            self._register_l3_agent(host['name'])

    def _list_dhcp_agents(self):
        return self._list_agents(query_string='binary=neutron-dhcp-agent')

    def _list_l3_agents(self):
        return self._list_agents(query_string='binary=neutron-l3-agent')

    def _prepare_test_dependencies(self, hosts, providernets,
                                   providernet_ranges, interfaces,
                                   networks, subnets):
        super(WrsAgentSchedulerTestCase, self)._prepare_test_dependencies(
            hosts=hosts, providernets=providernets,
            providernet_ranges=providernet_ranges,
            interfaces=interfaces)
        self._create_test_networks(networks=networks, subnets=subnets)

    def _cleanup_test_dependencies(self):
        self._delete_test_networks()
        super(WrsAgentSchedulerTestCase, self)._cleanup_test_dependencies()

    def _test_router_rescheduling_validate_result(
            self, agent_ids, initial_expected_distribution,
            final_expected_distribution, reschedule_threshold=1,
            max_time=None):
        # Count routers and check they match expected distribution
        agent_count = len(agent_ids)

        agent_routers_count = []
        for i in range(agent_count):
            agent_routers_count.append(
                len(self._l3_plugin.list_routers_on_l3_agent(
                    self.adminContext, agent_ids[i]
                )['routers'])
            )
        self.assertEqual(agent_routers_count, initial_expected_distribution)

        reschedule_start_time = datetime.datetime.now()
        reschedule_function = (lambda a, b: a > b + reschedule_threshold)
        self._l3_plugin.redistribute_routers(self.adminContext,
                                             reschedule_function)
        reschedule_end_time = datetime.datetime.now()
        reschedule_total_time = (reschedule_end_time - reschedule_start_time)
        # Validate maximum time not exceeded
        if max_time:
            self.assertLessEqual(reschedule_total_time.seconds, max_time)

        # Count routers and check they match new expected distribution
        agent_routers_count = []
        for i in range(agent_count):
            agent_routers_count.append(
                len(self._l3_plugin.list_routers_on_l3_agent(
                    self.adminContext, agent_ids[i]
                )['routers'])
            )
        self.assertEqual(sorted(agent_routers_count),
                         sorted(final_expected_distribution))

    def _test_router_rescheduling_by_count(self, router_count, agent_count,
                                           max_time=None, second_zone_count=0):
        """Runs rescheduling test with specified number of routers and agents.
           Maximum number of agents is 3 due to hosts that have interfaces on
           providernet vlan-pnet0.
        """

        # Define expected results
        initial_expected_distribution = [0] * agent_count
        initial_expected_distribution[0] = router_count
        redistributed_value = int(math.floor(router_count / agent_count))
        final_expected_distribution = [redistributed_value] * agent_count
        assigned_routers = redistributed_value * agent_count
        for i in range(router_count - assigned_routers):
            final_expected_distribution[i] += 1
        if second_zone_count:
            initial_expected_distribution.append(second_zone_count)
            final_expected_distribution.append(second_zone_count)

        # Set up routers and networks
        generic_subnets = []
        generic_routers = []
        network_data = {'network': self._get_network(NET1['name'])}
        for i in range(router_count + second_zone_count):
            if i == router_count:
                network_data = {'network': self._get_network(NET6['name'])}
            subnet_name = "generic-subnet-%d" % i
            tenant_id = "generic-tenant-%d" % i
            generic_subnet = {'name': subnet_name,
            'cidr': "172.16.%d.0/24" % i,
            'gateway': "172.16.%d.1" % i}
            data = self._make_subnet(self.fmt, network_data,
                                     generic_subnet['gateway'],
                                     generic_subnet['cidr'],
                                     tenant_id=tenant_id,
                                     enable_dhcp=False)
            generic_subnets.append(data['subnet'])
            router_name = "generic-router-%d" % i
            generic_router = self._make_router(self.fmt, tenant_id,
                                               router_name)
            generic_routers.append(generic_router)
            self._router_interface_action(
                'add', generic_router['router']['id'],
                generic_subnets[i]['id'], None)

        # Set up agents and auto-schedule routers
        for i in range(agent_count):
            self._register_l3_agent(HOSTS[i]['name'])
            self._l3_plugin.auto_schedule_routers(self.adminContext,
                                                  HOSTS[i]['name'], None)
        if second_zone_count:
            self._register_l3_agent(HOST5['name'])
            self._l3_plugin.auto_schedule_routers(self.adminContext,
                                                  HOST5['name'], None)

        # Validate that rescheduling with this setup works
        agents = self._list_l3_agents()['agents']
        agent_ids = [agent['id'] for agent in agents]
        self._test_router_rescheduling_validate_result(
            agent_ids, initial_expected_distribution,
            final_expected_distribution, 1, max_time
        )

        # Clean up routers
        for i in range(router_count + second_zone_count):
            self._router_interface_action(
                'remove', generic_routers[i]['router']['id'],
                generic_subnets[i]['id'], None)


class WrsL3AgentSchedulerTestCase(WrsAgentSchedulerTestCase):

    def test_router_without_interfaces(self):
        self._register_l3_agents(HOSTS)
        data = self._list_l3_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        with self.router(name='router1',
                         tenant_id=self._tenant_id) as r1:
            # Check that it has no candidate hosts
            agents = self._l3_scheduler.get_l3_agents_for_router(
                self._plugin, self.adminContext, r1['router']['id'])
            self.assertEqual(len(agents), 0)

    def test_router_with_isolated_host(self):
        self._register_l3_agents(HOSTS)
        data = self._list_l3_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        with self.router(name='router1',
                         tenant_id=self._tenant_id) as r1:
            # Attach it to an external network
            self._add_external_gateway_to_router(
                r1['router']['id'], self._get_net_id(NET3['name']))
            # Check that it has only 2 of 3 candidate hosts
            agents = self._l3_scheduler.get_l3_agents_for_router(
                self._plugin, self.adminContext, r1['router']['id'])
            self.assertEqual(len(agents), 2)
            # Confirm that the 1st host can support this router
            routers = self._l3_scheduler._get_routers_can_schedule(
                self._l3_plugin, self.adminContext, [r1['router']],
                self._l3_agents[HOST1['name']])
            self.assertEqual(len(routers), 1)
            # Confirm that the 2st host can support this router
            routers = self._l3_scheduler._get_routers_can_schedule(
                self._l3_plugin, self.adminContext, [r1['router']],
                self._l3_agents[HOST2['name']])
            self.assertEqual(len(routers), 1)
            # Confirm that the 3rd host cannot support this router
            routers = self._l3_scheduler._get_routers_can_schedule(
                self._l3_plugin, self.adminContext, [r1['router']],
                self._l3_agents[HOST3['name']])
            self.assertEqual(len(routers or []), 0)
            # Remove the attachment
            self._remove_external_gateway_from_router(
                r1['router']['id'], self._get_net_id(NET3['name']))
            # Check that it can no longer be scheduled
            agents = self._l3_scheduler.get_l3_agents_for_router(
                self._plugin, self.adminContext, r1['router']['id'])
            self.assertEqual(len(agents), 0)

    def test_router_with_multiple_interfaces(self):
        self._register_l3_agents(HOSTS)
        data = self._list_l3_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        with self.router(name='router1',
                         tenant_id=self._tenant_id) as r1:
            # Attach to 2 tenant networks
            self._router_interface_action(
                'add', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)
            self._router_interface_action(
                'add', r1['router']['id'],
                self._get_subnet_id(SUBNET2['name']), None)
            # Check that it has the first 3 hosts as candidates
            agents = self._l3_scheduler.get_l3_agents_for_router(
                self._plugin, self.adminContext, r1['router']['id'])
            self.assertEqual(len(agents), 3)
            # Attach it to an external network
            self._add_external_gateway_to_router(
                r1['router']['id'], self._get_net_id(NET3['name']))
            # Check that it can now only be scheduled to 2 of 3 hosts
            agents = self._l3_scheduler.get_l3_agents_for_router(
                self._plugin, self.adminContext, r1['router']['id'])
            self.assertEqual(len(agents), 2)
            # Remove the attachments
            self._remove_external_gateway_from_router(
                r1['router']['id'], self._get_net_id(NET3['name']))
            self._router_interface_action(
                'remove', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)
            self._router_interface_action(
                'remove', r1['router']['id'],
                self._get_subnet_id(SUBNET2['name']), None)

    def test_router_rescheduled_on_locked_host(self):
        self._register_l3_agents(HOSTS)
        data = self._list_l3_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        with self.router(name='router1',
                         tenant_id=self._tenant_id) as r1:
            # Attach to 2 tenant networks
            self._router_interface_action(
                'add', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)
            self._router_interface_action(
                'add', r1['router']['id'],
                self._get_subnet_id(SUBNET2['name']), None)
            # Check that it has the first 3 hosts as candidates
            agents = self._l3_scheduler.get_l3_agents_for_router(
                self._plugin, self.adminContext, r1['router']['id'])
            self.assertEqual(len(agents), 3)
            # Check that it was assigned to one of them
            original_host = self._query_router_host(r1['router']['id'])
            self.assertIsNotNone(original_host)
            self.assertIn(original_host, [h['name'] for h in HOSTS])
            # Lock that host
            self._lock_test_host(self._get_host_id(original_host))
            # Check that it was assigned to a different host
            current_host = self._query_router_host(r1['router']['id'])
            self.assertIsNotNone(current_host)
            self.assertIn(current_host, [h['name'] for h in HOSTS])
            self.assertNotEqual(current_host, original_host)
            # Remove the attachments
            self._router_interface_action(
                'remove', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)
            self._router_interface_action(
                'remove', r1['router']['id'],
                self._get_subnet_id(SUBNET2['name']), None)

    def test_redistribute_routers_trivial(self):
        with self.router(name='router1',
                         tenant_id='test-tenant') as r1:
            self._router_interface_action(
                'add', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)
            with self.router(name='router2',
                             tenant_id='test-tenant') as r2:
                self._router_interface_action(
                    'add', r2['router']['id'],
                    self._get_subnet_id(SUBNET2['name']), None)

                # Set up and auto-schedule routers
                self._register_l3_agent(HOST1['name'])
                self._register_l3_agent(HOST2['name'])
                agents = self._list_l3_agents()['agents']
                self._l3_plugin.auto_schedule_routers(self.adminContext,
                                                   HOST1['name'], None)
                self._l3_plugin.auto_schedule_routers(self.adminContext,
                                                   HOST2['name'], None)

                # Validate that rescheduling with this setup works
                agent_ids = [agent['id'] for agent in agents]
                self._test_router_rescheduling_validate_result(agent_ids,
                                                               [2, 0],
                                                               [1, 1], 1)

                self._router_interface_action(
                    'remove', r2['router']['id'],
                    self._get_subnet_id(SUBNET2['name']), None)
            self._router_interface_action(
                'remove', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)

    def test_redistribute_routers_invalid_agent(self):
        with self.router(name='router1',
                         tenant_id='test-tenant') as r1:
            self._router_interface_action(
                'add', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)
            with self.router(name='router2',
                             tenant_id='test-tenant') as r2:
                self._router_interface_action(
                    'add', r2['router']['id'],
                    self._get_subnet_id(SUBNET2['name']), None)

                # Set up and auto-schedule routers
                self._register_l3_agent(HOST1['name'])
                # HOST4 can not host router
                self._register_l3_agent(HOST4['name'])
                agents = self._list_l3_agents()['agents']
                self._l3_plugin.auto_schedule_routers(self.adminContext,
                                                   HOST1['name'], None)
                self._l3_plugin.auto_schedule_routers(self.adminContext,
                                                   HOST4['name'], None)

                # Validate that rescheduling with this setup works
                agent_ids = [agent['id'] for agent in agents]
                self._test_router_rescheduling_validate_result(agent_ids,
                                                               [2, 0],
                                                               [2, 0], 1)

                self._router_interface_action(
                    'remove', r2['router']['id'],
                    self._get_subnet_id(SUBNET2['name']), None)
            self._router_interface_action(
                'remove', r1['router']['id'],
                self._get_subnet_id(SUBNET1['name']), None)

    def test_redistribute_routers_none(self):
        router_count = 5
        agent_count = 1
        self._test_router_rescheduling_by_count(router_count, agent_count, 1)

    def test_redistribute_routers_few(self):
        router_count = 5
        agent_count = 2
        self._test_router_rescheduling_by_count(router_count, agent_count)

    def test_redistribute_routers_large_office(self):
        router_count = 10
        agent_count = 3
        self._test_router_rescheduling_by_count(router_count, agent_count,
                                                second_zone_count=9)

    # TODO(alegacy): disabled because it is timing out in unit tests
    def notest_redistribute_routers_many(self):
        router_count = 30
        agent_count = 3
        self._test_router_rescheduling_by_count(router_count, agent_count, 30)


class WrsDhcpAgentSchedulerTestCase(WrsAgentSchedulerTestCase):

    def test_get_dhcp_networks_for_host_with_no_networks(self):
        # Check which dhcp networks can be scheduled on this host
        data = self._dhcp_scheduler.get_dhcp_subnets_for_host(
            self._plugin, self.adminContext, HOST4['name'], fields=None)
        # Should not be any networks available for this agent as HOST4 is
        # only associated with pci-sriov data interfaces and those interface
        # types are excluded by the scheduler
        self.assertEqual(len(data), 0)

    def test_get_dhcp_networks_for_host(self):
        # Check which dhcp networks can be scheduled on this host
        data = self._dhcp_scheduler.get_dhcp_subnets_for_host(
            self._plugin, self.adminContext, HOST1['name'], fields=None)
        # Should be subnets 1, 2, and 7 to 10 that can be scheduled
        self.assertEqual(len(data), 6)

    def test_get_agents_for_network_without_agents(self):
        dhcp_filter = self._dhcp_scheduler.resource_filter
        data = dhcp_filter._get_network_hostable_dhcp_agents(
            self._plugin, self.adminContext,
            self._get_network(NET1['name']))
        # Should not have any candidate agents since there are no agents
        self.assertEqual(len(data['hostable_agents']), 0)

    def test_get_agents_for_network(self):
        self._register_dhcp_agents(HOSTS)
        data = self._list_dhcp_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        # Get the list of agents that can support this network
        dhcp_filter = self._dhcp_scheduler.resource_filter
        data = dhcp_filter._get_network_hostable_dhcp_agents(
            self._plugin, self.adminContext,
            self._get_network(NET1['name']))
        # It should be schedulable on the first 3 nodes
        self.assertEqual(len(data['hostable_agents']), 3)

    def test_get_agents_for_network_isolated(self):
        self._register_dhcp_agents(HOSTS)
        data = self._list_dhcp_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        # Get the list of agents that can support this network
        dhcp_filter = self._dhcp_scheduler.resource_filter
        data = dhcp_filter._get_network_hostable_dhcp_agents(
            self._plugin, self.adminContext,
            self._get_network(NET4['name']))
        # It should not be schedulable on any nodes
        self.assertEqual(len(data['hostable_agents']), 0)

    def test_get_agents_for_network_sriov(self):
        self._register_dhcp_agents(HOSTS)
        data = self._list_dhcp_agents()
        self.assertEqual(len(data['agents']), len(HOSTS))
        # Get the list of agents that can support this network
        dhcp_filter = self._dhcp_scheduler.resource_filter
        data = dhcp_filter._get_network_hostable_dhcp_agents(
            self._plugin, self.adminContext,
            self._get_network(NET5['name']))
        # It should not be schedulable on any nodes because NET5 is
        # associated only with pci-sriov data interfaces and the scheduler
        # should be excluding these from the choices.
        self.assertEqual(len(data['hostable_agents']), 0)

    def _get_agent_network_counts(self):
        counts = []
        agents = self._list_dhcp_agents()['agents']
        for agent in agents:
            networks = self._plugin.list_networks_on_dhcp_agent(
                self.adminContext, agent['id'])['networks']
            counts.append((agent['host'], len(networks)))
        return collections.OrderedDict(
            sorted(counts, reverse=True, key=lambda x: x[1]))

    def _assertAgentNetworkCounts(self, a, b):
        a_counts = sorted(a.values())
        b_counts = sorted(b.values())
        self.assertEqual(a_counts, b_counts)

    def test_autoschedule_networks(self):
        self._register_dhcp_agent(HOST1['name'])
        self._plugin.auto_schedule_networks(self.adminContext, HOST1['name'])
        counts = self._get_agent_network_counts()
        expected = {'compute-0': 3}
        self._assertAgentNetworkCounts(expected, counts)

    def test_redistribute_networks(self):
        self._register_dhcp_agents(HOSTS)
        self._plugin.auto_schedule_networks(self.adminContext, HOST1['name'])
        self._plugin.redistribute_networks(self.adminContext,
                                           (lambda a, b: a > b + 1))
        counts = self._get_agent_network_counts()
        expected = {'compute-0': 1,
                    'compute-1': 1,
                    'compute-2': 1,
                    'compute-3': 0,
                    'compute-4': 0}
        self._assertAgentNetworkCounts(expected, counts)

    def test_redistribute_networks_with_threshold_1(self):
        self._register_dhcp_agents(HOSTS)
        self._plugin.auto_schedule_networks(self.adminContext, HOST1['name'])
        self._plugin.redistribute_networks(self.adminContext,
                                           (lambda a, b: a > b + 1))
        counts = self._get_agent_network_counts()
        expected = {'compute-0': 1,
                    'compute-1': 1,
                    'compute-2': 1,
                    'compute-3': 0,
                    'compute-4': 0}
        self._assertAgentNetworkCounts(expected, counts)

    def test_redistribute_networks_with_threshold_2(self):
        self._register_dhcp_agents(HOSTS)
        self._plugin.auto_schedule_networks(self.adminContext, HOST1['name'])
        self._plugin.redistribute_networks(self.adminContext,
                                           (lambda a, b: a > b + 2))
        counts = self._get_agent_network_counts()
        expected = {'compute-0': 2,
                    'compute-1': 0,
                    'compute-2': 1,
                    'compute-3': 0,
                    'compute-4': 0}
        self._assertAgentNetworkCounts(expected, counts)

    def test_redistribute_networks_invalid_agent(self):
        self._register_dhcp_agent(HOST1['name'])
        self._register_dhcp_agent(HOST4['name'])
        self._plugin.auto_schedule_networks(self.adminContext, HOST1['name'])
        self._plugin.redistribute_networks(self.adminContext,
                                           (lambda a, b: a > b + 2))
        counts = self._get_agent_network_counts()
        expected = {'compute-0': 3, 'compute-3': 0}
        self._assertAgentNetworkCounts(expected, counts)

    def test_redistribute_networks_with_locked_host(self):
        self._register_dhcp_agent(HOST1['name'])
        self._register_dhcp_agent(HOST2['name'])
        self._register_dhcp_agent(HOST3['name'])
        # Start all the agents on the first host
        self._plugin.auto_schedule_networks(self.adminContext, HOST1['name'])
        # Lock the second host. The agent will still be seen but we
        # want to confirm that it is being ignored when calculating the
        # least busiest agents.
        self._lock_test_host(HOST2['id'])
        # The busiest network should get moved to the third host. The two
        # single subnet networks should stay on the first host.
        self._plugin.redistribute_networks(self.adminContext,
                                           (lambda a, b: a > b + 1))
        counts = self._get_agent_network_counts()
        expected = {'compute-0': 2,
                    'compute-1': 0,
                    'compute-2': 1}
        for k in sorted(counts.iterkeys()):
            self.assertEqual(expected[k], counts[k])
        self._assertAgentNetworkCounts(expected, counts)
