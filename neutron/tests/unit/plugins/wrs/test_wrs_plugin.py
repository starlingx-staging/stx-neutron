# Copyright (c) 2014 OpenStack Foundation
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

import functools

from oslo_log import log as logging

from neutron.api import extensions
from neutron.plugins.ml2 import config
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.plugins.ml2 import test_plugin as test_ml2_plugin
from neutron_lib import context

LOG = logging.getLogger(__name__)

PLUGIN_NAME = 'neutron.plugins.ml2.plugin.Ml2Plugin'


class WrsMl2PluginV2TestCase(test_plugin.NeutronDbPluginV2TestCase):

    _mechanism_drivers = ['vswitch', 'logger', 'test']

    def setup_parent(self):
        """Perform parent setup with the common plugin configuration class."""
        l3_plugin = ('neutron.services.l3_router.l3_router_plugin.'
                     'L3RouterPlugin')
        service_plugins = {
            'l3_plugin_name': l3_plugin,
            'segments_plugin_name': 'neutron.services.segments.plugin.Plugin'}
        # Ensure that the parent setup can be called without arguments
        # by the common configuration setUp.
        parent_setup = functools.partial(
            super(WrsMl2PluginV2TestCase, self).setUp,
            plugin=PLUGIN_NAME,
            service_plugins=service_plugins,
        )
        self.useFixture(test_ml2_plugin.Ml2ConfFixture(parent_setup))

    def setup_config(self):
        super(WrsMl2PluginV2TestCase, self).setup_config()
        # Setup the plugin configuration to match the WRS runtime
        # configuration
        config.cfg.CONF.set_override('type_drivers',
                                     ['managed_flat',
                                      'managed_vlan',
                                      'managed_vxlan'],
                                     group='ml2')
        config.cfg.CONF.set_override('tenant_network_types',
                                     ['flat', 'vlan', 'vxlan'],
                                     group='ml2')
        config.cfg.CONF.set_override('router_status_managed',
                                     True)
        # Setup our customer schedulers
        config.cfg.CONF.set_override(
            'network_scheduler_driver',
            'neutron.scheduler.dhcp_host_agent_scheduler.HostBasedScheduler')
        config.cfg.CONF.set_override(
            'router_scheduler_driver',
            'neutron.scheduler.l3_host_agent_scheduler.HostBasedScheduler')

    def setUp(self):
        # Enable the test mechanism driver to ensure that
        # we can successfully call through to all mechanism
        # driver apis.
        config.cfg.CONF.set_override('mechanism_drivers',
                                     self._mechanism_drivers,
                                     group='ml2')
        self.setup_parent()
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)
        self.adminContext = context.get_admin_context()
