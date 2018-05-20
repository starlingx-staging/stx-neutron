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
# Copyright (c) 2015 Wind River Systems, Inc.
#

import uuid

from oslo_log import log as logging

from neutron.common import constants
from neutron.drivers import host as host_driver
from neutron.extensions import host as ext_host
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)


class TestHostDriver(host_driver.HostDriver):

    def __init__(self):
        super(TestHostDriver, self).__init__()
        self._hosts_by_name = {}
        self._hosts_by_uuid = {}
        self._pnets_by_name = {}
        self._pnet_bindings = {}
        self._interface_by_host = {}
        self._plugin = None
        LOG.info("Test host driver loaded")

    def _get_plugin(self):
        if not self._plugin:
            self._plugin = directory.get_plugin()
        return self._plugin

    def get_host_uuid(self, context, hostname):
        if hostname in self._hosts_by_name[hostname]:
            host = self._hosts_by_name[hostname]
            return host['id']
        return None

    def get_host_providernets(self, context, host_uuid):
        if host_uuid not in self._hosts_by_uuid:
            return {}
        host = self._hosts_by_uuid[host_uuid]
        if host['name'] not in self._interface_by_host:
            return {}
        data = self._interface_by_host[host['name']]
        names = data['providernets'].strip()
        providernets = names.split(',') if names else []
        values = []
        for name in providernets:
            providernet = self._get_plugin().get_providernet_by_name(
                context, name.strip())
            if providernet:
                values.append(providernet['id'])
        return {data['uuid']: {'providernets': values}}

    def get_host_interfaces(self, context, host_uuid):
        if host_uuid in self._hosts_by_uuid:
            host = self._hosts_by_uuid[host_uuid]
            if host['name'] in self._interface_by_host:
                data = self._interface_by_host[host['name']]
                return {data['uuid']: data}
        return {}

    def add_host(self, host):
        self._hosts_by_name[host['name']] = host
        self._hosts_by_uuid[host['id']] = host
        self._interface_by_host[host['name']] = {
            'uuid': str(uuid.uuid4()),
            'mtu': constants.DEFAULT_MTU,
            'vlans': '',
            'network_type': 'data',
            'providernets': ''}

    def add_interface(self, host, interface):
        self._interface_by_host[host] = interface

    def is_host_available(self, context, hostname):
        """
        Returns whether the host is available or not.  This code should live in
        the plugin instead of the driver but since we do have our own subclass
        of the ml2 plugin this call needs to return true so that existing unit
        tests continue to work.  If we had our own subclass we would simply
        return true in the base class and run this code in our subclass.
        """
        try:
            host = self._get_plugin().get_host_by_name(context, hostname)
            return host['availability'] == constants.HOST_UP
        except ext_host.HostNotFoundByName:
            # Does not exist yet
            return False
