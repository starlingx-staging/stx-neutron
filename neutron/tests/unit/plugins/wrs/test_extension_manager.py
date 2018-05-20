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

from neutron.extensions import agent as ext_agent
from neutron.extensions import host as ext_host
from neutron.extensions import wrs_provider as ext_pnet


class WrsExtensionManager(object):

    def get_resources(self):
        return (ext_host.Host.get_resources() +
                ext_pnet.Wrs_provider.get_resources() +
                ext_agent.Agent.get_resources())

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return (ext_pnet.get_extended_resources(version) +
                ext_host.get_extended_resources(version) +
                ext_agent.get_extended_resources(version))
