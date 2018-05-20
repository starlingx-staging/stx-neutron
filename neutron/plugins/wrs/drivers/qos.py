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
from neutron.agent import qos


class VSwitchQoSDriver(qos.QoSDriver):

    vswitch_mgr = None

    def register_manager(self, manager):
        self.vswitch_mgr = manager

    def delete_qos_for_network(self, network_id):
        params = {'qos-policy': None}
        networks = self.vswitch_mgr.get_networks()
        if network_id in networks:
            self.vswitch_mgr.update_network(network_id, params)

    def delete_qos_for_port(self, port_id):
        # TODO(alegacy) port qos-policy is currently not supported
        # params = {'qos-policy': None}
        # self.vswitch_mgr.update_port(port_id, params)
        pass

    def network_qos_updated(self, policy, network_id):
        params = {'qos-policy': policy}
        networks = self.vswitch_mgr.get_networks()
        if network_id in networks:
            self.vswitch_mgr.update_network(network_id, params)

    def port_qos_updated(self, policy, port_id):
        # TODO(alegacy) port qos-policy is currently not supported
        # params = {'qos-policy': policy}
        # self.vswitch_mgr.update_port(port_id, params)
        pass
