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

import abc

import six

FM_SEVERITY_CRITICAL = "critical"
FM_SEVERITY_MAJOR = "major"
FM_SEVERITY_MINOR = "minor"
FM_SEVERITY_CLEAR = "clear"


@six.add_metaclass(abc.ABCMeta)
class FmDriver(object):

    @abc.abstractmethod
    def report_port_state_fault(self, hostname, port_id, severity):
        pass

    @abc.abstractmethod
    def clear_port_state_fault(self, hostname, port_id):
        pass

    @abc.abstractmethod
    def get_port_state_faults(self, hostname):
        pass

    @abc.abstractmethod
    def report_interface_state_fault(self, hostname, interface_id, severity):
        pass

    @abc.abstractmethod
    def clear_interface_state_fault(self, hostname, interface_id):
        pass

    @abc.abstractmethod
    def get_interface_state_faults(self, hostname):
        pass

    @abc.abstractmethod
    def report_agent_fault(self, hostname, agent_id):
        pass

    @abc.abstractmethod
    def clear_agent_fault(self, hostname, agent_id):
        pass

    @abc.abstractmethod
    def report_providernet_fault(self, providernet_id):
        pass

    @abc.abstractmethod
    def clear_providernet_fault(self, providernet_id):
        pass

    @abc.abstractmethod
    def report_providernet_connectivity_fault(self, providernet_id, hostname):
        pass

    @abc.abstractmethod
    def clear_providernet_connectivity_fault(self, providernet_id, hostname):
        pass


class NoopFmDriver(FmDriver):

    def report_port_state_fault(self, hostname, port_id, severity):
        pass

    def clear_port_state_fault(self, hostname, port_id):
        pass

    def get_port_state_faults(self, hostname):
        return None

    def report_interface_state_fault(self, hostname, interface_id, severity):
        pass

    def clear_interface_state_fault(self, hostname, interface_id):
        pass

    def get_interface_state_faults(self, hostname):
        return None

    def report_agent_fault(self, hostname, agent_id):
        pass

    def clear_agent_fault(self, hostname, agent_id):
        pass

    def report_providernet_fault(self, providernet_id):
        pass

    def clear_providernet_fault(self, providernet_id):
        pass

    def report_providernet_connectivity_fault(self, providernet_id, hostname):
        pass

    def clear_providernet_connectivity_fault(self, providernet_id, hostname):
        pass
