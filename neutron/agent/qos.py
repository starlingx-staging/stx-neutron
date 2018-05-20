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

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class QoSDriver(object):

    @abc.abstractmethod
    def delete_qos_for_network(self, network_id):
        pass

    @abc.abstractmethod
    def delete_qos_for_port(self, port_id):
        pass

    @abc.abstractmethod
    def network_qos_updated(self, policy, network_id):
        pass

    @abc.abstractmethod
    def port_qos_updated(self, policy, port_id):
        pass


class NoopQoSDriver(QoSDriver):

    def delete_qos_for_network(self, network_id):
        pass

    def delete_qos_for_port(self, port_id):
        pass

    def network_qos_updated(self, policy, network_id):
        pass

    def port_qos_updated(self, policy, port_id):
        pass
