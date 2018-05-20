# Copyright (c) 2013 OpenStack Foundation.
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
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

import abc
import uuid

import six

from neutron.common import constants
from neutron.db import providernet_db


@six.add_metaclass(abc.ABCMeta)
class HostDriver(object):
    def __init__(self):
        pass

    @abc.abstractmethod
    def get_host_uuid(self, context, hostname):
        pass

    @abc.abstractmethod
    def get_host_providernets(self, context, host_uuid):
        pass

    @abc.abstractmethod
    def get_host_interfaces(self, context, host_uuid):
        pass

    @abc.abstractmethod
    def is_host_available(self, context, hostname):
        pass


class NoopHostDriver(HostDriver):

    def get_host_uuid(self, context, hostname):
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, hostname))

    def get_host_providernets(self, context, host_uuid):
        interface_uuid = str(uuid.uuid5(uuid.UUID(host_uuid), "interface-0"))
        query = context.session.query(providernet_db.ProviderNet)
        providernets = [entry.id for entry in query.all()]
        return {interface_uuid: {'providernets': providernets}}

    def get_host_interfaces(self, context, host_uuid):
        # Create a fake interface so that we have something to setup bindings
        # against to satisfy unit tests.
        interface_uuid = str(uuid.uuid5(uuid.UUID(host_uuid), "interface-0"))
        result = {interface_uuid: {'uuid': interface_uuid,
                                   'mtu': constants.DEFAULT_MTU,
                                   'vlans': '',
                                   'network_type': 'data'}}
        return result

    def is_host_available(self, context, hostname):
        return True
