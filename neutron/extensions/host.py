# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#


import abc

from neutron_lib.api import extensions as api_extensions
from neutron_lib import exceptions as exc
from neutron_lib.plugins import constants

from neutron._i18n import _
from neutron.api.v2 import resource_helper

# Attribute Map
RESOURCE_NAME = 'host'
RESOURCE_ATTRIBUTE_MAP = {
    RESOURCE_NAME + 's': {
        # DB attributes
        'id': {'allow_post': True, 'allow_put': False,
               'is_visible': True,
               'validate': {'type:uuid': None}},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True},
        'availability': {'allow_post': True, 'allow_put': True,
                         'validate': {'type:values': ['UP', 'DOWN',
                                                      'up', 'down']},
                         'is_visible': True},
        'created_at': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        'updated_at': {'allow_post': False, 'allow_put': False,
                       'is_visible': True},
        # Operational attributes
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': False},
        'agents': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'subnets': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'routers': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'ports': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
    },
}

OPERATIONAL_ATTRIBUTES = ['agents', 'subnets', 'routers', 'ports', 'tenant_id']


class HostAlreadyExists(exc.Conflict):
    message = _("Host %(id)s already exists in the database")


class HostNotFoundById(exc.NotFound):
    message = _("Host %(id)s could not be found")


class HostNotFoundByName(exc.NotFound):
    message = _("Host %(hostname)s could not be found")


class HostInterfaceNotFoundById(exc.NotFound):
    message = _("Host interface %(id)s could not be found")


class HostMissingInterfaceBody(exc.BadRequest):
    message = _("Interface parameters missing from bind/unbind request")


class HostMissingInterfaceUuid(exc.BadRequest):
    message = _("Interface UUID missing from bind/unbind request")


class HostInvalidInterfaceUuid(exc.BadRequest):
    message = _("Interface UUID '%(value)s' is not a valid UUID")


class HostMissingInterfaceMtu(exc.BadRequest):
    message = _("Interface MTU missing from bind request")


class HostInvalidInterfaceMtu(exc.BadRequest):
    message = _("Interface MTU value is invalid; value %(value)s")


class HostInvalidInterfaceNetworkType(exc.BadRequest):
    message = _("Interface network type value is invalid; value %(value)s")


class HostOutOfRangeInterfaceMtu(exc.BadRequest):
    message = _("Interface MTU value is out of range; "
                "min %(minimum)s, max %(maximum)s")


class HostMissingInterfaceProviderNetworks(exc.BadRequest):
    message = _("Interface provider network list missing from bind request")


class HostInvalidInterfaceVlans(exc.BadRequest):
    message = _("Interface VLAN value(s) are invalid; "
                "expecting comma separated list of integers "
                "instead of %(values)s")


class HostOutOfRangeInterfaceVlan(exc.BadRequest):
    message = _("Interface VLAN value is out of range; %(vlan_id)s "
                "min %(minimum)s, max %(maximum)s")


class Host(api_extensions.ExtensionDescriptor):
    """Host based Agent management extension"""

    @classmethod
    def get_name(cls):
        return "Host based agent management"

    @classmethod
    def get_alias(cls):
        return "host"

    @classmethod
    def get_description(cls):
        return "The host based agent management extension."

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/host/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2013-02-03T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns extension resources """
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        action_map = {'host': {'bind_interface': 'PUT',
                               'unbind_interface': 'PUT'}}
        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.CORE,
                                                   action_map=action_map)

    def update_attributes_map(self, attributes):
        super(Host, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


class HostPluginBase(object):
    """REST API to manage agents based on host state.

    All of method must be in an admin context.
    """

    @abc.abstractmethod
    def create_host(self, context, host):
        """Create host record for given host data.

        Agents are stored in the database when they report state once the
        compute nodes have been initialized.  Upon receiving an agent state
        report the host record is created automatically.  If no agents have
        reported their state then this API may be used to create a host record.

        """
        pass

    @abc.abstractmethod
    def delete_host(self, context, id):
        """Delete host and agent records based on host id.

        Agents are stored in the database when they report state once the
        compute nodes have been initialized.  When a compute node is deleted
        this API is capable of purging stale information.

        """
        pass

    @abc.abstractmethod
    def update_host(self, context, id, host):
        """
        Updates the availability status of a host.  The result of this
        operation is that if the host is being marked as down then any
        agents running on that host will have their workload unassigned.  If
        the host is being marked as available then any unassigned networks or
        routers will be assigned to available agents on this host.
        @raise exc.BadRequest:
        """
        pass

    @abc.abstractmethod
    def get_hosts(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_host(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def bind_interface(self, context, id, body):
        """Bind an interface with a set of provider networks while also
        providing system information about an interface.
        """
        pass

    @abc.abstractmethod
    def unbind_interface(self, context, id, body):
        """Unbind an interface to clear all provider network mappings."""
        pass
