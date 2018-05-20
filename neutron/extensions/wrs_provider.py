# Copyright (c) 2012 OpenStack Foundation.
# All rights reserved.
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

import netaddr

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as exc
from neutron_lib.plugins import directory

from neutron.common import constants as n_const
from oslo_log import log as logging

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.api.v2 import resource
from neutron import policy
from neutron import wsgi

LOG = logging.getLogger(__name__)


def _validate_ip_mcast_address(data, valid_values=None):
    """
    Validates that an IP address is a multicast address.
    """
    if not netaddr.IPAddress(data).is_multicast():
        msg = _("'%s' is not a valid multicast IP address") % data
        LOG.debug(msg)
        return msg


validators.add_validator('type:ip_mcast_address', _validate_ip_mcast_address)

# wrs-provider:network_type
# wrs-provider:physical_network
# wrs-provider:segmentation_id
NETWORK_TYPE = '%sprovider:network_type' % n_const.WRS_FIELD_PREFIX
PHYSICAL_NETWORK = '%sprovider:physical_network' % n_const.WRS_FIELD_PREFIX
SEGMENTATION_ID = '%sprovider:segmentation_id' % n_const.WRS_FIELD_PREFIX
ATTRIBUTES = [NETWORK_TYPE, PHYSICAL_NETWORK, SEGMENTATION_ID]
# wrs-provider:mtu
MTU = '%sprovider:mtu' % n_const.WRS_FIELD_PREFIX

EXTENDED_ATTRIBUTES_2_0 = {
    'subnets': {
        NETWORK_TYPE: {'allow_post': False, 'allow_put': False,
                       'enforce_policy': True,
                       'is_visible': True},
        PHYSICAL_NETWORK: {'allow_post': False, 'allow_put': False,
                           'enforce_policy': True,
                           'is_visible': True},
        SEGMENTATION_ID: {'allow_post': False, 'allow_put': False,
                          'convert_to': int,
                          'enforce_policy': True,
                          'default': constants.ATTR_NOT_SPECIFIED,
                          'is_visible': True},
    },
}


# Provider Network Attribute Map
PROVIDERNET_TYPE_LIST = ['flat', 'vlan', 'vxlan', 'gre']
PROVIDERNET_TYPE_NAME = 'providernet_type'
PROVIDERNET_TYPE_ATTRIBUTES = {
    PROVIDERNET_TYPE_NAME + 's': {
        'type': {'allow_post': False, 'allow_put': False,
                 'validate': {'type:values': PROVIDERNET_TYPE_LIST},
                 'is_visible': True},
        'description': {'allow_post': False, 'allow_put': False,
                        'is_visible': True}
    },
}

# Provider Network Attribute Map
PROVIDERNET_NAME = 'providernet'
PROVIDERNET_ATTRIBUTES = {
    PROVIDERNET_NAME + 's': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True,
                 'validate': {'type:not_empty_string':
                              db_const.NAME_FIELD_SIZE}},
        'type': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:values': PROVIDERNET_TYPE_LIST},
                 'is_visible': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True,
                        'default': None},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'mtu': {'allow_post': True, 'allow_put': True,
                'convert_to': converters.convert_to_int,
                'validate': {'type:range': n_const.VALID_MTU_RANGE},
                'default': n_const.DEFAULT_MTU,
                'is_visible': True},
        'vlan_transparent': {'allow_post': True, 'allow_put': True,
                'convert_to': converters.convert_to_boolean,
                'default': False,
                'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': False,
                      'default': None},
        'ranges': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
    },
}

# Provider Network Attribute Map
PROVIDERNET_RANGE_NAME = 'providernet_range'
PROVIDERNET_RANGE_ATTRIBUTES = {
    PROVIDERNET_RANGE_NAME + 's': {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True,
                 'default': None},
        'description': {'allow_post': True, 'allow_put': True,
                        'is_visible': True,
                        'default': None},
        'shared': {'allow_post': True, 'allow_put': False,
                   'convert_to': converters.convert_to_boolean,
                   'is_visible': True,
                   'default': True},
        'minimum': {'allow_post': True, 'allow_put': True,
                    'convert_to': converters.convert_to_int,
                    'is_visible': True},
        'maximum': {'allow_post': True, 'allow_put': True,
                    'convert_to': converters.convert_to_int,
                    'is_visible': True},
        'providernet_id': {'allow_post': True, 'allow_put': False,
                           'is_visible': True},
        'providernet_name': {'allow_post': False, 'allow_put': False,
                             'is_visible': True},
        'providernet_type': {'allow_post': False, 'allow_put': False,
                             'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': True,
                      'default': None},
        'group': {'allow_post': True, 'allow_put': False,
                  'is_visible': True,
                  'validate': {'type:ip_mcast_address': None},
                  'default': constants.ATTR_NOT_SPECIFIED},
        'port': {'allow_post': True, 'allow_put': False,
                 'convert_to': converters.convert_to_int,
                 'validate': {'type:values': n_const.VALID_VXLAN_UDP_PORTS},
                 'default': n_const.DEFAULT_VXLAN_UDP_PORT,
                 'is_visible': True},
        'ttl': {'allow_post': True, 'allow_put': False,
                'convert_to': converters.convert_to_int,
                'validate': {'type:range': n_const.VALID_TTL_RANGE},
                'is_visible': True,
                'default': constants.ATTR_NOT_SPECIFIED},
        'mode': {'allow_post': True, 'allow_put': False,
                 'validate': {'type:values': n_const.PROVIDERNET_VXLAN_MODES},
                 'default': n_const.PROVIDERNET_VXLAN_DYNAMIC,
                 'is_visible': True},
        'vxlan': {'allow_post': False, 'allow_put': False,
                  'is_visible': True},
    },
}

# Provider Network Connectivity State Attribute Map
PROVIDERNET_CONNECTIVITY_TEST_NAME = 'providernet_connectivity_test'
PROVIDERNET_CONNECTIVITY_TEST_ATTRIBUTES = {
    PROVIDERNET_CONNECTIVITY_TEST_NAME + 's': {
        'host_id': {'allow_post': True, 'allow_put': False,
                    'is_visible': True, 'default': None},
        'host_name': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': None},
        'master_id': {'allow_post': False, 'allow_put': False,
                      'is_visible': True},
        'master_name': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
        'providernet_id': {'allow_post': True, 'allow_put': False,
                           'is_visible': True, 'default': None},
        'providernet_name': {'allow_post': True, 'allow_put': False,
                             'is_visible': True, 'default': None},
        'type': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'segmentation_id': {'allow_post': True, 'allow_put': False,
                            'is_visible': True, 'default': None},
        'status': {'allow_post': False, 'allow_put': False,
                   'is_visible': True},
        'message': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'audit_uuid': {'allow_post': False, 'allow_put': False,
                       'is_visible': True, 'default': None},
        'updated_at': {'allow_post': False, 'allow_put': False,
                       'is_visible': True, 'default': None},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'is_visible': False,
                      'default': None},
    },
}

RESOURCE_ATTRIBUTE_MAPS = dict(
    PROVIDERNET_TYPE_ATTRIBUTES.items() +
    PROVIDERNET_ATTRIBUTES.items() +
    PROVIDERNET_RANGE_ATTRIBUTES.items() +
    PROVIDERNET_CONNECTIVITY_TEST_ATTRIBUTES.items()
)


class ProviderNetTypeNotSupported(exc.NeutronException):
    message = _("Provider network %(type)s not supported")


class ProviderNetNotFoundById(exc.NotFound):
    message = _("Provider network %(id)s could not be found")


class ProviderNetNotFoundByName(exc.NotFound):
    message = _("Provider network %(name)s could not be found")


class ProviderNetNameAlreadyExists(exc.NeutronException):
    message = _("Provider network with name %(name)s already exists")


class ProviderNetReferencedByTenant(exc.NeutronException):
    message = _("Provider network %(name)s is referenced by one or "
                "more tenant networks")


class ProviderNetRangeReferencedByTenant(exc.NeutronException):
    message = _("Provider network range %(name)s is referenced by one or "
                "more tenant networks")


class ProviderNetRangeReferencedBySystemVlans(exc.NeutronException):
    message = _("Provider network range conflicts with system VLAN values "
                "assigned to interface %(interface)s on host %(host)s")


class ProviderNetRangeConflictsWithSystemVlans(exc.Conflict):
    message = _("Provider network %(providernet)s range %(providernet_range)s "
                "conflicts with system VLAN values: %(vlan_ids)s")


class ProviderNetReferencedByComputeNode(exc.NeutronException):
    message = _("Provider network %(name)s is referenced by one or "
                "more compute nodes")


class ProviderNetMtuExceedsInterfaceMtu(exc.NeutronException):
    message = _("%(type)s provider network MTU %(value)s requires an "
                "interface MTU of %(required)s which exceeds the "
                "smallest configured MTU of any interface: %(minimum)s")


class ProviderNetRequiresInterfaceMtu(exc.NeutronException):
    message = _("Provider network %(providernet)s requires an interface "
                "MTU value of at least %(mtu)s bytes")


class ProviderNetRangeNotFoundById(exc.NotFound):
    message = _("Provider network segmentation id range %(id)s "
                "could not be found")


class ProviderNetRangeNotAllowedOnFlatNet(exc.NeutronException):
    message = _("Provider network segmentation id range not allowed "
                "on flat network %(id)s")


class ProviderNetRangeOverlaps(exc.Conflict):
    message = _("Provider network segmentation id range overlaps "
                "with range with id %(id)s")


class ProviderNetRangeMismatchedTTL(exc.Conflict):
    message = _("VXLAN time-to-live attribute mismatched with "
                "other similar providernet range entry: %(id)s")


class ProviderNetExistingRangeOverlaps(exc.Conflict):
    message = _("Provider network range %(first)s overlaps "
                "with range %(second)s")


class ProviderNetTypesIncompatible(exc.Conflict):
    message = _("Provider network types cannot be assigned to the same "
                "interface; types: %(types)s")


class ProviderNetTypesIncompatibleWithPthru(exc.Conflict):
    message = _("Provider network types cannot be assigned to a "
                "PCI passthrough interface; types: %(types)s")


class ProviderNetRangeOutOfOrder(exc.NeutronException):
    message = _("Range minimum %(minimum)s is greater "
                "than maximum %(maximum)s")


class ProviderNetWithoutMulticastGroup(exc.NeutronException):
    message = _("VXLAN multicast group attributes missing")


class ProviderNetWithMulticastGroup(exc.NeutronException):
    message = _("Multicast group attribute only valid for "
                "VXLAN provider networks")


class ProviderNetWithoutTTL(exc.NeutronException):
    message = _("VXLAN time-to-live attribute missing")


class ProviderNetWithTTL(exc.NeutronException):
    message = _("Time-to-live attribute only valid for "
                "VXLAN provider networks")


class ProviderNetNonDynamicWithMulticastGroup(exc.NeutronException):
    message = _("Multicast group attribute only valid for "
                "dynamic VXLAN provider networks")


class ProviderNetWithoutPort(exc.NeutronException):
    message = _("UDP port attributes missing")


class ProviderNetWithPort(exc.NeutronException):
    message = _("UDP Port attribute only valid for "
                "VXLAN provider networks")


class ProviderNetWithInvalidTTL(exc.NeutronException):
    message = _("Time-to-live %(ttl)s is out of range 1 to 255")


class ProviderNetVlanIdOutOfRange(exc.NeutronException):
    message = _("VLAN id range %(minimum)s to "
                "%(maximum)s exceeds %(threshold)s")


class ProviderNetVxlanIdOutOfRange(exc.NeutronException):
    message = _("VXLAN id range %(minimum)s to "
                "%(maximum)s exceeds %(threshold)s")


class ProviderNetMustBeSameForSubnetAndNetwork(exc.NeutronException):
    message = _("Subnet physical network must match the parent "
                "network physical network")


class MultiSubnetProviderSegmentsNotSupported(exc.NeutronException):
    message = _("Multi-segment provider networks for subnets is not supported")


class ProviderNetDynamicVxlanNotSupported(exc.NeutronException):
    message = _("Dynamic VXLAN based tenant networks are not supported in SDN")


class ProviderNetTestingDisabled(exc.NeutronException):
    message = _("Provider network testing is not supported in "
                "this configuration.")


def _raise_if_updates_provider_attributes(attrs):
    """Raise exception if provider attributes are present.

    This method is used for plugins that do not support
    updating provider networks.
    """
    immutable = (NETWORK_TYPE, PHYSICAL_NETWORK, SEGMENTATION_ID)
    if any(attributes.is_attr_set(attrs.get(a)) for a in immutable):
        msg = _("Plugin does not support updating provider attributes")
        raise exc.InvalidInput(error_message=msg)

PNET_BINDING = 'providernet-binding'
PNET_BINDINGS = PNET_BINDING + 's'


class WrsProviderNetBindingsController(wsgi.Controller):
    def index(self, request, **kwargs):
        plugin = directory.get_plugin()
        policy.enforce(request.context,
                       "get_%s" % PNET_BINDINGS,
                       {})
        return plugin.list_networks_on_providernet(
            request.context, kwargs['providernet_id'])


class Wrs_provider(api_extensions.ExtensionDescriptor):
    """Extension class supporting provider networks.

    This class is used by neutron's extension framework to make
    metadata about the provider network extension available to
    clients. No new resources are defined by this extension. Instead,
    the existing network resource's request and response messages are
    extended with attributes in the provider namespace.

    With admin rights, network dictionaries returned will also include
    provider attributes.
    """

    @classmethod
    def get_name(cls):
        return "wrs-provider-network"

    @classmethod
    def get_alias(cls):
        return "wrs-provider"

    @classmethod
    def get_description(cls):
        return "WRS Provider Network Extensions."

    @classmethod
    def get_namespace(cls):
        return "http://docs.windriver.org/tis/ext/wrs-provider/v1"

    @classmethod
    def get_updated(cls):
        return "2014-10-01T12:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns extension resources"""
        ext_list = []
        my_plurals = [(key, key[:-1])
                      for key in RESOURCE_ATTRIBUTE_MAPS.keys()]
        plugin = directory.get_plugin()
        for plural, name in my_plurals:
            params = RESOURCE_ATTRIBUTE_MAPS.get(plural)
            plural = plural.replace('_', '-')
            controller = base.create_resource(plural, name, plugin, params)
            plural = "%s/%s" % (cls.get_alias(), plural)
            ext = extensions.ResourceExtension(plural, controller)
            ext_list.append(ext)

        # Add an extra extension for the binding controller
        controller = resource.Resource(WrsProviderNetBindingsController(),
                                       base.FAULT_MAP)
        ext_list.append(extensions.ResourceExtension(PNET_BINDINGS, controller,
                        dict(member_name="providernet",
                             collection_name="wrs-provider/providernets")))
        return ext_list

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


class ProviderNetPluginBase(object):
    """REST API to manage provider networks.

    All methods must be in an admin context.
    """

    @abc.abstractmethod
    def get_providernet_types(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def create_providernet(self, context, providernet):
        """
        Create a provider network record for given network data.
        """
        pass

    @abc.abstractmethod
    def delete_providernet(self, context, id):
        """
        Delete a provider network by id.
        """
        pass

    @abc.abstractmethod
    def update_providernet(self, context, id, providernet):
        """
        Update a provider network with given data
        @raise exc.BadRequest:
        """
        pass

    @abc.abstractmethod
    def get_providernets(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_providernet(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def create_providernet_range(self, context, range):
        """
        Create a provider network segmentation id range record for given
        network data.
        """
        pass

    @abc.abstractmethod
    def delete_providernet_range(self, context, id):
        """
        Delete a provider network segmentation id range by id.
        """
        pass

    @abc.abstractmethod
    def update_providernet_range(self, context, id, range):
        """
        Update a provider network segmentation id range with given data
        @raise exc.BadRequest:
        """
        pass

    @abc.abstractmethod
    def get_providernet_ranges(self, context, filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_providernet_range(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def list_networks_on_providernet(self, context, id,
                                     filters=None, fields=None):
        pass

    @abc.abstractmethod
    def get_providernet_connectivity_tests(self, context, filters=None,
                                           fields=None):
        pass
