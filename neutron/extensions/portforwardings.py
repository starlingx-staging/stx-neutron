# Copyright 2013 UnitedStack, Inc.
# Copyright 2014 INFN
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
# Copyright (c) 2015,2017 Wind River Systems, Inc.
#

import abc

import netaddr
import six

from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions as exc
from neutron_lib.plugins import constants as plugin_constants

from neutron._i18n import _
from neutron.api.v2 import resource_helper
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

# TODO(alegacy): upstream defined 'udp-lite' as 'udplite' so we have to move
# away from our value.  We have DB migration code that converts old values to
# new values, and we have AVR agent code that converts new values to have AVS
# is expecting so we should be convered for upgrades.
deprecated_protocol_values = ['udp-lite']

deprecated_protocol_map = {
    'udp-lite': constants.PROTO_NAME_UDPLITE,
}

valid_protocol_values = [constants.PROTO_NAME_TCP,
                         constants.PROTO_NAME_UDP,
                         constants.PROTO_NAME_UDPLITE,
                         constants.PROTO_NAME_SCTP,
                         constants.PROTO_NAME_DCCP,
                         constants.PROTO_NAME_ICMP]


class PortForwardingRuleNotFound(exc.NotFound):
    message = _("Port Forwarding Rule %(port_forwarding_rule_id)s could not be"
                " found.")


class DuplicatedOutsidePort(exc.InvalidInput):
    message = _("Outside port %(port)s has already been used.")


class DuplicatedInsidePort(exc.InvalidInput):
    message = _("Inside port %(port)s has already been used on %(address)s.")


class InvalidInsideAddress(exc.InvalidInput):
    message = _("inside address %(inside_addr)s does not match "
                "any subnets in this router.")


class InvalidProtocol(exc.InvalidInput):
    message = _("Invalid Protocol, allowed value are: {}").format(
        ', '.join(valid_protocol_values))


class MustAssignRuleToComputePort(exc.InvalidInput):
    message = _("Port Forwarding rules can only be applied to compute ports")


class NoAddressAllocationFound(exc.InvalidInput):
    message = _("No address allocation found for %(ip_address)s "
                "behind router %(router_id)s")


class NoPortFound(exc.InvalidInput):
    message = _("No port object found for %(portid)s")


def convert_port_to_string(value):
    if value is None:
        return
    else:
        return str(value)


def convert_protocol(value):
    if value is None:
        return
    value = value.lower()
    if value in deprecated_protocol_values:
        return deprecated_protocol_map[value]
    elif value in valid_protocol_values:
        return value
    else:
        raise InvalidProtocol()


def validate_port_range(data, key_specs=None):
    if data is None:
        return
    data = str(data)
    ports = data.split(':')
    for p in ports:
        try:
            val = int(p)
        except (ValueError, TypeError):
            msg = _("Port '%s' is not a valid number") % p
            LOG.debug(msg)
            return msg
        if val <= 0 or val > 65535:
            msg = _("Invalid port '%s'") % p
            LOG.debug(msg)
            return msg


def validate_ipv4_address_or_none(data, valid_values=None):
    if data is None:
        return None
    msg_ip = validators.validate_ip_address(data, valid_values)
    if not msg_ip:
        if netaddr.valid_ipv4(data):
            return None
        msg_ip = _("'%s' is not an IPv4 address") % data
    return msg_ip


validators.add_validator('ipv4_address_or_none', validate_ipv4_address_or_none)


# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'portforwardings': {
            'id': {'allow_post': False, 'allow_put': False,
                   'validate': {'type:uuid': None},
                   'is_visible': True, 'primary_key': True},
            'tenant_id': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'is_visible': True},
            'router_id': {'allow_post': True, 'allow_put': False,
                          'required_by_policy': True,
                          'is_visible': True},
            'port_id': {'allow_post': False, 'allow_put': False,
                        'is_visible': True},
            'protocol': {'allow_post': True, 'allow_put': True,
                         'is_visible': True, 'default': None,
                         'convert_to': convert_protocol,
                         'validate': {'type:values': valid_protocol_values}},
            'inside_addr': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:ipv4_address_or_none': None},
                            'is_visible': True, 'default': None},
            'inside_port': {'allow_post': True, 'allow_put': True,
                            'validate': {'type:port_range': None},
                            'convert_to': convert_port_to_string,
                            'default': None, 'is_visible': True},
            'outside_port': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:port_range': None},
                             'convert_to': convert_port_to_string,
                             'default': None, 'is_visible': True},
            'description': {'allow_post': True, 'allow_put': True,
                            'is_visible': True,
                            'default': None},
    }
}


class Portforwardings(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Port Forwarding"

    @classmethod
    def get_alias(cls):
        return "portforwarding"

    @classmethod
    def get_description(cls):
        return "Expose internal TCP/UDP port to external network"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/portforwarding/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2015-03-25T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
                            {}, RESOURCE_ATTRIBUTE_MAP)
        LOG.info('PortForwarding_plural_mappings:%s', plural_mappings)

        maps = resource_helper.build_resource_info(plural_mappings,
                                            RESOURCE_ATTRIBUTE_MAP,
                                            plugin_constants.L3,
                                            allow_bulk=True)
        LOG.info('PortForwarding_get_resources:%s', maps)
        return maps


@six.add_metaclass(abc.ABCMeta)
class PortforwardingsPluginBase(object):

    @abc.abstractmethod
    def create_portforwarding(self, context, portforwarding):
        pass

    @abc.abstractmethod
    def update_portforwarding(self, context, id, portforwarding):
        pass

    @abc.abstractmethod
    def delete_portforwarding(self, context, id):
        pass

    @abc.abstractmethod
    def get_portforwardings(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        pass

    @abc.abstractmethod
    def get_portforwarding(self, context, id, fields=None):
        pass
