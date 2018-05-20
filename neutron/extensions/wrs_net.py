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

from oslo_log import log as logging

from neutron_lib.api import extensions as api_extensions

from neutron.common import constants as n_const


LOG = logging.getLogger(__name__)

# wrs-net:vlan_id
VLAN = '%snet:vlan_id' % n_const.WRS_FIELD_PREFIX

# wrs-net:host
HOST = '%snet:host' % n_const.WRS_FIELD_PREFIX


EXTENDED_ATTRIBUTES_2_0 = {
    'routers': {
        HOST: {'allow_post': False, 'allow_put': False,
               'enforce_policy': True,
               'is_visible': True},
    },
}


class Wrs_net(api_extensions.ExtensionDescriptor):
    """Extension class supporting port bindings.

    This class is used by neutron's extension framework to make
    metadata about the port bindings available to external applications.

    With admin rights one will be able to update and read the values.
    """

    @classmethod
    def get_name(cls):
        return "wrs-tenant-network"

    @classmethod
    def get_alias(cls):
        return "wrs-net"

    @classmethod
    def get_description(cls):
        return "WRS Tenant Network Extensions."

    @classmethod
    def get_namespace(cls):
        return "http://docs.windriver.org/tis/ext/wrs-net/v1"

    @classmethod
    def get_updated(cls):
        return "2014-10-01T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
