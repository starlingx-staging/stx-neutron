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

from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants

from neutron.common import constants as n_const

# The MTU value is associated to the network to which the port is attached
# wrs-binding:mtu
MTU = '%sbinding:mtu' % n_const.WRS_FIELD_PREFIX

# The VIF model describes the type of emulated device in the guest.  This is
# analoguous to the hw_vif_model property in Nova.  For clarity, the
# 'vif_type' above represents the type of virtual switch that runs on the
# host, and this field represents type type of hardware emulated in the
# guest.
# wrs-binding:vif_model
VIF_MODEL = '%sbinding:vif_model' % n_const.WRS_FIELD_PREFIX

VIF_MODEL_DEFAULT = 'default'
VIF_MODEL_VIRTIO = 'virtio'
VIF_MODEL_PCI_PASSTHROUGH = 'pci-passthrough'

# The mac_filtering attribute describes whether the MAC filtering was enabled
# as an attribute of the project that this port is owned by.
# wrs-binding:mac_filtering
MAC_FILTERING = '%sbinding:mac_filtering' % n_const.WRS_FIELD_PREFIX

VIF_TYPE_AVS = 'avs'

# - vhostuser_enabled: Boolean value used to determine whether vhostuser can
#                      be enabled for this binding
VHOST_USER_ENABLED = 'vhostuser_enabled'

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        VIF_MODEL: {'allow_post': True, 'allow_put': True,
                    'default': constants.ATTR_NOT_SPECIFIED,
                    'enforce_policy': True,
                    'is_visible': True},
        MTU: {'allow_post': False, 'allow_put': False,
              'default': constants.ATTR_NOT_SPECIFIED,
              'enforce_policy': True,
              'is_visible': True},
        MAC_FILTERING: {'allow_post': False, 'allow_put': False,
              'default': constants.ATTR_NOT_SPECIFIED,
              'enforce_policy': True,
              'is_visible': True},
    }
}


class Wrs_binding(api_extensions.ExtensionDescriptor):
    """Extension class supporting port bindings.

    This class is used by neutron's extension framework to make
    metadata about the port bindings available to external applications.

    With admin rights one will be able to update and read the values.
    """

    @classmethod
    def get_name(cls):
        return "wrs-port-binding"

    @classmethod
    def get_alias(cls):
        return "wrs-binding"

    @classmethod
    def get_description(cls):
        return "WRS Port Binding Extensions."

    @classmethod
    def get_namespace(cls):
        return "http://docs.windriver.org/tis/ext/wrs-binding/v1"

    @classmethod
    def get_updated(cls):
        return "2014-10-01T12:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
