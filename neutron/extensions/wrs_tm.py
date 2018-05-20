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

import abc

from neutron_lib.api import extensions as api_extensions
from neutron_lib import exceptions as exc
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base
from neutron.common import constants as n_const

import six


RESOURCE_ATTRIBUTE_MAP = {
    'qos': {
        'id': {'allow_post': False,
               'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True,
                 'allow_put': True,
                 'is_visible': True},
        'description': {'allow_post': True,
                        'allow_put': True,
                        'is_visible': True,
                        'default': '',
                        'validate': {'type:string': None}},
        'tenant_id': {'allow_post': True,
                      'allow_put': False,
                      'is_visible': True,
                      'default': None},
        'policies': {'allow_post': True,
                     'allow_put': True,
                     'is_visible': True,
                     'validate': {'type:dict': None}},
    },
}

# wrs-tm:qos
QOS = "%stm:qos" % n_const.WRS_FIELD_PREFIX

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {QOS: {'allow_post': True,
                    'allow_put': True,
                    'enforce_policy': True,
                    'is_visible': True,
                    'default': None,
                    'validate': {'type:uuid_or_none': None}}},
    'networks': {QOS: {'allow_post': True,
                       'allow_put': True,
                       'enforce_policy': True,
                       'is_visible': True,
                       'default': None,
                       'validate': {'type:uuid_or_none': None}}},
}


class QoSValidationError(exc.InvalidInput):
    message = _("Invalid QoS Policy")


class Wrs_tm(api_extensions.ExtensionDescriptor):
    """Quality of Service extension."""

    @classmethod
    def get_name(cls):
        return "wrs-traffic-management"

    @classmethod
    def get_alias(cls):
        return "wrs-tm"

    @classmethod
    def get_description(cls):
        return "WRS Traffic Management Extensions."

    @classmethod
    def get_namespace(cls):
        return "http://docs.windriver.org/tis/ext/wrs-tm/v1"

    @classmethod
    def get_updated(cls):
        return "2014-10-01T12:00:00-00:00"

    @classmethod
    def get_resources(cls):
        #TODO(scollins)
        #my_plurals = [(key + 'es', key) for key in
        #              RESOURCE_ATTRIBUTE_MAP.keys()]
        attr.RESOURCE_FOREIGN_KEYS.update({'qoss': QOS})
        exts = []
        plugin = directory.get_plugin()
        resource = "qos"
        params = RESOURCE_ATTRIBUTE_MAP.get(resource, dict())
        collection = "qoses"
        controller = base.create_resource(collection, resource,
                                          plugin, params, allow_bulk=True,
                                          allow_pagination=True,
                                          allow_sorting=True)
        collection = "%s/%s" % (cls.get_alias(), collection)
        ex = extensions.ResourceExtension(collection,
                                          controller,
                                          attr_map=params)
        exts.append(ex)
        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class QoSPluginBase(object):

    @abc.abstractmethod
    def get_qoses(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        pass

    @abc.abstractmethod
    def create_qos(self, context, qos):
        pass

    @abc.abstractmethod
    def delete_qos(self, context, id):
        pass

    @abc.abstractmethod
    def update_qos(self, context, id, qos):
        pass

    @abc.abstractmethod
    def create_qos_for_network(self, context, qos_id, network_id):
        pass

    @abc.abstractmethod
    def delete_qos_for_network(self, context, network_id):
        pass

    @abc.abstractmethod
    def create_qos_for_port(self, context, qos_id, port_id):
        pass

    @abc.abstractmethod
    def delete_qos_for_port(self, context, port_id):
        pass

    @abc.abstractmethod
    def validate_qos(self, context, qos):
        pass
