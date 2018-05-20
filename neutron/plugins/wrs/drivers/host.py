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
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#

import re

import six

from oslo_config import cfg
from oslo_log import log as logging

from cgtsclient import exc as cgts_exceptions
from cgtsclient.v1 import client as cgts_client_v1
from keystoneclient.v2_0 import client as keystone_client_v2
from neutron_lib.plugins import directory

from neutron.common import constants
from neutron.drivers import host
from neutron.extensions import host as ext_host

LOG = logging.getLogger(__name__)


class DefaultHostDriver(host.HostDriver):

    def __init__(self):
        super(DefaultHostDriver, self).__init__()
        self._plugin = None

    def _get_plugin(self):
        if not self._plugin:
            self._plugin = directory.get_plugin()
        return self._plugin

    def _get_ksclient(self):
        auth_url = cfg.CONF.KEYSTONE_AUTHTOKEN.identity_uri + "v2.0"
        return keystone_client_v2.Client(
            username=cfg.CONF.KEYSTONE_AUTHTOKEN.admin_user,
            password=cfg.CONF.KEYSTONE_AUTHTOKEN.admin_password,
            tenant_name=cfg.CONF.KEYSTONE_AUTHTOKEN.admin_tenant_name,
            auth_url=auth_url)

    def _get_cgts_url(self):
        url = self._get_ksclient().service_catalog.url_for(
            service_type='platform', endpoint_type='admin')
        # The keystone endpoint has a version number at the end of the URL but
        # the CGTS client does not expect this so remove it.
        url = re.sub('/v[0-9\\.]+$', '/', url)
        return url

    def _get_cgtsclient(self):
        _ksclient = self._get_ksclient()
        token = _ksclient.auth_token
        return cgts_client_v1.Client(
            endpoint=self._get_cgts_url(),
            token=token,
            username=cfg.CONF.KEYSTONE_AUTHTOKEN.admin_user,
            password=cfg.CONF.KEYSTONE_AUTHTOKEN.admin_password,
            tenant_name=cfg.CONF.KEYSTONE_AUTHTOKEN.admin_tenant_name,
            auth_url=cfg.CONF.KEYSTONE_AUTHTOKEN.identity_uri + "v2.0")

    def get_host_uuid(self, context, hostname):
        try:
            host = self._get_cgtsclient().ihost.get(hostname)
            host_uuid = host.uuid
        except cgts_exceptions.HTTPNotFound:
            return None
        return host_uuid

    def _get_host_providernet_names(self, host_uuid):
        """
        Returns the list of provider network names that are currently
        assigned to any interface owned by the specified host UUID.  The names
        are retrieved from the sysinv database.  The data is
        organized as a dictionary keyed by interface uuid with a single key
        representing the providernet list.

           {<uuid>: {'providernets': [a, b, c]},
            <uuid>: {'providernets': [d, e, f]},
            ...}

        """
        result = {}
        try:
            interfaces = self._get_cgtsclient().iinterface.list(host_uuid)
            for interface in interfaces:
                if interface.networktype == "data":
                    names = set()
                    value = interface.providernetworks
                    providernets = value.split(',') if value else []
                    for providernet in providernets:
                        names.add(providernet)
                    result[interface.uuid] = {'providernets': list(names)}
        except cgts_exceptions.HTTPNotFound:
            pass
        return result

    def get_host_providernets(self, context, host_uuid):
        """
        Returns the list of provider network uuids that are currently
        assigned to interfaces owned by the specified host UUID.  The data is
        organized as a dictionary keyed by interface uuid with a single key
        representing the providernet list.

           {<uuid>: {'providernets': [1, 2, 3]},
            <uuid>: {'providernets': [4, 5, 6]},
            ...}

        """
        result = {}
        # Retrieve the results as providernet names and then convert to
        # providernet id values.
        data = self._get_host_providernet_names(host_uuid)
        for uuid, body in six.iteritems(data):
            values = []
            for name in body['providernets']:
                providernet = self._get_plugin().get_providernet_by_name(
                    context, name.strip())
                if providernet:
                    values.append(providernet['id'])
                else:
                    LOG.error(("host {} is referencing "
                               "non-existent provider network {}").format(
                                   host_uuid, name.strip()))
            result[uuid] = {'providernets': values}
        return result

    def get_host_interfaces(self, context, host_uuid):
        """
        Returns the list of data interfaces owned by the specified host UUID.
        The data is organized as a dictionary keyed by interface uuid with a
        dictionary representing the relevant interface fields.

           {<uuid>: { ...body... },
            <uuid>: { ...body... },
            ...}

        """
        result = {}
        interfaces = self._get_cgtsclient().iinterface.list(host_uuid)
        for interface in interfaces:
            if interface.networktype != "data":
                continue
            providernets = interface.providernetworks
            result[interface.uuid] = {'uuid': interface.uuid,
                                      'mtu': interface.imtu,
                                      'vlans': '',
                                      'network_type': interface.networktype,
                                      'providernets': providernets}
        return result

    def is_host_available(self, context, hostname):
        """
        Returns whether the host is available or not.  This code should live in
        the plugin instead of the driver but since we do have our own subclass
        of the ml2 plugin this call needs to return true so that existing unit
        tests continue to work.  If we had our own subclass we would simply
        return true in the base class and run this code in our subclass.
        """
        try:
            host = self._get_plugin().get_host_by_name(context, hostname)
            return host['availability'] == constants.HOST_UP
        except ext_host.HostNotFoundByName:
            # Does not exist yet
            return False
