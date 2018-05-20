# Copyright 2011 OpenStack Foundation.
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


from neutron_lib.api import converters
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
import webob

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource
from neutron.common import exceptions as q_exc
from neutron import setting as settings
from neutron import wsgi

from neutron_lib.api import extensions as api_extensions
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

RESOURCE_NAME = 'setting'
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
ENGINE = settings.ENGINE
DB_SETTING_DRIVER = 'neutron.db.settings_db.DbSettingsDriver'
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}


class SettingsController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin
        self._driver = importutils.import_class(
            cfg.CONF.SETTINGS.setting_driver
        )
        self._update_extended_attributes = True

    def _update_attributes(self):
        for setting in ENGINE.settings.iterkeys():
            attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
            attr_dict[setting] = {'allow_post': False,
                                  'allow_put': True,
                                  'convert_to': converters.convert_to_boolean,
                                  'is_visible': True}
        self._update_extended_attributes = False

    def _get_settings(self, request, tenant_id):
        return self._driver.get_tenant_settings(
            request.context, ENGINE.settings, tenant_id)

    def create(self, request, body=None):
        msg = _('POST requests are not supported on this resource.')
        raise webob.exc.HTTPNotImplemented(msg)

    def index(self, request):
        context = request.context
        self._check_admin(context)
        return {self._resource_name + "s":
                self._driver.get_all_settings(context, ENGINE.settings)}

    def tenant(self, request):
        """Retrieve the tenant info in context."""
        context = request.context
        if not context.tenant_id:
            raise q_exc.SettingMissingTenant()
        return {'tenant': {'tenant_id': context.tenant_id}}

    def show(self, request, id):
        if id != request.context.tenant_id:
            self._check_admin(request.context,
                              reason=_("Non-admin is not authorised to "
                                       "access settings for another tenant"))
        return {self._resource_name: self._get_settings(request, id)}

    def _check_admin(self, context,
                     reason=_("Only admin can view or configure settings")):
        if not context.is_admin:
            raise q_exc.AdminRequired(reason=reason)

    def delete(self, request, id):
        self._check_admin(request.context)
        self._driver.delete_tenant_settings(request.context, id)

    def update(self, request, id, body=None):
        self._check_admin(request.context)
        if self._update_extended_attributes:
            self._update_attributes()
        body = base.Controller.prepare_request_body(
            request.context, body, False, self._resource_name,
            EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION])
        for key, value in body[self._resource_name].items():
            self._driver.update_tenant_setting(request.context, id, key, value)
        return {self._resource_name: self._get_settings(request, id)}


class Wrs_tenant(api_extensions.ExtensionDescriptor):
    """Settings management support."""

    @classmethod
    def get_name(cls):
        return "wrs-tenant-settings"

    @classmethod
    def get_alias(cls):
        return "wrs-tenant"

    @classmethod
    def get_description(cls):
        return "WRS Tenant Network Settings Extensions."

    @classmethod
    def get_namespace(cls):
        return "http://docs.windriver.org/tis/ext/wrs-tenant/v1"

    @classmethod
    def get_updated(cls):
        return "2014-10-01T12:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extension Resources."""
        controller = resource.Resource(
            SettingsController(directory.get_plugin()),
            faults=base.FAULT_MAP)
        collection = "%s/%s" % (Wrs_tenant.get_alias(), RESOURCE_COLLECTION)
        return [extensions.ResourceExtension(
                collection, controller, collection_actions={'tenant': 'GET'})]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
