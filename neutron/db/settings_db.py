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

import logging

import sqlalchemy as sa

from neutron_lib.db import model_base

LOG = logging.getLogger(__name__)


def _str2bool(value):
    return bool(value.lower() in ('yes', 'true', 'enabled'))


class Setting(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    """Represent a single setting override for a tenant.

    If there is no row for a given tenant id and resource, then the
    default for the quota class is used.
    """
    name = sa.Column(sa.String(255))
    value = sa.Column(sa.String(255))


class DbSettingsDriver(object):
    """Driver to perform DB operations against settings."""

    @staticmethod
    def get_tenant_settings(context, settings, project_id):
        """Given a list of settings, retrieve the values for the given
        tenant.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param project_id: The ID of the tenant to return quotas for.
        :return dict: from resource name to dict of name and limit
        """

        # init with defaults
        tenant_settings = dict((key, setting.default)
                               for key, setting in settings.items())

        # update with tenant specific values
        q_qry = context.session.query(Setting).filter_by(project_id=project_id)
        tenant_settings.update((q['name'], _str2bool(q['value']))
                               for q in q_qry)
        return tenant_settings

    @staticmethod
    def get_tenant_setting(context, settings, project_id, key):
        """Given a list of settings, retrieve the specified value for the
        given tenant.
        """
        return DbSettingsDriver.get_tenant_settings(context,
                                                    settings,
                                                    project_id)[key]

    @staticmethod
    def delete_tenant_settings(context, project_id):
        """Delete the settings entries for a given project_id.

        Atfer deletion, this tenant will use default quota values in conf.
        """
        with context.session.begin():
            tenant_settings = context.session.query(Setting)
            tenant_settings = tenant_settings.filter_by(project_id=project_id)
            tenant_settings.delete()

    @staticmethod
    def get_all_settings(context, settings):
        """Given a list of settings, retrieve the values for the all tenants.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return quotas: list of dict of project_id:, resourcekey1:
        resourcekey2: ...
        """
        default_settings = dict((key, setting.default)
                                for key, setting in settings.items())

        all_tenant_settings = {}

        for setting in context.session.query(Setting):
            project_id = setting['project_id']

            tenant_settings = all_tenant_settings.get(project_id)
            if tenant_settings is None:
                tenant_settings = default_settings.copy()
                tenant_settings['project_id'] = project_id
                all_tenant_settings[project_id] = tenant_settings

            tenant_settings[setting['name']] = _str2bool(setting['value'])
        return all_tenant_settings.values()

    @staticmethod
    def update_tenant_setting(context, project_id, name, value):
        with context.session.begin():
            tenant_setting = context.session.query(Setting).filter_by(
                project_id=project_id, name=name).first()

            if tenant_setting:
                tenant_setting.update({'value': value})
            else:
                tenant_setting = Setting(project_id=project_id,
                                         name=name,
                                         value=str(value))
                context.session.add(tenant_setting)
