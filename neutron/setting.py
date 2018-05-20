#    Copyright 2011 OpenStack Foundation
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


"""Neutron settings for tenants."""

import six

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron._i18n import _


LOG = logging.getLogger(__name__)
SETTING_DB_MODULE = 'neutron.db.settings_db'
SETTING_DB_DRIVER = 'neutron.db.settings_db.DbSettingsDriver'

MAC_FILTERING = "mac_filtering"

setting_opts = [
    cfg.ListOpt('setting_items',
                default=[MAC_FILTERING],
                help=_('Setting name(s) that are supported in quota '
                       'features')),
    cfg.BoolOpt('setting_' + MAC_FILTERING,
                default=False,
                help=_('Enable/Disable source MAC filtering on all ports')),
    cfg.StrOpt('setting_driver',
               default=SETTING_DB_DRIVER,
               help=_('Default driver to use for setting management')),
]

# Register the configuration options
cfg.CONF.register_opts(setting_opts, 'SETTINGS')


class BaseSetting(object):
    """Describe a single setting."""

    def __init__(self, name, flag):
        """Initializes a setting.

        :param name: The name of the setting, i.e., "mac_filtering".
        :param flag: The name of the flag or configuration option as it
                     appears in the neutron.conf configuration file.
        """

        self.name = name
        self.flag = flag

    @property
    def default(self):
        """Return the default value of the settings."""
        return getattr(cfg.CONF.SETTINGS, self.flag, None)


class SettingEngine(object):
    """Represent the set of recognized settings."""

    def __init__(self, setting_driver_class=None):
        """Initialize a Setting object."""

        self._settings = {}
        self._driver = None
        self._driver_class = setting_driver_class

    def get_driver(self):
        if self._driver is None:
            _driver_class = (self._driver_class or
                             cfg.CONF.SETTINGS.setting_driver)
            if isinstance(_driver_class, six.string_types):
                _driver_class = importutils.import_object(_driver_class)
            self._driver = _driver_class
            LOG.info('Loaded setting_driver: %s.', _driver_class)
        return self._driver

    def __contains__(self, setting):
        return setting in self._settings

    def register_setting(self, setting):
        """Register a setting."""
        if setting.name in self._settings:
            LOG.warning('%s is already registered.', setting.name)
            return
        self._settings[setting.name] = setting

    def register_settings(self, settings):
        """Register a list of settings."""

        for setting in settings:
            self.register_setting(setting)

    @property
    def settings(self):
        return self._settings


ENGINE = SettingEngine()


def register_settings_from_config():
    settings = []
    for setting_item in cfg.CONF.SETTINGS.setting_items:
        settings.append(BaseSetting(setting_item, 'setting_' + setting_item))
    ENGINE.register_settings(settings)


register_settings_from_config()
