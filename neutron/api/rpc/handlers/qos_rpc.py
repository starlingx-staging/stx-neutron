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

from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import importutils

from neutron._i18n import _
from neutron.common import constants
from neutron.common import rpc as n_rpc


LOG = logging.getLogger(__name__)

QoSOpts = [
    cfg.StrOpt(
        'qos_driver',
        default='neutron.agent.qos.NoopQoSDriver',
        help=_("Default driver to use for quality of service")),
]

cfg.CONF.register_opts(QoSOpts, "agent")


class QoSServerRpcApi(object):
    """Agent-side RPC (stub) for agent-to-plugin interaction."""

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def get_policy_for_qos(self, context, qos_id):
        LOG.debug("Get policy for QoS ID: %s via RPC", qos_id)
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_policy_for_qos', qos_id=qos_id)

    def get_qos_by_network(self, context, network_id):
        LOG.debug("Checking for QoS policy for net: %s", network_id)
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_qos_by_network', network_id=network_id)

    def get_qos_by_port(self, context, port_id):
        LOG.debug("Checking for QoS policy for port: %s", port_id)
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_qos_by_port', port_id=port_id)


class QoSServerRpcCallback(object):
    """Plugin-side RPC (implementation) for agent-to-plugin interaction."""

    # History
    #   1.0 Initial version

    target = oslo_messaging.Target(version='1.0',
                                   namespace=constants.RPC_NAMESPACE_QOS)

    @property
    def plugin(self):
        if not getattr(self, '_plugin', None):
            self._plugin = directory.get_plugin()
        return self._plugin

    def get_policy_for_qos(self, context, **kwargs):
        qos_id = kwargs.get('qos_id')
        LOG.debug("QoS Agent requests policy qos %s", qos_id)
        return self.plugin.get_policy_for_qos(context, qos_id)

    def get_qos_by_network(self, context, **kwargs):
        network_id = kwargs.get('network_id')
        LOG.debug("QoS Agent requests qos for network %s", network_id)
        return self.plugin.get_qos_by_network(context, network_id)

    def get_qos_by_port(self, context, **kwargs):
        port_id = kwargs.get('port_id')
        LOG.debug("QoS Agent requests qos for port %s", port_id)
        return self.plugin.get_qos_by_port(context, port_id)


class QoSAgentRpc(object):
    """Agent-side RPC (implementation) for plugin-to-agent interaction."""

    def __init__(self, context, plugin_rpc):
        self.context = context
        self.plugin_rpc = plugin_rpc
        self.init_qos()

    def init_qos(self, *args, **kwargs):
        qos_driver = cfg.CONF.agent.qos_driver
        LOG.debug("Starting QoS driver %s", qos_driver)
        self.qos = importutils.import_object(qos_driver, *args, **kwargs)

    def register_manager(self, manager):
        if hasattr(self.qos, 'register_manager'):
            self.qos.register_manager(manager)

    def network_qos_deleted(self, context, qos_id, network_id):
        self.qos.delete_qos_for_network(network_id)

    def network_qos_updated(self, context, qos_id, network_id):
        qos_policy = self.plugin_rpc.get_policy_for_qos(context, qos_id)
        self.qos.network_qos_updated(qos_policy, network_id)

    def port_qos_updated(self, context, qos_id, port_id):
        qos_policy = self.plugin_rpc.get_policy_for_qos(context, qos_id)
        self.qos.port_qos_updated(qos_policy, port_id)

    def port_qos_deleted(self, context, qos_id, port_id):
        self.qos.delete_qos_for_port(port_id)


class QoSAgentRpcCallbackMixin(object):
    """Agent-side RPC (callback) for plugin-to-agent interaction."""

    qos_agent = None

    def network_qos_updated(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        network_id = kwargs.get('network_id', '')
        LOG.debug('QoS %(qos_id)s updated on network: %(network_id)s', kwargs)
        self.qos_agent.network_qos_updated(context, qos_id, network_id)

    def network_qos_deleted(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        network_id = kwargs.get('network_id', '')
        LOG.debug('QoS %(qos_id)s deleted on network: %(network_id)s', kwargs)
        self.qos_agent.network_qos_deleted(context, qos_id, network_id)

    def port_qos_deleted(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        if self.get_vif_port_by_id(port_id):
            LOG.debug('QoS %(qos_id)s deleted on port: %(port_id)s', kwargs)
            self.qos_agent.port_qos_deleted(context, qos_id, port_id)

    def port_qos_updated(self, context, **kwargs):
        qos_id = kwargs.get('qos_id', '')
        port_id = kwargs.get('port_id', '')
        if self.get_vif_port_by_id(port_id):
            LOG.debug('QoS %(qos_id)s updated on port: %(port_id)s', kwargs)
            self.qos_agent.port_qos_updated(context, qos_id, port_id)
