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
import mock

from oslo_context import context as oslo_context

from neutron.api.rpc.agentnotifiers import qos_rpc_agent_api
from neutron.api.rpc.handlers import qos_rpc
from neutron.db import qos_db
from neutron.tests import base
from neutron.tests.unit.plugins.wrs import test_extension_qos as test_qos


QOS_BASE_PACKAGE = 'neutron.services.qos.drivers'
OPENFLOW_DRIVER = QOS_BASE_PACKAGE + '.openflow.OpenflowQoSVlanDriver'


class FakeQoSCallback(qos_db.QoSDbMixin):
    pass


class QoSServerRpcCallbackMixinTestCase(test_qos.QoSDBTestCase):
    def setUp(self):
        super(QoSServerRpcCallbackMixinTestCase, self).setUp()
        self.rpc = FakeQoSCallback()


class QoSServerRpcApiTestCase(base.BaseTestCase):
    def setUp(self):
        self.client_p = mock.patch.object(qos_rpc.n_rpc, "get_client")
        self.client = self.client_p.start()
        self.rpc = qos_rpc.QoSServerRpcApi('fake_topic')
        self.mock_cctxt = self.rpc.client.prepare.return_value
        self.ctxt = mock.ANY
        super(QoSServerRpcApiTestCase, self).setUp()

    def test_get_policy_for_qos(self):
        self.rpc.get_policy_for_qos(self.ctxt, 'fake-qos')
        self.mock_cctxt.call.assert_called_with(
            self.ctxt, 'get_policy_for_qos', qos_id='fake-qos')

    def test_get_qos_by_network(self):
        self.rpc.get_qos_by_network(self.ctxt, 'fake-network')
        self.mock_cctxt.call.assert_called_with(
            self.ctxt, 'get_qos_by_network', network_id='fake-network')


class QoSAgentRpcTestCase(base.BaseTestCase):
    def setUp(self):
        super(QoSAgentRpcTestCase, self).setUp()
        self.ctxt = oslo_context.get_admin_context()
        self.fake_policy = {"fake": "qos"}
        rpc = mock.Mock()
        rpc.get_policy_for_qos.return_value = self.fake_policy
        self.agent = qos_rpc.QoSAgentRpc(self.ctxt, rpc)
        self.agent.qos = mock.Mock()

    def test_network_qos_deleted(self):
        self.agent.network_qos_deleted(self.ctxt, 'fake-qos', 'fake-network')
        self.agent.qos.delete_qos_for_network.assert_has_calls(
            [mock.call('fake-network')])

    def test_network_qos_updated(self):
        self.agent.network_qos_updated(self.ctxt, 'fake-qos', 'fake-network')
        self.agent.plugin_rpc.get_policy_for_qos.assert_has_calls(
            [mock.call(self.ctxt, 'fake-qos')])
        self.agent.qos.network_qos_updated.assert_has_calls(
            [mock.call(self.fake_policy, 'fake-network')])

    def test_port_qos_updated(self):
        self.agent.port_qos_updated(self.ctxt, 'fake-qos', 'fake-port')
        self.agent.qos.port_qos_updated.assert_has_calls(
            [mock.call(self.fake_policy, 'fake-port')])

    def test_port_qos_deleted(self):
        self.agent.port_qos_deleted(self.ctxt, 'fake-qos', 'fake-port')
        self.agent.qos.delete_qos_for_port.assert_has_calls(
            [mock.call('fake-port')])


class QoSAgentRpcApiMixinTestCase(base.BaseTestCase):
    def setUp(self):
        super(QoSAgentRpcApiMixinTestCase, self).setUp()
        self.ctxt = oslo_context.get_admin_context()
        self.notifier = qos_rpc_agent_api.QoSAgentNotifyAPI(topic='fake-topic')
        self.cctxt = mock.Mock().start()
        self.cctxt.cast.return_value = None

    def test_network_qos_updated(self):
        with mock.patch.object(self.notifier.client,
                               'prepare', return_value=self.cctxt):
            self.notifier.network_qos_updated(self.ctxt,
                                              network_id='fake-network',
                                              qos_id='fake-qos')
            self.cctxt.cast.assert_has_calls(
                [mock.call(self.ctxt, 'network_qos_updated',
                           qos_id='fake-qos', network_id='fake-network')])

    def test_network_qos_deleted(self):
        with mock.patch.object(self.notifier.client,
                               'prepare', return_value=self.cctxt):
            self.notifier.network_qos_deleted(self.ctxt,
                                              network_id='fake-network',
                                              qos_id='fake-qos')
            self.cctxt.cast.assert_has_calls(
                [mock.call(self.ctxt, 'network_qos_deleted',
                           qos_id='fake-qos', network_id='fake-network')])

    def test_port_qos_deleted(self):
        with mock.patch.object(self.notifier.client,
                               'prepare', return_value=self.cctxt):
            self.notifier.port_qos_deleted(self.ctxt,
                                           port_id='fake-port',
                                           qos_id='fake-qos')
            self.cctxt.cast.assert_has_calls(
                [mock.call(self.ctxt, 'port_qos_deleted',
                           qos_id='fake-qos', port_id='fake-port')])

    def test_port_qos_updated(self):
        with mock.patch.object(self.notifier.client,
                               'prepare', return_value=self.cctxt):
            self.notifier.port_qos_updated(self.ctxt,
                                           port_id='fake-port',
                                           qos_id='fake-qos')
            self.cctxt.cast.assert_has_calls(
                [mock.call(self.ctxt, 'port_qos_updated',
                           qos_id='fake-qos', port_id='fake-port')])
