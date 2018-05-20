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
# Copyright (c) 2016 Wind River Systems, Inc.
#

import oslo_messaging

from oslo_log import log as logging

from neutron.common import rpc as n_rpc

LOG = logging.getLogger(__name__)


class PnetConnectivityCallback(object):
    """Plugin-side RPC (callback) for agent-to-plugin interaction."""

    def __init__(self, pnet_connectivity_manager):
        self.pnet_connectivity_manager = pnet_connectivity_manager

    def report_connectivity_results(self, context, **kwargs):
        audit_results = kwargs['audit_results']
        audit_uuid = kwargs['audit_uuid']
        self.pnet_connectivity_manager.record_audit_results(context,
                                                            audit_results,
                                                            audit_uuid)


class PnetConnectivityRpcApi(object):
    """Agent-side RPC (callback) for agent-to-plugin interaction."""

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def report_connectivity_results(self, context, audit_results, audit_uuid):
        cctxt = self.client.prepare()
        cctxt.cast(context, 'report_connectivity_results',
                   audit_results=audit_results, audit_uuid=audit_uuid)


class PnetConnectivityRpc(object):
    """Agent-side RPC (callback) for plugin-to-agent interaction."""

    pnet_connectivity_manager = None

    def setup_connectivity_audit(self, context, **kwargs):
        self.pnet_connectivity_manager.pnet_connectivity_audit_uuid = \
            kwargs['audit_uuid']
        return self.pnet_connectivity_manager._setup_connectivity_audit(
            kwargs['providernet'],
            kwargs['segments'],
            kwargs['extra_data']
        )

    def start_connectivity_audit(self, context, **kwargs):
        self.pnet_connectivity_manager._start_connectivity_audit(
            kwargs['audit_uuid'],
            kwargs['masters'],
            kwargs['hosts'],
            kwargs['providernet'],
            kwargs['segments'],
            kwargs['extra_data']
        )

    def teardown_connectivity_audit(self, context, **kwargs):
        """
        If the audit IDs mismatch, such as when the agent is relaunched,
         then teardown all non-attached interfaces vlan provider
        """
        if (self.pnet_connectivity_manager.pnet_connectivity_audit_uuid !=
                kwargs['audit_uuid']):
            clearall = True
        else:
            clearall = False
        return self.pnet_connectivity_manager._teardown_connectivity_audit(
            clearall
        )
