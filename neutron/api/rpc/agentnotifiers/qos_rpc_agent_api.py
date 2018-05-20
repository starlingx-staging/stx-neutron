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

import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics


class QoSAgentNotifyAPI(object):
    """Plugin-side RPC (stub) for plugin-to-agent interaction."""

    def __init__(self, topic=topics.AGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self.topic_qos_update = topics.get_topic_name(topic,
                                                      topics.QOS,
                                                      topics.UPDATE)

    def network_qos_deleted(self, context, qos_id, network_id):
        cctxt = self.client.prepare(topic=self.topic_qos_update, fanout=True)
        cctxt.cast(context, 'network_qos_deleted',
                   qos_id=qos_id, network_id=network_id)

    def network_qos_updated(self, context, qos_id, network_id):
        cctxt = self.client.prepare(topic=self.topic_qos_update, fanout=True)
        cctxt.cast(context, 'network_qos_updated',
                   qos_id=qos_id, network_id=network_id)

    def port_qos_deleted(self, context, qos_id, port_id):
        cctxt = self.client.prepare(topic=self.topic_qos_update, fanout=True)
        cctxt.cast(context, 'port_qos_deleted',
                   qos_id=qos_id, port_id=port_id)

    def port_qos_updated(self, context, qos_id, port_id):
        cctxt = self.client.prepare(topic=self.topic_qos_update, fanout=True)
        cctxt.cast(context, 'port_qos_updated',
                   qos_id=qos_id, port_id=port_id)
