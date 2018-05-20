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
from neutron.common import topics


LOG = logging.getLogger(__name__)


class PnetConnectivityAgentNotifyAPI(object):
    """Plugin-side RPC (stub) for plugin-to-agent interaction."""

    def __init__(self, topic=topics.AGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.topic = topic
        self.client = n_rpc.get_client(target)
        self.topic_pnet_connectivity_cast = topics.get_topic_name(
            topic,
            topics.PNET_CONNECTIVITY,
            topics.UPDATE
        )

    def setup_connectivity_audit(self, context, audit_uuid, hostname,
                                 providernet, segments, extra_data):
        topic_pnet_connectivity_call = topics.get_topic_name(
            self.topic,
            topics.PNET_CONNECTIVITY,
            topics.UPDATE,
            hostname
        )
        cctxt = self.client.prepare(topic=topic_pnet_connectivity_call,
                                    fanout=False)
        return cctxt.call(context, 'setup_connectivity_audit',
                          audit_uuid=audit_uuid,
                          providernet=providernet,
                          segments=segments,
                          extra_data=extra_data)

    def start_connectivity_audit(self, context, audit_uuid, masters, hosts,
                                 providernet, segments, extra_data):
        """Sets up on non masters, runs on all, and then tears down"""
        cctxt = self.client.prepare(topic=self.topic_pnet_connectivity_cast,
                                    fanout=True)
        cctxt.cast(context, 'start_connectivity_audit', audit_uuid=audit_uuid,
                   masters=masters, hosts=hosts, providernet=providernet,
                   segments=segments, extra_data=extra_data)

    def teardown_connectivity_audit(self, context, audit_uuid, hostname):
        """
        Call teardown_connectivity_audit for given host,
        or cast for all if none is specified.
        """
        if hostname:
            topic_pnet_connectivity_call = topics.get_topic_name(
                self.topic,
                topics.PNET_CONNECTIVITY,
                topics.UPDATE,
                hostname
            )
            cctxt = self.client.prepare(topic=topic_pnet_connectivity_call,
                                        fanout=False)
            return cctxt.call(context, 'teardown_connectivity_audit',
                              audit_uuid=audit_uuid)
        else:
            cctxt = self.client.prepare(
                topic=self.topic_pnet_connectivity_cast,
                fanout=True
            )
            cctxt.cast(context, 'teardown_connectivity_audit',
                       audit_uuid=audit_uuid)
            return True
