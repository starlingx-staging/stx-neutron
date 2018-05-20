# Copyright (c) 2013 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

from oslo_log import log as logging
import oslo_messaging

from neutron.common import rpc as n_rpc
from neutron.common import topics


LOG = logging.getLogger(__name__)


class HostAgentNotifyAPI(object):
    """API for plugin to notify agents of host state change."""

    def __init__(self, topic=topics.AGENT):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.topic = topic
        self.client = n_rpc.get_client(target)

    def _notification_host(self, context, method, payload, host):
        """Notify the agents that are hosted on the host."""
        LOG.debug('Notify agents on %(host)s of the message '
                  '%(method)s', {'host': host,
                                 'method': method})
        topic_host_updated = topics.get_topic_name(self.topic,
                                                   topics.HOST,
                                                   topics.UPDATE,
                                                   host)
        cctxt = self.client.prepare(topic=topic_host_updated,
                                    server=host)
        cctxt.cast(context, method, payload=payload)

    def host_updated(self, context, host_state_up, host):
        self._notification_host(context, 'host_updated',
                                {'host_state_up': host_state_up},
                                host)
