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

import socket

import eventlet
from oslo_serialization import jsonutils

VIF_BUFFER_LENGTH = 1024
VIF_UDP_ADDRESS = '127.0.0.1'
VIF_UDP_PORT = 9001


class VifAgentListenerMixin(object):
    """Abstract representation of the API that must be implemented by the
    listener agent.
    """
    def vif_created(self, vif_id):
        pass

    def vif_deleted(self, vif_id):
        pass

    def vif_error_handler(self, exception):
        pass


class VifAgentListener(object):
    """Implements the server side of the VIF notification API."""
    def __init__(self, agent, **kwargs):
        self.address = kwargs.get('address', VIF_UDP_ADDRESS)
        self.port = kwargs.get('port', VIF_UDP_PORT)
        self.agent = agent
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.address, self.port))
        self.running = True
        self.thread = eventlet.greenthread.spawn(
            self._vif_message_handler, self.agent, self.sock)

    def _vif_message_handler(self, agent, sock):
        """Implements the UDP receive function that relays valid messages
        to the agent object.
        """
        while self.running:
            try:
                data, addr = sock.recvfrom(VIF_BUFFER_LENGTH)
                msg = jsonutils.loads(data)
                for key in msg.keys():
                    if 'vif_created' in msg:
                        body = msg['vif_created']
                        agent.vif_created(body['uuid'])
                    if 'vif_deleted' in msg:
                        body = msg['vif_deleted']
                        agent.vif_created(body['uuid'])
            except Exception as e:
                agent.vif_error_handler(e)

    def wait(self):
        """Waits for the listener thread to terminate voluntarily"""
        self.running = False
        return self.thread.wait()

    def kill(self):
        """Kills the listener thread"""
        return self.thread.kill()


class VifAgentNotifier(object):
    """Implements the client side of the VIF notification API."""
    def __init__(self, **kwargs):
        self.address = kwargs.get('address', VIF_UDP_ADDRESS)
        self.port = kwargs.get('port', VIF_UDP_PORT)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def vif_created(self, vif_id):
        msg = {'vif_created': {'uuid': vif_id}}
        self.sock.sendto(jsonutils.dumps(msg), (self.address, self.port))

    def vif_deleted(self, vif_id):
        msg = {'vif_deleted': {'uuid': vif_id}}
        self.sock.sendto(jsonutils.dumps(msg), (self.address, self.port))
