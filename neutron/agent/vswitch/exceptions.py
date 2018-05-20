# Copyright 2012 OpenStack Foundation
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


class VSwitchError(Exception):
    """
    Base exception class for all VSwitch errors.
    """
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return "{}".format(self.message)


class VSwitchCommunicationError(VSwitchError):
    """
    Exception raised to signal errors communicating with the vswitch server
    process.
    """
    def __init__(self, message):
        super(VSwitchCommunicationError, self).__init__(message)


class VSwitchEngineError(VSwitchError):
    """
    Exception raised to signal errors during port operations.
    """
    def __init__(self, message, engine):
        super(VSwitchEngineError, self).__init__(message)
        self.engine = engine

    def __str__(self):
        if self.engine:
            return "request failed with error {} on engine {}".format(
                self.message, self.engine['id'])
        else:
            return "request failed with error {}".format(self.message)


class VSwitchEngineNotFoundError(VSwitchEngineError):
    """
    Exception raised to signal that a engine operation targeted a non-existent
    engine object instance.
    """
    def __init__(self, message, engine):
        super(VSwitchEngineNotFoundError, self).__init__(message, engine)


class VSwitchPortError(VSwitchError):
    """
    Exception raised to signal errors during port operations.
    """
    def __init__(self, message, port):
        super(VSwitchPortError, self).__init__(message)
        self.port = port

    def __str__(self):
        if self.port:
            return "request failed with error {} on port {}".format(
                self.message, self.port['uuid'])
        else:
            return "request failed with error {}".format(self.message)


class VSwitchPortNotFoundError(VSwitchPortError):
    """
    Exception raised to signal that a port operation targeted a non-existent
    port object instance.
    """
    def __init__(self, message, port):
        super(VSwitchPortNotFoundError, self).__init__(message, port)


class VSwitchPortRetryNeeded(VSwitchPortError):
    """
    Exception raised to signal that a port operation was rejected due to
    contention at the server.  A retry is needed.
    """
    def __init__(self, message, port):
        super(VSwitchPortRetryNeeded, self).__init__(message, port)


class VSwitchNetworkError(VSwitchError):
    """
    Exception raised to signal errors during network operations.
    """
    def __init__(self, message, network):
        super(VSwitchNetworkError, self).__init__(message)
        self.network = network

    def __str__(self):
        if self.network:
            return "request failed with error {} on network {}".format(
                self.message, self.network['uuid'])
        else:
            return "request failed with error {}".format(self.message)


class VSwitchNetworkNotFoundError(VSwitchNetworkError):
    """
    Exception raised to signal that a network operation targeted a non-existent
    network object instance.
    """
    def __init__(self, message, network):
        super(VSwitchNetworkNotFoundError, self).__init__(
            message, network)


class VSwitchInterfaceError(VSwitchError):
    """
    Exception raised to signal errors during interface operations.
    """
    def __init__(self, message, interface):
        super(VSwitchInterfaceError, self).__init__(message)
        self.interface = interface

    def __str__(self):
        if self.interface:
            return "request failed with error {} on interface {}".format(
                self.message, self.interface['uuid'])
        else:
            return "request failed with error {}".format(self.message)


class VSwitchInterfaceNotFoundError(VSwitchInterfaceError):
    """
    Exception raised to signal that a interface operation targeted a
    non-existent interface object instance.
    """
    def __init__(self, message, interface):
        super(VSwitchInterfaceNotFoundError, self).__init__(
            message, interface)


class VSwitchFilterError(VSwitchError):
    """
    Exception raised to signal errors during filter operations.
    """
    def __init__(self, message, rule, port):
        super(VSwitchFilterError, self).__init__(message)
        self.rule = rule
        self.port = port

    def __str__(self):
        if self.rule and self.port:
            msg = ("request failed with error {} on "
                   "filter rule {} and port {}".format(
                       self.message, self.rule['uuid'], self.port))
        elif self.rule:
            msg = ("request failed with error {} on "
                   "filter rule {}".format(
                       self.message, self.rule['uuid']))
        elif self.port:
            msg = ("request failed with error {} on "
                   "filter port {}".format(
                       self.message, self.port))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchFilterNotFoundError(VSwitchFilterError):
    """
    Exception raised to signal that a filter operation targeted a non-existent
    filter object instance.
    """
    def __init__(self, message, rule, port):
        super(VSwitchFilterNotFoundError, self).__init__(
            message, rule, port)


class VSwitchFilterForbiddenError(VSwitchFilterError):
    """
    Exception raised to signal that a filter operation is not permitted.
    """
    def __init__(self, message, rule, port):
        super(VSwitchFilterForbiddenError, self).__init__(
            message, rule, port)


class VSwitchNeighbourError(VSwitchError):
    """
    Exception raised to signal errors during neighbour operations.
    """
    def __init__(self, message, neighbour):
        super(VSwitchNeighbourError, self).__init__(message)
        self.interface = getattr(neighbour, 'interface-uuid', None)
        self.neighbour = neighbour

    def __str__(self):
        if self.interface and self.neighbour:
            msg = (
                "request failed with error {} for "
                "neighbour {} on interface {}".format(
                    self.message, self.neighbour, self.interface))
        elif self.neighbour:
            msg = (
                "request failed with error {} on "
                "neighbour {}".format(
                    self.message, self.neighbour))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchNeighbourNotFoundError(VSwitchNeighbourError):
    """
    Exception raised to signal that a neighbour operation targeted a
    non-existent neighbour object instance.
    """
    def __init__(self, message, neighbour):
        super(VSwitchNeighbourNotFoundError, self).__init__(
            message, neighbour)


class VSwitchNeighbourForbiddenError(VSwitchNeighbourError):
    """
    Exception raised to signal that a neighbour operation is not permitted.
    """
    def __init__(self, message, neighbour):
        super(VSwitchNeighbourForbiddenError, self).__init__(
            message, neighbour)


class VSwitchAddressError(VSwitchError):
    """
    Exception raised to signal errors during address operations.
    """
    def __init__(self, message, address):
        super(VSwitchAddressError, self).__init__(message)
        self.interface = getattr(address, 'interface-uuid', None)
        self.address = address

    def __str__(self):
        if self.interface and self.address:
            msg = (
                "request failed with error {} for "
                "address {} on interface {}".format(
                    self.message, self.address, self.interface))
        elif self.address:
            msg = (
                "request failed with error {} on "
                "address {}".format(
                    self.message, self.address))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchAddressNotFoundError(VSwitchAddressError):
    """
    Exception raised to signal that a address operation targeted a non-existent
    address object instance.
    """
    def __init__(self, message, address):
        super(VSwitchAddressNotFoundError, self).__init__(
            message, address)


class VSwitchAddressForbiddenError(VSwitchAddressError):
    """
    Exception raised to signal that a address operation is not permitted.
    """
    def __init__(self, message, address):
        super(VSwitchAddressForbiddenError, self).__init__(
            message, address)


class VSwitchRouteError(VSwitchError):
    """
    Exception raised to signal errors during route operations.
    """
    def __init__(self, message, route):
        super(VSwitchRouteError, self).__init__(message)
        self.route = route

    def __str__(self):
        if self.route:
            msg = ("request failed with error {} on "
                   "route {}".format(
                       self.message, self.route))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchRouteNotFoundError(VSwitchRouteError):
    """
    Exception raised to signal that a route operation targeted a non-existent
    route object instance.
    """
    def __init__(self, message, route):
        super(VSwitchRouteNotFoundError, self).__init__(
            message, route)


class VSwitchRouteForbiddenError(VSwitchRouteError):
    """
    Exception raised to signal that a route operation is not permitted.
    """
    def __init__(self, message, route):
        super(VSwitchRouteForbiddenError, self).__init__(
            message, route)


class VSwitchRouterError(VSwitchError):
    """
    Exception raised to signal errors during router operations.
    """
    def __init__(self, message, router):
        super(VSwitchRouterError, self).__init__(message)
        self.router = router

    def __str__(self):
        if self.router:
            msg = ("request failed with error {} on "
                   "router {}".format(
                       self.message, self.router))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchRouterNotFoundError(VSwitchRouterError):
    """
    Exception raised to signal that a router operation targeted a non-existent
    router object instance.
    """
    def __init__(self, message, router):
        super(VSwitchRouterNotFoundError, self).__init__(
            message, router)


class VSwitchRouterForbiddenError(VSwitchRouterError):
    """
    Exception raised to signal that a router operation is not permitted.
    """
    def __init__(self, message, router):
        super(VSwitchRouterForbiddenError, self).__init__(
            message, router)


class VSwitchDvrError(VSwitchError):
    """
    Exception raised to signal errors during DVR operations.
    """
    def __init__(self, message):
        super(VSwitchDvrError, self).__init__(message)

    def __str__(self):
        msg = "DVR request failed with error {}".format(self.message)
        return msg


class VSwitchSnatError(VSwitchError):
    """
    Exception raised to signal errors during SNAT operations.
    """
    def __init__(self, message, snat):
        super(VSwitchSnatError, self).__init__(message)
        self.snat = snat

    def __str__(self):
        if self.snat:
            msg = ("request failed with error {} on "
                   "snat {}".format(
                       self.message, self.snat))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchSnatNotFoundError(VSwitchSnatError):
    """
    Exception raised to signal that a SNAT operation targeted a non-existent
    SNAT object instance.
    """
    def __init__(self, message, snat):
        super(VSwitchSnatNotFoundError, self).__init__(
            message, snat)


class VSwitchSnatPortBusyError(VSwitchSnatError):
    """
    Exception raised to signal that a SNAT operation targeted a non-existent
    address and port combination that is already in use by another static SNAT
    entry.
    """
    def __init__(self, message, snat):
        super(VSwitchSnatPortBusyError, self).__init__(
            message, snat)


class VSwitchEndpointError(VSwitchError):
    """
    Exception raised to signal errors during VTEP Endpoint operations.
    """
    def __init__(self, message, endpoint):
        super(VSwitchEndpointError, self).__init__(message)
        self.endpoint = endpoint

    def __str__(self):
        if self.endpoint:
            msg = ("request failed with error {} on "
                   "endpoint {}".format(
                       self.message, self.endpoint))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchEndpointNotFoundError(VSwitchEndpointError):
    """
    Exception raised to signal that a VTEP Endpoint operation targeted a
    non-existent Endpoint object instance.
    """
    def __init__(self, message, endpoint):
        super(VSwitchEndpointNotFoundError, self).__init__(
            message, endpoint)


class VSwitchFlowError(VSwitchError):
    """
    Exception raised to signal errors during flow operations.
    """
    def __init__(self, message, network):
        super(VSwitchFlowError, self).__init__(message)
        self.network = network

    def __str__(self):
        if self.network:
            msg = ("request failed with error {} on "
                   "network {}".format(
                       self.message, self.network))
        else:
            msg = "request failed with error {}".format(self.message)
        return msg


class VSwitchFlowSwitchNotFoundError(VSwitchFlowError):
    """
    Exception raised to signal that a flow operation targeted a
    non-existent flow switch object instance.
    """
    def __init__(self, message, network):
        super(VSwitchFlowSwitchNotFoundError, self).__init__(
            message, network)
