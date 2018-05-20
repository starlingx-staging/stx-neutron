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

#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

import threading

from neutron.agent.vswitch import constants
from neutron.agent.vswitch import exceptions
from neutron.agent.vswitch import vif_api

from vswitchclient import client
from vswitchclient import exc


class VSwitchManagementAPI(object):
    """
    Implements a wrapper to the vswitch client API
    """

    def __init__(self):
        self.client = client.Client(constants.VSWITCH_CLIENT_VERSION,
                                    constants.VSWITCH_CLIENT_ENDPOINT)
        self._lock = threading.Lock()
        self.vif_notifier = vif_api.VifAgentNotifier()

    def _do_request(self, callable):
        """
        Thread safe wrapper for executing client requests.
        """
        with self._lock:
            return callable()

    def vif_created(self, port_uuid):
        """
        Send a notification to the L2 agent to signal that a new interface has
        been added.
        """
        self._do_request(
            lambda: self.vif_notifier.vif_created(port_uuid))

    def vif_deleted(self, port_uuid):
        """
        Send a notification to the L2 agent to signal that a new interface has
        been removed.
        """
        self._do_request(
            lambda: self.vif_notifier.vif_deleted(port_uuid))

    def _execute_engine_request(self, callable, engine=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchEngineNotFoundError(str(e), engine)
        except exc.HTTPException as e:
            raise exceptions.VSwitchEngineError(str(e), engine)

    def _execute_port_request(self, callable, port=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchPortNotFoundError(str(e), port)
        except exc.HTTPException as e:
            raise exceptions.VSwitchPortError(str(e), port)

    def _execute_interface_request(self, callable, interface=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchInterfaceNotFoundError(str(e), interface)
        except exc.HTTPException as e:
            raise exceptions.VSwitchInterfaceError(str(e), interface)

    def _execute_network_request(self, callable, network=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchNetworkNotFoundError(str(e), network)
        except exc.HTTPException as e:
            raise exceptions.VSwitchNetworkError(str(e), network)

    def _execute_filter_request(self, callable, rule=None, port=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchFilterNotFoundError(str(e), rule, port)
        except exc.HTTPForbidden as e:
            raise exceptions.VSwitchFilterForbiddenError(str(e), rule, port)
        except exc.HTTPException as e:
            raise exceptions.VSwitchFilterError(str(e), rule, port)

    def _execute_neighbour_request(self, callable, neighbour=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchNeighbourNotFoundError(str(e), neighbour)
        except exc.HTTPForbidden as e:
            raise exceptions.VSwitchNeighbourForbiddenError(str(e), neighbour)
        except exc.HTTPException as e:
            raise exceptions.VSwitchNeighbourError(str(e), neighbour)

    def _execute_address_request(self, callable, address=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchAddressNotFoundError(str(e), address)
        except exc.HTTPForbidden as e:
            raise exceptions.VSwitchAddressForbiddenError(str(e), address)
        except exc.HTTPException as e:
            raise exceptions.VSwitchAddressError(str(e), address)

    def _execute_route_request(self, callable, route=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchRouteNotFoundError(str(e), route)
        except exc.HTTPForbidden as e:
            raise exceptions.VSwitchRouteForbiddenError(str(e), route)
        except exc.HTTPException as e:
            raise exceptions.VSwitchRouteError(str(e), route)

    def _execute_router_request(self, callable, router=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchRouterNotFoundError(str(e), router)
        except exc.HTTPForbidden as e:
            raise exceptions.VSwitchRouterForbiddenError(str(e), router)
        except exc.HTTPException as e:
            raise exceptions.VSwitchRouterError(str(e), router)

    def _execute_dvr_request(self, callable, router=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except Exception as e:
            raise exceptions.VSwitchDvrError(str(e))

    def _execute_snat_request(self, callable, snat=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchSnatNotFoundError(str(e), snat)
        except exc.HTTPConflict as e:
            raise exceptions.VSwitchSnatPortBusyError(str(e), snat)
        except exc.HTTPException as e:
            raise exceptions.VSwitchSnatError(str(e), snat)

    def _execute_ping_request(self, callable, body=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))

    def _execute_vtep_request(self, callable, endpoint=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchEndpointNotFoundError(str(e), endpoint)
        except exc.HTTPException as e:
            raise exceptions.VSwitchEndpointError(str(e), endpoint)

    def _execute_flow_request(self, callable, network=None):
        try:
            return self._do_request(callable)
        except exc.CommunicationError as e:
            raise exceptions.VSwitchCommunicationError(str(e))
        except exc.HTTPNotFound as e:
            raise exceptions.VSwitchFlowSwitchNotFoundError(str(e), network)
        except exc.HTTPException as e:
            raise exceptions.VSwitchFlowError(str(e), network)

    def get_engine_list_stats(self):
        """
        Sends a request to the vswitch requesting the current list of engine
        object instances along with their statistics
        """
        return self._execute_engine_request(self.client.engine.list_stats)

    def lock_port(self, port):
        """
        Sends a request to the vswitch requesting the lock of a port object
        instance.
        """
        self._execute_port_request(
            lambda: self.client.port.lock(port['uuid']), port)

    def unlock_port(self, port):
        """
        Sends a request to the vswitch requesting the unlock of a port
        object instance.
        """
        self._execute_port_request(
            lambda: self.client.port.unlock(port['uuid']), port)

    def attach_port(self, port):
        """
        Sends a request to the vswitch requesting the attachment of a port
        object instance to a network object instance.
        """
        self._execute_port_request(
            lambda: self.client.port.attach(
                port['uuid'], port['network-uuid']), port)

    def detach_port(self, port):
        """
        Sends a request to the vswitch requesting the attachment of a port
        object instance to a network object instance.
        """
        self._execute_port_request(
            lambda: self.client.port.detach(port['uuid']), port)

    def add_port(self, port):
        """
        Sends a request to the vswitch requesting the addition of a new port
        object instance.
        """
        result = self._execute_port_request(
            lambda: self.client.port.create(port), port)
        self.vif_created(port['uuid'])
        return result

    def update_port(self, port):
        """
        Sends a request to the vswitch requesting the update of a port object
        """
        self._execute_port_request(
            lambda: self.client.port.update(port['uuid'], port), port)

    def delete_port(self, port):
        """
        Sends a request to the vswitch requesting the deletion of a port
        object instance.
        """
        self._execute_port_request(
            lambda: self.client.port.delete(port['uuid']), port)
        self.vif_deleted(port['uuid'])

    def destroy_port(self, port):
        """
        This is an extension API to do a best-effort attempt at locking,
        detaching, and deleting of a given port.  It exists to ignore attempts
        at deleting ports that do not actually exist.
        """
        try:
            self.lock_port(port)
            self.detach_port(port)
            self.delete_port(port)
        except exceptions.VSwitchPortNotFoundError:
            pass

    def get_port_list(self):
        """
        Sends a request to the vswitch requesting the current list of port
        object instances along with their attributes.
        """
        return self._execute_port_request(self.client.port.list)

    def get_port(self, uuid):
        """
        Sends a request to the vswitch requesting the attributes of a port
        object instance.
        """
        return self._execute_port_request(
            lambda: self.client.port.get(uuid))

    def get_port_status(self, port):
        """
        Retrieves the current link operational state for a given port object
        instance.
        """
        data = self.get_port(port['uuid'])
        if 'admin-state' in data and 'link-state' in data:
            if data['admin-state'] == "down":
                return False
            elif data['link-state'] == "up":
                return True
        return False

    def get_port_list_stats(self):
        """
        Sends a request to the vswitch requesting the current list of port
        object instances along with their statistics
        """
        return self._execute_port_request(self.client.port.list_stats)

    def update_interface(self, interface):
        """
        Sends a request to the vswitch requesting an update of an interface
        object instance.
        """
        self._execute_interface_request(
            lambda: self.client.interface.update(interface['uuid'], interface))

    def attach_interface(self, interface):
        """
        Sends a request to the vswitch requesting the attachment of a
        interface object instance to a network object instance.
        """
        self._execute_interface_request(
            lambda: self.client.interface.attach(
                interface['uuid'], interface['network-uuid']), interface)

    def detach_interface(self, interface):
        """
        Sends a request to the vswitch requesting the attachment of a
        interface object instance to a network object instance.
        """
        self._execute_interface_request(
            lambda: self.client.interface.detach(interface['uuid']), interface)

    def add_interface(self, interface):
        """
        Sends a request to the vswitch requesting the addition of a new
        interface object instance.
        """
        return self._execute_interface_request(
            lambda: self.client.interface.create(interface), interface)

    def delete_interface(self, interface):
        """
        Sends a request to the vswitch requesting the deletion of a interface
        object instance.
        """
        self._execute_interface_request(
            lambda: self.client.interface.delete(interface['uuid']), interface)

    def get_interface_list(self):
        """
        Sends a request to the vswitch requesting the current list of interface
        object instances along with their attributes.
        """
        return self._execute_interface_request(self.client.interface.list)

    def get_interface(self, uuid):
        """
        Sends a request to the vswitch requesting the attributes of a interface
        object instance.
        """
        return self._execute_interface_request(
            lambda: self.client.interface.get(uuid))

    def get_interface_list_stats(self):
        """
        Sends a request to the vswitch requesting the current list of interface
        object instances along with their statisitcs.
        """
        return self._execute_interface_request(
            self.client.interface.list_stats)

    def get_lacp_interface_list(self):
        """
        Sends a request to the vswitch requesting the current list of LACP
        enabled interface object instances
        """
        return self._execute_interface_request(self.client.lacp.interfaces)

    def add_network(self, network):
        """
        Sends a request to the vswitch requesting the addition of a new
        logical network object instance.
        """
        return self._execute_network_request(
            lambda: self.client.network.create(network), network)

    def update_network(self, network):
        """
        Sends a request to the vswitch requesting the update of a network
        object
        """
        self._execute_network_request(
            lambda: self.client.network.update(network['uuid'],
                                               network), network)

    def delete_network(self, network):
        """
        Sends a request to the vswitch requesting the deletion of a logical
        network object instance.
        """
        self._execute_network_request(
            lambda: self.client.network.delete(network['uuid']), network)

    def add_network_entry(self, interface_uuid, mac_address):
        """
        Sends a request to the vswitch requesting a static layer2 address
        entry against an interface.  The network is derived from the interface
        once the request arrives at the vswitch.
        """
        self._execute_interface_request(
            lambda: self.client.network.add(interface_uuid, mac_address))

    def remove_network_entry(self, interface_uuid, mac_address):
        """
        Sends a request to the vswitch requesting the removal of a static
        layer2 address entry against an interface.  The network is derived
        from the interface once the request arrives at the vswitch.
        """
        self._execute_interface_request(
            lambda: self.client.network.remove(interface_uuid, mac_address))

    def get_network_list(self):
        """
        Sends a request to the vswitch requesting the current list of logical
        network object instances along with their attributes.
        """
        return self._execute_network_request(self.client.network.list)

    def get_network_interface_list(self, uuid):
        """
        Sends a request to the vswitch requesting the current list of logical
        interface objects that are attached to the specified network object
        instances.
        """
        return self._execute_interface_request(
            lambda: self.client.interface.list_network(uuid))

    def get_network(self, uuid):
        """
        Sends a request to the vswitch requesting the attributes of a logical
        network object instance.
        """
        return self._execute_network_request(
            lambda: self.client.network.get(uuid))

    def add_filter_rule(self, rule):
        """
        Sends a request to the vswitch requesting the addition of a new
        filter rule.
        """
        return self._execute_filter_request(
            lambda: self.client.filter.create(rule), rule=rule)

    def delete_filter_rule(self, rule):
        """
        Sends a request to the vswitch requesting the deletion of an existing
        filter rule.
        """
        self._execute_filter_request(
            lambda: self.client.filter.delete(rule['uuid']), rule=rule)

    def add_filter_binding(self, rule, port_uuid):
        """
        Sends a request to the vswitch requesting the addition of a new
        filter binding.
        """
        return self._execute_filter_request(
            lambda: self.client.filter.bind(
                rule['uuid'], port_uuid), rule=rule, port=port_uuid)

    def delete_filter_binding(self, rule, port_uuid):
        """
        Sends a request to the vswitch requesting the deletion of an existing
        filter binding.
        """
        self._execute_filter_request(
            lambda: self.client.filter.unbind(
                rule['uuid'], port_uuid), rule=rule, port=port_uuid)

    def get_filter_bindings(self, port_uuid):
        """
        Sends a request to the vswitch requesting the current list of filter
        rule bindings for the supplied port
        """
        return self._execute_filter_request(
            lambda: self.client.filter.get_bindings(port_uuid), port=port_uuid)

    def add_neighbour(self, neighbour):
        """
        Sends a request to the vswitch requesting the addition of a neighbour
        entry to a logical interface.
        """
        return self._execute_neighbour_request(
            lambda: self.client.neighbour.add(
                neighbour['interface-uuid'], neighbour), neighbour)

    def delete_neighbour(self, neighbour):
        """
        Sends a request to the vswitch requesting the deletion of a neighbour
        entry from a logical interface.
        """
        self._execute_neighbour_request(
            lambda: self.client.neighbour.remove(
                neighbour['interface-uuid'], neighbour['address']), neighbour)

    def get_neighbours(self, interface_uuid):
        """
        Sends a request to the vswitch requesting the list of neighbours on a
        specific interface.
        """
        return self._execute_neighbour_request(
            lambda: self.client.neighbour.list_interface(interface_uuid))

    def add_address(self, address):
        """
        Sends a request to the vswitch requesting the addition of an IP
        address to a logical interface.
        """
        return self._execute_address_request(
            lambda: self.client.address.add(
                address['interface-uuid'], address), address)

    def delete_address(self, address):
        """
        Sends a request to the vswitch requesting the deletion of an IP
        address from a logical interface.
        """
        self._execute_address_request(
            lambda: self.client.address.remove(
                    address['interface-uuid'],
                    address['address']), address)

    def get_address_list(self, family=None, interface_uuid=None):
        """
        Sends a request to the vswitch requesting the current list of logical
        interface addresse objects along with their attributes.
        """
        return self._execute_address_request(
            lambda: self.client.address.list_table(
                family=family, interface_uuid=interface_uuid))

    def add_route(self, route):
        """
        Sends a request to the vswitch requesting the addition of an IP
        route.
        """
        router_uuid = route['router-uuid'] if 'router-uuid' in route else None
        return self._execute_route_request(
            lambda: self.client.route.add(route, router_uuid), route)

    def replace_route(self, route):
        """
        Sends a request to the vswitch requesting the replacement of an IP
        route.  If the route does not already exist, it will be added.
        """
        router_uuid = route['router-uuid'] if 'router-uuid' in route else None
        return self._execute_route_request(
            lambda: self.client.route.replace(route, router_uuid), route)

    def delete_route(self, route):
        """
        Sends a request to the vswitch requesting the deletion of an IP
        route.
        """
        router_uuid = route['router-uuid'] if 'router-uuid' in route else None
        self._execute_route_request(
            lambda: self.client.route.remove(
                        route['prefix'],
                        route['prefix-length'],
                        router_uuid), route)

    def get_router_list(self):
        """
        Sends a request to the vswitch requesting the current list of router
        object instances along with their attributes.
        """
        return self._execute_router_request(self.client.router.list)

    def get_router_interfaces(self, uuid):
        """
        Sends a request to the vswitch requesting a list of interfaces for the
        supplied router
        """
        return self._execute_interface_request(
            lambda: self.client.interface.list_router(uuid))

    def get_router_routes(self, uuid):
        """
        Sends a request to the vswitch requesting a list of routes for the
        supplied router
        """
        return self._execute_route_request(
            lambda: self.client.route.list_table(router=uuid))

    def get_router(self, uuid):
        """
        Sends a request to the vswitch requesting the attributes of a virtual
        router object instance.
        """
        return self._execute_router_request(
            lambda: self.client.router.get(uuid))

    def add_router(self, router):
        """
        Sends a request to the vswitch requesting the addition of a
        router.
        """
        return self._execute_router_request(
            lambda: self.client.router.create(router), router)

    def update_router(self, router):
        """
        Sends a request to the vswitch requesting the update of a
        router.
        """
        return self._execute_router_request(
            lambda: self.client.router.update(router['uuid'], router), router)

    def delete_router(self, router):
        """
        Sends a request to the vswitch requesting the deletion of a router.
        """
        self._execute_router_request(
            lambda: self.client.router.delete(router['uuid']), router)

    def router_attach_interface(self, router):
        """
        Sends a request to the vswitch requesting the attachment of an
        interface object instance to a router object instance.
        """
        self._execute_router_request(
            lambda: self.client.router.attach(
                router['uuid'], router['interface-uuid']), router)

    def router_detach_interface(self, router):
        """
        Sends a request to the vswitch requesting the attachment of a
        interface object instance to a router object instance.
        """
        self._execute_router_request(
            lambda: self.client.router.detach(
                router['uuid'], router['interface-uuid']), router)

    def get_dvr_host_macs(self):
        """
        Sends a request to the vswitch requesting the current set of known
        unique MAC addresses.
        """
        return self._execute_dvr_request(self.client.dvr.list_host_macs)

    def update_dvr_host_macs(self, host_macs):
        """
        Sends a request to the vswitch notifying it that the list of unique
        MAC addresses has changed.
        """
        self._execute_dvr_request(
            lambda: self.client.dvr.update_host_macs(host_macs))

    def add_snat_entry(self, snat):
        """
        Sends a request to the vswitch requesting the addition of a static IPv4
        SNAT entry.
        """
        return self._execute_snat_request(
            lambda: self.client.snat.create(snat), snat)

    def delete_snat_entry(self, interface_uuid, src_address, src_port,
                          protocol):
        """
        Sends a request to the vswitch requesting the deletion of a static IPv4
        SNAT entry.
        """
        self._execute_snat_request(
            lambda: self.client.snat.delete(interface_uuid, src_address,
                                            src_port, protocol))

    def get_snat_list(self):
        """
        Sends a request to the vswitch requesting the full list of IPv4 SNAT
        entries.
        """
        return self._execute_snat_request(
            self.client.snat.list_table)

    def send_ping_request(self, body):
        """
        Sends a request to the vswitch requesting to ping the given address
        """
        return self._execute_ping_request(
            lambda: self.client.ping.send(body))

    def get_ping_response(self, ping_id):
        """
        Gets the response from a given ping from vswitch
        """
        return self._execute_ping_request(
            lambda: self.client.ping.get(ping_id))

    def add_vtep_endpoint(self, interface_uuid, endpoint):
        """
        Sends a request to the vswitch requesting the addition of a static
        VTEP Endpoint entry.
        """
        return self._execute_vtep_request(
            lambda: self.client.vxlan.add(interface_uuid, endpoint), endpoint)

    def delete_vtep_endpoint(self, interface_uuid, mac_address):
        """
        Sends a request to the vswitch requesting the deletion of a static
        VTEP Endpoint entry.
        """
        self._execute_vtep_request(
            lambda: self.client.vxlan.remove(interface_uuid, mac_address))

    def get_vtep_endpoint_list(self, interface_uuid):
        """
        Sends a request to the vswitch requesting the full list of VTEP
        Endpoint entries.
        """
        return self._execute_vtep_request(
            lambda: self.client.vxlan.get_endpoints(interface_uuid))

    def add_vtep_peer(self, interface_uuid, peer):
        """
        Sends a request to the vswitch requesting the addition of a static
        VTEP peer entry.
        """
        return self._execute_vtep_request(
            lambda: self.client.vxlan.add_peer(interface_uuid, peer), peer)

    def delete_vtep_peer(self, interface_uuid, ip_address):
        """
        Sends a request to the vswitch requesting the deletion of a VTEP peer
        entry.
        """
        self._execute_vtep_request(
            lambda: self.client.vxlan.remove_peer(interface_uuid, ip_address))

    def get_vtep_peer_list(self, interface_uuid):
        """
        Sends a request to the vswitch requesting the full list of VTEP
        peer entries.
        """
        return self._execute_vtep_request(
            lambda: self.client.vxlan.get_peers(interface_uuid))

    def add_vtep_ip_endpoint(self, interface_uuid, endpoint):
        """
        Sends a request to the vswitch requesting the addition of a static
        VTEP IP Endpoint entry.
        """
        return self._execute_vtep_request(
            lambda: self.client.vxlan.add_ip_endpoint(
                interface_uuid, endpoint), endpoint)

    def delete_vtep_ip_endpoint(self, interface_uuid, ip_address):
        """
        Sends a request to the vswitch requesting the deletion of a static
        VTEP IP Endpoint entry.
        """
        self._execute_vtep_request(
            lambda: self.client.vxlan.remove_ip_endpoint(
                interface_uuid, ip_address))

    def get_vtep_ip_endpoint_list(self, interface_uuid):
        """
        Sends a request to the vswitch requesting the full list of VTEP
        Endpoint entries.
        """
        return self._execute_vtep_request(
            lambda: self.client.vxlan.get_ip_endpoints(interface_uuid))

    def get_flow_list(self, network_uuid, table_id):
        """
        Sends a request to the vswitch requesting the full list of flows
        for a given table id on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowrule.list(network_uuid, table_id))

    def get_flow(self, network_uuid, table_id, cookie):
        """
        Sends a request to the vswitch requesting a specific
        flow rule for a given table id on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowrule.get(network_uuid, table_id, cookie))

    def add_flow(self, network_uuid, table_id, rule):
        """
        Sends a request to the vswitch requesting the addition of a
        flow rule for a given table id on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowrule.create(network_uuid, table_id, rule))

    def delete_flow(self, network_uuid, table_id, cookie):
        """
        Sends a request to the vswitch requesting the deletion of a
        flow rule for a given table id on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowrule.delete(network_uuid, table_id,
                                                cookie))

    def get_flow_group_list(self, network_uuid):
        """
        Sends a request to the vswitch requesting the full list of flow groups
        on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowgroup.list(network_uuid))

    def get_flow_group(self, network_uuid, group_id):
        """
        Sends a request to the vswitch requesting a specific flow group
        on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowgroup.get(network_uuid, group_id))

    def add_flow_group(self, network_uuid, group):
        """
        Sends a request to the vswitch requesting the addition of a
        flow group on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowgroup.create(network_uuid, group))

    def delete_flow_group(self, network_uuid, group_id):
        """
        Sends a request to the vswitch requesting the deletion of a
        flow group for a given group id on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowgroup.delete(network_uuid, group_id))

    def update_flow_group(self, network_uuid, group_id, group):
        """
        Sends a request to the vswitch requesting the update of a
        flow group for a given group id on a given network.
        """
        return self._execute_flow_request(
            lambda: self.client.flowgroup.update(network_uuid,
                                                 group_id,
                                                 group))
