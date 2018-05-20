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
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#

from vswitchclient import constants

# Client parameters
VSWITCH_CLIENT_VERSION = "1"
VSWITCH_CLIENT_ENDPOINT = constants.VSWITCHCLIENT_URL

# vswitch port types
VSWITCH_PHYSICAL_PORT = "physical"
VSWITCH_AVP_GUEST_PORT = "avp-guest"
VSWITCH_AVP_HOST_PORT = "avp-host"
VSWITCH_AVP_VHOST_USER = "vhost-user"

VSWITCH_DVR_SERVICED_PORTS = [VSWITCH_AVP_GUEST_PORT,
                              VSWITCH_AVP_HOST_PORT,
                              VSWITCH_AVP_VHOST_USER]

# vswitch network types
VSWITCH_LAYER2_NETWORK = "layer2"

# vswitch interface types
VSWITCH_AE_INTERFACE = "ae"
VSWITCH_ETHERNET_INTERFACE = "ethernet"
VSWITCH_VLAN_INTERFACE = "vlan"
VSWITCH_VXLAN_INTERFACE = "vxlan"
VSWITCH_ROUTER_INTERFACE = "router"

# vswitch interface classes
VSWITCH_PROVIDER_INTERFACE = "provider"
VSWITCH_TENANT_INTERFACE = "tenant"
VSWITCH_HOST_INTERFACE = "host"

# vswitch port admin states
VSWITCH_ADMIN_STATE_UP = "up"
VSWITCH_ADMIN_STATE_DOWN = "down"

# vswitch port link states
VSWITCH_LINK_STATE_UP = "up"
VSWITCH_LINK_STATE_DOWN = "down"

# vswitch AE member states
VSWITCH_AE_MEMBER_STATE_ACTIVE = "active"
VSWITCH_AE_MEMBER_STATE_STANDBY = "standby"
VSWITCH_AE_MEMBER_STATE_DOWN = "down"

# vswitch AE protection modes
VSWITCH_AE_PROTECTION_MODE_FAILOVER = "failover"
VSWITCH_AE_PROTECTION_MODE_LOADBALANCE = "loadbalance"
VSWITCH_AE_PROTECTION_MODE_8023AD = "802.3ad"

# vswitch LACP states
VSWITCH_LACP_STATE_COLLECTING = "collecting"
VSWITCH_LACP_STATE_DISTRIBUTING = "distributing"

# vswitch threshold for stale ports
VSWITCH_STALE_PORT_THRESHOLD_MINS = 5

# vswitch NUMA socket identifiers
VSWITCH_SOCKET_ID_0 = 0
VSWITCH_SOCKET_ID_1 = 1

# vswitch NDP router advertisement modes
VSWITCH_NDP_RA_MODE_NONE = None
VSWITCH_NDP_RA_MODE_SLAAC = "slaac"
VSWITCH_NDP_RA_MODE_STATELESS = "stateless"
VSWITCH_NDP_RA_MODE_STATEFUL = "stateful"

# vswitch neighbour types
VSWITCH_NEIGH_STATIC = "static"
VSWITCH_NEIGH_DYNAMIC = "dynamic"

# vswitch number of bytes overhead for ICMP packet
VSWITCH_IPV6_ICMP_HEADER_SIZE = 48

# vswitch minimum ping size to try
VSWITCH_PING_MINIMUM_SIZE = 64

# vswitch get_ping_response wait time parameters
VSWITCH_PING_RESPONSE_CHECK_INTERVAL = 0.0025
VSWITCH_PING_RESPONSE_CHECK_MULTIPLIER = 2.0
VSWITCH_PING_RESPONSE_CHECK_COUNT = 10
