# Copyright (c) 2014 OpenStack Foundation
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

import uuid

import netaddr

from oslo_log import log as logging

from neutron.agent import firewall
from neutron_lib import constants as n_const

LOG = logging.getLogger(__name__)

DIRECTION_IP_PREFIX = {'ingress': 'source_ip_prefix',
                       'egress': 'dest_ip_prefix'}

METADATA_DEFAULT_PREFIX = 32
METADATA_DEFAULT_IP = '169.254.169.254'
METADATA_DEFAULT_CIDR = '%s/%d' % (METADATA_DEFAULT_IP,
                                   METADATA_DEFAULT_PREFIX)
METADATA_DEFAULT_PORT = 80


class VSwitchFirewallDriver(firewall.FirewallDriver):
    """VSwitch Firewall Driver."""

    vswitch_mgr = None

    def __init__(self):
        # list of port which has security groups
        self.filtered_ports = {}

    def add_ingress_metadata_rule(self, port):
        rule = {'direction': 'ingress',
                'ethertype': n_const.IPv4,
                'protocol': 'tcp',
                'source_ip_prefix': METADATA_DEFAULT_CIDR,
                'port_range_min': METADATA_DEFAULT_PORT,
                'port_range_max': METADATA_DEFAULT_PORT}
        #Required to avoid duplicates of rule
        if rule not in port['security_group_rules']:
            port['security_group_rules'].append(rule)

    def register_manager(self, manager):
        self.vswitch_mgr = manager

    def update_security_group_rules(self, sg_id, sg_rules):
        LOG.debug("Update rules of security group (%s)", sg_id)

    def update_security_group_members(self, sg_id, sg_members):
        LOG.debug("Update members of security group (%s)", sg_id)

    def prepare_port_filter(self, port):
        LOG.debug("Preparing port (%s) filter", port['device'])
        self.filtered_ports[port['device']] = port
        self._update_port_rules(port)

    def update_port_filter(self, port):
        LOG.debug("Update port (%s) filter", port['device'])
        self.filtered_ports[port['device']] = port
        self._update_port_rules(port)

    def remove_port_filter(self, port):
        LOG.debug("Remove port (%s) filter", port['device'])
        self.filtered_ports.pop(port['device'], None)
        self._remove_port_rules(port)

    @property
    def ports(self):
        return self.filtered_ports

    def _update_port_rules(self, port):
        rules = []
        if port['security_group_rules']:
            self.add_ingress_metadata_rule(port)
        for sg_rule in port['security_group_rules']:
            rules.append(self._convert_security_group_rule(sg_rule))
        self.vswitch_mgr.update_port_filters(port['id'], rules)

    def _remove_port_rules(self, port):
        rules = []
        for sg_rule in port['security_group_rules']:
            rules.append({'uuid': sg_rule['id']})
        self.vswitch_mgr.remove_port_filters(port['id'], rules)

    @classmethod
    def _convert_security_group_rule(cls, sg_rule):

        # build match criteria
        direction = str(sg_rule.get('direction')).lower()
        ethertype = str(sg_rule.get('ethertype')).lower()

        match = {
            "direction": direction,
            "ethernet": {
                "type-name": ethertype
            }
        }

        ip_protocol = sg_rule.get('protocol', None)
        ip_prefix = sg_rule.get(DIRECTION_IP_PREFIX[direction], None)
        if ip_protocol or ip_prefix:
            match['ip'] = {}
            if ip_protocol:
                if ip_protocol in ["tcp", "udp"]:
                    match['ip']['protocol-name'] = ip_protocol

                    # setup destination port range
                    port_min = sg_rule.get('port_range_min', None)
                    port_max = sg_rule.get('port_range_max', None)
                    if port_min is not None:
                        match.setdefault(ip_protocol, {})
                        match[ip_protocol]['dst-port-min'] = port_min
                    if port_max is not None:
                        match.setdefault(ip_protocol, {})
                        match[ip_protocol]['dst-port-max'] = port_max

                elif ip_protocol == "icmp":
                    if ethertype == n_const.IPv4.lower():
                        match['ip']['protocol-name'] = "icmpv4"
                    else:
                        match['ip']['protocol-name'] = "icmpv6"

                    # setup icmp type/code (stored in min/max range field)
                    icmp_type = sg_rule.get('port_range_min', None)
                    icmp_code = sg_rule.get('port_range_max', None)
                    if (icmp_type is not None) and (icmp_code is not None):
                        match['icmp'] = {
                            'type': icmp_type,
                            'code': icmp_code
                        }
                else:
                    # custom protocol, if it is not valid, then an exception
                    # will be raised
                    match['ip']['protocol-value'] = int(ip_protocol)

            if ip_prefix:
                ip_network = netaddr.IPNetwork(ip_prefix)
                match['ip']['remote-network'] = {
                    'family': 'ipv{}'.format(ip_network.version),
                    'prefix-length': ip_network.prefixlen,
                    'address': str(ip_network.ip)
                }

        # generate a unique rule identifier for generated rule
        rule_id = str(uuid.uuid5(uuid.NAMESPACE_OID,
                                 str(match).encode('utf-8')))
        sg_rule['id'] = rule_id

        rule = {"uuid": rule_id, "match": match}

        LOG.debug("sg_rule {} converted to rule {}".format(sg_rule, rule))

        return rule
