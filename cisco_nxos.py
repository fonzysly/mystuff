"""
https://docs.nautobot.com/projects/core/en/stable/development/jobs/

"""

from .discover_utils import utils
from django.contrib.contenttypes.models import ContentType
from nautobot.apps.jobs import Job, register_jobs
from nautobot.dcim.models import Platform
from django.core.exceptions import ValidationError, ObjectDoesNotExist
import napalm
import ipaddress
import os
import pathlib


# IPAM

from nautobot.ipam.models import (
    IPAddress,
    VRFPrefixAssignment,
    IPAddressToInterface,
)

# Job
from nautobot.apps.jobs import (
    Job,
    ObjectVar,
    BooleanVar,
    MultiObjectVar,
)

# DCIM
from nautobot.dcim.choices import (
    InterfaceTypeChoices,
    InterfaceModeChoices,
)
from nautobot.dcim.models import (
    Platform,
    Device,
    Interface,
    Cable,
    InventoryItem,
)
# BGP
from nautobot_bgp_models.models import (
    BGPRoutingInstance,
)

# Extras
from nautobot.extras.models import SecretsGroup, Status

name = "Discovery"


class CiscoNXOS(Job):
    class Meta:
        name = "Discovery: Cisco NX-OS"
        description = """
            Discovers additional information for Cisco NX-OS devices by connecting via SSH and running various show commands.
        """
        has_sensitive_variables = False
        soft_time_limit = 86400
        time_limit = 86410

    status = MultiObjectVar(
        model=Status,
        required=False,
        description="Select status to filter device discovery scope.",
    )
    device = MultiObjectVar(
        model=Device,
        query_params={"platform": "cisco_nxos"},
        required=False,
        description="Select a specific device or leave empty for all NX-OS devices.",
    )

    credentials = ObjectVar(
        model=SecretsGroup,
        required=True,
        description="SecretsGroup for Device connection credentials.",
    )

    debug = BooleanVar(
        label="Debug",
        description="If enabled provide more detailed logs",
        default=False,
    )

    def run(self, *args, **kwargs):
        self.nos = "nxos_ssh"
        self.debug = kwargs["debug"]
        self.util = utils(logger=self.logger, debug=self.debug)
        self.genie_nos = "nxos"
        creds = self.util.parse_credentials(kwargs["credentials"])
        self.username = creds["username"]
        self.password = creds["password"]
        self.credentials = kwargs["credentials"]

        self.util.prefetch_device_types(manufacturer="Cisco")

        self.commands = [
            "show interface",
            "show vrf all detail",
            "show hsrp all",
            "show version",
            "show vlan",
            "show interface switchport",
            "show port-channel summary",
            "show ip interface vrf all",
            "show boot",
            "show cdp neighbors",
            "show lldp neighbors detail",
            "show bgp all summary vrf all",
            "show bgp all neighbors vrf all",
            "show inventory",
            "show interface transceiver",
            "show ip prefix-list",
            "show route-map"
        ]

        devices = Device.objects.filter(platform__name="cisco_nxos")

        status = [x.name for x in kwargs.get("status", [])]

        if status:
            devices = devices.filter(status__name__in=status)

        if kwargs.get("device", []):
            devices = devices.intersection(kwargs["device"])

        for device in devices:
            self._discover(host=device)

    def _discover(self, host: Device):

        if host.primary_ip4:
            if self.debug:
                self.logger.debug(
                    f"{host.name}: Gather information from device. ")
            parsed_results = self._parse_cli(
                address=str(ipaddress.ip_interface(host.primary_ip4).ip),
                commands=self.commands,
            )

            for cmd in parsed_results.keys():
                # if cmd in parsed_results:
                parsed = parsed_results[cmd]
                if self.debug:
                    self.logger.debug(f"{host.name}: Processing '{cmd}'")
                match cmd:
                    case "show route-map":
                        try:
                            table = parsed.get("TABLE_rmap", {})
                            rows = table.get("ROW_rmap", [])
                            if isinstance(rows, dict):
                                rows = [rows]

                            route_maps = {}
                            for row in rows:
                                name = row.get("name")
                                if not name:
                                    continue
                                entry = {
                                    "seq": int(row.get("seq")) if isinstance(row.get("seq"), (int, str)) and str(row.get("seq")).isdigit() else row.get("seq"),
                                    "action": row.get("action"),
                                    "description": row.get("descript"),
                                    "match": [],
                                    "set": [],
                                }
                                # Matches
                                mtable = row.get("TABLE_rmap_match", {})
                                mrows = mtable.get("ROW_rmap_match", [])
                                if isinstance(mrows, dict):
                                    mrows = [mrows]
                                for m in mrows:
                                    entry["match"].append({
                                        "type": m.get("match_type"),
                                        "stmt": m.get("match_stmt"),
                                    })
                                # Sets
                                stable = row.get("TABLE_rmap_set", {})
                                srows = stable.get("ROW_rmap_set", [])
                                if isinstance(srows, dict):
                                    srows = [srows]
                                for s in srows:
                                    entry["set"].append({
                                        "type": s.get("set_type"),
                                        "stmt": s.get("set_stmt"),
                                    })

                                route_maps.setdefault(name, []).append(entry)

                            # Sort entries by sequence
                            for k in route_maps:
                                try:
                                    route_maps[k] = sorted(
                                        route_maps[k], key=lambda x: (
                                            x["seq"] if isinstance(x["seq"], int) else 0)
                                    )
                                except Exception:
                                    pass

                            context = host.local_config_context_data or {}
                            context_changed = context.get(
                                "route_maps") != route_maps
                            if context_changed:
                                context["route_maps"] = route_maps
                                host.local_config_context_data = context
                                if hasattr(host, "has_local_config_context_data") and host.has_local_config_context_data is not True:
                                    host.has_local_config_context_data = True
                                host.validated_save()
                            self.logger.info(
                                f"{host.name}: Attached {len(route_maps)} route-map(s) to local config context"
                            )
                        except Exception as e:
                            if self.debug:
                                self.logger.debug(
                                    f"{host.name}: Route-map parse failed: {e}")
                    case "show ip prefix-list":
                        # Normalize NX-OS JSON into a dict of name -> entries
                        try:
                            table = parsed.get("TABLE_ip_pfl", {})
                            rows = table.get("ROW_ip_pfl", [])
                            # Some platforms return a single dict instead of list
                            if isinstance(rows, dict):
                                rows = [rows]

                            prefix_lists = {}
                            for row in rows:
                                name = row.get("name")
                                if not name:
                                    continue
                                entry = {
                                    "seq": int(row.get("seq")) if str(row.get("seq", "")).isdigit() else row.get("seq"),
                                    "action": row.get("action"),
                                    "rule": row.get("rule"),
                                }
                                prefix_lists.setdefault(name, []).append(entry)

                            # Sort entries by seq for consistency
                            for k in prefix_lists:
                                try:
                                    prefix_lists[k] = sorted(
                                        prefix_lists[k], key=lambda x: (
                                            x["seq"] if isinstance(x["seq"], int) else 0)
                                    )
                                except Exception:
                                    # Leave as-is if seq isn't sortable
                                    pass

                            context = host.local_config_context_data or {}
                            context_changed = context.get(
                                "prefix_lists") != prefix_lists
                            if context_changed:
                                context["prefix_lists"] = prefix_lists
                                host.local_config_context_data = context
                                if hasattr(host, "has_local_config_context_data") and host.has_local_config_context_data is not True:
                                    host.has_local_config_context_data = True
                                host.validated_save()
                            self.logger.info(
                                f"{host.name}: Attached {len(prefix_lists)} prefix-list(s) to local config context"
                            )
                        except Exception as e:
                            if self.debug:
                                self.logger.debug(
                                    f"{host.name}: Prefix-list parse failed: {e}")
                    case "show interface transceiver":
                        if parsed:
                            if self.debug:
                                self.logger.debug(
                                    f"{host.name}: Processing 'show interface transceiver', {parsed}")
                            for part in [x for x in parsed['TABLE_interface']['ROW_interface'] if "serialnum" in x]:
                                pid = part['cisco_product_id'] if "cisco_product_id" in part else part['type']
                                exists = InventoryItem.objects.filter(
                                    device=host,
                                    name=part['interface'].replace('"', '')
                                )
                                if exists.exists():
                                    nb_part = exists[0]
                                    changed = False
                                    if nb_part.serial != part['serialnum']:
                                        nb_part.serial = part['serialnum']
                                        changed = True
                                    pid = part['cisco_product_id'] if "cisco_product_id" in part else part['type']
                                    if nb_part.part_id != pid:
                                        nb_part.part_id = pid
                                        changed = True

                                    if nb_part.description != part['type'].replace('"', ''):
                                        nb_part.description = part['type'].replace(
                                            '"', '')
                                        changed = True
                                    if changed:
                                        nb_part.save()
                                        self.logger.info(
                                            f"{host.name}: Updated inventory item {nb_part.name}")
                                else:
                                    nb_part, created = InventoryItem.objects.update_or_create(
                                        device=host,
                                        name=part['interface'].replace(
                                            '"', ''),
                                        part_id=pid,
                                        serial=part['serialnum'],
                                        manufacturer=self.util.get_manufacturer(
                                            name="Cisco"),
                                        description=part['type'].replace(
                                            '"', ''),
                                        discovered=True,
                                    )
                                if created:
                                    self.logger.info(
                                        f"{host.name}: Added inventory item {nb_part.name}"
                                    )
                    case "show inventory":
                        if parsed:
                            if self.debug:
                                self.logger.debug(
                                    f"{host.name}: Processing 'show inventory', {parsed}")
                            for part in [x for x in parsed['TABLE_inv']['ROW_inv'] if "serialnum" in x]:
                                nb_part, created = InventoryItem.objects.update_or_create(
                                    device=host,
                                    name=part['name'].replace('"', ''),
                                    part_id=part['productid'],
                                    serial=part['serialnum'],
                                    manufacturer=self.util.get_manufacturer(
                                        name="Cisco"),
                                    description=part['desc'].replace('"', ''),
                                    discovered=True,
                                )
                                if created:
                                    self.logger.info(
                                        f"{host.name}: Added inventory item {nb_part.name}"
                                    )

                    case "show bgp all summary vrf all":
                        if 'TABLE_vrf' in parsed:
                            for vrf_instance in parsed['TABLE_vrf']['ROW_vrf']:
                                vrf_name = vrf_instance['vrf-name-out']
                                vrf_router_id = vrf_instance['vrf-router-id']
                                vrf_local_asn = vrf_instance['vrf-local-as']
                                nb_local_asn = self.util.get_or_create_asn(
                                    asn=vrf_local_asn)
                                nb_router = self.util.get_or_create_router(
                                    host=host, asn=nb_local_asn, router_id=vrf_router_id)
                                if vrf_name == 'default':
                                    self.util.get_or_create_afi_safi(
                                        afi='ipv4', safi='unicast', router=nb_router, vrf=None)
                                else:
                                    self.util.get_or_create_afi_safi(
                                        afi='vpnv4', safi='unicast', router=nb_router, vrf=self.util.get_vrf(name=vrf_name))

                    case "show bgp all neighbors vrf all":
                        if 'TABLE_neighbor' in parsed:
                            summary_rows = self._as_list(
                                parsed_results.get(
                                    'show bgp all summary vrf all', {})
                                .get('TABLE_vrf', {})
                                .get('ROW_vrf')
                            )
                            for neighbor in self._as_list(parsed['TABLE_neighbor'].get('ROW_neighbor')):
                                vrf_name = neighbor['vrf']
                                peer_ip = neighbor['neighbor']
                                peer_asn = neighbor['remoteas']
                                peer_router_id = neighbor['remote-id']
                                nb_src_addr = self._resolve_bgp_source_address(
                                    host=host,
                                    neighbor=neighbor,
                                )
                                if nb_src_addr is None:
                                    self.logger.warning(
                                        f"{host.name}: Unable to resolve local source for BGP neighbor {peer_ip} in VRF {vrf_name}; skipping peering."
                                    )
                                    continue

                                local_asn = next(
                                    (
                                        row['vrf-local-as']
                                        for row in summary_rows
                                        if row.get('vrf-name-out') == vrf_name
                                    ),
                                    None,
                                )
                                if local_asn is None:
                                    self.logger.warning(
                                        f"{host.name}: Unable to resolve local ASN for VRF {vrf_name}; skipping BGP neighbor {peer_ip}."
                                    )
                                    continue

                                nb_local_asn = self.util.get_or_create_asn(
                                    asn=local_asn)
                                nb_router = self._first_item(
                                    BGPRoutingInstance.objects.filter(
                                        device=host, autonomous_system=nb_local_asn)
                                )
                                if nb_router is None:
                                    self.logger.warning(
                                        f"{host.name}: Unable to find local BGP routing instance for ASN {local_asn}; skipping neighbor {peer_ip}."
                                    )
                                    continue
                                nb_peer_asn = self.util.get_or_create_asn(
                                    asn=peer_asn)
                                try:
                                    if self.debug:
                                        self.logger.debug(
                                            f'{host.name}: peer_IP: {peer_ip}')
                                    nb_peer_addr = IPAddress.objects.get(
                                        host=peer_ip)
                                    for ip_to_int in IPAddressToInterface.objects.filter(ip_address=nb_peer_addr, interface__enabled=True):
                                        nb_peer_host = ip_to_int.interface.device
                                        nb_peer_router = self.util.get_or_create_router(
                                            nb_peer_host, asn=nb_peer_asn, router_id=peer_router_id)
                                        self.util.ensure_peering(
                                            router_a=nb_router, router_z=nb_peer_router, address_a=nb_src_addr, address_z=nb_peer_addr)
                                        if vrf_name == 'default':
                                            self.util.ensure_afi_association(
                                                peering_address=nb_src_addr, afi_safi='ipv4_unicast')
                                        else:
                                            self.util.ensure_afi_association(
                                                peering_address=nb_src_addr, afi_safi='vpnv4_unicast')
                                except ObjectDoesNotExist as e:

                                    cidr = self.util.find_best_cidr(
                                        address=peer_ip)
                                    nb_peer_addr = self.util.get_or_create_address(
                                        address_with_cidr=f"{peer_ip}/{cidr}")

                                    self.util.ensure_external_peering(
                                        router_a=nb_router, source_address=nb_src_addr, peer_asn=nb_peer_asn, peer_address=nb_peer_addr)
                                except Exception as e:
                                    if self.debug:
                                        self.logger.info(f"{host.name}: {e}")

                    case "show hsrp all":
                        if 'TABLE_grp_detail' in parsed:
                            for instance in parsed['TABLE_grp_detail']['ROW_grp_detail']:
                                iface_gen = (x for x in parsed_results['show interface']['TABLE_interface']
                                             ['ROW_interface'] if x['interface'] == instance['sh_if_index'])
                                iface = next(iface_gen, None)
                                if iface:
                                    raw_iface_name = iface['interface']
                                    iface_name = self.util.real_interface_name(
                                        raw_iface_name)
                                    iface_type = self._guess_interface_type(
                                        name=iface_name,
                                        interface=iface,
                                    )
                                    nb_iface = self.util.get_interface(
                                        device=host,
                                        name=iface_name,
                                        interface_type=iface_type,
                                    )
                                    vip = instance['sh_vip']
                                    if 'svi_ip_mask' in iface:
                                        cidr = iface['svi_ip_mask']
                                    elif 'eth_ip_mask' in iface:
                                        cidr = iface['eth_ip_mask']

                                    nb_vip = self.util.get_or_create_address(
                                        address_with_cidr=f"{vip}/{cidr}", interface=nb_iface)
                                    nb_irg = self.util.get_interface_redundancy_group(
                                        name=f"{host.name}_{instance['sh_ip_redund_name']}",
                                        group_id=instance["sh_group_num"],
                                        virtual_ip=nb_vip,
                                    )
                                    nb_irg_assoc = self.util.get_interface_redundancy_group_association(
                                        interface=nb_iface,
                                        interface_redundancy_group=nb_irg,
                                        priority=int(instance["sh_prio"]),
                                    )
                    case "show ip interface vrf all":
                        for port in parsed['TABLE_intf']['ROW_intf']:
                            raw_name = port['intf-name']
                            name = self.util.real_interface_name(raw_name)
                            iface_gen = (
                                x for x in parsed_results['show interface']['TABLE_interface']['ROW_interface'] if x['interface'] == raw_name)
                            iface = next(iface_gen, None)
                            if iface:
                                nb_iface = self.util.get_interface(
                                    device=host,
                                    name=name,
                                    interface_type=self._guess_interface_type(
                                        name,
                                        iface,
                                    ),
                                )

                                nb_vrf = self.util.get_vrf(
                                    name=port['vrf-name-out'])

                                if "prefix" in port:
                                    try:
                                        address = f"{port['prefix']}/{port['masklen']}"
                                        ip_int = ipaddress.ip_interface(
                                            address)
                                        if ip_int.is_global:
                                            nb_tag = self.util.get_tag(
                                                name="EXTERNAL",
                                                content_types=[
                                                    self.util.get_content_type(Interface)],
                                                color="aa1409",
                                            )
                                            if "EXTERNAL" not in [x for x in nb_iface.tags.values_list("name", flat=True)]:
                                                nb_iface.tags.add(nb_tag)
                                                self.logger.info(
                                                    f"{host.name}: Tagged 'EXTERNAL' to interface {nb_iface.name}")

                                        nb_address = self.util.get_or_create_address(
                                            address_with_cidr=address, interface=nb_iface)
                                        if nb_vrf and nb_address:
                                            nb_vrf_to_prefix = VRFPrefixAssignment.objects.get_or_create(
                                                vrf=nb_vrf, prefix=nb_address.parent)
                                            if nb_vrf_to_prefix[1]:
                                                self.logger.info(
                                                    f"{host.name}: Associated VRF {nb_vrf.name} to {nb_address.parent.network}/{nb_address.parent.prefix_length}")

                                        nb_location = self.util.get_validated_location(
                                            host.location)
                                        if "Vlan" in name:
                                            vid = name.replace("Vlan", "")
                                            nb_vlan = self.util.get_or_create_vlan(vlan=int(
                                                vid), vlan_group=self.util.get_vlan_group(name=nb_location.name, location=nb_location))
                                            if nb_vlan:
                                                if nb_address:
                                                    self.util.tag_vlan_to_prefix(
                                                        device=host, vlan=nb_vlan, prefix=nb_address.parent)
                                                self.util.access_vlan_on_interface(
                                                    interface=nb_iface, vlan_group=nb_vlan.vlan_group, vlan=vid)
                                        try:
                                            nb_iface.ip_addresses.add(
                                                nb_address)
                                            nb_address.parent.locations.add(
                                                nb_location)
                                        except Exception as e:
                                            if self.debug:
                                                self.logger.debug(
                                                    f"{host.name}: {e}")

                                    except ValueError:
                                        if self.debug:
                                            self.logger.debug(
                                                f"{host.name}: Skipping {address} as not a valid IP")

                    case "show vrf all detail":
                        for vrf in parsed['TABLE_vrf']['ROW_vrf']:
                            name = vrf['vrf_name']
                            if name == "default":
                                continue
                            nb_vrf = self.util.get_vrf(name=name)
                            if nb_vrf:
                                nb_vrf_device_assignment = self.util.get_vrf_device_assignment(
                                    vrf=nb_vrf, device=host)

                                if nb_vrf_device_assignment:
                                    interfaces = [x for x in parsed_results["show ip interface vrf all"]
                                                  ['TABLE_intf']['ROW_intf'] if x['vrf-name-out'] == name]
                                    for interface in interfaces:
                                        iface_gen = (
                                            x for x in parsed_results['show interface']['TABLE_interface']['ROW_interface'] if x['interface'] == interface['intf-name'])
                                        iface = next(iface_gen, None)
                                        if iface:
                                            nb_iface = self.util.get_interface(
                                                device=host,
                                                name=self.util.real_interface_name(
                                                    interface['intf-name']),
                                                interface_type=self._guess_interface_type(
                                                    name=self.util.real_interface_name(
                                                        interface['intf-name']),
                                                    interface=iface,
                                                ),
                                            )
                                            if nb_iface:
                                                if nb_iface.vrf is None or (nb_iface.vrf != nb_vrf):
                                                    nb_iface.vrf = nb_vrf
                                                    self.logger.info(
                                                        (f"{host.name}: VRF {nb_vrf.name} assigned to {nb_iface.name}."))
                                                    nb_iface.validated_save()
                                                address = f"{interface['prefix']}/{interface['masklen']}"
                                                ip_int = ipaddress.ip_interface(
                                                    address)
                                                if ip_int.is_global:
                                                    nb_tag = self.util.get_tag(
                                                        name="EXTERNAL",
                                                        content_types=[
                                                            self.util.get_content_type(Interface)],
                                                        color="aa1409",
                                                    )
                                                    if "EXTERNAL" not in [x for x in nb_iface.tags.values_list("name", flat=True)]:
                                                        nb_iface.tags.add(
                                                            nb_tag)
                                                        self.logger.info(
                                                            f"{host.name}: Tagged 'EXTERNAL' to interface {nb_iface.name}")
                                                nb_address = self.util.get_or_create_address(
                                                    address_with_cidr=address, interface=nb_iface)
                                                try:
                                                    nb_iface.ip_addresses.add(
                                                        nb_address)
                                                    nb_location = self.util.get_validated_location(
                                                        host.location)
                                                    nb_address.parent.locations.add(
                                                        nb_location)
                                                except Exception as e:
                                                    if self.debug:
                                                        self.logger.debug(
                                                            f"{host.name}: {e}")

                    case "show version":
                        nb_version = self.util.get_version(
                            version=parsed['nxos_ver_str'],
                            platform=host.platform,
                        )
                        image = parsed['nxos_file_name'].split("/")[-1]
                        nb_image = self.util.get_software_image(
                            version=nb_version,
                            imagename=image,
                        )

                        if nb_image:
                            self.util.associate_image_to_device_type(
                                host.device_type, nb_image)

                        if nb_version and nb_image and host.software_version != nb_version:
                            host.software_version = nb_version
                            host.validated_save()

                    case "show vlan":
                        for vlan in parsed['TABLE_vlanbrief']['ROW_vlanbrief']:
                            nb_location = self.util.get_validated_location(
                                host.location)
                            nb_vlg = self.util.get_vlan_group(
                                name=nb_location.name, location=nb_location)

                            if nb_vlg:
                                try:
                                    existing_vlan_name = self.util.get_vlan_by_name(
                                        name=vlan["vlanshowbr-vlanname"], vlan_group=nb_vlg)
                                    if existing_vlan_name and existing_vlan_name.vid != vlan['vlanshowbr-vlanid']:
                                        vlan_name = f"{vlan['vlanshowbr-vlanname']}_{vlan['vlanshowbr-vlanid']}"
                                    else:
                                        vlan_name = vlan["vlanshowbr-vlanname"]
                                except:
                                    vlan_name = vlan["vlanshowbr-vlanname"]
                                finally:
                                    self.util.get_or_create_vlan(
                                        vlan=vlan['vlanshowbr-vlanid'],
                                        vlan_group=nb_vlg,
                                        vlan_name=vlan_name,
                                    )

                    case "show interface switchport":
                        if 'TABLE_interface' in parsed:
                            for port in parsed['TABLE_interface']['ROW_interface']:

                                raw_name = port['interface']
                                name = self.util.real_interface_name(raw_name)
                                iface_gen = (
                                    x for x in parsed_results['show interface']['TABLE_interface']['ROW_interface'] if x['interface'] == name)
                                iface = next(iface_gen, None)
                                if iface and port['switchport'] == "Enabled":
                                    nb_iface = self.util.get_interface(
                                        device=host,
                                        name=name,
                                        interface_type=self._guess_interface_type(
                                            name,
                                            iface,
                                        ),
                                    )
                                    nb_location = self.util.get_validated_location(
                                        host.location)
                                    nb_vlg = self.util.get_vlan_group(
                                        name=nb_location.name,
                                        location=nb_location,
                                    )
                                    switchport_changed = False

                                    match port["oper_mode"]:
                                        case "access":
                                            if nb_iface.mode != InterfaceModeChoices.MODE_ACCESS:
                                                nb_iface.mode = InterfaceModeChoices.MODE_ACCESS
                                                switchport_changed = True
                                        case "trunk":
                                            if "vlan" in name.lower():
                                                nb_iface.tagged_vlans.clear()
                                                if nb_iface.mode != InterfaceModeChoices.MODE_ACCESS:
                                                    nb_iface.mode = InterfaceModeChoices.MODE_ACCESS
                                                    switchport_changed = True
                                            elif "trunk_vlans" in port:
                                                if port["trunk_vlans"] == "1-4094":
                                                    if nb_iface.mode != InterfaceModeChoices.MODE_TAGGED_ALL:
                                                        nb_iface.mode = InterfaceModeChoices.MODE_TAGGED_ALL
                                                        switchport_changed = True
                                                else:
                                                    if nb_iface.mode != InterfaceModeChoices.MODE_TAGGED:
                                                        nb_iface.mode = InterfaceModeChoices.MODE_TAGGED
                                                        switchport_changed = True
                                                    self.util.tag_vlans_to_interface(
                                                        nb_iface,
                                                        nb_vlg,
                                                        port["trunk_vlans"],
                                                    )
                                            else:
                                                continue

                                    if "access_vlan" in port and nb_iface.mode is not None:
                                        new_untagged = self.util.get_or_create_vlan(
                                            vlan=port["access_vlan"],
                                            vlan_group=nb_vlg,
                                        )
                                        if nb_iface.untagged_vlan != new_untagged:
                                            nb_iface.untagged_vlan = new_untagged
                                            switchport_changed = True

                                    if switchport_changed:
                                        nb_iface.validated_save()

                    case "show port-channel summary":
                        for lag in parsed['TABLE_channel']['ROW_channel']:
                            name = lag['port-channel']

                            nb_lag = self.util.get_interface(
                                device=host,
                                name=self.util.real_interface_name(name),
                                interface_type=InterfaceTypeChoices.TYPE_LAG,
                            )
                            if nb_lag and nb_lag.type != InterfaceTypeChoices.TYPE_LAG:
                                self.logger.info(
                                    (f"{host.name}: Changing {name} interface type to LAG"))
                                nb_lag.type = InterfaceTypeChoices.TYPE_LAG
                                nb_lag.validated_save()
                            if nb_lag and "TABLE_member" in lag.keys():
                                for member in lag["TABLE_member"]['ROW_member']:
                                    iface_gen = (
                                        x for x in parsed_results['show interface']['TABLE_interface']['ROW_interface'] if x['interface'] == name)
                                    iface = next(iface_gen, None)
                                    if iface:
                                        nb_member = self.util.get_interface(
                                            device=host,
                                            name=self.util.real_interface_name(
                                                member['port']),
                                            interface_type=self._guess_interface_type(
                                                member['port'],
                                                iface,
                                            ),
                                        )

                                        if nb_member and nb_member.lag != nb_lag:
                                            nb_member.lag = nb_lag
                                            nb_member.validated_save()
                                            self.logger.info(
                                                (f"{host.name}: Added {member['port']} to {name}"))

                    case "show interface":
                        real_interfaces = [self.util.real_interface_name(
                            x['interface']).lower() for x in parsed['TABLE_interface']['ROW_interface']]
                        self.util.prune_interfaces(
                            device=host, interfaces=real_interfaces)

                        for iface in parsed['TABLE_interface']['ROW_interface']:
                            raw_name = iface['interface']
                            name = self.util.real_interface_name(
                                iface['interface'])

                            nb_iface = self.util.get_interface(
                                device=host,
                                name=name,
                                interface_type=self._guess_interface_type(
                                    name, iface),
                            )

                            if "." in name:
                                nb_parent = self.util.get_interface(
                                    device=host,
                                    name=name.split(".")[0],
                                    interface_type=self._guess_interface_type(
                                        name, iface),
                                )
                                if nb_iface.parent_interface != nb_parent:
                                    if nb_iface.type != InterfaceTypeChoices.TYPE_VIRTUAL:
                                        nb_iface.type = InterfaceTypeChoices.TYPE_VIRTUAL
                                        self.logger.info(
                                            (f"{host.name}: changed {name} type to virtual"))
                                    nb_iface.parent_interface = nb_parent
                                    nb_iface.validated_save()
                                    self.logger.info(
                                        (f"{host.name}: set {name} parent interface to {nb_parent.name}"))

                            if nb_iface:
                                iface_changed = False
                                if "description" in iface:
                                    if nb_iface.description != iface["desc"]:
                                        nb_iface.description = iface["desc"]
                                        iface_changed = True
                                        self.logger.info(
                                            (f"{host.name}: Updating {name} Description to: {iface['desc']}"))
                                if "admin_state" in iface:
                                    if iface['admin_state'] == "down" and nb_iface.enabled != False:
                                        nb_iface.enabled = False
                                        iface_changed = True
                                        self.logger.info(
                                            (f"{host.name}: Updating {name} Admin status to: {iface['admin_state']}"))
                                    elif iface['admin_state'] == "up" and nb_iface.enabled != True:
                                        nb_iface.enabled = True
                                        iface_changed = True
                                        self.logger.info(
                                            (f"{host.name}: Updating {name} Admin status to: {iface['admin_state']}"))

                                if "eth_hw_addr" in iface:
                                    if nb_iface.mac_address != self.util.extract_mac(iface["eth_hw_addr"]):
                                        nb_iface.mac_address = self.util.extract_mac(
                                            iface["eth_hw_addr"])
                                        iface_changed = True
                                        self.logger.info(
                                            (f"{host.name}: Updating {name} MAC Address to: {self.util.extract_mac( iface['eth_hw_addr'])}"))
                                if "eth_mtu" in iface:
                                    if nb_iface.mtu != int(iface["eth_mtu"]):
                                        nb_iface.mtu = int(iface["eth_mtu"])
                                        iface_changed = True
                                        self.logger.info(
                                            (f"{host.name}: Updating {name} MTU to: {iface['eth_mtu']}"))

                                if IPAddressToInterface.objects.filter(interface=nb_iface).count() and 'eth_ip_addr' not in iface and 'svi_ip_addr' not in iface:
                                    nb_address = IPAddressToInterface.objects.get(
                                        interface=nb_iface).ip_address
                                    nb_iface.ip_addresses.remove(nb_address)
                                    self.logger.info(
                                        f"{host.name}: Removed IP address {nb_address.address} from {nb_iface.name} as it is no longer configured")
                                if iface_changed:
                                    nb_iface.validated_save()
                    case "show cdp neighbors":
                        for neighbor in parsed['TABLE_cdp_neighbor_brief_info']['ROW_cdp_neighbor_brief_info']:
                            nbr_host = neighbor["device_id"]
                            nbr_host = nbr_host.split(".")[0]
                            nbr_host = nbr_host.split("(")[0]
                            nbr_host = self.util.nautobot_hostname(nbr_host)
                            nbr_iface = self.util.real_interface_name(
                                neighbor["port_id"])
                            nbr_iface = nbr_iface.split(".")[0]
                            loc_iface = self.util.real_interface_name(
                                neighbor["intf_id"])
                            loc_iface = loc_iface.split(".")[0]
                            try:
                                nb_nbr_host = Device.objects.get(
                                    name__iexact=nbr_host)
                                nb_nbr_iface = self.util.get_interface(
                                    device=nb_nbr_host,
                                    name=nbr_iface,
                                    interface_type=self.util.guess_interface_type_from_name(
                                        nbr_iface),
                                )
                                nb_loc_iface = self.util.get_interface(
                                    device=host,
                                    name=loc_iface,
                                    interface_type=self.util.guess_interface_type_from_name(
                                        loc_iface),
                                )
                                if not nb_loc_iface.connected_endpoint and not nb_nbr_iface.connected_endpoint:
                                    nb_cbl = Cable.objects.get_or_create(
                                        termination_a_id=nb_loc_iface.id,
                                        termination_a_type=ContentType.objects.get_for_model(
                                            nb_loc_iface),
                                        termination_b_id=nb_nbr_iface.id,
                                        termination_b_type=ContentType.objects.get_for_model(
                                            nb_nbr_iface),
                                        defaults={
                                            "status": self.util.status_connected},
                                    )
                                    if nb_cbl[1]:
                                        self.logger.info(
                                            f"{host.name}: connected {loc_iface} to {nbr_host} {nbr_iface}")

                            except Exception as e:
                                if self.debug:
                                    self.logger.debug(f"{host.name}: {e}")
                    case "show lldp neighbors detail":
                        parsed = parsed_results[cmd]

                        for lldp_data in parsed['TABLE_nbor_detail']['ROW_nbor_detail']:
                            nbr_host = lldp_data['sys_name']
                            nbr_iface = lldp_data['port_id']
                            loc_iface = lldp_data['l_port_id']
                            nbr_host = nbr_host.split(".")[0]
                            nbr_host = nbr_host.split("(")[0]
                            nbr_host = self.util.nautobot_hostname(nbr_host)
                            nbr_iface = self.util.real_interface_name(
                                nbr_iface)
                            nbr_iface = nbr_iface.split(".")[0]
                            loc_iface = self.util.real_interface_name(
                                loc_iface)
                            loc_iface = loc_iface.split(".")[0]
                            try:
                                nb_nbr_host = Device.objects.get(
                                    name__iexact=nbr_host)
                                nb_nbr_iface = self.util.get_interface(
                                    device=nb_nbr_host,
                                    name=nbr_iface,
                                    interface_type=self.util.guess_interface_type_from_name(
                                        nbr_iface),
                                )
                                nb_loc_iface = self.util.get_interface(
                                    device=host,
                                    name=loc_iface,
                                    interface_type=self.util.guess_interface_type_from_name(
                                        loc_iface),
                                )
                                if not nb_loc_iface.connected_endpoint and not nb_nbr_iface.connected_endpoint:
                                    nb_cbl = Cable.objects.get_or_create(
                                        termination_a_id=nb_loc_iface.id,
                                        termination_a_type=ContentType.objects.get_for_model(
                                            nb_loc_iface),
                                        termination_b_id=nb_nbr_iface.id,
                                        termination_b_type=ContentType.objects.get_for_model(
                                            nb_nbr_iface),
                                        defaults={
                                            "status": self.util.status_connected},
                                    )
                                    if nb_cbl[1]:
                                        self.logger.info(
                                            f"{host.name}: connected {loc_iface} to {nbr_host} {nbr_iface}")

                            except Exception as e:
                                if self.debug:
                                    self.logger.debug(f"{host.name}: {e}")

            # After processing standard commands, parse static routes from running-config
            try:
                static_routes = self._parse_static_routes_from_running_config(
                    address=str(ipaddress.ip_interface(host.primary_ip4).ip)
                )
                if static_routes is not None:
                    context = host.local_config_context_data or {}
                    context_changed = context.get(
                        "static_routes") != static_routes
                    if context_changed:
                        context["static_routes"] = static_routes
                        host.local_config_context_data = context
                        # Set flag when available on this model version
                        if hasattr(host, "has_local_config_context_data") and host.has_local_config_context_data is not True:
                            host.has_local_config_context_data = True
                        host.validated_save()
                    self.logger.info(
                        f"{host.name}: Attached {len(static_routes)} static route entries to local config context"
                    )
            except Exception as e:
                if self.debug:
                    self.logger.debug(
                        f"{host.name}: Static routes parse failed: {e}")

    def _guess_interface_type(self, name, interface):

        if "eth_media" in interface:
            types = interface["eth_media"]
            if "400G" in types:
                return InterfaceTypeChoices.TYPE_400GE_QSFP112
            elif "100G" in types:
                return InterfaceTypeChoices.TYPE_100GE_QSFP28
            elif "50G" in types:
                return InterfaceTypeChoices.TYPE_50GE_QSFP28
            elif "40G" in types:
                return InterfaceTypeChoices.TYPE_40GE_QSFP_PLUS
            elif "25G" in types:
                return InterfaceTypeChoices.TYPE_25GE_SFP28
            elif "10G" in types:
                return InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
            elif "1G" in types:
                return InterfaceTypeChoices.TYPE_1GE_SFP
            elif "100M" in types:
                return InterfaceTypeChoices.TYPE_100ME_FIXED
            else:
                return self.util.guess_interface_type_from_name(name=name)
        else:
            return self.util.guess_interface_type_from_name(name=name)

    @staticmethod
    def _as_list(value):
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _first_item(value):
        if value is None:
            return None
        if hasattr(value, "first"):
            return value.first()
        if isinstance(value, list):
            return value[0] if value else None
        try:
            return next(iter(value))
        except StopIteration:
            return None

    @staticmethod
    def _first_neighbor_value(neighbor, *keys):
        for key in keys:
            value = neighbor.get(key)
            if value not in (None, ""):
                return value
        return None

    def _resolve_bgp_source_address(self, host, neighbor):
        local_iface_name = self._first_neighbor_value(
            neighbor,
            "connectedif",
            "connected-if",
            "connected_if",
            "localif",
            "local-if",
            "local_if",
            "srcif",
            "src-if",
            "src_if",
            "sourceif",
            "source-if",
            "source_if",
            "interface",
        )
        if local_iface_name:
            local_iface = self.util.real_interface_name(name=local_iface_name)
            if self.debug:
                self.logger.debug(f'{host.name}: local_iface: {local_iface}')
            nb_local_iface = self._first_item(
                host.interfaces.filter(name=local_iface))
            if nb_local_iface is not None:
                mapping = self._first_item(
                    IPAddressToInterface.objects.filter(
                        interface=nb_local_iface)
                )
                if mapping is not None:
                    return mapping.ip_address

        local_address = self._first_neighbor_value(
            neighbor,
            "localaddress",
            "local-address",
            "local_address",
            "localaddr",
            "local-addr",
            "local_addr",
            "update-source",
            "update_source",
            "source-address",
            "source_address",
            "sourceaddr",
            "source-addr",
            "source_addr",
        )
        if local_address and local_address not in ("0.0.0.0", "::"):
            mapping = self._first_item(
                IPAddressToInterface.objects.filter(
                    interface__device=host,
                    ip_address__host=local_address,
                )
            )
            if mapping is not None:
                if self.debug:
                    self.logger.debug(
                        f'{host.name}: local_address: {local_address}')
                return mapping.ip_address

        return None

    def _parse_cli(self, address, commands):
        results = {}
        driver = napalm.get_network_driver(self.nos)

        device = driver(hostname=address, username=self.username,
                        password=self.password, optional_args={'read_time_override': 60})
        import json

        try:
            device.open()
            if self.debug:
                self.logger.debug(f"Connected to {address}")
            suffix = " | json native"
            cli_results = device.cli(commands=[x + suffix for x in commands])
            device.close()

            for cmd in commands:
                try:
                    data = cli_results[cmd + suffix]
                    json_data = json.loads(data)
                    results[cmd] = json_data
                except Exception as e:
                    if self.debug:
                        self.logger.debug(f"{address}: {cmd}: {e}")

        except Exception as e:
            self.logger.critical(f"Unable to connect to {address}")
            if self.debug:
                self.logger.debug(f"{address}: {e}")
        return results

    def _parse_static_routes_from_running_config(self, address: str):
        """Retrieve running-config and parse static routes via TTP template.

        Returns a list of static route dicts, or None if unavailable.
        """
        try:
            from ttp import ttp
            import json
        except Exception as e:
            # TTP not available
            if self.debug:
                self.logger.debug(f"{address}: TTP import failed: {e}")
            return None

        driver = napalm.get_network_driver(self.nos)
        device = driver(
            hostname=address,
            username=self.username,
            password=self.password,
            optional_args={"read_time_override": 60},
        )

        try:
            device.open()
            if self.debug:
                self.logger.debug(f"Connected for running-config: {address}")
            cfg = device.get_config(retrieve="running").get("running", "")
            device.close()

            if not cfg:
                return None

            template_path = os.path.join(
                pathlib.Path(__file__).parent.resolve(),
                "templates",
                "nxos",
                "show run_static_routes.ttp",
            )
            with open(template_path) as f:
                ttp_template = f.read()

            parser = ttp(data=cfg, template=ttp_template)
            parser.parse()
            # TTP returns list of lists JSON; sample shape: [[{"static_routes": [...]}]]
            result_json = parser.result(format="json")[0]
            data = json.loads(result_json)
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], list) and len(data[0]) > 0:
                obj = data[0][0]
                if isinstance(obj, dict) and "static_routes" in obj:
                    return obj["static_routes"]
            return None
        except Exception as e:
            if self.debug:
                self.logger.debug(
                    f"{address}: running-config/static-routes parse error: {e}")
            try:
                device.close()
            except Exception:
                pass
            return None


register_jobs(CiscoNXOS)
