"""
https://docs.nautobot.com/projects/core/en/stable/development/jobs/

"""

from .discover_utils import utils
from django.contrib.contenttypes.models import ContentType
from nautobot.apps.jobs import Job, register_jobs
from nautobot.dcim.models import Platform
from nautobot.ipam.models import Prefix
from django.core.exceptions import ValidationError, ObjectDoesNotExist
import napalm
import ipaddress
import re

# IPAM

from nautobot.ipam.models import (
    IPAddress,
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
    PowerPort,
    VirtualChassis,
    InventoryItem
)

# BGP
from nautobot_bgp_models.models import (
    BGPRoutingInstance,
)

# Extras
from nautobot.extras.models import SecretsGroup, Status

name = "Discovery"


class CiscoIOS(Job):
    class Meta:
        name = "Discovery: Cisco IOS"
        description = """
            Discovers additional information for Cisco IOS devices by connecting via SSH and running various show commands.
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
        query_params={"platform": ["cisco_ios", "cisco_xe"]},
        required=False,
        description="Select a specific device or leave empty for all IOS/IOS-XE devices.",
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
        self.nos = "ios"

        self.debug = kwargs["debug"]
        self.util = utils(logger=self.logger, debug=self.debug)
        creds = self.util.parse_credentials(kwargs["credentials"])
        self.username = creds["username"]
        self.password = creds["password"]
        self.credentials = kwargs["credentials"]

        self.statuses = kwargs["status"]
        self.logger
        self.util.prefetch_device_types(manufacturer="Cisco")
        self.platforms = Platform.objects.filter(
            name__in=['cisco_ios', 'cisco_xe'])

        # TODO: enable job for webhook

        self.commands = [
            "show switch",
            "show version",  # Version, Image
            "show vlan",  # Vlan ID, Name
            "show interfaces",  # MAC, enabled, IP, Type, Description, MTU, Port channel
            "show vrf detail",  # VRF
            "show etherchannel summary",  # Port Channel
            "show interfaces switchport",  # Mode, Untagged, tagged vlans
            "show standby all",  # HSRP
            "show cdp neighbors",
            "show lldp neighbors",
            "show bgp all summary",
            "show bgp all neighbors",
            "show environment power",
            "show inventory"
        ]
        status = [x.name for x in self.statuses]
        devices = Device.objects.filter(platform__name__in=[
            "cisco_ios", "cisco_xe"])
        if status:
            devices = devices.filter(status__name__in=status)
        if kwargs.get("device", []):
            devices = devices.intersection(kwargs["device"])

        for device in devices:
            if self.statuses and device.status in self.statuses:
                self._discover(host=device)
            elif not self.statuses:
                self._discover(host=device)

    def _discover(self, host: Device):
        try:
            if host.primary_ip4:
                discover_ip = host.primary_ip4
                if self.debug:
                    self.logger.debug(
                        f"{host.name}: Gather information from device. ")

                parsed_results = self._parse_cli(
                    address=(host.primary_ip4.host),
                    commands=self.commands,
                )
                if host.secrets_group != self.credentials:
                    host.secrets_group = self.credentials
                    host.validated_save()
                    self.logger.info(
                        f"{host.name}: Assigned Secrets Group '{self.credentials.name}'"
                    )

                for cmd in parsed_results.keys():
                    # if cmd in parsed_results:
                    parsed = parsed_results[cmd]
                    if self.debug:
                        self.logger.debug(f"{host.name}: Processing '{cmd}'")
                    match cmd:
                        case "show inventory":
                            if parsed:
                                for part in [x for x in parsed if "sn" in x]:
                                    exists = InventoryItem.objects.filter(
                                        device=host, name=part['name'])
                                    if exists:
                                        nb_part = exists[0]
                                        part_changed = False
                                        if nb_part.part_id != part['pid']:
                                            nb_part.part_id = part['pid']
                                            part_changed = True
                                            self.logger.info(
                                                f"{host.name}: Updated inventory item {nb_part.name} part_id to {part['pid']}"
                                            )
                                        if nb_part.serial != part['sn']:
                                            nb_part.serial = part['sn']
                                            part_changed = True
                                            self.logger.info(
                                                f"{host.name}: Updated inventory item {nb_part.name} serial to {part['sn']}"
                                            )
                                        if nb_part.description != part['descr']:
                                            nb_part.description = part['descr']
                                            part_changed = True
                                            self.logger.info(
                                                f"{host.name}: Updated inventory item {nb_part.name} description to {part['descr']}"
                                            )
                                        if part_changed:
                                            nb_part.save()
                                    else:
                                        nb_part, created = InventoryItem.objects.update_or_create(
                                            device=host,
                                            name=part['name'],
                                            part_id=part['pid'],
                                            serial=part['sn'],
                                            manufacturer=self.util.get_manufacturer(
                                                name="Cisco"),
                                            discovered=True,
                                            description=part['descr']
                                        )
                                        if created:
                                            self.logger.info(
                                                f"{host.name}: Added inventory item {nb_part.name}"
                                            )

                        case "show environment power":
                            if parsed:
                                nb_power_ports = PowerPort.objects.filter(
                                    device=host)
                                if self.debug:
                                    self.logger.debug(parsed)
                                psus = [
                                    x for x in parsed if x["Watts"].isnumeric()]
                                if len(psus) != len(nb_power_ports):
                                    for nb_port in nb_power_ports:
                                        nb_port.delete()
                                    for psu in psus:
                                        PowerPort.objects.create(
                                            name=psu["SW"],
                                            device=host,
                                            maximum_draw=psu["Watts"],
                                            allocated_draw=psu["Watts"],
                                            type="iec-60320-c14",
                                        )
                                else:
                                    for x in range(len(psus)):
                                        port_changed = False
                                        if nb_power_ports[x].name != psus[x]["SW"]:
                                            nb_power_ports[x].name = psus[x]["SW"]
                                            port_changed = True
                                            self.logger.info(
                                                f"{host.name}: Renamed power port {psus[x]['SW']}"
                                            )
                                        if nb_power_ports[x].maximum_draw != int(
                                            psus[x]["Watts"]
                                        ):
                                            nb_power_ports[x].maximum_draw = psus[x][
                                                "Watts"
                                            ]
                                            port_changed = True
                                            self.logger.info(
                                                f"{host.name}: Adjusted power port wattage {psus[x]['Watts']}"
                                            )
                                        if (
                                            nb_power_ports[x].allocated_draw
                                            != nb_power_ports[x].maximum_draw
                                        ):
                                            nb_power_ports[
                                                x
                                            ].allocated_draw = nb_power_ports[
                                                x
                                            ].maximum_draw
                                            port_changed = True
                                            self.logger.info(
                                                f"{host.name}: Adjusted power port allocated wattage {psus[x]['Watts']}"
                                            )
                                        if port_changed:
                                            nb_power_ports[x].validated_save()

                        case "show bgp all summary":
                            if parsed:
                                if isinstance(parsed, list):
                                    parsed = parsed[0]
                                local_asn = parsed["asn"]
                                if self.debug:
                                    self.logger.debug(
                                        f"local_asn: {local_asn}")

                                nb_local_asn = self.util.get_or_create_asn(
                                    asn=local_asn
                                )

                                router_id = parsed["router_id"]
                                if self.debug:
                                    self.logger.debug(
                                        f"router_id: {router_id}")

                                nb_router = self.util.get_or_create_router(
                                    host=host, asn=nb_local_asn, router_id=router_id
                                )

                        case "show bgp all neighbors":
                            if parsed:
                                if isinstance(
                                    parsed_results["show bgp all summary"], list
                                ):
                                    local_asn = parsed_results["show bgp all summary"][
                                        0
                                    ]["asn"]
                                else:
                                    local_asn = parsed_results["show bgp all summary"][
                                        "asn"
                                    ]
                                if self.debug:
                                    self.logger.debug(
                                        f"local_asn: {local_asn}")

                                nb_local_asn = self.util.get_or_create_asn(
                                    asn=local_asn
                                )
                                nb_router = BGPRoutingInstance.objects.filter(
                                    device=host, autonomous_system=nb_local_asn
                                )[0]

                                for afi_name, afi in parsed.items():
                                    for safi_name, safi in afi.items():
                                        for peer, config in safi.items():
                                            peer_asn = config["asn"]
                                            if self.debug:
                                                self.logger.debug(
                                                    f"peer address: {peer}"
                                                )

                                            self.util.get_or_create_afi_safi(
                                                afi=afi_name,
                                                safi=safi_name,
                                                router=nb_router,
                                                vrf=self.util.get_vrf(
                                                    name=config.get(
                                                        "vrf", "default")
                                                ),
                                            )

                                            if "vrf" in config:
                                                nb_namespace = self.util.get_vrf(
                                                    name=config["vrf"]
                                                ).namespace
                                            else:
                                                nb_namespace = (
                                                    self.util.global_namespace
                                                )

                                            src = config.get("source", None)
                                            if src:
                                                nb_peer_asn = (
                                                    self.util.get_or_create_asn(
                                                        asn=peer_asn
                                                    )
                                                )

                                                if host.virtual_chassis:
                                                    for device in host.virtual_chassis.members.all():
                                                        try:
                                                            nb_src_addr = IPAddress.objects.get(
                                                                interfaces__device=device,
                                                                host=src,
                                                            )
                                                            break
                                                        except:
                                                            continue
                                                else:
                                                    try:
                                                        nb_src_addr = IPAddress.objects.get(
                                                            host=src,
                                                            parent__namespace=nb_namespace,
                                                        )
                                                    except Exception as e:
                                                        self.logger.warning(
                                                            f"{host.name}: {e}. Peer: {peer}. Namespace: {nb_namespace.name}."
                                                        )
                                                        continue
                                                try:
                                                    nb_peer_addr = IPAddress.objects.get(
                                                        host=peer,
                                                        parent__namespace=nb_namespace,
                                                    )
                                                    for ip_to_int in IPAddressToInterface.objects.filter(
                                                        ip_address=nb_peer_addr,
                                                        interface__enabled=True,
                                                    ):
                                                        nb_peer_host = (
                                                            ip_to_int.interface.device
                                                        )

                                                        peer_router_id = config[
                                                            "router_id"
                                                        ]

                                                        nb_peer_router = self.util.get_or_create_router(
                                                            host=nb_peer_host,
                                                            asn=nb_peer_asn,
                                                            router_id=peer_router_id,
                                                        )
                                                        self.util.ensure_peering(
                                                            router_a=nb_router,
                                                            router_z=nb_peer_router,
                                                            address_a=nb_src_addr,
                                                            address_z=nb_peer_addr,
                                                        )
                                                        self.util.ensure_afi_association(
                                                            peering_address=nb_src_addr,
                                                            afi_safi=f"{afi_name}_{safi_name}",
                                                        )
                                                except ObjectDoesNotExist as e:

                                                    cidr = self.util.find_best_cidr(
                                                        address=peer)
                                                    nb_peer_addr = self.util.get_or_create_address(
                                                        address_with_cidr=f"{peer}/{cidr}")

                                                    self.util.ensure_external_peering(
                                                        router_a=nb_router, source_address=nb_src_addr, peer_asn=nb_peer_asn, peer_address=nb_peer_addr)

                                                except Exception as e:
                                                    self.logger.warning(
                                                        f"{host.name}: {e}. Peer: {peer}. Namespace: {nb_namespace.name}."
                                                    )

                        case "show standby all":
                            if "interface" in parsed:
                                for iface in parsed["interface"]:
                                    iface_type = self._guess_interface_type(
                                        name=iface["interface"],
                                        interface=parsed_results["show interfaces"][
                                            iface["interface"]
                                        ],
                                    )
                                    nb_iface = self.util.get_interface(
                                        device=host,
                                        name=self.util.real_interface_name(
                                            iface["interface"]
                                        ),
                                        interface_type=iface_type,
                                    )

                                    if "vip" in iface:
                                        vip = iface["vip"]

                                        ip_section = parsed_results["show interfaces"][
                                            iface["interface"]
                                        ]["ipv4"]
                                        cidr = self.util.find_by_key(
                                            data=ip_section,
                                            target="prefix_length",
                                        )
                                        nb_vip = self.util.get_or_create_address(
                                            address_with_cidr=f"{vip}/{cidr}",
                                            interface=nb_iface,
                                        )
                                        nb_irg = self.util.get_interface_redundancy_group(
                                            name=f"{host.name}_{iface['session_name']}",
                                            group_id=iface["group_number"],
                                            virtual_ip=nb_vip,
                                        )

                                        nb_irg_assoc = self.util.get_interface_redundancy_group_association(
                                            interface=nb_iface,
                                            interface_redundancy_group=nb_irg,
                                            priority=int(
                                                iface.get("priority", "100")),
                                        )

                        case "show vrf detail":
                            ignore_vrfs = ["__Platform_iVRF:_ID00_"]
                            for name, vrf in parsed.items():
                                if name in ignore_vrfs:
                                    continue
                                import_rts = []
                                export_rts = []

                                if "address_family" in vrf:
                                    for af in ["ipv4 unicast", "ipv6 unicast"]:
                                        if (
                                            af in vrf["address_family"]
                                            and "route_targets"
                                            in vrf["address_family"][af]
                                        ):
                                            for rt in vrf["address_family"][af][
                                                "route_targets"
                                            ]:
                                                nb_rt = self.util.get_route_target(
                                                    name=rt["route_target"]
                                                )

                                                if nb_rt:
                                                    if rt["rt_type"] == "export":
                                                        export_rts.append(
                                                            nb_rt)
                                                    elif rt["rt_type"] == "import":
                                                        import_rts.append(
                                                            nb_rt)
                                nb_vrf = self.util.get_vrf(name=name)

                                if nb_vrf:
                                    for rt in import_rts:
                                        nb_vrf.import_targets.add(rt)
                                        self.logger.info(
                                            (
                                                f"{host.name}: Added import RT[{rt.name}] to VRF {nb_vrf.name}"
                                            )
                                        )

                                    for rt in export_rts:
                                        nb_vrf.import_targets.add(rt)
                                        self.logger.info(
                                            (
                                                f"{host.name}: Added export RT[{rt.name}] to VRF {nb_vrf.name}"
                                            )
                                        )

                                    if host.virtual_chassis:
                                        for member in Device.objects.filter(
                                            virtual_chassis=host.virtual_chassis
                                        ):
                                            nb_vrf_device_assignment = (
                                                self.util.get_vrf_device_assignment(
                                                    vrf=nb_vrf, device=member
                                                )
                                            )

                                            if nb_vrf_device_assignment:
                                                for iface in vrf.get("interfaces", []):
                                                    iface = (
                                                        self.util.real_interface_name(
                                                            iface
                                                        )
                                                    )
                                                    nb_iface = self.util.get_interface(
                                                        device=member,
                                                        name=iface,
                                                        interface_type=InterfaceTypeChoices.TYPE_OTHER,
                                                    )
                                                    if nb_iface:
                                                        if nb_iface.vrf is None or (
                                                            nb_iface.vrf is not None
                                                            and nb_iface.vrf != nb_vrf
                                                        ):
                                                            self.util.get_vrf_device_assignment(
                                                                device=member,
                                                                vrf=nb_vrf,
                                                            )
                                                            nb_iface.vrf = nb_vrf
                                                            self.logger.info(
                                                                (
                                                                    f"{host.name}: VRF {nb_vrf.name} assigned to {nb_iface.name}."
                                                                )
                                                            )
                                                            nb_iface.validated_save()
                                    else:
                                        nb_vrf_device_assignment = (
                                            self.util.get_vrf_device_assignment(
                                                vrf=nb_vrf, device=host
                                            )
                                        )
                                        if nb_vrf_device_assignment:
                                            for iface in vrf.get("interfaces", []):
                                                iface = self.util.real_interface_name(
                                                    iface
                                                )
                                                nb_iface = self.util.get_interface(
                                                    device=host,
                                                    name=iface,
                                                    interface_type=InterfaceTypeChoices.TYPE_OTHER,
                                                )
                                                if nb_iface:
                                                    if nb_iface.vrf is None or (
                                                        nb_iface.vrf is not None
                                                        and nb_iface.vrf != nb_vrf
                                                    ):
                                                        nb_iface.vrf = nb_vrf
                                                        self.logger.info(
                                                            (
                                                                f"{host.name}: VRF {nb_vrf.name} assigned to {nb_iface.name}."
                                                            )
                                                        )
                                                        nb_iface.validated_save()

                        case "show version":
                            switches = parsed_results["show switch"].get(
                                "switches", {})
                            normalized_switches = {}
                            for position, switch in switches.items():
                                try:
                                    normalized_switches[int(position)] = switch
                                except Exception:
                                    continue

                            my_position = 0
                            for position, switch in normalized_switches.items():
                                if switch.get("active", False):
                                    my_position = position
                                    break

                            def _clear_rack_position(device_obj: Device):
                                for field_name in ["position", "face"]:
                                    if hasattr(device_obj, field_name):
                                        setattr(device_obj, field_name, None)

                            def _get_unique_retired_name(base_name: str, exclude_pk: int):
                                idx = 1
                                while True:
                                    candidate = f"{base_name}-replaced-{idx}"
                                    if not Device.objects.filter(name=candidate).exclude(pk=exclude_pk).exists():
                                        return candidate
                                    idx += 1

                            decommission_status = Status.objects.filter(
                                name="Decommissioning"
                            ).first()

                            def _detach_replaced_member(device_obj: Device):
                                device_obj.virtual_chassis = None
                                device_obj.vc_position = None
                                device_obj.vc_priority = None
                                if decommission_status and device_obj.status != decommission_status:
                                    device_obj.status = decommission_status
                                device_obj.validated_save()

                            nb_location = host.location
                            nb_device_type = self.util.get_device_type(
                                model=parsed["version"]["model_num"],
                                manufacturer="Cisco",
                            )
                            nb_version = self.util.get_version(
                                version=parsed["version"]["version"],
                                platform=host.platform,
                            )

                            nb_image = self.util.get_software_image(
                                version=nb_version,
                                imagename=parsed["version"]["image_id"],
                            )

                            if host.virtual_chassis:
                                nb_virtual_chassis = host.virtual_chassis
                            else:
                                nb_virtual_chassis = None

                            discovered_sn = parsed["version"]["system_sn"]
                            discovered_hostname = self.util.nautobot_hostname(
                                parsed["version"]["hostname"]
                            )

                            if discovered_sn != host.serial:
                                self.logger.warning(
                                    f"{host.name}: Replaced chassis detected. New serial {discovered_sn}, old serial {host.serial}."
                                )
                                old_host = host
                                replacement_host = Device.objects.filter(
                                    serial=discovered_sn
                                ).first()

                                if replacement_host and replacement_host.pk != old_host.pk:
                                    if old_host.name == discovered_hostname:
                                        old_host.name = _get_unique_retired_name(
                                            old_host.name, old_host.pk
                                        )
                                        old_host.validated_save()
                                    host = replacement_host
                                elif old_host.pk == host.pk:
                                    old_host.name = _get_unique_retired_name(
                                        old_host.name, old_host.pk
                                    )
                                    old_host.validated_save()
                                    host = self.util.get_device(
                                        name=discovered_hostname,
                                        device_type=nb_device_type,
                                        location=nb_location,
                                        platform=old_host.platform,
                                        version=nb_version,
                                        serial=discovered_sn,
                                        role=old_host.role,
                                    )

                                host.name = discovered_hostname
                                host.device_type = nb_device_type
                                host.platform = old_host.platform
                                host.software_version = nb_version
                                host.location = old_host.location
                                host.rack = old_host.rack
                                _clear_rack_position(host)
                                host.validated_save()

                                if nb_virtual_chassis and nb_virtual_chassis.master == old_host:
                                    nb_virtual_chassis.master = host
                                    nb_virtual_chassis.validated_save()

                                if old_host.pk != host.pk:
                                    _detach_replaced_member(old_host)
                                    self.logger.info(
                                        f"{host.name}: Detached replaced device {old_host.name} ({old_host.serial}) from VC."
                                    )

                            if host.name != discovered_hostname:
                                if host.virtual_chassis and host.virtual_chassis.master != host:
                                    self.logger.info(
                                        f"{host.name}: Updated hostname to {discovered_hostname}-{my_position}"
                                    )
                                    host.name = self.util.nautobot_hostname(
                                        f"{discovered_hostname}-{my_position}"
                                    )
                                    host.validated_save()
                                else:
                                    self.logger.info(
                                        f"{host.name}: Updated hostname to {discovered_hostname}"
                                    )
                                    host.name = discovered_hostname
                                    host.validated_save()

                            if nb_image:
                                self.util.associate_image_to_device_type(
                                    nb_device_type, nb_image
                                )

                            if nb_version and nb_image and host.software_version != nb_version:
                                host.software_version = nb_version
                                host.validated_save()

                            stack_members = {}
                            if "switch_num" in parsed["version"]:
                                for switch_id, switch_data in parsed["version"]["switch_num"].items():
                                    try:
                                        stack_members[int(
                                            switch_id)] = switch_data
                                    except Exception:
                                        continue

                            if len(stack_members.keys()) > 0:
                                if not nb_virtual_chassis:
                                    nb_virtual_chassis = self.util.get_virtual_chassis(
                                        name=host.name
                                    )

                                if nb_virtual_chassis.name != host.name:
                                    nb_virtual_chassis.name = host.name
                                    nb_virtual_chassis.validated_save()

                                host.virtual_chassis = nb_virtual_chassis
                                host.vc_position = my_position
                                host.vc_priority = normalized_switches.get(my_position, {}).get(
                                    "priority"
                                )
                                host.validated_save()

                                if nb_virtual_chassis.master != host:
                                    nb_virtual_chassis.master = host
                                    nb_virtual_chassis.validated_save()

                                authoritative_serials = {discovered_sn}

                                for switch_id, switch in stack_members.items():
                                    member_sn = switch.get("system_sn")
                                    if not member_sn:
                                        continue
                                    authoritative_serials.add(member_sn)

                                    if switch_id == my_position:
                                        continue

                                    if parsed["version"]["model_num"] == switch.get("model_num"):
                                        member_device_type = host.device_type
                                    else:
                                        member_device_type = self.util.get_device_type(
                                            model=switch["model_num"]
                                        )

                                    self.util.associate_image_to_device_type(
                                        device_type=member_device_type,
                                        software_image=nb_image,
                                    )

                                    desired_priority = normalized_switches.get(
                                        switch_id, {}
                                    ).get("priority")
                                    desired_name = f"{host.name}-{switch_id}"
                                    old_member = None

                                    if nb_virtual_chassis.members.filter(serial=member_sn):
                                        nb_switch = nb_virtual_chassis.members.get(
                                            serial=member_sn
                                        )
                                    elif nb_virtual_chassis.members.filter(vc_position=switch_id):
                                        old_member = nb_virtual_chassis.members.get(
                                            vc_position=switch_id
                                        )
                                        replacement_switch = Device.objects.filter(
                                            serial=member_sn
                                        ).exclude(pk=old_member.pk).first()
                                        if replacement_switch:
                                            nb_switch = replacement_switch
                                        else:
                                            nb_switch = self.util.get_device(
                                                name=desired_name,
                                                device_type=member_device_type,
                                                platform=host.platform,
                                                version=nb_version,
                                                serial=member_sn,
                                                location=host.location,
                                            )

                                        nb_switch.location = old_member.location
                                        nb_switch.rack = old_member.rack
                                        _clear_rack_position(nb_switch)
                                        nb_switch.name = desired_name
                                        nb_switch.device_type = member_device_type
                                        nb_switch.platform = host.platform
                                        nb_switch.software_version = nb_version
                                        nb_switch.virtual_chassis = nb_virtual_chassis
                                        nb_switch.vc_position = switch_id
                                        nb_switch.vc_priority = desired_priority
                                        nb_switch.validated_save()

                                        _detach_replaced_member(old_member)
                                        self.logger.info(
                                            f"{host.name}: Replaced stack member at position {switch_id}. Detached {old_member.name} ({old_member.serial})."
                                        )
                                    else:
                                        nb_switch = self.util.get_device(
                                            name=desired_name,
                                            device_type=member_device_type,
                                            platform=host.platform,
                                            version=nb_version,
                                            serial=member_sn,
                                            location=host.location,
                                        )

                                    switch_changed = False
                                    if nb_switch.name != desired_name:
                                        nb_switch.name = desired_name
                                        switch_changed = True
                                    if nb_switch.device_type != member_device_type:
                                        nb_switch.device_type = member_device_type
                                        switch_changed = True
                                    if nb_switch.platform != host.platform:
                                        nb_switch.platform = host.platform
                                        switch_changed = True
                                    if nb_switch.software_version != nb_version:
                                        nb_switch.software_version = nb_version
                                        switch_changed = True
                                    if nb_switch.location != host.location:
                                        nb_switch.location = host.location
                                        switch_changed = True
                                    if nb_switch.virtual_chassis != nb_virtual_chassis:
                                        nb_switch.virtual_chassis = nb_virtual_chassis
                                        switch_changed = True
                                    if nb_switch.vc_position != switch_id:
                                        nb_switch.vc_position = switch_id
                                        switch_changed = True
                                    if nb_switch.vc_priority != desired_priority:
                                        nb_switch.vc_priority = desired_priority
                                        switch_changed = True
                                    if switch_changed:
                                        nb_switch.validated_save()

                                    for iface in Interface.objects.filter(device=nb_switch):
                                        if re.match(
                                            f"^[a-zA-Z]+{my_position}\/\d+/\d+.*$",
                                            iface.name,
                                        ):
                                            iface.name = re.sub(
                                                "^([a-zA-Z]+)(\d+)(/\d+/\d+.*)$",
                                                f"\g<1>{switch_id}\g<3>",
                                                iface.name,
                                            )
                                            try:
                                                iface.validated_save()
                                            except Exception:
                                                pass
                                        elif re.match(
                                            f"^[a-zA-Z]+\d+/\d+$",
                                            iface.name,
                                        ):
                                            iface.delete()

                                stale_members = nb_virtual_chassis.members.exclude(
                                    serial__in=authoritative_serials
                                )
                                for stale_member in stale_members:
                                    _detach_replaced_member(stale_member)
                                    self.logger.info(
                                        f"{host.name}: Detached stale VC member {stale_member.name} ({stale_member.serial})."
                                    )

                        case "show vlan":
                            if "vlans" in parsed:
                                for id, vlan in parsed["vlans"].items():
                                    nb_location = self.util.get_validated_location(
                                        host.location
                                    )
                                    nb_vlg = self.util.get_vlan_group(
                                        name=nb_location.name, location=nb_location
                                    )

                                    if nb_vlg:
                                        try:
                                            existing_vlan_name = (
                                                self.util.get_vlan_by_name(
                                                    name=vlan["name"], vlan_group=nb_vlg
                                                )
                                            )
                                            if (
                                                existing_vlan_name
                                                and existing_vlan_name.vid != int(id)
                                            ):
                                                # Duplicate VLAN name, need to rename
                                                vlan_name = f"{vlan['name']}_{id}"
                                            else:
                                                vlan_name = vlan["name"]
                                        except:
                                            vlan_name = vlan["name"]
                                        finally:
                                            self.util.get_or_create_vlan(
                                                vlan=int(id),
                                                vlan_group=nb_vlg,
                                                vlan_name=vlan_name,
                                            )

                        case "show interfaces switchport":
                            parsed_results[cmd] = self.util.fix_interface_keys(
                                data=parsed
                            )
                            parsed = parsed_results[cmd]

                            for name, port in parsed.items():
                                raw_name = name
                                name = self.util.real_interface_name(name)
                                try:
                                    nb_iface_type = self._guess_interface_type(
                                        name,
                                        parsed_results["show interfaces"][raw_name],
                                    )
                                except:
                                    nb_iface_type = InterfaceTypeChoices.TYPE_OTHER

                                if port.get("switchport_mode", False):
                                    nb_iface = self.util.get_interface(
                                        device=host,
                                        name=name,
                                        interface_type=nb_iface_type,
                                    )
                                    nb_location = self.util.get_validated_location(
                                        host.location
                                    )
                                    nb_vlg = self.util.get_vlan_group(
                                        name=nb_location.name,
                                        location=nb_location,
                                    )
                                    switchport_changed = False

                                    match port["switchport_mode"]:
                                        case "static access":
                                            if nb_iface.mode != InterfaceModeChoices.MODE_ACCESS:
                                                nb_iface.mode = (
                                                    InterfaceModeChoices.MODE_ACCESS
                                                )
                                                switchport_changed = True
                                        case "trunk":
                                            if "trunk_vlans" in port:
                                                if port["trunk_vlans"] == "all":
                                                    if nb_iface.mode != InterfaceModeChoices.MODE_TAGGED_ALL:
                                                        nb_iface.mode = InterfaceModeChoices.MODE_TAGGED_ALL
                                                        switchport_changed = True
                                                else:
                                                    if nb_iface.mode != InterfaceModeChoices.MODE_TAGGED:
                                                        nb_iface.mode = (
                                                            InterfaceModeChoices.MODE_TAGGED
                                                        )
                                                        switchport_changed = True
                                                    self.util.tag_vlans_to_interface(
                                                        nb_iface,
                                                        nb_vlg,
                                                        port["trunk_vlans"],
                                                    )
                                            else:
                                                continue

                                        case "dynamic auto":
                                            if "operational_mode" in port:
                                                match port["operational_mode"]:
                                                    case "down":
                                                        continue
                                                    case "static access":
                                                        if nb_iface.mode != InterfaceModeChoices.MODE_ACCESS:
                                                            nb_iface.mode = InterfaceModeChoices.MODE_ACCESS
                                                            switchport_changed = True
                                                    case "trunk":
                                                        if "trunk_vlans" in port:
                                                            if (
                                                                port["trunk_vlans"]
                                                                == "all"
                                                            ):
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
                                            else:
                                                continue
                                        case "dynamic desirable":
                                            if "operational_mode" in port:
                                                match port["operational_mode"]:
                                                    case "down":
                                                        continue
                                                    case "static access":
                                                        if nb_iface.mode != InterfaceModeChoices.MODE_ACCESS:
                                                            nb_iface.mode = InterfaceModeChoices.MODE_ACCESS
                                                            switchport_changed = True
                                                    case "trunk":
                                                        if "trunk_vlans" in port:
                                                            if (
                                                                port["trunk_vlans"]
                                                                == "all"
                                                            ):
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
                                            else:
                                                continue

                                    if (
                                        "access_vlan" in port
                                        and nb_iface.mode is not None
                                    ):
                                        untagged_vlan = self.util.get_or_create_vlan(
                                            vlan=int(port["access_vlan"]),
                                            vlan_group=nb_vlg,
                                        )
                                        if nb_iface.untagged_vlan != untagged_vlan:
                                            nb_iface.untagged_vlan = untagged_vlan
                                            switchport_changed = True

                                    if switchport_changed:
                                        nb_iface.validated_save()

                        case "show etherchannel summary":
                            if "interfaces" in parsed:
                                for lag in parsed["interfaces"]:
                                    name = self.util.real_interface_name(
                                        lag["interface"]
                                    )
                                    if "members" in lag:
                                        nb_lag = self.util.get_interface(
                                            device=host,
                                            name=name,
                                            interface_type=InterfaceTypeChoices.TYPE_LAG,
                                        )
                                        if (
                                            nb_lag
                                            and nb_lag.type
                                            != InterfaceTypeChoices.TYPE_LAG
                                        ):
                                            self.logger.info(
                                                (
                                                    f"{host.name}: Changing {name} interface type to LAG"
                                                )
                                            )
                                            nb_lag.type = InterfaceTypeChoices.TYPE_LAG
                                            nb_lag.validated_save()
                                        if nb_lag:
                                            for member in lag["members"]:
                                                member = self.util.real_interface_name(
                                                    member
                                                )
                                                try:
                                                    nb_iface_type = (
                                                        self._guess_interface_type(
                                                            member,
                                                            parsed_results[
                                                                "show interfaces"
                                                            ][member],
                                                        )
                                                    )
                                                except:
                                                    nb_iface_type = (
                                                        InterfaceTypeChoices.TYPE_OTHER
                                                    )

                                                nb_member = self.util.get_interface(
                                                    device=host,
                                                    name=member,
                                                    interface_type=nb_iface_type,
                                                )

                                                if (
                                                    nb_member
                                                    and nb_member.lag != nb_lag
                                                ):
                                                    nb_member.lag = nb_lag
                                                    nb_member.validated_save()
                                                    self.logger.info(
                                                        (
                                                            f"{host.name}: Added {member} to {name}"
                                                        )
                                                    )

                        case "show interfaces":
                            parsed_results[cmd] = self.util.fix_interface_keys(
                                data=parsed
                            )
                            parsed = parsed_results[cmd]
                            real_interfaces = [
                                self.util.real_interface_name(x).lower()
                                for x in parsed.keys()
                            ]

                            self.util.prune_interfaces(
                                device=host, interfaces=real_interfaces
                            )

                            for name, iface in parsed.items():
                                raw_name = name
                                name = self.util.real_interface_name(name)
                                iface_changed = False
                                nb_iface = self.util.get_interface(
                                    device=host,
                                    name=name,
                                    interface_type=self._guess_interface_type(
                                        name, iface
                                    ),
                                )

                                if "." in name:
                                    nb_parent = self.util.get_interface(
                                        device=host,
                                        name=name.split(".")[0],
                                        interface_type=self._guess_interface_type(
                                            name, iface
                                        ),
                                    )
                                    if nb_iface.parent_interface != nb_parent:
                                        if (
                                            nb_iface.type
                                            != InterfaceTypeChoices.TYPE_VIRTUAL
                                        ):
                                            nb_iface.type = (
                                                InterfaceTypeChoices.TYPE_VIRTUAL
                                            )
                                            iface_changed = True
                                            self.logger.info(
                                                (
                                                    f"{host.name}: changed {name} type to virtual"
                                                )
                                            )
                                        nb_iface.parent_interface = nb_parent
                                        iface_changed = True
                                        nb_iface.validated_save()
                                        self.logger.info(
                                            (
                                                f"{host.name}: set {name} parent interface to {nb_parent.name}"
                                            )
                                        )

                                if "description" in iface:
                                    if nb_iface.description != iface["description"]:
                                        nb_iface.description = iface["description"]
                                        iface_changed = True
                                        self.logger.info(
                                            (
                                                f"{host.name}: Updating {name} Description to: {iface['description']}"
                                            )
                                        )

                                if "enabled" in iface:
                                    if nb_iface.enabled != iface["enabled"]:
                                        nb_iface.enabled = iface["enabled"]
                                        iface_changed = True
                                        self.logger.info(
                                            (
                                                f"{host.name}: Updating {name} Admin status to: {iface['enabled']}"
                                            )
                                        )

                                if "mac_address" in iface:
                                    if nb_iface.mac_address != self.util.extract_mac(
                                        iface["mac_address"]
                                    ):
                                        nb_iface.mac_address = self.util.extract_mac(
                                            iface["mac_address"]
                                        )
                                        iface_changed = True
                                        self.logger.info(
                                            (
                                                f"{host.name}: Updating {name} MAC Address to: {self.util.extract_mac(iface['mac_address'])}"
                                            )
                                        )

                                if "mtu" in iface:
                                    if not nb_iface.mtu or int(nb_iface.mtu) != int(
                                        iface["mtu"]
                                    ):
                                        nb_iface.mtu = int(iface["mtu"])
                                        iface_changed = True
                                        self.logger.info(
                                            (
                                                f"{host.name}: Updating {name} Old MTU ({nb_iface.mtu}) to: {iface['mtu']}"
                                            )
                                        )

                                if "ipv4" in iface:
                                    for address in iface["ipv4"].keys():
                                        try:
                                            ip_int = ipaddress.ip_interface(
                                                address)
                                            if ip_int.is_global:
                                                nb_tag = self.util.get_tag(
                                                    name="EXTERNAL",
                                                    content_types=[
                                                        self.util.get_content_type(
                                                            Interface
                                                        )
                                                    ],
                                                    color="aa1409",
                                                )
                                                if "EXTERNAL" not in [
                                                    x
                                                    for x in nb_iface.tags.values_list(
                                                        "name", flat=True
                                                    )
                                                ]:
                                                    nb_iface.tags.add(nb_tag)
                                                    self.logger.info(
                                                        f"{host.name}: Tagged 'EXTERNAL' to interface {nb_iface.name}"
                                                    )

                                            nb_address = (
                                                self.util.get_or_create_address(
                                                    address_with_cidr=address,
                                                    interface=nb_iface,
                                                )
                                            )
                                            nb_location = (
                                                self.util.get_validated_location(
                                                    host.location
                                                )
                                            )
                                            try:
                                                # TODO: Sort out master and IP Assignment when dealing with stacks
                                                # TODO: Ensure Primary IP is preserved

                                                nb_iface.ip_addresses.add(
                                                    nb_address)
                                                if nb_address.host == discover_ip.host:
                                                    if host.primary_ip4 != discover_ip:
                                                        host.primary_ip4 = discover_ip
                                                        host.validated_save()
                                                nb_address.parent.locations.add(
                                                    nb_location
                                                )
                                            except Exception as e:
                                                if self.debug:
                                                    self.logger.debug(
                                                        f"{host.name}: {e}"
                                                    )

                                            if "Vlan" in name:
                                                vid = name.replace("Vlan", "")
                                                nb_vlan = self.util.get_or_create_vlan(
                                                    vlan=int(vid),
                                                    vlan_group=self.util.get_vlan_group(
                                                        name=nb_location.name,
                                                        location=nb_location,
                                                    ),
                                                )
                                                if nb_vlan:
                                                    self.util.tag_vlan_to_prefix(
                                                        device=host,
                                                        vlan=nb_vlan,
                                                        prefix=nb_address.parent,
                                                    )
                                                    if self.debug:
                                                        self.logger.debug(
                                                            f"Attempting to set access vlan to {vid}. Interface {nb_iface.name}, VLG {nb_vlan.vlan_group} "
                                                        )
                                                    self.util.access_vlan_on_interface(
                                                        interface=nb_iface,
                                                        vlan_group=nb_vlan.vlan_group,
                                                        vlan=vid,
                                                    )

                                            if (
                                                "encapsulations" in iface
                                                and iface["encapsulations"][
                                                    "encapsulation"
                                                ]
                                                == "dot1q"
                                            ):
                                                vid = iface["encapsulations"][
                                                    "first_dot1q"
                                                ]
                                                nb_vlan = self.util.get_or_create_vlan(
                                                    vlan=int(vid),
                                                    vlan_group=self.util.get_vlan_group(
                                                        name=nb_location.name,
                                                        location=nb_location,
                                                    ),
                                                )
                                                if nb_vlan:
                                                    self.util.tag_vlan_to_prefix(
                                                        device=host,
                                                        vlan=nb_vlan,
                                                        prefix=nb_address.parent,
                                                    )
                                                    self.util.tag_vlans_to_interface(
                                                        nb_iface=nb_iface,
                                                        nb_vlg=nb_vlan.vlan_group,
                                                        vlans=vid,
                                                    )

                                        except ValueError:
                                            if self.debug:
                                                self.logger.debug(
                                                    f"{host.name}: Skipping {address} as not a valid IP"
                                                )
                                if iface_changed:
                                    try:
                                        nb_iface.validated_save()
                                    except ValidationError as e:
                                        if "untagged_vlan" in e and [
                                            x for x in e["untagged_vlan"] if "location" in x
                                        ]:
                                            nb_iface.save()
                                        else:
                                            self.logger.error(
                                                f"{host.name}: Interface: {name}, Exception:{e}"
                                            )

                        case "show bgp all summary":
                            pass
                        case "show cdp neighbors":
                            parsed = parsed_results[cmd]
                            if "cdp" in parsed:
                                for neighbor in parsed["cdp"]:
                                    nbr_host = neighbor["device_id"]
                                    nbr_host = nbr_host.split(".")[0]
                                    nbr_host = nbr_host.split("(")[0]
                                    nbr_host = self.util.nautobot_hostname(
                                        nbr_host)
                                    nbr_iface = self.util.real_interface_name(
                                        neighbor["port_id"]
                                    )
                                    nbr_iface = nbr_iface.split(".")[0]
                                    loc_iface = self.util.real_interface_name(
                                        neighbor["local_interface"]
                                    )
                                    loc_iface = loc_iface.split(".")[0]
                                    try:
                                        nb_nbr_host = Device.objects.get(
                                            name__iexact=nbr_host)
                                        nb_nbr_iface = self.util.get_interface(
                                            device=nb_nbr_host,
                                            name=nbr_iface,
                                            interface_type=self.util.guess_interface_type_from_name(
                                                nbr_iface
                                            ),
                                        )
                                        nb_loc_iface = self.util.get_interface(
                                            device=host,
                                            name=loc_iface,
                                            interface_type=self.util.guess_interface_type_from_name(
                                                loc_iface
                                            ),
                                        )
                                        if (
                                            not nb_loc_iface.connected_endpoint
                                            and not nb_nbr_iface.connected_endpoint
                                        ):
                                            nb_cbl = Cable.objects.get_or_create(
                                                termination_a_id=nb_loc_iface.id,
                                                termination_a_type=ContentType.objects.get_for_model(
                                                    nb_loc_iface
                                                ),
                                                termination_b_id=nb_nbr_iface.id,
                                                termination_b_type=ContentType.objects.get_for_model(
                                                    nb_nbr_iface
                                                ),
                                                defaults={
                                                    "status": self.util.status_connected
                                                },
                                            )
                                            if nb_cbl[1]:
                                                self.logger.info(
                                                    f"{host.name}: connected {loc_iface} to {nbr_host} {nbr_iface}"
                                                )

                                    except Exception as e:
                                        if self.debug:
                                            self.logger.debug(
                                                f"{host.name}: {e}")

                        case "show lldp neighbors":
                            parsed = parsed_results[cmd]
                            if "lldp" in parsed:
                                for nbr_data in parsed["lldp"]:
                                    nbr_host = nbr_data["device_id"].split(".")[
                                        0]
                                    nbr_host = nbr_host.split("(")[0]
                                    nbr_host = self.util.nautobot_hostname(
                                        nbr_host)
                                    nbr_iface = self.util.real_interface_name(
                                        nbr_data["port_id"]
                                    )
                                    nbr_iface = nbr_iface.split(".")[0]
                                    loc_iface = self.util.real_interface_name(
                                        nbr_data["local_interface"]
                                    )
                                    loc_iface = loc_iface.split(".")[0]
                                    try:
                                        nb_nbr_host = Device.objects.get(
                                            name__iexact=nbr_host)
                                        nb_nbr_iface = self.util.get_interface(
                                            device=nb_nbr_host,
                                            name=nbr_iface,
                                            interface_type=self.util.guess_interface_type_from_name(
                                                nbr_iface
                                            ),
                                        )
                                        nb_loc_iface = self.util.get_interface(
                                            device=host,
                                            name=loc_iface,
                                            interface_type=self.util.guess_interface_type_from_name(
                                                loc_iface
                                            ),
                                        )
                                        if (
                                            not nb_loc_iface.connected_endpoint
                                            and not nb_nbr_iface.connected_endpoint
                                        ):
                                            nb_cbl = Cable.objects.get_or_create(
                                                termination_a_id=nb_loc_iface.id,
                                                termination_a_type=ContentType.objects.get_for_model(
                                                    nb_loc_iface
                                                ),
                                                termination_b_id=nb_nbr_iface.id,
                                                termination_b_type=ContentType.objects.get_for_model(
                                                    nb_nbr_iface
                                                ),
                                                defaults={
                                                    "status": self.util.status_connected
                                                },
                                            )
                                            if nb_cbl[1]:
                                                self.logger.info(
                                                    f"{host.name}: connected {loc_iface} to {nbr_host} {nbr_iface}"
                                                )
                                    except Exception as e:
                                        if self.debug:
                                            self.logger.debug(
                                                f"{host.name}: {e}")
        except Exception as e:
            self.logger.error(f"{host.name}: {e}")

    def _guess_interface_type(self, name, interface):
        if name.startswith("Vlan"):
            return InterfaceTypeChoices.TYPE_VIRTUAL

        if interface["type"] == "EtherChannel":
            return InterfaceTypeChoices.TYPE_LAG
        if interface["type"] == "Ethernet SVI":
            return InterfaceTypeChoices.TYPE_VIRTUAL
        if "media_type" in interface:
            match interface["media_type"]:
                case "Virtual":
                    return InterfaceTypeChoices.TYPE_VIRTUAL
                case "10/100/1000BaseTX":
                    return InterfaceTypeChoices.TYPE_1GE_FIXED
                case "100BaseTX/FX":
                    return InterfaceTypeChoices.TYPE_1GE_FIXED
                case "Not Present":
                    if interface["type"] == "Gigabit Ethernet":
                        return InterfaceTypeChoices.TYPE_1GE_SFP
                    elif interface["type"] == "Ten Gigabit Ethernet":
                        return InterfaceTypeChoices.TYPE_1GE_SFP
                    else:
                        return self.util.guess_interface_type_from_name(name=name)
                case "unknown":
                    if interface["type"] == "Gigabit Ethernet":
                        return InterfaceTypeChoices.TYPE_1GE_SFP
                    elif interface["type"] == "Ten Gigabit Ethernet":
                        return InterfaceTypeChoices.TYPE_1GE_SFP
                    else:
                        return self.util.guess_interface_type_from_name(name=name)
                case "MII":
                    return InterfaceTypeChoices.TYPE_100ME_FIXED
                case "10GBase-SR":
                    return InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
                case "10GBase-LR":
                    return InterfaceTypeChoices.TYPE_10GE_SFP_PLUS
                case _:
                    return self.util.guess_interface_type_from_name(name=name)
        else:
            return self.util.guess_interface_type_from_name(name=name)

    def _parse_cli(self, address, commands):
        results = {}
        driver = napalm.get_network_driver(self.nos)
        from ttp import ttp
        import os
        import pathlib
        import json

        device = driver(
            hostname=address, username=self.username, password=self.password
        )
        try:
            device.open()
            if self.debug:
                self.logger.debug(f"Connected to {address}")
            cli_results = device.cli(commands=commands)
            device.close()

            for cmd in commands:
                try:
                    path = os.path.join(
                        pathlib.Path(__file__).parent.resolve(),
                        "templates",
                        "ios",
                        f"{cmd}.ttp",
                    )
                    if self.debug:
                        self.logger.debug(f"Loading TTP Template: {path}")
                    with open(path) as template:
                        ttp_template = template.read()
                        parser = ttp(
                            data=cli_results[cmd], template=ttp_template)
                        parser.parse()
                        result = json.loads(parser.result(format="json")[0])
                        if len(result) > 0:
                            results[cmd] = result[0]
                except Exception as e:
                    if self.debug:
                        self.logger.debug(f"{address}: {cmd}: {e}")
        except Exception as e:
            self.logger.critical(f"Unable to connect to {address}")
            if self.debug:
                self.logger.debug(f"{address}: {e}")
        return results


register_jobs(CiscoIOS)
