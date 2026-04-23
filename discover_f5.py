from django.contrib.contenttypes.models import ContentType
from typing import List
from .discover_utils import utils
from nautobot.apps.jobs import Job, register_jobs, ObjectVar, BooleanVar, MultiObjectVar

import requests

# DCIM
from nautobot.dcim.choices import (
    InterfaceTypeChoices,
    InterfaceModeChoices,
    SoftwareImageFileHashingAlgorithmChoices,
)
from nautobot.dcim.models import (
    Platform,
    Device,
    DeviceType,
    # Interface,
    # Cable,
    # PowerPort,
    # VirtualChassis,
)


from nautobot.virtualization.models import (
    ClusterType,
    Cluster,
    VirtualMachine,
)

# Extras
from nautobot.extras.models import Role, SecretsGroup, Status

name = "Discovery"


class F5Image:
    version: str
    file_name: str
    hash: str
    size: int

    def __init__(self):
        self.version = ""
        self.file_name = ""
        self.hash = ""
        self.size = 0


class F5VLAN:
    name: str
    path: str
    tag: int

    def __init__(self):
        self.name = ""
        self.path = ""
        self.tag = 1


class F5Address:
    address: str
    vlan: F5VLAN

    def __init__(self):
        self.address = ""
        self.vlan = None


class F5Interface:
    name: str
    mtu: int
    mac: str
    enabled: bool
    lag: bool
    members: List[str]
    vlans: List[F5VLAN]

    def __init__(self):
        self.name = ""
        self.mtu = 1500
        self.mac = ""
        self.enabled = False
        self.lag = False
        self.members = []
        self.vlans = []

    def vlan_list(self) -> str:
        return ",".join([str(x.tag) for x in self.vlans])


class F5Guest:
    hostname: str
    mgmt_ip: str
    cpu_count: int

    def __init__(self):
        self.hostname = ""
        self.mgmt_ip = ""
        self.cpu_count = 1


class F5Device:
    hostname: str
    serial: str
    model: str
    mgmt_ip: str
    version: str
    vcmp_guests: List[F5Guest]
    interfaces: List[F5Interface]
    vlans: List[F5VLAN]
    addresses: List[F5Address]
    images: List[F5Image]

    def __init__(self):
        self.hostname = ""
        self.serial = ""
        self.model = ""
        self.mgmt_ip = ""
        self.version = ""
        self.vcmp_guests = []
        self.interfaces = []
        self.vlans = []
        self.addresses = []
        self.images = []

    def get_vlan(self, name: str) -> F5VLAN:
        return next((x for x in self.vlans if x.name == name), None)

    def get_vlans(self, names: List[str]) -> List[F5VLAN]:
        return [x for x in self.vlans if x.name in names]

    def interface_names(self) -> List[str]:
        names = []
        names.extend([x.name for x in self.interfaces])
        names.extend([x.name for x in self.vlans])
        return names


class DiscoverF5(Job):
    class Meta:
        name = "Discovery: F5"
        description = """
            Discovers additional information for F5 devices.
        """
        has_sensitive_variables = False
        soft_time_limit = 1200
        time_limit = 1210

    status = ObjectVar(
        model=Status,
        required=False,
        description="Select status to filter device discovery scope.",
    )
    device = MultiObjectVar(
        model=Device,
        query_params={"platform": ["bigip_f5"], "has_primary_ip": True},
        required=False,
        label="Physical F5s",
        description="Select a specific device or leave empty for all physical F5 devices.",
    )

    vm = MultiObjectVar(
        model=VirtualMachine,
        query_params={"platform": ["bigip_f5"], "has_primary_ip": True},
        required=False,
        label="Virtual F5s",
        description="Select a specific device or leave empty for all virtual F5 devices.",
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

    def _build_data(self, host: Device | VirtualMachine) -> F5Device:
        device = F5Device()
        device.mgmt_ip = host.primary_ip4.host

        for api in self.endpoints:
            try:
                result = requests.get(
                    f"https://{device.mgmt_ip}/{api}",
                    auth=(self.username, self.password),
                    verify=False,
                )
            except Exception:
                self.logger.error(
                    f"{host.name}: Unable to query API https://{device.mgmt_ip}/{api}"
                )
            if 200 <= result.status_code < 400:
                data = result.json()
                match api:
                    case "mgmt/tm/sys/hardware":
                        device.serial = data["entries"][
                            "https://localhost/mgmt/tm/sys/hardware/system-info"
                        ]["nestedStats"]["entries"][
                            "https://localhost/mgmt/tm/sys/hardware/system-info/0"
                        ]["nestedStats"]["entries"]["bigipChassisSerialNum"][
                            "description"
                        ].strip()
                        device.model = data["entries"][
                            "https://localhost/mgmt/tm/sys/hardware/platform"
                        ]["nestedStats"]["entries"][
                            "https://localhost/mgmt/tm/sys/hardware/platform/0"
                        ]["nestedStats"]["entries"]["marketingName"][
                            "description"
                        ].strip()

                    case "mgmt/tm/vcmp/guest":
                        if isinstance(host, Device):
                            for guest in data["items"]:
                                vcmp = F5Guest()
                                fqdn = guest["name"]
                                vcmp.hostname = self.util.nautobot_hostname(
                                    fqdn.split(".")[0]
                                )
                                vcmp.mgmt_ip = guest["managementIp"]
                                vcmp.cpu_count = guest.get("coresPerSlot", 1)
                                device.vcmp_guests.append(vcmp)

                    case "mgmt/tm/net/interface":
                        for iface in data["items"]:
                            interface = F5Interface()
                            interface.name = iface["name"]
                            interface.mtu = iface.get("mtu", 1500)
                            interface.mac = iface.get("macAddress", "")
                            interface.enabled = iface.get("enabled", False)
                            interface.lag = False
                            interface.members = []
                            device.interfaces.append(interface)

                    case "mgmt/tm/net/trunk":
                        for lag in data["items"]:
                            interface = F5Interface()
                            interface.name = lag["name"]
                            interface.mac = lag.get("macAddress", "")
                            interface.enabled = lag["lacp"] == "enabled"
                            interface.lag = True
                            interface.members = lag.get("interfaces", [])
                            device.interfaces.append(interface)

                    case "mgmt/tm/net/vlan":
                        for vlan in data["items"]:
                            lan = F5VLAN()
                            lan.name = vlan["name"]
                            lan.path = vlan["fullPath"]
                            lan.tag = vlan["tag"]
                            device.vlans.append(lan)

                    case "mgmt/tm/net/self":
                        for address in data["items"]:
                            addr = F5Address()
                            addr.address = address["address"]
                            addr.vlan = [
                                x for x in device.vlans if x.path == address["vlan"]
                            ][0]
                            device.addresses.append(addr)

                    case "mgmt/tm/sys/software/image":
                        for image in data["items"]:
                            img = F5Image()
                            img.file_name = image["fullPath"]
                            img.hash = image["checksum"]
                            img.version = image["version"]
                            img.size = self.convert_to_bytes(image["fileSize"])
                            device.images.append(img)
                    case "mgmt/tm/sys/version":
                        device.version = data["entries"][
                            "https://localhost/mgmt/tm/sys/version/0"
                        ]["nestedStats"]["entries"]["Version"]["description"].strip()
                        if self.debug:
                            self.logger.debug(
                                f"{host.name}: detected software version: {device.version}"
                            )
                    case "mgmt/tm/sys/global-settings":
                        device.hostname = self.util.nautobot_hostname(
                            data["hostname"].split('.')[0]
                        )
                    case "mgmt/tm/net/stp":
                        for item in data["items"]:
                            vlan_names = [
                                x.split("/")[-1] for x in item.get("vlans", [])
                            ]
                            for iface in item.get("interfaces", []):
                                f5_interface = next(
                                    (
                                        x
                                        for x in device.interfaces
                                        if x.name == iface["name"]
                                    ),
                                    None,
                                )
                                if f5_interface:
                                    f5_interface.vlans.extend(
                                        device.get_vlans(vlan_names)
                                    )
                            for iface in item.get("trunks", []):
                                f5_interface = next(
                                    (
                                        x
                                        for x in device.interfaces
                                        if x.name == iface["name"]
                                    ),
                                    None,
                                )
                                if f5_interface:
                                    f5_interface.vlans.extend(
                                        device.get_vlans(vlan_names)
                                    )

            else:
                if self.debug:
                    self.logger.debug(
                        f"{host.name}: Skipping API https://{device.mgmt_ip}/{api}.  Result: HTTP-{result.status_code} {result.text}"
                    )
        return device

    def run(self, *args, **kwargs):
        self.debug = kwargs["debug"]
        self.util = utils(logger=self.logger, debug=self.debug)
        creds = self.util.parse_credentials(kwargs["credentials"])
        self.username = creds["username"]
        self.password = creds["password"]
        self.credentials = kwargs["credentials"]
        self.devices = kwargs["device"]
        self.vms = kwargs["vm"]
        self.status = kwargs["status"]
        self.logger
        self.util.prefetch_device_types(manufacturer="F5")

        self.platform = Platform.objects.get(name="bigip_f5")

        self.endpoints = [
            "mgmt/tm/sys/global-settings",  # Hostname
            "mgmt/tm/sys/version",  # Current Version
            "mgmt/tm/sys/software/image",  # Image versions
            "mgmt/tm/sys/hardware",  # Serial, Platform
            "mgmt/tm/vcmp/guest",  # VCMP Guests
            "mgmt/tm/net/interface",  # Interfaces
            "mgmt/tm/net/trunk",  # LAGs
            "mgmt/tm/net/vlan",  # VLANs
            "mgmt/tm/net/self",  # Self IPs
            "mgmt/tm/net/stp",  # VLAN to Iface mapping
        ]

        to_scan = []
        if not self.devices and not self.vms:
            if self.status:
                to_scan.extend(
                    list(
                        VirtualMachine.objects.filter(
                            platform=self.platform, status=self.status
                        ).exclude(primary_ip4=None)
                    )
                )
                to_scan.extend(
                    list(
                        Device.objects.filter(
                            platform=self.platform, status=self.status
                        ).exclude(primary_ip4=None)
                    )
                )
            else:
                to_scan.extend(
                    list(
                        VirtualMachine.objects.filter(platform=self.platform).exclude(
                            primary_ip4=None
                        )
                    )
                )
                to_scan.extend(
                    list(
                        Device.objects.filter(platform=self.platform).exclude(
                            primary_ip4=None
                        )
                    )
                )
        else:
            to_scan.extend(list(self.vms))
            to_scan.extend(list(self.devices))

        self.logger.info(f"Scanning devices: {[x.name for x in to_scan]}")
        for host in to_scan:
            self._discover(host)

    def _discover(self, host: Device | VirtualMachine):
        device = self._build_data(host=host)
        if device.version:

            # Prune deleted interfaces
            # if self.debug:
            #     self.logger.debug(f"{host.name}: discovered interfaces {device.interface_names()}")
            # for nb_iface in host.interfaces.all():
            #     if nb_iface.name not in device.interface_names():
            #         nb_iface.delete()
            #         self.logger.info(f"{host.name}: Removed interface {nb_iface.name}")

            for image in device.images:
                if image.version != "":
                    nb_version = self.util.get_version(
                        version=image.version, platform=self.platform
                    )
                    nb_image = self.util.get_software_image(
                        version=nb_version, imagename=image.file_name
                    )
                    image_changed = False
                    if nb_image.image_file_size != image.size:
                        nb_image.image_file_size = image.size
                        image_changed = True
                    if nb_image.image_file_checksum != image.hash:
                        nb_image.image_file_checksum = image.hash
                        image_changed = True
                    if nb_image.hashing_algorithm != SoftwareImageFileHashingAlgorithmChoices.MD5:
                        nb_image.hashing_algorithm = (
                            SoftwareImageFileHashingAlgorithmChoices.MD5
                        )
                        image_changed = True
                    nb_device_types = DeviceType.objects.filter(
                        manufacturer__name="F5")
                    for dt in nb_device_types:
                        nb_image.device_types.add(dt)
                    if image_changed:
                        nb_image.validated_save()

            nb_version = self.util.get_version(
                version=device.version, platform=self.platform
            )
            if host.software_version != nb_version:
                host.software_version = nb_version
                self.logger.info(
                    f"{host.name}: set Software Version to {device.version}")
                host.validated_save()

            if device.hostname != host.name:
                host.name = device.hostname
                host.validated_save()
            if isinstance(host, Device):
                if host.serial != device.serial:
                    host.serial = device.serial
                    host.validated_save()
                if device.model != host.device_type.model:
                    device_type = self.util.get_device_type(
                        device.model, manufacturer="F5")
                    host.device_type = device_type
                    host.validated_save()

            nb_site = host.location
            while nb_site.parent:
                nb_site = nb_site.parent
            nb_vlg = self.util.get_vlan_group(
                name=nb_site.name, location=nb_site)

            for vlan in device.vlans:
                nb_vlan = self.util.get_or_create_vlan(
                    vlan=vlan.tag, vlan_group=nb_vlg)
                if isinstance(host, Device):
                    nb_iface = self.util.get_interface(
                        device=host,
                        name=vlan.name,
                        interface_type=InterfaceTypeChoices.TYPE_VIRTUAL,
                    )
                else:
                    nb_iface = self.util.get_vm_interface(
                        virtual_machine=host,
                        name=vlan.name,
                        status=self.util.status_active,
                    )
                iface_changed = False
                if nb_iface.enabled != True:
                    nb_iface.enabled = True
                    iface_changed = True
                if nb_iface.mode != InterfaceModeChoices.MODE_ACCESS:
                    nb_iface.mode = InterfaceModeChoices.MODE_ACCESS
                    iface_changed = True
                if nb_iface.untagged_vlan != nb_vlan:
                    nb_iface.untagged_vlan = nb_vlan
                    iface_changed = True
                if iface_changed:
                    nb_iface.validated_save()

                # For VMs, find GUID interface parent by matching MAC address
                if isinstance(host, VirtualMachine) and nb_iface.mac_address:
                    self._assign_parent_by_mac(host, nb_iface)

                assigned_ip = next(
                    (x for x in device.addresses if x.vlan.name == vlan.name), None
                )
                if assigned_ip:
                    nb_address = self.util.get_or_create_address(
                        address_with_cidr=assigned_ip.address
                    )
                    try:
                        nb_iface.add_ip_addresses(nb_address)
                    except Exception:
                        pass

            for iface in device.interfaces:
                if iface.lag:
                    iface_type = InterfaceTypeChoices.TYPE_LAG
                else:
                    iface_type = InterfaceTypeChoices.TYPE_OTHER

                if isinstance(host, Device):
                    nb_iface = self.util.get_interface(
                        device=host, name=iface.name, interface_type=iface_type
                    )
                else:
                    nb_iface = self.util.get_vm_interface(
                        virtual_machine=host,
                        name=iface.name,
                        status=self.util.status_active,
                    )

                if nb_iface.enabled != iface.enabled:
                    nb_iface.enabled = iface.enabled
                    self.logger.info(
                        f"{host.name}: Changed {iface.name} enabled to {iface.enabled}"
                    )
                    nb_iface.validated_save()

                if nb_iface.mac_address != iface.mac and iface.mac != "none":
                    nb_iface.mac_address = iface.mac
                    self.logger.info(
                        f"{host.name}: Changed {iface.name} MAC to {iface.mac}"
                    )
                    nb_iface.validated_save()

                if nb_iface.mtu != iface.mtu:
                    nb_iface.mtu = iface.mtu
                    self.logger.info(
                        f"{host.name}: Changed {iface.name} MTU to {iface.mtu}"
                    )
                    nb_iface.validated_save()

                if iface.vlans:
                    self.util.tag_vlans_to_interface(
                        nb_iface=nb_iface, nb_vlg=nb_vlg, vlans=iface.vlan_list()
                    )

                # For VMs, find GUID interface parent by matching MAC address
                if isinstance(host, VirtualMachine) and nb_iface.mac_address:
                    self._assign_parent_by_mac(host, nb_iface)

                for member in iface.members:
                    if isinstance(host, Device):
                        nb_member = self.util.get_interface(
                            device=host,
                            name=member,
                            interface_type=InterfaceTypeChoices.TYPE_OTHER,
                        )
                        if nb_member.lag != nb_iface:
                            nb_member.lag = nb_iface
                            nb_member.validated_save()
                            self.logger.info(
                                f"{host.name}: Added {member} to {nb_iface.name}"
                            )

            if device.vcmp_guests and isinstance(host, Device):
                nb_cluster_type = self.get_cluster_type(name="F5 VCMP Host")

                nb_cluster = self.get_cluster(
                    name=host.name, cluster_type=nb_cluster_type, location=host.location
                )

                nb_lb_role = self.get_role(
                    name="Traffic Load Balancer", content_type=VirtualMachine
                )

                for guest in device.vcmp_guests:
                    nb_vm = self.get_vm(
                        name=guest.hostname,
                        cluster=nb_cluster,
                        status=self.util.status_active,
                        role=nb_lb_role,
                    )

                    nb_mgt = self.util.get_vm_interface(
                        virtual_machine=nb_vm,
                        name="mgmt",
                        status=self.util.status_active,
                    )
                    nb_address = self.util.get_or_create_address(
                        address_with_cidr=guest.mgmt_ip
                    )
                    try:
                        nb_mgt.add_ip_addresses(nb_address)
                        self.logger.info(
                            f"{nb_vm.name}: Assigned IP Address {nb_address.host} to interface {nb_mgt.name}"
                        )
                    except Exception:
                        pass
                    vm_changed = False
                    if nb_vm.primary_ip4 != nb_address:
                        nb_vm.primary_ip4 = nb_address
                        vm_changed = True
                    if nb_vm.vcpus != guest.cpu_count:
                        nb_vm.vcpus = guest.cpu_count
                        vm_changed = True
                    if nb_vm.platform != self.platform:
                        nb_vm.platform = self.platform
                        vm_changed = True
                    if vm_changed:
                        nb_vm.validated_save()

    def _assign_parent_by_mac(self, host: VirtualMachine, nb_iface):
        """Find and assign GUID interface as parent based on MAC address match."""
        if not nb_iface.mac_address:
            return

        # Normalize the MAC address for comparison
        iface_mac_normalized = str(nb_iface.mac_address).replace(
            ":", "").replace(".", "").replace("-", "").lower()

        if self.debug:
            self.logger.debug(
                f"{host.name}: Looking for GUID parent for interface {nb_iface.name} with MAC {nb_iface.mac_address}"
            )

        # Look for existing VM interfaces with GUID-like names (UUID format: 8-4-4-4-12)
        import re
        uuid_pattern = re.compile(
            r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

        for vm_iface in host.interfaces.all():
            # Skip the interface itself
            if vm_iface == nb_iface:
                continue

            # Check if this looks like a GUID interface (UUID format)
            if uuid_pattern.match(vm_iface.name) and vm_iface.mac_address:
                vm_mac_normalized = str(vm_iface.mac_address).replace(
                    ":", "").replace(".", "").replace("-", "").lower()

                if self.debug:
                    self.logger.debug(
                        f"{host.name}: Comparing with GUID interface {vm_iface.name} MAC {vm_iface.mac_address}"
                    )

                if iface_mac_normalized == vm_mac_normalized:
                    if nb_iface.parent_interface != vm_iface:
                        nb_iface.parent_interface = vm_iface
                        nb_iface.validated_save()
                        self.logger.info(
                            f"{host.name}: Set interface {nb_iface.name} parent to GUID interface {vm_iface.name} (MAC: {nb_iface.mac_address})"
                        )
                    return  # Found parent, stop searching

    def get_vm(self, name, cluster, status, role):
        name = self.util.nautobot_hostname(name)
        nb_vm = VirtualMachine.objects.get_or_create(
            name=name, cluster=cluster, status=status, defaults={"role": role}
        )
        if nb_vm[1]:
            self.logger.info(f"Created VirtualMachine: {name}")
        return nb_vm[0]

    def get_cluster_type(self, name):
        nb_cluster_type = ClusterType.objects.get_or_create(name=name)
        if nb_cluster_type[1]:
            self.logger.info(f"Created VM Cluster Type: {name}")
        return nb_cluster_type[0]

    def get_cluster(self, name, cluster_type, location):
        name = name.upper()
        nb_cluster = Cluster.objects.get_or_create(
            name=name, cluster_type=cluster_type, location=location
        )
        if nb_cluster[1]:
            self.logger.info(f"Created VM Cluster: {name}")
        try:
            host = Device.objects.get(name=name)
            nb_cluster[0].devices.add(host)
        except Exception:
            pass
        return nb_cluster[0]

    def get_role(self, name, content_type):
        nb_role = Role.objects.get_or_create(name=name)
        if nb_role[1]:
            self.logger.info(f"Created Role: {name}")
        nb_content_type = ContentType.objects.get_for_model(content_type)
        if nb_content_type not in nb_role[0].content_types.all():
            nb_role[0].content_types.add(nb_content_type)
            nb_role[0].validated_save()
        return nb_role[0]

    def convert_to_bytes(self, size_str: str) -> int:
        size_str = size_str.strip().upper()
        if size_str.endswith("GB"):
            return int(float(size_str[:-2]) * 1024**3)
        elif size_str.endswith("MB"):
            return int(float(size_str[:-2]) * 1024**2)
        elif size_str.endswith("B"):
            return int(size_str[:-1])
        else:
            raise ValueError(
                "Invalid size format. Must end with 'B', 'MB', or 'GB'.")


register_jobs(DiscoverF5)
