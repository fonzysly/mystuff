"""
https://docs.nautobot.com/projects/core/en/stable/development/jobs/

"""
import xml.etree.ElementTree as ET
from pyedgeconnect import Orchestrator
from netmiko import ConnectHandler
from datetime import datetime, timedelta
from nautobot.extras.choices import ObjectChangeActionChoices
from nautobot.apps.jobs import (
    Job,
    register_jobs,
    BooleanVar,
    IntegerVar,
)


from nautobot.extras.jobs import JobHookReceiver
from django.contrib.contenttypes.models import ContentType

# Job
from nautobot.apps.jobs import (
    Job,
)

# DCIM
from nautobot.dcim.models import Device, Platform

# IPAM
from nautobot.ipam.models import (
    IPAddress,
)

# Extras
from nautobot.extras.models import (
    Secret,
    SecretsGroup,
    SecretsGroupAssociation,
    ExternalIntegration,
)
from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)
from nautobot.extras.models import Status
from netutils.password import (
    encrypt_cisco_type5,
    encrypt_cisco_type7,
    encrypt_cisco_type9,
)
from passlib.hash import sha256_crypt
import requests
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
name = "Data Management"


class ChangePasswords(Job):
    class Meta:
        name = "Change Passwords"
        description = """
            Change passwords on devices.
        """
        has_sensitive_variables = False

    enable_new_password = BooleanVar(
        default=False,
        label="Enable New Password Generation",
        description="Create new password and store in vault",
    )
    enable_ios = BooleanVar(
        default=True,
        label="Enable IOS",
        description="Enable IOS",
    )
    enable_nxos = BooleanVar(
        default=True,
        label="Enable NXOS",
        description="Enable NXOS",
    )
    enable_f5 = BooleanVar(
        default=True,
        label="Enable F5",
        description="Enable F5",
    )
    enable_wti = BooleanVar(
        default=True,
        label="Enable WTI",
        description="Enable WTI",
    )
    enable_aci = BooleanVar(
        default=True,
        label="Enable ACI",
        description="Enable ACI",
    )

    enable_asa = BooleanVar(
        default=True,
        label="Enable ASA",
        description="Enable ASA",
    )
    enable_paloalto = BooleanVar(
        default=True,
        label="Enable Palo Alto",
        description="Enable Palo Alto",
    )
    enable_silverpeak = BooleanVar(
        default=True,
        label="Enable Silverpeak",
        description="Enable Silverpeak",
    )

    enable_infoblox = BooleanVar(
        default=True,
        label="Enable Infoblox",
        description="Enable Infoblox",
    )

    enable_ise = BooleanVar(
        default=True,
        label="Enable Cisco ISE",
        description="Enable Cisco ISE",
    )

    enable_cimc = BooleanVar(
        default=True,
        label="Enable Cisco CIMC",
        description="Change Cisco CIMC Passwords",
    )

    def run(
        self,
        enable_new_password,
        enable_ios,
        enable_nxos,
        enable_f5,
        enable_wti,
        enable_aci,
        enable_asa,
        enable_paloalto,
        enable_silverpeak,
        enable_infoblox,
        enable_ise,
        enable_cimc,
    ):
        """
        Run the job to change passwords on devices.
        """
        # Retrieve current local user and password from vault
        # store as self.local_user and self.local_password
        self.get_vault_token()
        self.get_password_from_vault()

        if enable_new_password:
            # Create new password
            self.new_password = self.generate_password()

            # Save new password to vault
            self.save_password_to_vault(self.new_password)
        else:
            self.new_password = self.local_password
            self.logger.info(
                "New password not enabled, skipping new password generation.  Will set password to existing password."
            )

        self.logger.info("Running Change Passwords job")

        platforms = []
        if enable_ios:
            platforms.append("cisco_ios")
        if enable_nxos:
            platforms.append("cisco_nxos")
        if enable_f5:
            platforms.append("bigip_f5")
        if enable_wti:
            platforms.append("wti_api")
        if enable_aci:
            platforms.append("cisco_aci")
        if enable_asa:
            platforms.append("cisco_asa")
        if enable_paloalto:
            platforms.append("paloalto_panos")
        if enable_silverpeak:
            platforms.append("Silverpeak")
        if enable_infoblox:
            platforms.append("infoblox_wapi")
        if enable_ise:
            platforms.append("cisco_ise")
        if enable_cimc:
            platforms.append("cisco_cimc")

        if enable_silverpeak:
            self.change_silverpeak_password(self.new_password)

        for device in Device.objects.filter(
            primary_ip4__isnull=False,
            status__name="Active",
            secrets_group__isnull=False,
            platform__name__in=platforms,
        ):
            self.logger.info(f"Processing device: {device.name}")
            if device.platform.name == "cisco_ios" and enable_ios:
                # new_password = self.generate_password()
                self.change_ios_password(device, self.new_password)
            elif device.platform.name == "cisco_nxos" and enable_nxos:
                # new_password = self.generate_password()
                self.change_nxos_password(device, self.new_password)
            elif device.platform.name == "bigip_f5" and enable_f5:
                # new_password = self.generate_password()
                self.change_f5_password(device, self.new_password)
            elif device.platform.name == "wti_api" and enable_wti:
                # new_password = self.generate_password()
                self.change_wti_password(device, self.new_password)
            elif (
                device.platform.name == "cisco_aci"
                and device.role.name == "controller"
                and enable_aci
            ):
                # new_password = self.generate_password()
                self.change_aci_password(device, self.new_password)
            elif device.platform.name == "cisco_asa" and enable_asa:
                # new_password = self.generate_password()
                self.change_asa_password(device, self.new_password)
            elif device.platform.name == "paloalto_panos" and enable_paloalto:
                # new_password = self.generate_password()
                self.change_paloalto_password(device, self.new_password)

            elif device.platform.name == "infoblox_wapi" and enable_infoblox:
                # new_password = self.generate_password()
                self.change_infoblox_password(device, self.new_password)
            elif device.platform.name == "cisco_ise" and enable_ise:
                # new_password = self.generate_password()
                self.change_ise_password(device, self.new_password)
            elif device.platform.name == "cisco_cimc" and enable_cimc:
                # new_password = self.generate_password()
                self.change_cimc_password(device, self.new_password)

    def generate_password(self, length=12):
        import random
        import string

        if length < 3:
            # need room for at least one letter, one digit and one punctuation
            raise ValueError("length must be at least 3")

        avoid_chars = ["<", ">", ",", "&", "'", '"', "\\", "/"]
        puncts = string.punctuation
        for char in avoid_chars:
            puncts = puncts.replace(char, "")

        letters = string.ascii_letters
        digits = string.digits

        # Start with one guaranteed of each required class
        password_chars = [
            random.choice(letters),
            random.choice(digits),
            random.choice(puncts),
        ]

        # Fill the rest with the full allowed set
        all_chars = letters + digits + puncts
        remaining = length - len(password_chars)
        password_chars += [random.choice(all_chars) for _ in range(remaining)]

        # Shuffle to avoid predictable placement
        random.shuffle(password_chars)
        return "".join(password_chars)

    def parse_secretgroup(self, secret_group: SecretsGroup):
        username = secret_group.get_secret_value(
            access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
            secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
        )
        password = secret_group.get_secret_value(
            access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
            secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
        )
        return username, password

    def change_cimc_password(self, device, new_password):
        # Placeholder for the logic to change the password on a CIMC device
        self.logger.warning(
            f"Changing password on Cisco CIMC device {device.name} is not yet implemented."
        )
        # Implement the actual password change logic here
        # SSH into device (use existing local username and password or TACACS?)
        # 'scope user <username>'
        # 'set password'

    def change_ise_password(self, device, new_password):
        # Placeholder for the logic to change the password on an ISE device
        self.logger.warning(
            f"Changing password on Cisco ISE device {device.name} is not yet implemented."
        )
        # Implement the actual password change logic here
        # Login via CLI
        # To change the CLI Admin password, simply enter the command password
        # application reset-passwd ise <admin username> <new password>

    def change_ios_password(self, device, new_password):
        # Placeholder for the logic to change the password on an IOS device
        self.logger.info(f"Changing password on IOS device {device.name}.")
        # Implement the actual password change logic here
        try:
            username, password = self.parse_secretgroup(device.secrets_group)
            net_connect = ConnectHandler(
                device_type=device.platform.network_driver,
                host=device.primary_ip4.host,
                username=username,
                password=password,
            )
            salt = "OLCDl6A0bn4GUg"

            config_commands = [
                f"username {self.local_user} privilege 15 secret 9 {encrypt_cisco_type9(new_password, salt)}",
            ]
            net_connect.send_config_set(config_commands)
            net_connect.save_config()
            net_connect.disconnect()
            self.logger.info(
                f"Password changed successfully on IOS device {device.name}.")
        except Exception as e:
            self.logger.error(
                f"Failed to change password on IOS device {device.name}. Error: {str(e)}")

    def change_nxos_password(self, device, new_password):
        # Placeholder for the logic to change the password on an NXOS device
        self.logger.info(f"Changing password on NXOS device {device.name}.")
        # Implement the actual password change logic here
        try:
            username, password = self.parse_secretgroup(device.secrets_group)
            net_connect = ConnectHandler(
                device_type=device.platform.network_driver,
                host=device.primary_ip4.host,
                username=username,
                password=password,
            )
            salt = "BGENBL"

            config_commands = [
                f"username {self.local_user} password 5 {self.get_nxos_type5_hash(new_password, salt)}",
            ]
            net_connect.send_config_set(config_commands)
            net_connect.save_config()
            net_connect.disconnect()
            self.logger.info(
                f"Password changed successfully on NX-OS device {device.name}."
            )
        except Exception as e:
            self.logger.error(
                f"Failed to change password on NX-OS device {device.name}. Error: {str(e)}"
            )

    def change_f5_password(self, device, new_password):
        # Placeholder for the logic to change the password on an F5 device
        self.logger.info(f"Changing password on F5 device {device.name}.")
        # Implement the actual password change logic here
        try:
            username, password = self.parse_secretgroup(device.secrets_group)
            net_connect = ConnectHandler(
                device_type="f5_tmsh",
                host=device.primary_ip4.host,
                username=username,
                password=password,
            )

            config_commands = [
                f"modify auth user {self.local_user} password {new_password}",
            ]
            net_connect.send_config_set(config_commands)
            net_connect.save_config()
            net_connect.disconnect()
            self.logger.info(
                f"Password changed successfully on NX-OS device {device.name}."
            )
        except Exception as e:
            self.logger.error(
                f"Failed to change password on F5 device {device.name}. Error: {str(e)}"
            )

    def change_wti_password(self, device, new_password):
        # Placeholder for the logic to change the password on a WTI device
        self.logger.info(f"Changing password on WTI device {device.name}.")
        # Implement the actual password change logic here
        try:
            username, password = self.parse_secretgroup(device.secrets_group)
            payload = {
                "users": {
                    "username": self.local_user,
                    "newpasswd": new_password,
                    "accesslevel": 3,
                    "accessserial": 1,
                    "accessssh": 1,
                    "accessweb": 1,
                    "accessoutbound": 1,
                }
            }
            params = {
                "username": self.local_user,
            }

            # Check if the user already exists
            result = requests.get(
                url=f"https://{device.primary_ip4.host}/api/v2/config/users",
                auth=(username, password),
                params=params,
                verify=False,
            )

            if result.status_code == 200:
                method = "PUT"
            else:
                ["users"]
                method = "POST"

            # Change the password
            result = requests.request(
                method=method,
                url=f"https://{device.primary_ip4.host}/api/v2/config/users",
                auth=(username, password),
                json=payload,
                verify=False,
            )
            if result.status_code == 200:
                self.logger.info(
                    f"Password changed successfully on WTI device {device.name}."
                )
            else:
                self.logger.error(
                    f"Failed to change password on WTI device {device.name}. Status code: {result.status_code}"
                )
                self.logger.error(f"Error: {result.text}")
        except Exception as e:
            self.logger.error(
                f"Failed to change password on WTI device {device.name}. Error: {str(e)}"
            )

    def change_aci_password(self, device, new_password):
        # Placeholder for the logic to change the password on an ACI device
        self.logger.info(f"Changing password on ACI device {device.name}.")
        # Implement the actual password change logic here
        try:
            username, password = self.parse_secretgroup(device.secrets_group)
            net_connect = ConnectHandler(
                device_type=device.platform.network_driver,
                host=device.primary_ip4.host,
                username=username,
                password=password,
            )

            config_commands = [
                f"aaa user {self.local_user}",
                f"password {new_password}",
                "commit",
            ]
            net_connect.send_config_set(config_commands)
            net_connect.disconnect()
            self.logger.info(
                f"Password changed successfully on Cisco ACI Fabric.")
        except Exception as e:
            self.logger.error(
                f"Failed to change password on ACI device {device.name}. Error: {str(e)}"
            )

    def change_asa_password(self, device, new_password):
        # Placeholder for the logic to change the password on an ASA device
        self.logger.info(f"Changing password on ASA device {device.name}.")
        # Implement the actual password change logic here
        try:
            username, password = self.parse_secretgroup(device.secrets_group)
            net_connect = ConnectHandler(
                device_type=device.platform.network_driver,
                host=device.primary_ip4.host,
                username=username,
                password=password,
            )

            config_commands = [
                f"username {self.local_user} password {new_password}",
            ]
            net_connect.send_config_set(config_commands)
            net_connect.save_config()
            net_connect.disconnect()
            self.logger.info(
                f"Password changed successfully on Cisco ASA device {device.name}."
            )
        except Exception as e:
            self.logger.error(
                f"Failed to change password on ASA device {device.name}. Error: {str(e)}"
            )

    def get_apikey_from_xml(self, content):
        root = ET.fromstring(content)
        if root.attrib["status"] == "success":
            return root[0][0].text
        else:
            raise ValueError("Error parsing XML with API Key.")

    def get_phash_from_xml(self, content):
        root = ET.fromstring(content)
        if root.attrib["status"] == "success":
            return root[0][0].text
        else:
            raise ValueError("Error parsing XML with Password Hash.")

    def change_paloalto_password(self, device, new_password):
        # Placeholder for the logic to change the password on a Palo Alto device
        self.logger.info(
            f"Changing password on Palo Alto device {device.name}.")
        # Implement the actual password change logic here
        try:
            # Get Token
            username, password = self.parse_secretgroup(device.secrets_group)
            params = {
                "type": "keygen",
                "user": username,
                "password": password
            }
            url = f"https://{device.primary_ip4.host}/api/"
            response = requests.get(url, params=params, verify=False)
            if response.status_code == 200:
                if 'application/xml' in response.headers['Content-Type']:
                    token = self.get_apikey_from_xml(response.text)
                if token:
                    self.logger.info(
                        f"Successfully retrieved token for Palo Alto device {device.name}."
                    )
            else:
                self.logger.error(
                    f"Failed to retrieve Vault token. Status code: {response.status_code}, Error: {response.text}"
                )

            # Generate phash
            params = {
                "type": "op",
                "cmd": f"<request><password-hash><password><![CDATA[{new_password}]]></password></password-hash></request>",
            }
            path = f"https://{device.primary_ip4.host}/api/"
            response = requests.post(
                path, params=params, headers={"X-PAN-KEY": token}, verify=False
            )
            if response.status_code == 200:
                phash = self.get_phash_from_xml(response.text)
                if phash:
                    self.logger.info(
                        f"Successfully generated password hash for Palo Alto device {device.name}."
                    )
            else:
                self.logger.error(
                    f"Failed to generate password hash for Palo Alto device {device.name}. Status code: {response.status_code}, Error: {response.text}"
                )
            # Change password
            params = {
                "type": "op",
                "cmd": f"<set><user><name>{self.local_user}</name><password>{phash}</password></user></set>",
            }
            path = f"https://{device.primary_ip4.host}/api/"
            response = requests.post(
                path, params=params, headers={"X-PAN-KEY": token}, verify=False
            )
            if response.status_code == 200:
                self.logger.info(
                    f"Successfully changed password for Palo Alto device {device.name}."
                )
            else:
                self.logger.error(
                    f"Failed to change password on Palo Alto device {device.name}. Status code: {response.status_code}"
                )
                self.logger.error(f"Error: {response.text}")
        except Exception as e:
            self.logger.error(
                f"Failed to change password on Palo Alto device {device.name}. Error: {str(e)}"
            )

    def build_template_group_body(self, from_get_result):
        body = {}
        body['name'] = from_get_result.get('name')
        if 'comment' in from_get_result:
            body['comment'] = from_get_result.get('comment') or ""
        if from_get_result.get('selectedTemplateNames'):
            body['selectedTemplateNames'] = list(
                from_get_result.get('selectedTemplateNames'))
        # Build templates list - include only the data we want to set:
        body['templates'] = []
        # prefer 'templates' key (full canonical list); fall back to 'selectedTemplates'
        templates_list = from_get_result.get(
            'templates') or from_get_result.get('selectedTemplates') or []
        for t in templates_list:
            sanitized = {'name': t.get('name')}
            # include the configuration payload - typically 'value' (this is the important part)
            if 'value' in t:
                sanitized['valObject'] = t['value']
            # Some APIs accept 'valObject' instead of value; include if present and meaningful
            elif 'valObject' in t and t['valObject'] is not None:
                sanitized['valObject'] = t['valObject']
            # optionally preserve whether template is selected for group usage
            if 'isSelected' in t:
                sanitized['isSelected'] = bool(t['isSelected'])
            body['templates'].append(sanitized)

        return body

    def change_silverpeak_password(self, new_password):
        # Placeholder for the logic to change the password on a SilverPeak device
        self.logger.info(
            f"Changing password on SilverPeak Orchestrator.")
        # Implement the actual password change logic here
        try:
            secretgroup = SecretsGroup.objects.get(
                name="Silverpeak Local Account")
            api_key = secretgroup.get_secret_value(
                access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                secret_type=SecretsGroupSecretTypeChoices.TYPE_AUTHKEY,
            )
            orch = Orchestrator(
                "standard-orch-use1-orch-use1.silverpeak.cloud", api_key=api_key, verify_ssl=False)
            templategroup = orch.get_template_group(
                template_group="Default Template Group")
            body = templategroup[0]
            body = self.build_template_group_body(body)
            for template in body["templates"]:
                if template["name"] == "users":
                    template["valObject"]["users"]["admin"]["password"] = new_password
            if orch.post_template_group(
                    template_group="Default Template Group", template_group_body=body):
                self.logger.info(
                    f"Successfully updated template group password on SilverPeak Orchestrator."
                )
            if orch.reset_user_password(username=self.local_user, password=new_password, repeat_password=new_password, two_factor_email=True, two_factor_app=False):
                self.logger.info(
                    f"Password changed successfully on SilverPeak Orchestrator."
                )
            else:
                self.logger.error(
                    f"Failed to change password on SilverPeak Orchestrator."
                )
        except Exception as e:
            self.logger.error(
                f"Failed to change password on SilverPeak Orchestrator. Error: {str(e)}"
            )

    def change_infoblox_password(self, device, new_password):
        # Placeholder for the logic to change the password on an Infoblox device
        self.logger.info(
            f"Changing password on Infoblox device {device.name}.")
        # Implement the actual password change logic here
        try:
            params = {"name": self.local_user}
            response = requests.get(
                url=f"https://{device.primary_ip4.host}/wapi/v2.10/adminuser",
                auth=(self.user, self.password),
                params=params,
                verify=False,
            )
            if response.status_code == 200:
                objref = response.json()[0].get("_ref", None)
                if objref:
                    response = requests.put(
                        url=f"https://{device.primary_ip4.host}/wapi/v2.10/{objref}",
                        auth=(self.user, self.password),
                        json={"password": new_password},
                        verify=False,
                    )
                    if response.status_code == 200:
                        self.logger.info(
                            f"Password changed successfully on Infoblox device {device.name}."
                        )
                    else:
                        self.logger.error(
                            f"Failed to change password on Infoblox device {device.name}. Status code: {response.status_code}"
                        )
                        self.logger.error(f"Error: {response.text}")
        except Exception as e:
            self.logger.error(
                f"Failed to change password on Infoblox device {device.name}. Error: {str(e)}"
            )

    def get_vault_token(self):
        """
        Retrieve the Vault token from the Nautobot secrets group.

        Returns:
            str: The Vault token
        """
        vault = ExternalIntegration.objects.get(name="Vault")
        role_id = vault.secrets_group.get_secret_value(
            access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
            secret_type=SecretsGroupSecretTypeChoices.TYPE_USERNAME,
        )
        secret_id = vault.secrets_group.get_secret_value(
            access_type=SecretsGroupAccessTypeChoices.TYPE_GENERIC,
            secret_type=SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
        )
        payload = {
            "role_id": role_id,
            "secret_id": secret_id,
        }
        response = requests.post(
            url=f"{vault.remote_url}/v1/auth/approle/login",
            verify=vault.verify_ssl,
            json=payload,
        )
        if response.status_code == 200:
            self.vault_token = response.json().get("auth", {}).get("client_token")
            self.vault_token_expiration = datetime.now() + timedelta(
                seconds=response.json().get("auth", {}).get("lease_duration")
            )
        else:
            self.logger.error(
                f"Failed to retrieve Vault token. Status code: {response.status_code}, Error: {response.text}"
            )

    def get_password_from_vault(self):
        """
        Retrieve the password from Hashicorp Vault using KV v2 secrets engine.

        Returns:
            str: The password retrieved from vault
        """
        vault = ExternalIntegration.objects.get(name="Vault")

        if not self.vault_token or datetime.now() > self.vault_token_expiration:
            self.get_vault_token()
        # API endpoint for KV v2 secret
        url = f"{vault.remote_url}{vault.extra_config['password_change']['api_path']}"

        # Request headers
        headers = {
            "X-Vault-Token": self.vault_token,
            "Content-Type": "application/json",
        }

        try:
            # GET request to retrieve the secret
            response = requests.get(
                url,
                headers=headers,
                verify=vault.verify_ssl,  # Consider setting to True in production
            )

            if response.status_code == 200:
                self.local_password = (
                    response.json().get("data", {}).get("data", {}).get("password")
                )
                self.local_user = (
                    response.json().get("data", {}).get("data", {}).get("username")
                )

            else:
                self.logger.error(
                    f"Failed to retrieve password from vault. Status code: {response.status_code}"
                )
                self.logger.error(f"Error: {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error connecting to vault: {str(e)}")
            raise

    def save_password_to_vault(self, new_password):
        """
        Save new password to Hashicorp Vault using KV v2 secrets engine.

        Args:
            new_password (str): The new password to store in vault
        """
        vault = ExternalIntegration.objects.get(name="Vault")
        if not self.vault_token or datetime.now() > self.vault_token_expiration:
            self.get_vault_token()
        # API endpoint for KV v2 secret
        url = f"{vault.remote_url}{vault.extra_config['password_change']['api_path']}"

        # Request headers
        headers = {
            "X-Vault-Token": self.vault_token,
            "Content-Type": "application/json",
        }

        # Request payload - KV v2 requires data to be nested under 'data' key
        payload = {"data": {"password": new_password}}

        try:
            # POST request to create new version of secret
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                verify=vault.verify_ssl,  # Consider setting to True in production
            )

            if response.status_code == 200:
                self.logger.info("Successfully saved new password to vault.")
            else:
                self.logger.error(
                    f"Failed to save password to vault. Status code: {response.status_code}"
                )
                self.logger.error(f"Error: {response.text}")

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error connecting to vault: {str(e)}")
            raise

    def get_nxos_type5_hash(self, password: str, salt: str) -> str:
        """Generate NXOS Type 5 hash using SHA256.

        Args:
            password (str): Password to hash
            salt (str): Salt for hashing
        Returns:
            str: Generated hash
        """
        hash = sha256_crypt.using(salt=salt, rounds=5000).hash(password)
        return hash


register_jobs(ChangePasswords)
