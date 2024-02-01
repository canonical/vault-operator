#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import logging
from typing import Dict, List, Optional, Tuple

import hcl  # type: ignore[import-untyped]
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v2 import snap
from charms.vault_k8s.v0.vault_client import Vault
from jinja2 import Environment, FileSystemLoader
from machine import Machine
from ops import ActionEvent, BlockedStatus, SecretNotFoundError
from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, ModelError, WaitingStatus

logger = logging.getLogger(__name__)

CHARM_POLICY_NAME = "charm-access"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
PEER_RELATION_NAME = "vault-peers"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
VAULT_CONFIG_PATH = "/var/snap/vault/common"
VAULT_CONFIG_FILE_NAME = "vault.hcl"
VAULT_PORT = 8200
VAULT_CLUSTER_PORT = 8201
VAULT_SNAP_NAME = "vault"
VAULT_SNAP_CHANNEL = "1.15/beta"
VAULT_SNAP_REVISION = "2181"
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"


def render_vault_config_file(
    default_lease_ttl: str,
    max_lease_ttl: str,
    cluster_address: str,
    api_address: str,
    tcp_address: str,
    raft_storage_path: str,
    node_id: str,
    retry_joins: List[Dict[str, str]],
) -> str:
    """Render the Vault config file."""
    jinja2_environment = Environment(loader=FileSystemLoader(CONFIG_TEMPLATE_DIR_PATH))
    template = jinja2_environment.get_template(CONFIG_TEMPLATE_NAME)
    content = template.render(
        default_lease_ttl=default_lease_ttl,
        max_lease_ttl=max_lease_ttl,
        cluster_address=cluster_address,
        api_address=api_address,
        tcp_address=tcp_address,
        raft_storage_path=raft_storage_path,
        node_id=node_id,
        retry_joins=retry_joins,
    )
    return content


def config_file_content_matches(existing_content: str, new_content: str) -> bool:
    """Return whether two Vault config file contents match.

    We check if the retry_join addresses match, and then we check if the rest of the config
    file matches.

    Returns:
        bool: Whether the vault config file content matches
    """
    existing_config_hcl = hcl.loads(existing_content)
    new_content_hcl = hcl.loads(new_content)
    if not existing_config_hcl:
        logger.info("Existing config file is empty")
        return existing_config_hcl == new_content_hcl
    if not new_content_hcl:
        logger.info("New config file is empty")
        return existing_config_hcl == new_content_hcl

    new_retry_joins = new_content_hcl["storage"]["raft"].pop("retry_join", [])

    try:
        existing_retry_joins = existing_config_hcl["storage"]["raft"].pop("retry_join", [])
    except KeyError:
        existing_retry_joins = []

    # If there is only one retry join, it is a dict
    if isinstance(new_retry_joins, dict):
        new_retry_joins = [new_retry_joins]
    if isinstance(existing_retry_joins, dict):
        existing_retry_joins = [existing_retry_joins]

    new_retry_join_api_addresses = {address["leader_api_addr"] for address in new_retry_joins}
    existing_retry_join_api_addresses = {
        address["leader_api_addr"] for address in existing_retry_joins
    }
    return (
        new_retry_join_api_addresses == existing_retry_join_api_addresses
        and new_content_hcl == existing_config_hcl
    )


class VaultOperatorCharm(CharmBase):
    """Machine Charm for Vault."""

    def __init__(self, *args):
        super().__init__(*args)
        self.machine = Machine()
        self._cos_agent = COSAgentProvider(
            self,
            scrape_configs=[
                {
                    "scheme": "http",
                    "tls_config": {"insecure_skip_verify": True},
                    "metrics_path": "/v1/sys/metrics",
                    "static_configs": [{"targets": [f"*:{VAULT_PORT}"]}],
                }
            ],
        )
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_created, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_changed, self._configure)
        self.framework.observe(self.on.authorize_charm_action, self._on_authorize_charm_action)

    def _on_authorize_charm_action(self, event: ActionEvent):
        """Authorize the charm to interact with Vault."""
        if not self.unit.is_leader():
            event.fail("This action can only be run by the leader unit")
            return
        logger.info("Authorizing the charm to interact with Vault")
        if not self._api_address:
            event.fail("API address is not available. Something is wrong.")
            return
        token = event.params["token"]
        vault = Vault(url=self._api_address, ca_cert_path=False)
        vault.set_token(token)
        vault.enable_audit_device(device_type="file", path="stdout")
        vault.enable_approle_auth()
        vault.configure_charm_access_policy(name=CHARM_POLICY_NAME)
        cidrs = [f"{self._bind_address}/24"]
        role_id = vault.configure_approle(
            name="charm",
            cidrs=cidrs,
            policies=[CHARM_POLICY_NAME],
        )
        vault_secret_id = vault.generate_role_secret_id(name="charm", cidrs=cidrs)
        self._create_approle_secret(role_id, vault_secret_id)
        self.on.config_changed.emit()

    def _create_approle_secret(self, role_id, secret_id):
        secret = self.app.add_secret(
            {"role-id": role_id, "secret-id": secret_id},
            label=VAULT_CHARM_APPROLE_SECRET_LABEL,
        )
        assert (
            secret and secret.id
        ), f"Unexpected error while attempting to create secret {VAULT_CHARM_APPROLE_SECRET_LABEL}"
        return secret

    @property
    def _ingress_address(self) -> Optional[str]:
        """Fetch ingress address from peer relation and return it.

        Returns:
            str: Ingress address
        """
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not peer_relation:
            return None
        try:
            binding = self.model.get_binding(peer_relation)
            if not binding or not binding.network.ingress_address:
                return None
            return str(binding.network.ingress_address)
        except ModelError:
            return None

    def _configure(self, _):
        """Handle Vault installation.

        This includes:
          - Installing the Vault snap
          - Generating the Vault config file
        """
        if not self._is_peer_relation_created():
            self.unit.status = WaitingStatus("Waiting for peer relation")
            return
        if not self._bind_address:
            self.unit.status = WaitingStatus("Waiting for bind address")
            return
        if not self.unit.is_leader() and len(self._other_peer_node_api_addresses()) == 0:
            self.unit.status = WaitingStatus("Waiting for other units to provide their addresses")
            return
        self._install_vault_snap()
        self._create_backend_directory()
        self._generate_vault_config_file()
        self._start_vault_service()
        self._set_peer_relation_node_api_address()

        if not self._api_address:
            self.unit.status = WaitingStatus("Expected API address to be available")
            return
        vault = Vault(url=self._api_address, ca_cert_path=False)
        if not vault.is_api_available():
            self.unit.status = WaitingStatus("Waiting for Vault to be available")
            return
        if not vault.is_initialized():
            self.unit.status = BlockedStatus("Waiting for Vault to be initialized")
            return
        if vault.is_sealed():
            self.unit.status = BlockedStatus("Waiting for Vault to be unsealed")
            return
        if not (approle_details := self._get_vault_approle_secret()):
            self.unit.status = BlockedStatus("Waiting for charm to be authorized")
            return
        vault.authenticate(
            method="approle",
            details={"role-id": approle_details[0], "secret-id": approle_details[1]},
        )

        if vault.is_active() and not vault.is_raft_cluster_healthy():
            logger.warning("Raft cluster is not healthy: %s", vault.get_raft_cluster_state())

        self.unit.status = ActiveStatus()

    def _get_authorized_vault_client(self) -> Optional[Vault]:
        """Return an initialized vault client.

        Creates a Vault client and returns it if:
            - Vault is initialized
            - Vault API is available
            - Vault is unsealed
        Otherwise, returns None.

        Returns:
            Vault: Vault client
        """
        if not self._api_address:
            return None
        vault = Vault(url=self._api_address, ca_cert_path=False)
        if not vault.is_initialized():
            logger.error("Vault is not initialized.")
            return None
        if not vault.is_api_available():
            logger.error("Vault API is not available.")
            return None
        if not (approle_auth := self._get_vault_approle_secret()):
            logger.error("Charm not authorized yet.")
            return None
        vault.authenticate(
            method="approle",
            details={"role-id": approle_auth[0], "secret-id": approle_auth[1]},
        )
        return vault

    def _get_vault_approle_secret(self) -> Optional[Tuple[str, str]]:
        """Get the approle secret."""
        try:
            secret = self.model.get_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
        except SecretNotFoundError:
            return None
        content = secret.peek_content()
        if not (role_id := content.get("role-id")) or not (secret_id := content.get("secret-id")):
            return None
        return (role_id, secret_id)

    def _install_vault_snap(self) -> None:
        """Installs the Vault snap in the machine."""
        try:
            snap_cache = snap.SnapCache()
            vault_snap = snap_cache[VAULT_SNAP_NAME]
            if vault_snap.latest:
                return
            self.unit.status = MaintenanceStatus("Installing Vault")
            vault_snap.ensure(
                snap.SnapState.Latest, channel=VAULT_SNAP_CHANNEL, revision=VAULT_SNAP_REVISION
            )
            vault_snap.hold()
            logger.info("Vault snap installed")
        except snap.SnapError as e:
            logger.error("An exception occurred when installing Vault. Reason: %s", str(e))
            raise e

    def _create_backend_directory(self) -> None:
        self.machine.make_dir(path=VAULT_STORAGE_PATH)

    def _start_vault_service(self) -> None:
        """Start the Vault service."""
        snap_cache = snap.SnapCache()
        vault_snap = snap_cache[VAULT_SNAP_NAME]
        vault_snap.start(services=["vaultd"])
        logger.debug("Vault service started")

    def _generate_vault_config_file(self) -> None:
        """Create the Vault config file and push it to the Machine."""
        assert self._cluster_address
        assert self._api_address
        retry_joins = [
            {
                "leader_api_addr": node_api_address,
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]
        content = render_vault_config_file(
            default_lease_ttl=self.model.config["default_lease_ttl"],
            max_lease_ttl=self.model.config["max_lease_ttl"],
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tcp_address=f"[::]:{VAULT_PORT}",
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
        )
        existing_content = ""
        vault_config_file_path = f"{VAULT_CONFIG_PATH}/{VAULT_CONFIG_FILE_NAME}"
        if self.machine.exists(path=vault_config_file_path):
            existing_content = self.machine.pull(path=vault_config_file_path)

        if not config_file_content_matches(existing_content=existing_content, new_content=content):
            self.machine.push(
                path=vault_config_file_path,
                source=content,
            )

    def _is_peer_relation_created(self) -> bool:
        """Check if the peer relation is created."""
        return bool(self.model.get_relation(PEER_RELATION_NAME))

    def _set_peer_relation_node_api_address(self) -> None:
        """Set the unit address in the peer relation."""
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        assert peer_relation
        assert self._api_address
        peer_relation.data[self.unit].update({"node_api_address": self._api_address})

    def _get_peer_relation_node_api_addresses(self) -> List[str]:
        """Return the list of peer unit addresses."""
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        node_api_addresses = []
        if not peer_relation:
            return []
        for peer in peer_relation.units:
            if "node_api_address" in peer_relation.data[peer]:
                node_api_addresses.append(peer_relation.data[peer]["node_api_address"])
        return node_api_addresses

    def _other_peer_node_api_addresses(self) -> List[str]:
        """Return the list of other peer unit addresses.

        We exclude our own unit address from the list.
        """
        return [
            node_api_address
            for node_api_address in self._get_peer_relation_node_api_addresses()
            if node_api_address != self._api_address
        ]

    @property
    def _bind_address(self) -> Optional[str]:
        """Fetches bind address from peer relation and returns it.

        Returns:
            str: Bind address
        """
        peer_relation = self.model.get_relation(PEER_RELATION_NAME)
        if not peer_relation:
            return None
        try:
            binding = self.model.get_binding(peer_relation)
            if not binding or not binding.network.bind_address:
                return None
            return str(binding.network.bind_address)
        except ModelError:
            return None

    @property
    def _api_address(self) -> Optional[str]:
        """Returns the IP with the http schema and vault port.

        Example: "http://1.2.3.4:8200"
        """
        if not self._bind_address:
            return None
        # TODO: Should this be the fqdn?
        return f"http://{self._bind_address}:{VAULT_PORT}"

    @property
    def _cluster_address(self) -> Optional[str]:
        """Return the IP with the http schema and vault port.

        Example: "http://1.2.3.4:8201"
        """
        if not self._bind_address:
            return None
        return f"http://{self._bind_address}:{VAULT_CLUSTER_PORT}"

    @property
    def _node_id(self) -> str:
        """Return node id for vault.

        Example of node id: "vault-0"
        """
        return f"{self.model.name}-{self.unit.name}"


if __name__ == "__main__":  # pragma: nocover
    main(VaultOperatorCharm)
