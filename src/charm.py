#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import logging
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple

import hcl
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v2 import snap
from charms.tls_certificates_interface.v3.tls_certificates import (
    CertificateAvailableEvent,
    TLSCertificatesRequiresV3,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    Vault,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_tls import (
    File,
    VaultTLSManager,
)
from cryptography import x509
from jinja2 import Environment, FileSystemLoader
from machine import Machine
from ops import ActionEvent, BlockedStatus, ErrorStatus, Secret, SecretNotFoundError
from ops.charm import CharmBase, CollectStatusEvent, RelationJoinedEvent
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, ModelError, WaitingStatus

logger = logging.getLogger(__name__)

CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
MACHINE_TLS_FILE_DIRECTORY_PATH = "/var/snap/vault/common/certs"
PEER_RELATION_NAME = "vault-peers"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
VAULT_PKI_CSR_SECRET_LABEL = "pki-csr"
VAULT_CHARM_POLICY_NAME = "charm-access"
VAULT_CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
VAULT_CLUSTER_PORT = 8201
VAULT_CONFIG_FILE_NAME = "vault.hcl"
VAULT_CONFIG_PATH = "/var/snap/vault/common"
VAULT_DEFAULT_POLICY_NAME = "default"
VAULT_PORT = 8200
VAULT_SNAP_CHANNEL = "1.15/beta"
VAULT_SNAP_NAME = "vault"
VAULT_SNAP_REVISION = "2181"
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"
VAULT_PKI_MOUNT = "charm-pki"
VAULT_PKI_ROLE = "charm-pki"


def render_vault_config_file(
    default_lease_ttl: str,
    max_lease_ttl: str,
    cluster_address: str,
    api_address: str,
    tls_cert_file: str,
    tls_key_file: str,
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
        tls_cert_file=tls_cert_file,
        tls_key_file=tls_key_file,
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
                    "scheme": "https",
                    "metrics_path": "/v1/sys/metrics",
                    "static_configs": [{"targets": [f"*:{VAULT_PORT}"]}],
                }
            ],
        )
        self.tls = VaultTLSManager(
            charm=self,
            workload=self.machine,
            service_name=VAULT_SNAP_NAME,
            tls_directory_path=MACHINE_TLS_FILE_DIRECTORY_PATH,
        )
        self.tls_certificates_pki = TLSCertificatesRequiresV3(
            self, TLS_CERTIFICATES_PKI_RELATION_NAME
        )
        self.framework.observe(self.on.install, self._configure)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.update_status, self._configure)
        self.framework.observe(self.on.config_changed, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_created, self._configure)
        self.framework.observe(self.on[PEER_RELATION_NAME].relation_changed, self._configure)
        self.framework.observe(self.on.authorize_charm_action, self._on_authorize_charm_action)
        self.framework.observe(
            self.on.tls_certificates_pki_relation_joined,
            self._on_tls_certificates_pki_relation_joined,
        )
        self.framework.observe(
            self.tls_certificates_pki.on.certificate_available,
            self._on_tls_certificate_pki_certificate_available,
        )

    @contextmanager
    def temp_maintenance_status(self, message: str):
        """Context manager to set the charm status temporarily.

        Useful around long-running operations to indicate that the charm is
        busy.
        """
        previous_status = self.unit.status
        self.unit.status = MaintenanceStatus(message)
        yield
        self.unit.status = previous_status

    def _on_authorize_charm_action(self, event: ActionEvent):
        """Authorize the charm to interact with Vault."""
        if not self.unit.is_leader():
            event.fail("This action can only be run by the leader unit")
            return
        logger.info("Authorizing the charm to interact with Vault")
        if not self._api_address:
            event.fail("API address is not available.")
            return
        if not self.tls.tls_file_available_in_charm(File.CA):
            event.fail("CA certificate is not available in the charm. Something is wrong.")
            return
        token = event.params["token"]
        vault = self._get_vault_client()
        if not vault:
            event.fail("Failed to initialize the Vault client")
            return
        vault.authenticate(Token(token))
        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.configure_policy(
                policy_name=VAULT_CHARM_POLICY_NAME, policy_path=VAULT_CHARM_POLICY_PATH
            )
            role_id = vault.configure_approle(
                role_name="charm",
                policies=[VAULT_CHARM_POLICY_NAME, VAULT_DEFAULT_POLICY_NAME],
            )
            vault_secret_id = vault.generate_role_secret_id(name="charm")
            self._create_approle_secret(role_id, vault_secret_id)
        except VaultClientError as e:
            logger.exception("Vault returned an error while authorizing the charm")
            event.fail(f"Vault returned an error while authorizing the charm: {str(e)}")
            return

    def _create_approle_secret(self, role_id: str, secret_id: str) -> Secret:
        secret_content = {"role-id": role_id, "secret-id": secret_id}
        try:
            secret = self.model.get_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)
        except SecretNotFoundError:
            # The secret doesn't exist yet, so we can continue like normal.
            return self.app.add_secret(
                secret_content,
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
            )

        # The secret already exists, so we will update it and log a warning.
        logger.warning(
            f"Secret with label `{VAULT_CHARM_APPROLE_SECRET_LABEL}` already exists. Is the charm already authorized?"
        )
        secret.set_content(secret_content)
        return secret

    def _get_vault_client(self) -> Vault | None:
        if not self._api_address:
            return None
        if not self.tls.tls_file_available_in_charm(File.CA):
            return None
        return Vault(
            url=self._api_address,
            ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
        )

    def _on_collect_status(self, event: CollectStatusEvent):  # noqa: C901
        """Handle the collect status event."""
        if not self._is_peer_relation_created():
            event.add_status(WaitingStatus("Waiting for peer relation"))
            return
        if not self._bind_address:
            event.add_status(WaitingStatus("Waiting for bind address"))
            return
        if not self.unit.is_leader() and len(self._other_peer_node_api_addresses()) == 0:
            event.add_status(WaitingStatus("Waiting for other units to provide their addresses"))
            return
        if not self.tls.tls_file_pushed_to_workload(File.CA):
            event.add_status(WaitingStatus("Waiting for CA certificate in workload"))
            return
        if not self._api_address:
            event.add_status(WaitingStatus("No address received from Juju yet"))
            return
        if not self.tls.tls_file_available_in_charm(File.CA):
            event.add_status(WaitingStatus("Certificate is unavailable in the charm"))
            return
        if not self._is_vault_service_started():
            event.add_status(WaitingStatus("Waiting for Vault service to start"))
            return
        vault = self._get_vault_client()
        if not vault:
            event.add_status(ErrorStatus("Failed to initialize the Vault client"))
            return
        if not vault.is_api_available():
            event.add_status(WaitingStatus("Vault API is not yet available"))
            return
        if not vault.is_initialized():
            event.add_status(BlockedStatus("Waiting for Vault to be initialized"))
            return
        if vault.is_sealed():
            event.add_status(BlockedStatus("Waiting for Vault to be unsealed"))
            return
        if not self._get_vault_approle_secret():
            event.add_status(
                BlockedStatus("Waiting for charm to be authorized (see `authorize-charm` action)")
            )
            return
        event.add_status(ActiveStatus())

    def _configure(self, _):  # noqa: C901
        """Handle Vault installation.

        This includes:
          - Installing the Vault snap
          - Generating the Vault config file
        """
        self._create_backend_directory()
        self._create_certs_directory()
        self._install_vault_snap()
        if not self._is_peer_relation_created():
            return
        if not self._bind_address:
            return
        if not self.unit.is_leader():
            if len(self._other_peer_node_api_addresses()) == 0:
                return
            if not self.tls.ca_certificate_is_saved():
                return
        self.tls.configure_certificates(self._bind_address)
        self._generate_vault_config_file()
        self._start_vault_service()
        self._set_peer_relation_node_api_address()
        self._configure_pki_secrets_engine()
        self._add_intermediate_ca_certificate_to_pki_secrets_engine()
        self.tls.send_ca_cert()

        if not self._api_address or not self.tls.tls_file_available_in_charm(File.CA):
            return
        vault = self._get_vault_client()
        if (
            not vault
            or not vault.is_api_available()
            or not vault.is_initialized()
            or vault.is_sealed()
        ):
            return
        if not (approle_auth := self._get_vault_approle_secret()):
            return
        vault.authenticate(AppRole(approle_auth[0], approle_auth[1]))

        if vault.is_active() and not vault.is_raft_cluster_healthy():
            logger.warning("Raft cluster is not healthy: %s", vault.get_raft_cluster_state())

    def _on_tls_certificates_pki_relation_joined(self, _: RelationJoinedEvent) -> None:
        """Handle the tls-certificates-pki relation joined event."""
        self._configure_pki_secrets_engine()

    def _on_tls_certificate_pki_certificate_available(self, _: CertificateAvailableEvent):
        """Handle the tls-certificates-pki certificate available event."""
        self._add_intermediate_ca_certificate_to_pki_secrets_engine()

    def _configure_pki_secrets_engine(self) -> None:
        """Configure the PKI secrets engine."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request, skipping")
            return
        vault = self._get_vault_client()
        if (
            not vault
            or not vault.is_api_available()
            or not vault.is_initialized()
            or vault.is_sealed()
        ):
            logger.debug("Vault is not ready to handle a vault-pki certificate request, skipping")
            return
        if not (approle_auth := self._get_vault_approle_secret()):
            return
        vault.authenticate(AppRole(approle_auth[0], approle_auth[1]))
        if not self._tls_certificates_pki_relation_created():
            logger.debug("TLS Certificates PKI relation not created, skipping")
            return
        if not self._common_name_config_is_valid():
            logger.debug("Common name config is not valid, skipping")
            return
        common_name = self._get_config_common_name()
        vault.enable_secrets_engine(SecretsBackend.PKI, VAULT_PKI_MOUNT)
        if not self._is_intermediate_ca_set(vault, common_name):
            csr = vault.generate_pki_intermediate_ca_csr(mount=VAULT_PKI_MOUNT, common_name=common_name)
            self.tls_certificates_pki.request_certificate_creation(
                certificate_signing_request=csr.encode(),
                is_ca=True,
            )
            self._set_pki_csr_secret(csr)

    def _is_intermediate_ca_set(self, vault: Vault, common_name: str) -> bool:
        """Check if the intermediate CA is set in the PKI secrets engine."""
        intermediate_ca = vault.get_intermediate_ca(mount=VAULT_PKI_MOUNT)
        if not intermediate_ca:
            return False
        intermediate_ca_common_name = get_common_name_from_certificate(intermediate_ca)
        return intermediate_ca_common_name == common_name

    def _add_intermediate_ca_certificate_to_pki_secrets_engine(self) -> None:
        """Add the CA certificate to the PKI secrets engine."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request")
            return
        vault = self._get_vault_client()
        if (
            not vault
            or not vault.is_api_available()
            or not vault.is_initialized()
            or vault.is_sealed()
        ):
            logger.debug("Vault is not ready to handle a vault-pki certificate request")
            return
        if not (approle_auth := self._get_vault_approle_secret()):
            return
        vault.authenticate(AppRole(approle_auth[0], approle_auth[1]))
        common_name = self._get_config_common_name()
        if not common_name:
            logger.error("Common name is not set in the charm config")
            return
        certificate = self._get_pki_intermediate_ca_certificate()
        if not certificate:
            logger.debug("No certificate available")
            return
        if not vault.is_intermediate_ca_set(mount=VAULT_PKI_MOUNT, certificate=certificate):
            vault.set_pki_intermediate_ca_certificate(certificate=certificate, mount=VAULT_PKI_MOUNT)
        if not vault.is_pki_role_created(role=VAULT_PKI_ROLE, mount=VAULT_PKI_MOUNT):
            vault.create_pki_charm_role(
                allowed_domains=common_name,
                mount=VAULT_PKI_MOUNT,
                role=VAULT_PKI_ROLE,
            )

    def _get_pki_intermediate_ca_certificate(self) -> Optional[str]:
        """Return the PKI CA certificate provided by the TLS provider.

        Validate that the CSR matches the one in secrets.
        """
        assigned_certificates = self.tls_certificates_pki.get_assigned_certificates()
        if not assigned_certificates:
            return None
        if not self._pki_csr_secret_set():
            logger.info("PKI CSR not set in secrets")
            return None
        pki_csr = self._get_pki_csr_secret()
        if not pki_csr:
            logger.warning("PKI CSR not found in secrets")
            return None
        for assigned_certificate in assigned_certificates:
            if assigned_certificate.csr == pki_csr:
                return assigned_certificate.certificate
        logger.info("No certificate matches the PKI CSR in secrets")
        return None

    def _set_pki_csr_secret(self, csr: str) -> None:
        """Set the PKI CSR secret."""
        juju_secret_content = {"csr": csr}
        if not self._pki_csr_secret_set():
            self.app.add_secret(juju_secret_content, label=VAULT_PKI_CSR_SECRET_LABEL)
            return
        secret = self.model.get_secret(label=VAULT_PKI_CSR_SECRET_LABEL)
        secret.set_content(content=juju_secret_content)

    def _get_pki_csr_secret(self) -> Optional[str]:
        """Return the PKI CSR secret."""
        if not self._pki_csr_secret_set():
            raise RuntimeError("PKI CSR secret not set.")
        secret = self.model.get_secret(label=VAULT_PKI_CSR_SECRET_LABEL)
        return secret.get_content()["csr"]

    def _pki_csr_secret_set(self) -> bool:
        """Return whether PKI CSR secret is stored."""
        try:
            self.model.get_secret(label=VAULT_PKI_CSR_SECRET_LABEL)
            return True
        except SecretNotFoundError:
            return False

    def _get_config_common_name(self) -> str:
        """Return the common name to use for the PKI backend."""
        return self.config.get("common_name", "")

    def _common_name_config_is_valid(self) -> bool:
        """Return whether the config value for the common name is valid."""
        common_name = self._get_config_common_name()
        return common_name != ""

    def _tls_certificates_pki_relation_created(self) -> bool:
        """Check if the TLS Certificates PKI relation is created."""
        return self._is_relation_created(TLS_CERTIFICATES_PKI_RELATION_NAME)

    def _is_relation_created(self, relation_name: str) -> bool:
        """Check if the relation is created.

        Args:
            relation_name: Checked relation name
        """
        return bool(self.model.get_relation(relation_name))

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
            with self.temp_maintenance_status("Installing Vault"):
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

    def _create_certs_directory(self) -> None:
        self.machine.make_dir(path=MACHINE_TLS_FILE_DIRECTORY_PATH)

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
                "leader_ca_cert_file": f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.CA.name.lower()}.pem",
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]
        content = render_vault_config_file(
            default_lease_ttl=self.model.config["default_lease_ttl"],
            max_lease_ttl=self.model.config["max_lease_ttl"],
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tls_cert_file=f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.CERT.name.lower()}.pem",
            tls_key_file=f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.KEY.name.lower()}.pem",
            tcp_address=f"[::]:{VAULT_PORT}",
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
        )
        existing_content = ""
        vault_config_file_path = f"{VAULT_CONFIG_PATH}/{VAULT_CONFIG_FILE_NAME}"
        if self.machine.exists(path=vault_config_file_path):
            existing_content_stringio = self.machine.pull(path=vault_config_file_path)
            existing_content = existing_content_stringio.read()

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

    def _is_vault_service_started(self) -> bool:
        """Check if the Vault service is started."""
        snap_cache = snap.SnapCache()
        vault_snap = snap_cache[VAULT_SNAP_NAME]
        vault_services = vault_snap.services
        vaultd_service = vault_services.get("vaultd")
        if not vaultd_service:
            return False
        if not vaultd_service["active"]:
            return False
        return True

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
        """Returns the IP with the https schema and vault port.

        Example: "https://1.2.3.4:8200"
        """
        if not self._bind_address:
            return None
        return f"https://{self._bind_address}:{VAULT_PORT}"

    @property
    def _cluster_address(self) -> Optional[str]:
        """Return the IP with the https schema and vault port.

        Example: "https://1.2.3.4:8201"
        """
        if not self._bind_address:
            return None
        return f"https://{self._bind_address}:{VAULT_CLUSTER_PORT}"

    @property
    def _node_id(self) -> str:
        """Return node id for vault.

        Example of node id: "vault-0"
        """
        return f"{self.model.name}-{self.unit.name}"

def get_common_name_from_certificate(certificate: str) -> str:
    """Get the common name from a certificate."""
    loaded_certificate = x509.load_pem_x509_certificate(certificate.encode("utf-8"))
    return str(
        loaded_certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value  # type: ignore[reportAttributeAccessIssue]
    )

if __name__ == "__main__":  # pragma: nocover
    main(VaultOperatorCharm)
