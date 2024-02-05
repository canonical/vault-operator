#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import logging
from typing import Dict, List, Optional, Tuple

import hcl  # type: ignore[import-untyped]
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v1 import snap
from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_ca,
    generate_private_key,
    generate_csr,
    generate_certificate,
)
from jinja2 import Environment, FileSystemLoader
from machine import Machine
from ops.charm import CharmBase
from ops.main import main
from ops.model import (
    ActiveStatus,
    ModelError,
    SecretNotFoundError,
    WaitingStatus,
)

logger = logging.getLogger(__name__)

CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
PEER_RELATION_NAME = "vault-peers"
VAULT_CONFIG_PATH = "/var/snap/vault/common"
VAULT_CONFIG_FILE_NAME = "vault.hcl"
VAULT_PORT = 8200
VAULT_CLUSTER_PORT = 8201
VAULT_SNAP_NAME = "vault"
VAULT_SNAP_CHANNEL = "1.15/beta"
VAULT_SNAP_REVISION = 2181
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"
TLS_DIR_PATH = "/var/snap/vault/common/certs"
TLS_CERT_FILE_PATH = "/var/snap/vault/common/certs/cert.pem"
TLS_KEY_FILE_PATH = "/var/snap/vault/common/certs/key.pem"
TLS_CA_FILE_PATH = "/var/snap/vault/common/certs/ca.pem"
CA_CERTIFICATE_JUJU_SECRET_LABEL = "vault-ca-certificate"
VAULT_CA_SUBJECT = "Vault self signed CA"


def generate_vault_ca_certificate() -> Tuple[str, str]:
    """Generate Vault CA certificates valid for 50 years.

    Returns:
        Tuple[str, str]: CA Private key, CA certificate
    """
    ca_private_key = generate_private_key()
    ca_certificate = generate_ca(
        private_key=ca_private_key,
        subject=VAULT_CA_SUBJECT,
        validity=365 * 50,
    )

    return ca_private_key.decode(), ca_certificate.decode()


def generate_vault_unit_certificate(
    subject: str,
    sans_ip: List[str],
    sans_dns: List[str],
    ca_certificate: bytes,
    ca_private_key: bytes,
) -> Tuple[str, str]:
    """Generate Vault unit certificates valid for 50 years.

    Args:
        subject: Subject of the certificate
        sans_ip: List of IP addresses to add to the SAN
        sans_dns: List of DNS subject alternative names
        ca_certificate: CA certificate
        ca_private_key: CA private key

    Returns:
        Tuple[str, str]: Unit private key, Unit certificate
    """
    vault_private_key = generate_private_key()
    csr = generate_csr(
        private_key=vault_private_key, subject=subject, sans_ip=sans_ip, sans_dns=sans_dns
    )
    vault_certificate = generate_certificate(
        ca=ca_certificate,
        ca_key=ca_private_key,
        csr=csr,
        validity=365 * 50,
    )
    return vault_private_key.decode(), vault_certificate.decode()


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


class PeerSecretError(Exception):
    """Exception raised when a peer secret is not found."""

    def __init__(
        self, secret_name: str, message: str = "Could not retrieve secret from peer relation"
    ):
        self.secret_name = secret_name
        self.message = message
        super().__init__(self.message)


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
        if not self.unit.is_leader() and not self._ca_certificate_secret_is_set():
            self.unit.status = WaitingStatus(
                "Waiting for CA certificate to be set in peer relation"
            )
            return
        self._install_vault_snap()
        self._create_backend_directory()
        self._create_certs_directory()
        self._configure_certificates()
        self._generate_vault_config_file()
        self._start_vault_service()
        self._set_peer_relation_node_api_address()
        self.unit.status = ActiveStatus()

    def _install_vault_snap(self) -> None:
        """Installs the Vault snap in the machine."""
        try:
            snap_cache = snap.SnapCache()
            vault_snap = snap_cache[VAULT_SNAP_NAME]
            vault_snap.ensure(
                snap.SnapState.Latest, channel=VAULT_SNAP_CHANNEL, revision=VAULT_SNAP_REVISION
            )
            vault_snap.hold()
            logger.info("Vault snap installed")
        except snap.SnapError as e:
            logger.error("An exception occurred when installing Vault. Reason: %s", str(e))
            raise e

    def _configure_certificates(self) -> None:
        if not self._ca_certificate_secret_is_set() and self.unit.is_leader():
            ca_private_key, ca_certificate = generate_vault_ca_certificate()
            self._set_ca_certificate_secret(private_key=ca_private_key, certificate=ca_certificate)
            self._push_ca_certificate_to_workload(certificate=ca_certificate)
        else:
            ca_private_key, ca_certificate = self._get_ca_certificate_secret()
        if not self._unit_certificate_pushed_to_workload():
            sans_ip = [self._bind_address]
            private_key, certificate = generate_vault_unit_certificate(
                subject=self._bind_address,  # type: ignore[arg-type]
                sans_ip=sans_ip,  # type: ignore[arg-type]
                sans_dns=[self._bind_address],  # type: ignore[list-item]
                ca_certificate=ca_certificate.encode(),
                ca_private_key=ca_private_key.encode(),
            )
            self._push_unit_certificate_to_workload(
                certificate=certificate, private_key=private_key
            )

    def _create_backend_directory(self) -> None:
        self.machine.make_dir(path=VAULT_STORAGE_PATH)

    def _create_certs_directory(self) -> None:
        self.machine.make_dir(path=TLS_DIR_PATH)

    def _start_vault_service(self) -> None:
        """Start the Vault service."""
        snap_cache = snap.SnapCache()
        vault_snap = snap_cache[VAULT_SNAP_NAME]
        vault_snap.start(services=["vaultd"])
        logger.info("Vault service started")

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
            tls_cert_file=TLS_CERT_FILE_PATH,
            tls_key_file=TLS_KEY_FILE_PATH,
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

    def _get_ca_certificate_secret(self) -> Tuple[str, str]:
        """Get the vault CA certificate secret.

        Returns:
            Tuple[Optional[str], Optional[str]]: The CA private key and certificate
        """
        try:
            juju_secret = self.model.get_secret(label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
            content = juju_secret.get_content()
            return content["privatekey"], content["certificate"]
        except (TypeError, SecretNotFoundError, AttributeError):
            raise PeerSecretError(secret_name=CA_CERTIFICATE_JUJU_SECRET_LABEL)

    def _ca_certificate_secret_is_set(self) -> bool:
        """Returns whether CA certificate is stored."""
        try:
            ca_private_key, ca_certificate = self._get_ca_certificate_secret()
            if ca_private_key and ca_certificate:
                return True
        except PeerSecretError:
            return False
        return False

    def _set_ca_certificate_secret(
        self,
        private_key: str,
        certificate: str,
    ) -> None:
        """Set the value of the vault CA certificate secret.

        Args:
            private_key: Private key
            certificate: certificate
        """
        juju_secret_content = {
            "privatekey": private_key,
            "certificate": certificate,
        }
        self.app.add_secret(juju_secret_content, label=CA_CERTIFICATE_JUJU_SECRET_LABEL)
        logger.info("Vault CA certificate secret set in peer relation")

    def _push_ca_certificate_to_workload(self, certificate: str) -> None:
        """Push the CA certificate to the workload.

        Args:
            certificate: CA certificate
        """
        self.machine.push(path=TLS_CA_FILE_PATH, source=certificate)
        logger.info("Pushed CA certificate to workload")

    def _push_unit_certificate_to_workload(self, private_key: str, certificate: str) -> None:
        """Push the unit certificate to the workload.

        Args:
            private_key: Private key
            certificate: Certificate
        """
        self.machine.push(path=TLS_KEY_FILE_PATH, source=private_key)
        self.machine.push(path=TLS_CERT_FILE_PATH, source=certificate)
        logger.info("Pushed unit certificate to workload")

    def _ca_certificate_pushed_to_workload(self) -> bool:
        """Returns whether CA certificate is pushed to the workload."""
        return self.machine.exists(path=TLS_CA_FILE_PATH)

    def _unit_certificate_pushed_to_workload(self) -> bool:
        """Returns whether unit certificate is pushed to the workload."""
        return self.machine.exists(path=TLS_KEY_FILE_PATH) and self.machine.exists(
            path=TLS_CERT_FILE_PATH
        )

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
