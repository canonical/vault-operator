#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


"""A machine charm for Vault."""

import json
import logging
import socket
from contextlib import contextmanager
from datetime import datetime
from typing import Dict, List, Tuple

import hcl
from charms.data_platform_libs.v0.s3 import S3Requirer
from charms.grafana_agent.v0.cos_agent import COSAgentProvider
from charms.operator_libs_linux.v2 import snap
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    ProviderCertificate,
    RequirerCertificateRequest,
    TLSCertificatesProvidesV4,
    TLSCertificatesRequiresV4,
)
from charms.vault_k8s.v0.juju_facade import (
    JujuFacade,
    NoSuchSecretError,
    SecretRemovedError,
)
from charms.vault_k8s.v0.vault_autounseal import (
    VaultAutounsealProvides,
    VaultAutounsealRequires,
)
from charms.vault_k8s.v0.vault_client import (
    AppRole,
    AuditDeviceType,
    SecretsBackend,
    Token,
    VaultClient,
    VaultClientError,
)
from charms.vault_k8s.v0.vault_kv import (
    NewVaultKvClientAttachedEvent,
    VaultKvClientDetachedEvent,
    VaultKvProvides,
)
from charms.vault_k8s.v0.vault_managers import (
    AutounsealConfigurationDetails,
    File,
    VaultAutounsealProviderManager,
    VaultAutounsealRequirerManager,
    VaultTLSManager,
)
from charms.vault_k8s.v0.vault_s3 import S3, S3Error
from jinja2 import Environment, FileSystemLoader
from ops import ActionEvent, BlockedStatus, ErrorStatus
from ops.charm import CharmBase, CollectStatusEvent, RemoveEvent
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, Relation, WaitingStatus

from machine import Machine

logger = logging.getLogger(__name__)

AUTOUNSEAL_MOUNT_PATH = "charm-autounseal"
AUTOUNSEAL_PROVIDES_RELATION_NAME = "vault-autounseal-provides"
AUTOUNSEAL_REQUIRES_RELATION_NAME = "vault-autounseal-requires"
BACKUP_KEY_PREFIX = "vault-backup"
CONFIG_TEMPLATE_DIR_PATH = "src/templates/"
CONFIG_TEMPLATE_NAME = "vault.hcl.j2"
KV_RELATION_NAME = "vault-kv"
KV_SECRET_PREFIX = "kv-creds-"
MACHINE_TLS_FILE_DIRECTORY_PATH = "/var/snap/vault/common/certs"
METRICS_ALERT_RULES_PATH = "./src/prometheus_alert_rules"
PEER_RELATION_NAME = "vault-peers"
PKI_RELATION_NAME = "vault-pki"
REQUIRED_S3_PARAMETERS = ["bucket", "access-key", "secret-key", "endpoint"]
S3_RELATION_NAME = "s3-parameters"
TLS_CERTIFICATES_PKI_RELATION_NAME = "tls-certificates-pki"
VAULT_CHARM_APPROLE_SECRET_LABEL = "vault-approle-auth-details"
VAULT_CHARM_POLICY_NAME = "charm-access"
VAULT_CHARM_POLICY_PATH = "src/templates/charm_policy.hcl"
VAULT_CLUSTER_PORT = 8201
VAULT_CONFIG_FILE_NAME = "vault.hcl"
VAULT_CONFIG_PATH = "/var/snap/vault/common"
VAULT_DEFAULT_POLICY_NAME = "default"
VAULT_PKI_MOUNT = "charm-pki"
VAULT_PKI_ROLE = "charm-pki"
VAULT_PORT = 8200
VAULT_SNAP_CHANNEL = "1.16/stable"
VAULT_SNAP_NAME = "vault"
VAULT_SNAP_REVISION = "2300"
VAULT_STORAGE_PATH = "/var/snap/vault/common/raft"


def _render_vault_config_file(
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
    autounseal_details: AutounsealConfigurationDetails | None = None,
) -> str:
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
        autounseal_address=autounseal_details.address if autounseal_details else None,
        autounseal_key_name=autounseal_details.key_name if autounseal_details else None,
        autounseal_mount_path=autounseal_details.mount_path if autounseal_details else None,
        autounseal_token=autounseal_details.token if autounseal_details else None,
        autounseal_tls_ca_cert=autounseal_details.ca_cert_path if autounseal_details else None,
    )
    return content


def _seal_types_are_different(content_a: str, content_b: str) -> bool:
    """Check if the seal type has changed between two versions of the Vault configuration file.

    Currently only checks if the transit stanza is present or not, since this
    is all we support. This function will need to be extended to support
    alternate cases if and when we support them.
    """
    config_a = hcl.loads(content_a)
    config_b = hcl.loads(content_b)
    return _contains_transit_stanza(config_a) != _contains_transit_stanza(config_b)


def _contains_transit_stanza(config: dict) -> bool:
    if "seal" in config and "transit" in config["seal"]:
        return True
    return False


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
        self.juju_facade = JujuFacade(self)
        self.machine = Machine()
        self._cos_agent = COSAgentProvider(
            self,
            refresh_events=[
                self.on[PEER_RELATION_NAME].relation_changed,
            ],
            scrape_configs=self.generate_vault_scrape_configs,
            dashboard_dirs=["./src/grafana_dashboards"],
            metrics_rules_dir=METRICS_ALERT_RULES_PATH,
        )
        self.tls = VaultTLSManager(
            charm=self,
            workload=self.machine,
            service_name=VAULT_SNAP_NAME,
            tls_directory_path=MACHINE_TLS_FILE_DIRECTORY_PATH,
            common_name=self._bind_address if self._bind_address else "",
            sans_dns=frozenset([socket.getfqdn()]),
            sans_ip=frozenset([self._bind_address] if self._bind_address else []),
        )
        self.vault_kv = VaultKvProvides(self, KV_RELATION_NAME)
        self.vault_pki = TLSCertificatesProvidesV4(
            charm=self,
            relationship_name=PKI_RELATION_NAME,
        )
        certificate_request = self._get_certificate_request()
        self.tls_certificates_pki = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name=TLS_CERTIFICATES_PKI_RELATION_NAME,
            certificate_requests=[certificate_request] if certificate_request else [],
            mode=Mode.APP,
            refresh_events=[self.on.config_changed],
        )
        self.s3_requirer = S3Requirer(self, S3_RELATION_NAME)
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)
        self.framework.observe(self.on.remove, self._on_remove)
        self.vault_autounseal_provides = VaultAutounsealProvides(
            self, AUTOUNSEAL_PROVIDES_RELATION_NAME
        )
        self.vault_autounseal_requires = VaultAutounsealRequires(
            self, AUTOUNSEAL_REQUIRES_RELATION_NAME
        )
        configure_events = [
            self.on.config_changed,
            self.on[PEER_RELATION_NAME].relation_created,
            self.on[PEER_RELATION_NAME].relation_changed,
            self.on.install,
            self.on.update_status,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_broken,
            self.vault_autounseal_requires.on.vault_autounseal_details_ready,
            self.vault_autounseal_provides.on.vault_autounseal_requirer_relation_created,
            self.vault_autounseal_requires.on.vault_autounseal_provider_relation_broken,
            self.tls_certificates_pki.on.certificate_available,
            self.on.tls_certificates_pki_relation_joined,
        ]
        for event in configure_events:
            self.framework.observe(event, self._configure)
        self.framework.observe(self.on.authorize_charm_action, self._on_authorize_charm_action)
        self.framework.observe(
            self.vault_kv.on.new_vault_kv_client_attached, self._on_new_vault_kv_client_attached
        )
        self.framework.observe(
            self.vault_kv.on.vault_kv_client_detached, self._on_vault_kv_client_detached
        )
        self.framework.observe(self.on.create_backup_action, self._on_create_backup_action)
        self.framework.observe(self.on.list_backups_action, self._on_list_backups_action)
        self.framework.observe(self.on.restore_backup_action, self._on_restore_backup_action)

    def _on_vault_kv_client_detached(self, event: VaultKvClientDetachedEvent):
        label = self._get_vault_kv_secret_label(unit_name=event.unit_name)
        self.juju_facade.remove_secret(label=label)

    def _get_active_vault_client(self) -> VaultClient | None:
        """Return an initialized vault client.

        Returns:
            Vault: An active Vault client configured with the cluster address
                   and CA certificate, and authorized with the AppRole
                   credentials set upon initial authorization of the charm, or
                   `None` if the client could not be successfully created or
                   has not been authorized.
        """
        vault = self._get_vault_client()
        if not vault:
            return None
        if not vault.is_api_available():
            return None
        approle = self._get_vault_approle_secret()
        if not approle:
            return None
        if not vault.authenticate(approle):
            return None
        if not vault.is_active_or_standby():
            return None
        return vault

    def _sync_vault_autounseal(self, vault_client: VaultClient) -> None:
        """Go through all the vault-autounseal relations and send necessary credentials.

        This looks for any outstanding requests for auto-unseal that may have
        been missed. If there are any, it generates the credentials and sets
        them in the relation databag.
        """
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-autounseal request")
            return
        autounseal_provider_manager = VaultAutounsealProviderManager(
            charm=self,
            client=vault_client,
            provides=self.vault_autounseal_provides,
            ca_cert=self.tls.pull_tls_file_from_workload(File.CA),
            mount_path=AUTOUNSEAL_MOUNT_PATH,
        )
        outstanding_autounseal_requests = (
            self.vault_autounseal_provides.get_relations_without_credentials()
        )
        if outstanding_autounseal_requests:
            vault_client.enable_secrets_engine(
                SecretsBackend.TRANSIT, autounseal_provider_manager.mount_path
            )
        for relation in outstanding_autounseal_requests:
            relation_address = self._get_relation_api_address(relation)
            if not relation_address:
                logger.warning("Relation address not found for relation %s", relation.id)
                continue
            autounseal_provider_manager.create_credentials(relation, relation_address)
        autounseal_provider_manager.clean_up_credentials()

    def generate_vault_scrape_configs(self) -> List[Dict] | None:
        """Generate the scrape configs for the COS agent.

        Returns:
            The scrape configs for the COS agent or an empty list.
        """
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            return []
        return [
            {
                "scheme": "https",
                "tls_config": {
                    "insecure_skip_verify": False,
                    "ca": self.tls.pull_tls_file_from_workload(File.CA),
                },
                "metrics_path": "/v1/sys/metrics",
                "static_configs": [{"targets": [f"{self._bind_address}:{VAULT_PORT}"]}],
            }
        ]

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

        secret_id = event.params.get("secret-id", "")
        try:
            if not (
                token := self.juju_facade.get_latest_secret_content(id=secret_id).get("token", "")
            ):
                logger.warning("Token not found in the secret when authorizing charm.")
                event.fail("Token not found in the secret. Please provide a valid token secret.")
                return
        except (NoSuchSecretError, SecretRemovedError):
            logger.warning(
                "Secret id provided could not be found by the charm when authorizing charm."
            )
            event.fail(
                "The secret id provided could not be found by the charm. Please grant the token secret to the charm."
            )
            return

        logger.info("Authorizing the charm to interact with Vault")
        if not self._api_address:
            event.fail("API address is not available.")
            return
        if not self.tls.tls_file_available_in_charm(File.CA):
            event.fail("CA certificate is not available in the charm. Something is wrong.")
            return
        vault = self._get_vault_client()
        if not vault:
            event.fail("Failed to initialize the Vault client")
            return
        if not vault.authenticate(Token(token)):
            event.fail("Failed to authenticate with Vault")
            return
        try:
            vault.enable_audit_device(device_type=AuditDeviceType.FILE, path="stdout")
            vault.enable_approle_auth_method()
            vault.create_or_update_policy_from_file(
                name=VAULT_CHARM_POLICY_NAME, path=VAULT_CHARM_POLICY_PATH
            )
            role_id = vault.create_or_update_approle(
                name="charm",
                policies=[VAULT_CHARM_POLICY_NAME, VAULT_DEFAULT_POLICY_NAME],
                token_ttl="1h",
                token_max_ttl="1h",
            )
            vault_secret_id = vault.generate_role_secret_id(name="charm")
            self.juju_facade.set_app_secret_content(
                content={"role-id": role_id, "secret-id": vault_secret_id},
                label=VAULT_CHARM_APPROLE_SECRET_LABEL,
                description="The authentication details for the charm's access to vault.",
            )
            event.set_results(
                {"result": "Charm authorized successfully. You may now remove the secret."}
            )
        except VaultClientError as e:
            logger.exception("Vault returned an error while authorizing the charm")
            event.fail(f"Vault returned an error while authorizing the charm: {str(e)}")
            return

    def _get_vault_client(self) -> VaultClient | None:
        if not self._api_address:
            return None
        if not self.tls.tls_file_available_in_charm(File.CA):
            return None
        return VaultClient(
            url=self._api_address,
            ca_cert_path=self.tls.get_tls_file_path_in_charm(File.CA),
        )

    def _on_collect_status(self, event: CollectStatusEvent):  # noqa: C901
        """Handle the collect status event."""
        if (
            self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME)
            and not self._common_name_config_is_valid()
        ):
            event.add_status(
                BlockedStatus(
                    "Common name is not set in the charm config, "
                    "cannot configure PKI secrets engine"
                )
            )
            return
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
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
            if vault.is_seal_type_transit():
                event.add_status(BlockedStatus("Please initialize Vault"))
                return

            event.add_status(
                BlockedStatus("Please initialize Vault or integrate with an auto-unseal provider")
            )
            return
        try:
            if vault.is_sealed():
                if vault.needs_migration():
                    event.add_status(BlockedStatus("Please migrate Vault"))
                    return
                event.add_status(BlockedStatus("Please unseal Vault"))
                return
        except VaultClientError:
            event.add_status(MaintenanceStatus("Seal check failed, waiting for Vault to recover"))
            return
        if not self._get_vault_approle_secret():
            event.add_status(
                BlockedStatus("Please authorize charm (see `authorize-charm` action)")
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
        try:
            self._install_vault_snap()
        except snap.SnapError as e:
            logger.error("Failed to install Vault snap: %s", e)
            return
        if not self.juju_facade.relation_exists(PEER_RELATION_NAME):
            return
        if not self._bind_address:
            return
        if not self.juju_facade.is_leader:
            if len(self._other_peer_node_api_addresses()) == 0:
                return
            if not self.tls.ca_certificate_is_saved():
                return
        self._generate_vault_config_file()
        try:
            self._start_vault_service()
        except snap.SnapError as e:
            logger.error("Failed to start Vault service: %s", e)
            return
        self._set_peer_relation_node_api_address()

        vault = self._get_active_vault_client()
        if not vault:
            return
        self._configure_pki_secrets_engine(vault)
        self._sync_vault_autounseal(vault)
        self._sync_vault_kv(vault)
        self._sync_vault_pki()

        if not self._api_address or not self.tls.tls_file_available_in_charm(File.CA):
            return

        if vault.is_active() and not vault.is_raft_cluster_healthy():
            logger.warning("Raft cluster is not healthy: %s", vault.get_raft_cluster_state())

    def _on_remove(self, event: RemoveEvent):
        """Handle remove charm event.

        Removes the vault service and the raft data and removes the node from the raft cluster.
        """
        self._remove_node_from_raft_cluster()
        if self._vault_service_is_running():
            self.machine.stop(VAULT_SNAP_NAME)
        self._delete_vault_data()

    def _on_new_vault_kv_client_attached(self, event: NewVaultKvClientAttachedEvent):
        """Handle vault-kv-client attached event."""
        if not self.juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        vault = self._get_active_vault_client()
        if not vault:
            logger.debug("Failed to get initialized Vault")
            return
        self._generate_kv_for_requirer(
            vault=vault,
            relation=event.relation,
            app_name=event.app_name,
            unit_name=event.unit_name,
            mount_suffix=event.mount_suffix,
            egress_subnets=event.egress_subnets,
            nonce=event.nonce,
        )

    def _on_create_backup_action(self, event: ActionEvent) -> None:
        """Handle the create-backup action.

        Creates a snapshot and stores it on S3 storage.
        Outputs the ID of the backup to the user.

        Args:
            event: ActionEvent
        """
        s3_pre_requisites_err = self._check_s3_pre_requisites()
        if s3_pre_requisites_err:
            event.fail(message=f"S3 pre-requisites not met. {s3_pre_requisites_err}.")
            return

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error:
            event.fail(message="Failed to create S3 session.")
            logger.error("Failed to run create-backup action - Failed to create S3 session.")
            return

        if not (s3.create_bucket(bucket_name=s3_parameters["bucket"])):
            event.fail(message="Failed to create S3 bucket.")
            logger.error("Failed to run create-backup action - Failed to create S3 bucket.")
            return
        backup_key = self._get_backup_key()
        vault = self._get_active_vault_client()
        if not vault:
            event.fail(message="Failed to initialize Vault client.")
            logger.error("Failed to run create-backup action - Failed to initialize Vault client.")
            return
        response = vault.create_snapshot()
        content_uploaded = s3.upload_content(
            content=response.raw,  # type: ignore[reportArgumentType]
            bucket_name=s3_parameters["bucket"],
            key=backup_key,
        )
        if not content_uploaded:
            event.fail(message="Failed to upload backup to S3 bucket.")
            logger.error(
                "Failed to run create-backup action - Failed to upload backup to S3 bucket."
            )
            return
        logger.info("Backup uploaded to S3 bucket %s", s3_parameters["bucket"])
        event.set_results({"backup-id": backup_key})

    def _on_list_backups_action(self, event: ActionEvent) -> None:
        """Handle the list-backups action.

        Lists all backups stored in S3 bucket.

        Args:
            event: ActionEvent
        """
        s3_pre_requisites_err = self._check_s3_pre_requisites()
        if s3_pre_requisites_err:
            event.fail(message=f"S3 pre-requisites not met. {s3_pre_requisites_err}.")
            return

        s3_parameters = self._get_s3_parameters()

        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error as e:
            event.fail(message="Failed to create S3 session.")
            logger.error("Failed to run list-backups action - %s", e)
            return

        try:
            backup_ids = s3.get_object_key_list(
                bucket_name=s3_parameters["bucket"], prefix=BACKUP_KEY_PREFIX
            )
        except S3Error as e:
            logger.error("Failed to list backups: %s", e)
            event.fail(message="Failed to run list-backups action - Failed to list backups.")
            return

        event.set_results({"backup-ids": json.dumps(backup_ids)})

    def _on_restore_backup_action(self, event: ActionEvent) -> None:
        """Handle the restore-backup action.

        Restores the snapshot with the provided ID.

        Args:
            event: ActionEvent
        """
        s3_pre_requisites_err = self._check_s3_pre_requisites()
        if s3_pre_requisites_err:
            event.fail(message=f"S3 pre-requisites not met. {s3_pre_requisites_err}.")
            return

        s3_parameters = self._get_s3_parameters()
        try:
            s3 = S3(
                access_key=s3_parameters["access-key"],
                secret_key=s3_parameters["secret-key"],
                endpoint=s3_parameters["endpoint"],
                region=s3_parameters.get("region"),
            )
        except S3Error as e:
            logger.error("Failed to create S3 session: %s", e)
            event.fail(message="Failed to create S3 session.")
            return
        try:
            snapshot = s3.get_content(
                bucket_name=s3_parameters["bucket"],
                object_key=event.params.get("backup-id"),  # type: ignore[reportArgumentType]
            )
        except S3Error as e:
            logger.error("Failed to retrieve snapshot from S3 storage: %s", e)
            event.fail(message="Failed to retrieve snapshot from S3 storage.")
            return
        if not snapshot:
            logger.error("Backup %s not found in S3 bucket", event.params.get("backup-id"))
            event.fail(message="Backup not found in S3 bucket.")
            return
        vault = self._get_vault_client()
        if not vault or not vault.is_api_available():
            logger.error("Failed to restore vault. Vault API is not available.")
            event.fail(message="Failed to restore vault. Vault API is not available.")
            return
        if not (approle := self._get_vault_approle_secret()):
            logger.error("Failed to authenticate to Vault.")
            event.fail(message="Failed to authenticate to Vault.")
            return
        vault.authenticate(approle)
        try:
            response = vault.restore_snapshot(snapshot)  # type: ignore[arg-type]
        except VaultClientError as e:
            logger.error("Failed to restore vault: %s", e)
            event.fail(message="Failed to restore vault.")
            return
        if not 200 <= response.status_code < 300:
            logger.error("Failed to restore snapshot: %s", response.json())
            event.fail(message="Failed to restore snapshot. Vault API returned an error.")
            return

        self.juju_facade.remove_secret(label=VAULT_CHARM_APPROLE_SECRET_LABEL)

        event.set_results({"restored": event.params.get("backup-id")})

    def _vault_service_is_running(self) -> bool:
        """Check if the Vault service is running."""
        service = self.machine.get_service(process=VAULT_SNAP_NAME)
        return False if not service else service.is_running()

    def _delete_vault_data(self) -> None:
        """Delete Vault's data."""
        try:
            self.machine.remove_path(path=f"{VAULT_STORAGE_PATH}/vault.db")
            logger.info("Removed Vault's main database")
        except ValueError:
            logger.info("No Vault database to remove")
        try:
            self.machine.remove_path(path=f"{VAULT_STORAGE_PATH}/raft/raft.db")
            logger.info("Removed Vault's Raft database")
        except ValueError:
            logger.info("No Vault raft database to remove")

    def _remove_node_from_raft_cluster(self):
        """Remove the node from the raft cluster."""
        if not (approle := self._get_vault_approle_secret()):
            logger.error("Failed to authenticate to Vault")
            return
        api_address = self._api_address
        if not api_address:
            logger.error("Can't remove node from cluster - Vault API address is not available")
            return
        vault = VaultClient(url=api_address, ca_cert_path=None)
        if not vault.is_api_available():
            logger.error("Can't remove node from cluster - Vault API is not available")
            return
        if not vault.is_initialized():
            logger.error("Can't remove node from cluster - Vault is not initialized")
            return
        try:
            if vault.is_sealed():
                logger.error("Can't remove node from cluster - Vault is sealed")
                return
        except VaultClientError as e:
            logger.error("Can't remove node from cluster - Vault status check failed: %s", e)
            return
        vault.authenticate(approle)
        if vault.is_node_in_raft_peers(id=self._node_id) and vault.get_num_raft_peers() > 1:
            vault.remove_raft_node(id=self._node_id)

    def _check_s3_pre_requisites(self) -> str | None:
        """Check if the S3 pre-requisites are met."""
        if not self.unit.is_leader():
            return "Only leader unit can perform backup operations"
        if not self.juju_facade.relation_exists(S3_RELATION_NAME):
            return "S3 relation not created"
        if missing_parameters := self._get_missing_s3_parameters():
            return "S3 parameters missing ({})".format(", ".join(missing_parameters))
        return None

    def _get_backup_key(self) -> str:
        """Return the backup key.

        Returns:
            str: The backup key
        """
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return f"{BACKUP_KEY_PREFIX}-{self.model.name}-{timestamp}"

    def _get_s3_parameters(self) -> Dict[str, str]:
        """Retrieve S3 parameters from the S3 integrator relation.

        Removes leading and trailing whitespaces from the parameters.

        Returns:
            Dict[str, str]: Dictionary of the S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        for key, value in s3_parameters.items():
            if isinstance(value, str):
                s3_parameters[key] = value.strip()
        return s3_parameters

    def _get_missing_s3_parameters(self) -> List[str]:
        """Return the list of missing S3 parameters.

        Returns:
            List[str]: List of missing required S3 parameters.
        """
        s3_parameters = self.s3_requirer.get_s3_connection_info()
        return [param for param in REQUIRED_S3_PARAMETERS if param not in s3_parameters]

    def _generate_kv_for_requirer(
        self,
        vault: VaultClient,
        relation: Relation,
        app_name: str,
        unit_name: str,
        mount_suffix: str,
        egress_subnets: List[str],
        nonce: str,
    ):
        if not self.juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        ca_certificate = self.tls.pull_tls_file_from_workload(File.CA)
        if not ca_certificate:
            logger.debug("Vault CA certificate not available")
            return
        if not (vault_url := self._api_address):
            logger.debug("Failed to get Vault URL when generating KV credentials, skipping")
            return
        mount = f"charm-{app_name}-{mount_suffix}"
        credentials_juju_secret_id = self._ensure_unit_credentials(
            vault=vault,
            relation=relation,
            unit_name=unit_name,
            mount=mount,
            nonce=nonce,
            egress_subnets=egress_subnets,
        )
        self.vault_kv.set_kv_data(
            relation=relation,
            mount=mount,
            ca_certificate=ca_certificate,
            vault_url=vault_url,
            nonce=nonce,
            credentials_juju_secret_id=credentials_juju_secret_id,
        )
        credential_nonces = self.vault_kv.get_credentials(relation).keys()
        if nonce not in set(credential_nonces):
            self.vault_kv.remove_unit_credentials(relation, nonce=nonce)

    def _get_relation_api_address(self, relation: Relation) -> str:
        """Get the API address for the given relation."""
        ingress_address = self.juju_facade.get_ingress_address(relation=relation)
        return f"https://{ingress_address}:{VAULT_PORT}"

    def _is_vault_kv_role_configured(
        self,
        vault: VaultClient,
        label: str,
        egress_subnets: List[str],
        role_name: str,
        credentials_juju_secret_id: str,
    ) -> bool:
        try:
            role_secret_id = self.juju_facade.get_latest_secret_content(
                label=label,
                id=credentials_juju_secret_id,
            ).get("role-secret-id")
        except NoSuchSecretError:
            return False
        if not role_secret_id:
            return False
        role_data = vault.read_role_secret(role_name, role_secret_id)
        if egress_subnets in role_data["cidr_list"]:
            return True
        return False

    def _ensure_unit_credentials(
        self,
        vault: VaultClient,
        relation: Relation,
        unit_name: str,
        mount: str,
        nonce: str,
        egress_subnets: List[str],
    ) -> str:
        policy_name = role_name = mount + "-" + unit_name.replace("/", "-")
        juju_secret_label = self._get_vault_kv_secret_label(unit_name=unit_name)
        current_credentials = self.vault_kv.get_credentials(relation)
        credentials_juju_secret_id = current_credentials.get(nonce, None)
        if self._is_vault_kv_role_configured(
            vault=vault,
            label=juju_secret_label,
            egress_subnets=egress_subnets,
            role_name=role_name,
            credentials_juju_secret_id=credentials_juju_secret_id,
        ):
            logger.info("Vault KV role already configured for the provided egress subnets")
            return credentials_juju_secret_id
        vault.enable_secrets_engine(SecretsBackend.KV_V2, mount)
        vault.create_or_update_policy_from_file(
            name=policy_name, path="src/templates/kv_mount.hcl", mount=mount
        )
        role_id = vault.create_or_update_approle(
            name=role_name,
            policies=[policy_name],
            cidrs=egress_subnets,
            token_ttl="1h",
            token_max_ttl="1h",
        )
        role_secret_id = vault.generate_role_secret_id(name=role_name, cidrs=egress_subnets)
        secret = self.juju_facade.set_app_secret_content(
            content={"role-id": role_id, "role-secret-id": role_secret_id},
            label=juju_secret_label,
        )
        self.juju_facade.grant_secret(relation, secret=secret)
        if not secret.id:
            raise ValueError(
                f"Unexpected error, just created secret {juju_secret_label!r} has no id"
            )
        return secret.id

    def _sync_vault_kv(self, vault: VaultClient) -> None:
        """Goes through all the vault-kv relations and sends necessary KV information."""
        if not self.juju_facade.is_leader:
            logger.debug("Only leader unit can handle a vault-kv request")
            return
        kv_requests = self.vault_kv.get_kv_requests()
        for kv_request in kv_requests:
            self._generate_kv_for_requirer(
                vault=vault,
                relation=kv_request.relation,
                app_name=kv_request.app_name,
                unit_name=kv_request.unit_name,
                mount_suffix=kv_request.mount_suffix,
                egress_subnets=kv_request.egress_subnets,
                nonce=kv_request.nonce,
            )

    def _generate_pki_certificate_for_requirer(self, requirer_csr: RequirerCertificateRequest):
        """Generate a PKI certificate for a TLS requirer."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request")
            return
        if not self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            logger.debug("TLS Certificates PKI relation not created")
            return
        vault = self._get_active_vault_client()
        if not vault:
            return
        common_name = self._get_config_common_name()
        if not common_name:
            logger.error("Common name is not set in the charm config")
            return
        if not vault.is_pki_role_created(role=VAULT_PKI_ROLE, mount=VAULT_PKI_MOUNT):
            logger.debug("PKI role not created")
            return
        intermediate_ca_certificate, _ = self._get_pki_intermediate_ca()
        if not intermediate_ca_certificate:
            return
        allowed_cert_validity = self._calculate_pki_certificates_ttl(
            intermediate_ca_certificate.certificate
        )
        certificate = vault.sign_pki_certificate_signing_request(
            mount=VAULT_PKI_MOUNT,
            role=VAULT_PKI_ROLE,
            csr=str(requirer_csr.certificate_signing_request),
            common_name=requirer_csr.certificate_signing_request.common_name,
            ttl=f"{allowed_cert_validity}s",
        )
        if not certificate:
            logger.debug("Failed to sign the certificate")
            return
        provider_certificate = ProviderCertificate(
            relation_id=requirer_csr.relation_id,
            certificate=Certificate.from_string(certificate.certificate),
            certificate_signing_request=requirer_csr.certificate_signing_request,
            ca=Certificate.from_string(certificate.ca),
            chain=[Certificate.from_string(cert) for cert in certificate.chain],
        )
        self.vault_pki.set_relation_certificate(
            provider_certificate=provider_certificate,
        )

    def _get_certificate_request(self) -> CertificateRequestAttributes | None:
        common_name = self._get_config_common_name()
        if not common_name:
            return None
        return CertificateRequestAttributes(
            common_name=common_name,
            is_ca=True,
        )

    def _sync_vault_pki(self) -> None:
        """Goes through all the vault-pki relations and sends necessary TLS certificate."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki request")
            return
        outstanding_pki_requests = self.vault_pki.get_outstanding_certificate_requests()
        for pki_request in outstanding_pki_requests:
            self._generate_pki_certificate_for_requirer(
                requirer_csr=pki_request,
            )

    def _configure_pki_secrets_engine(self, vault: VaultClient) -> None:  # noqa: C901
        """Configure the PKI secrets engine."""
        if not self.unit.is_leader():
            logger.debug("Only leader unit can handle a vault-pki certificate request, skipping")
            return
        if not self.juju_facade.relation_exists(TLS_CERTIFICATES_PKI_RELATION_NAME):
            logger.debug("TLS Certificates PKI relation not created, skipping")
            return
        if not self._common_name_config_is_valid():
            logger.debug("Common name config is not valid, skipping")
            return
        config_common_name = self._get_config_common_name()
        if not config_common_name:
            logger.error("Common name is not set in the charm config")
            return
        intermediate_ca_certificate, private_key = self._get_pki_intermediate_ca()
        if not intermediate_ca_certificate or not private_key:
            return
        vault.enable_secrets_engine(SecretsBackend.PKI, VAULT_PKI_MOUNT)
        existing_ca_certificate = vault.get_intermediate_ca(mount=VAULT_PKI_MOUNT)
        existing_certificate = (
            Certificate.from_string(existing_ca_certificate) if existing_ca_certificate else None
        )
        if (
            existing_certificate
            and existing_certificate == intermediate_ca_certificate.certificate
        ):
            if not self._intermediate_ca_exceeds_role_ttl(vault, existing_certificate):
                self.tls_certificates_pki.renew_certificate(
                    intermediate_ca_certificate,
                )
                logger.debug("Renewing the intermediate CA certificate")
                return
            logger.debug("CA certificate already set in the PKI secrets engine")
            return
        self.vault_pki.revoke_all_certificates()
        vault.import_ca_certificate_and_key(
            certificate=str(intermediate_ca_certificate.certificate),
            private_key=str(private_key),
            mount=VAULT_PKI_MOUNT,
        )
        issued_certificate_validity = self._calculate_pki_certificates_ttl(
            intermediate_ca_certificate.certificate
        )
        if not vault.is_common_name_allowed_in_pki_role(
            role=VAULT_PKI_ROLE,
            mount=VAULT_PKI_MOUNT,
            common_name=config_common_name,
        ) or issued_certificate_validity != vault.get_role_max_ttl(
            role=VAULT_PKI_ROLE,
            mount=VAULT_PKI_MOUNT,
        ):
            vault.create_or_update_pki_charm_role(
                allowed_domains=config_common_name,
                mount=VAULT_PKI_MOUNT,
                role=VAULT_PKI_ROLE,
                max_ttl=f"{issued_certificate_validity}s",
            )
        # Can run only after the first issuer has been actually created.
        try:
            vault.make_latest_pki_issuer_default(mount=VAULT_PKI_MOUNT)
        except VaultClientError as e:
            logger.error("Failed to make latest issuer default: %s", e)

    def _get_config_common_name(self) -> str:
        """Return the common name to use for the PKI backend."""
        common_name = self.config.get("common_name")
        if not common_name or not isinstance(common_name, str):
            return ""
        return common_name

    def _get_default_lease_ttl(self) -> str:
        """Return the default lease ttl config."""
        default_lease_ttl = self.config.get("default_lease_ttl")
        if not default_lease_ttl or not isinstance(default_lease_ttl, str):
            raise ValueError("Invalid config default_lease_ttl")
        return default_lease_ttl

    def _get_max_lease_ttl(self) -> str:
        """Return the max lease ttl config."""
        max_lease_ttl = self.config.get("max_lease_ttl")
        if not max_lease_ttl or not isinstance(max_lease_ttl, str):
            raise ValueError("Invalid config max_lease_ttl")
        return max_lease_ttl

    def _common_name_config_is_valid(self) -> bool:
        """Return whether the config value for the common name is valid."""
        common_name = self._get_config_common_name()
        return common_name != ""

    def _get_vault_approle_secret(self) -> AppRole | None:
        """Get the approle details from the secret.

        Returns:
            AppRole: An AppRole object with role_id and secret_id set from the
                     values stored in the Juju secret, or None if the secret is
                     not found or either of the values are not set.
        """
        try:
            role_id, secret_id = self.juju_facade.get_secret_content_values(
                "role-id", "secret-id", label=VAULT_CHARM_APPROLE_SECRET_LABEL
            )
        except NoSuchSecretError:
            logger.warning("Apprle secret not yet created")
            return None
        return AppRole(role_id, secret_id) if role_id and secret_id else None

    def _install_vault_snap(self) -> None:
        """Installs the Vault snap in the machine."""
        try:
            snap_cache = snap.SnapCache()
            vault_snap = snap_cache[VAULT_SNAP_NAME]
            if VAULT_SNAP_REVISION == vault_snap.revision:
                return
            with self.temp_maintenance_status("Installing Vault"):
                vault_snap.ensure(
                    snap.SnapState.Latest, channel=VAULT_SNAP_CHANNEL, revision=VAULT_SNAP_REVISION
                )
                vault_snap.hold()
            logger.info("Vault snap installed")
            if self._vault_service_is_running():
                self.machine.stop(VAULT_SNAP_NAME)
                logger.debug("Previously running Vault service stopped")
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
                "leader_ca_cert_file": f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.CA.name.lower()}.pem",  # noqa: E501
            }
            for node_api_address in self._other_peer_node_api_addresses()
        ]

        autounseal_configuration_details = self._get_vault_autounseal_configuration()

        content = _render_vault_config_file(
            default_lease_ttl=self._get_default_lease_ttl(),
            max_lease_ttl=self._get_max_lease_ttl(),
            cluster_address=self._cluster_address,
            api_address=self._api_address,
            tls_cert_file=f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.CERT.name.lower()}.pem",
            tls_key_file=f"{MACHINE_TLS_FILE_DIRECTORY_PATH}/{File.KEY.name.lower()}.pem",
            tcp_address=f"[::]:{VAULT_PORT}",
            raft_storage_path=VAULT_STORAGE_PATH,
            node_id=self._node_id,
            retry_joins=retry_joins,
            autounseal_details=autounseal_configuration_details,
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
            # If the seal type has changed, we need to restart Vault to apply
            # the changes. SIGHUP is currently only supported as a beta feature
            # for the enterprise version in Vault 1.16+
            if _seal_types_are_different(existing_content, content):
                if self._vault_service_is_running():
                    self.machine.restart(VAULT_SNAP_NAME)

    def _get_vault_autounseal_configuration(self) -> AutounsealConfigurationDetails | None:
        autounseal_relation_details = self.vault_autounseal_requires.get_details()
        if not autounseal_relation_details:
            return None
        autounseal_requirer_manager = VaultAutounsealRequirerManager(
            self, self.vault_autounseal_requires
        )
        self.tls.push_autounseal_ca_cert(autounseal_relation_details.ca_certificate)
        provider_vault_token = autounseal_requirer_manager.get_provider_vault_token(
            autounseal_relation_details, self.tls.get_tls_file_path_in_charm(File.AUTOUNSEAL_CA)
        )
        return AutounsealConfigurationDetails(
            autounseal_relation_details.address,
            autounseal_relation_details.mount_path,
            autounseal_relation_details.key_name,
            provider_vault_token,
            self.tls.get_tls_file_path_in_workload(File.AUTOUNSEAL_CA),
        )

    def _set_peer_relation_node_api_address(self) -> None:
        """Set the unit address in the peer relation."""
        assert self._api_address
        self.juju_facade.set_unit_relation_data(
            data={"node_api_address": self._api_address},
            name=PEER_RELATION_NAME,
        )

    def _get_peer_relation_node_api_addresses(self) -> List[str]:
        """Return the list of peer unit addresses."""
        peer_relation_data = self.juju_facade.get_remote_units_relation_data(
            name=PEER_RELATION_NAME,
        )
        return [
            databag["node_api_address"]
            for databag in peer_relation_data
            if "node_api_address" in databag
        ]

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

    def _get_vault_kv_secret_label(self, unit_name: str):
        unit_name_dash = unit_name.replace("/", "-")
        return f"{KV_SECRET_PREFIX}{unit_name_dash}"

    def _intermediate_ca_exceeds_role_ttl(
        self, vault: VaultClient, intermediate_ca_certificate: Certificate
    ) -> bool:
        """Check if the intermediate CA's remaining validity exceeds the role's max TTL.

        Vault PKI enforces that issued certificates cannot outlast their signing CA.
        This method ensures that the intermediate CA's remaining validity period
        is longer than the maximum TTL allowed for certificates issued by this role.
        """
        current_ttl = vault.get_role_max_ttl(role=VAULT_PKI_ROLE, mount=VAULT_PKI_MOUNT)
        if (
            not current_ttl
            or not intermediate_ca_certificate.expiry_time
            or not intermediate_ca_certificate.validity_start_time
        ):
            return False
        certificate_validity = (
            intermediate_ca_certificate.expiry_time
            - intermediate_ca_certificate.validity_start_time
        )
        certificate_validity_seconds = certificate_validity.total_seconds()
        return certificate_validity_seconds > current_ttl

    def _calculate_pki_certificates_ttl(self, certificate: Certificate) -> int:
        """Calculate the maximum allowed validity of certificates issued by PKI.

        Return half the CA certificate validity in seconds.
        """
        if not certificate.expiry_time or not certificate.validity_start_time:
            raise ValueError("Invalid CA certificate with no expiry time or validity start time")
        ca_validity_time = certificate.expiry_time - certificate.validity_start_time
        ca_validity_seconds = ca_validity_time.total_seconds()
        return int(ca_validity_seconds / 2)

    def _get_pki_intermediate_ca(
        self,
    ) -> Tuple[ProviderCertificate | None, PrivateKey | None]:
        """Get the intermediate CA certificate."""
        certificate_request = self._get_certificate_request()
        if not certificate_request:
            logger.error("Certificate request is not valid")
            return None, None
        provider_certificate, private_key = self.tls_certificates_pki.get_assigned_certificate(
            certificate_request=certificate_request
        )
        if not provider_certificate:
            logger.debug("No intermediate CA certificate available")
            return None, None
        if not private_key:
            logger.debug("No private key available")
            return None, None
        return provider_certificate, private_key

    @property
    def _bind_address(self) -> str | None:
        """Fetches bind address from peer relation and returns it.

        Returns:
            str: Bind address
        """
        return self.juju_facade.get_bind_address(relation_name=PEER_RELATION_NAME)

    @property
    def _api_address(self) -> str | None:
        """Returns the IP with the https schema and vault port.

        Example: "https://1.2.3.4:8200"
        """
        if not self._bind_address:
            return None
        return f"https://{self._bind_address}:{VAULT_PORT}"

    @property
    def _cluster_address(self) -> str | None:
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


if __name__ == "__main__":  # pragma: nocover
    main(VaultOperatorCharm)
