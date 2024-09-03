#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import requests
import scenario
from charms.vault_k8s.v0.vault_client import VaultClientError
from charms.vault_k8s.v0.vault_s3 import S3Error

from tests.unit.fixtures import VaultCharmFixtures


class TestCharmRestoreBackupAction(VaultCharmFixtures):
    def test_given_non_leader_when_restore_backup_action_then_fails(self):
        state_in = scenario.State(
            leader=False,
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert (
            action_output.failure
            == "S3 pre-requisites not met. Only leader unit can perform backup operations."
        )

    def test_given_s3_relation_not_created_when_restore_backup_action_then_fails(self):
        state_in = scenario.State(
            leader=True,
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "S3 pre-requisites not met. S3 relation not created."

    def test_given_missing_s3_parameters_when_restore_backup_then_action_fails(self):
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            leader=True,
            relations=[s3_relation],
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert (
            action_output.failure
            == "S3 pre-requisites not met. S3 parameters missing (bucket, access-key, secret-key, endpoint)."
        )

    def test_given_s3_error_during_instantiation_when_restore_backup_then_action_fails(self):
        self.mock_s3_requirer.configure_mock(
            **{
                "get_s3_connection_info.return_value": {
                    "access-key": "my-access-key",
                    "secret-key": "my-secret-key",
                    "endpoint": "my-endpoint",
                    "bucket": "my bucket",
                    "region": "my-region",
                },
            },
        )
        self.mock_s3.side_effect = S3Error()

        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            leader=True,
            relations=[s3_relation],
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to create S3 session."

    def test_given_s3_error_during_get_content_when_restore_backup_then_action_fails(self):
        self.mock_s3_requirer.configure_mock(
            **{
                "get_s3_connection_info.return_value": {
                    "access-key": "my-access-key",
                    "secret-key": "my-secret-key",
                    "endpoint": "my-endpoint",
                    "bucket": "my bucket",
                    "region": "my-region",
                },
            },
        )
        self.mock_s3.return_value.configure_mock(
            **{
                "get_content.side_effect": S3Error(),
            },
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            leader=True,
            relations=[s3_relation],
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to retrieve snapshot from S3 storage."

    def test_given_no_snapshot_when_restore_backup_then_action_fails(self):
        self.mock_s3_requirer.configure_mock(
            **{
                "get_s3_connection_info.return_value": {
                    "access-key": "my-access-key",
                    "secret-key": "my-secret-key",
                    "endpoint": "my-endpoint",
                    "bucket": "my bucket",
                    "region": "my-region",
                },
            },
        )
        self.mock_s3.return_value.configure_mock(
            **{
                "get_content.return_value": None,
            },
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        state_in = scenario.State(
            leader=True,
            relations=[s3_relation],
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Backup not found in S3 bucket."

    def test_given_failed_to_restore_vault_when_restore_backup_then_action_fails(self):
        self.mock_s3_requirer.configure_mock(
            **{
                "get_s3_connection_info.return_value": {
                    "access-key": "my-access-key",
                    "secret-key": "my-secret-key",
                    "endpoint": "my-endpoint",
                    "bucket": "my bucket",
                    "region": "my-region",
                },
            },
        )
        self.mock_s3.return_value.configure_mock(
            **{
                "get_content.return_value": "my snapshot content",
            },
        )
        self.mock_vault.configure_mock(
            **{
                "restore_snapshot.side_effect": VaultClientError(),
            },
        )
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            leader=True,
            relations=[s3_relation, peer_relation],
            secrets=[approle_secret],
        )
        action = scenario.Action(
            name="restore-backup",
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is False
        assert action_output.failure == "Failed to restore vault."

    def test_given_200_response_when_restore_backup_then_action_success(self):
        self.mock_s3_requirer.configure_mock(
            **{
                "get_s3_connection_info.return_value": {
                    "access-key": "my-access-key",
                    "secret-key": "my-secret-key",
                    "endpoint": "my-endpoint",
                    "bucket": "my bucket",
                    "region": "my-region",
                },
            },
        )
        self.mock_s3.return_value.configure_mock(
            **{
                "get_content.return_value": "my snapshot content",
            },
        )
        response = requests.Response()
        response.status_code = 200
        self.mock_vault.configure_mock(
            **{
                "restore_snapshot.return_value": response,
            },
        )
        approle_secret = scenario.Secret(
            id="0",
            label="vault-approle-auth-details",
            contents={0: {"role-id": "role id", "secret-id": "secret id"}},
        )
        s3_relation = scenario.Relation(
            endpoint="s3-parameters",
            interface="s3",
        )
        peer_relation = scenario.PeerRelation(
            endpoint="vault-peers",
        )
        state_in = scenario.State(
            leader=True,
            relations=[s3_relation, peer_relation],
            secrets=[approle_secret],
        )
        action = scenario.Action(
            name="restore-backup",
            params={"backup-id": "my-backup-id"},
        )

        action_output = self.ctx.run_action(action, state_in)

        assert action_output.success is True
        assert action_output.results
        assert action_output.results == {"restored": "my-backup-id"}
        self.mock_vault.restore_snapshot.assert_called_with("my snapshot content")
