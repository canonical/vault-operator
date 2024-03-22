#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import os
from os.path import abspath
from pathlib import Path
from typing import List

import hvac  # type: ignore[import-untyped]
import pytest
import yaml
from juju.application import Application
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
PEER_RELATION_NAME = "vault-peers"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"
VAULT_PKI_REQUIRER_APPLICATION_NAME = "tls-certificates-requirer"
NUM_VAULT_UNITS = 5

# Vault status codes, see
# https://developer.hashicorp.com/vault/api-docs/system/health for more details
VAULT_STATUS_ACTIVE = 200
VAULT_STATUS_UNSEALED_AND_STANDBY = 429
VAULT_STATUS_NOT_INITIALIZED = 501
VAULT_STATUS_SEALED = 503


async def run_get_ca_certificate_action(ops_test: OpsTest, timeout: int = 60) -> dict:
    """Run the `get-certificate` on the `self-signed-certificates` unit.

    Args:
        ops_test (OpsTest): OpsTest
        timeout (int, optional): Timeout in seconds. Defaults to 60.

    Returns:
        dict: Action output
    """
    assert ops_test.model
    self_signed_certificates_unit = ops_test.model.units[
        f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}/0"
    ]
    assert isinstance(self_signed_certificates_unit, Unit)
    action = await self_signed_certificates_unit.run_action(
        action_name="get-ca-certificate",
    )
    return await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=timeout)


async def validate_vault_status(
    expected_vault_status_code: int | List[int], ops_test: OpsTest, vault_client: hvac.Client
):
    assert ops_test.model
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    response = vault_client.sys.read_health_status()
    if isinstance(expected_vault_status_code, list):
        assert response.status_code in expected_vault_status_code
    else:
        assert response.status_code == expected_vault_status_code


async def get_leader(app: Application) -> Unit | None:
    for unit in app.units:
        assert isinstance(unit, Unit)
        if await unit.is_leader_from_status():
            return unit
    return None

async def run_get_certificate_action(ops_test: OpsTest) -> dict:
    """Run `get-certificate` on the `tls-requirer-requirer/0` unit.

    Args:
        ops_test (OpsTest): OpsTest

    Returns:
        dict: Action output
    """
    tls_requirer_unit = ops_test.model.units[f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}/0"]
    action = await tls_requirer_unit.run_action(
        action_name="get-certificate",
    )
    action_output = await ops_test.model.get_action_output(action_uuid=action.entity_id, wait=240)
    return action_output

@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    assert ops_test.model
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        trust=True,
        num_units=NUM_VAULT_UNITS,
        config={"common_name": "example.com"},
    )


@pytest.mark.abort_on_fail
@pytest.fixture(scope="module")
async def deploy_grafana_agent(ops_test: OpsTest) -> None:
    """Deploys grafana-agent-operator.

    Args:
        ops_test: Ops test Framework.
    """
    assert ops_test.model
    await ops_test.model.deploy(
        GRAFANA_AGENT_APPLICATION_NAME,
        application_name=GRAFANA_AGENT_APPLICATION_NAME,
        trust=True,
    )


@pytest.mark.abort_on_fail
@pytest.fixture(scope="module")
async def deploy_self_signed_certificates_operator(ops_test: OpsTest):
    """Deploy Self Signed Certificates Operator.

    Args:
        ops_test: Ops test Framework.
    """
    assert ops_test.model
    await ops_test.model.deploy(
        SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        application_name=SELF_SIGNED_CERTIFICATES_APPLICATION_NAME,
        channel="stable",
    )

@pytest.mark.abort_on_fail
@pytest.fixture(scope="module")
async def deploy_tls_certificates_requirer_operator(ops_test: OpsTest):
    """Deploy TLS Certificates Requirer Operator.

    Args:
        ops_test: Ops test Framework.
    """
    assert ops_test.model
    await ops_test.model.deploy(
        VAULT_PKI_REQUIRER_APPLICATION_NAME,
        application_name=VAULT_PKI_REQUIRER_APPLICATION_NAME,
        channel="stable",
        config={"common_name": "test.example.com"},
    )

@pytest.mark.abort_on_fail
async def test_given_charm_build_when_deploy_then_status_blocked(
    ops_test: OpsTest, build_and_deploy
):
    assert ops_test.model
    async with ops_test.fast_forward():
        # Charm should go to blocked state because it needs to be manually
        # initialized.
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )


@pytest.mark.abort_on_fail
async def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(
    ops_test: OpsTest, build_and_deploy, deploy_self_signed_certificates_operator
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:tls-certificates-access",
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
        await ops_test.model.wait_for_idle(
            apps=[SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    assert isinstance(unit := ops_test.model.units.get(f"{APP_NAME}/0"), Unit)
    unit_ip = unit.public_address
    vault_endpoint = f"https://{unit_ip}:8200"
    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    with open("ca_file.txt", mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
    response = client.sys.read_health_status()
    assert response.status_code == VAULT_STATUS_NOT_INITIALIZED
    os.remove("ca_file.txt")


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_when_vault_initialized_and_unsealed_and_authorized_then_status_is_active(
    ops_test: OpsTest,
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    assert isinstance(app, Application)
    leader = await get_leader(app)
    assert leader

    leader_ip = leader.public_address
    vault_endpoint = f"https://{leader_ip}:8200"

    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    with open("ca_file.txt", mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
    await validate_vault_status(VAULT_STATUS_NOT_INITIALIZED, ops_test, client)

    init_output = client.sys.initialize(secret_shares=1, secret_threshold=1)
    keys = init_output["keys"]
    root_token = init_output["root_token"]
    await validate_vault_status(VAULT_STATUS_SEALED, ops_test, client)
    client.sys.submit_unseal_keys(keys)
    await validate_vault_status(VAULT_STATUS_ACTIVE, ops_test, client)

    await unseal_all_vault_units(ops_test, ca_file.name, keys)
    await leader.run_action("authorize-charm", token=root_token)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
        )
    os.remove("ca_file.txt")


async def unseal_all_vault_units(ops_test: OpsTest, ca_file_name: str, keys: str):
    """Unseal all the vault units."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    assert isinstance(app, Application)
    clients = []
    for unit in app.units:
        assert isinstance(unit, Unit)
        unit_endpoint = f"https://{unit.public_address}:8200"
        client = hvac.Client(url=unit_endpoint, verify=abspath(ca_file_name))
        if client.sys.read_health_status() not in (
            VAULT_STATUS_ACTIVE,
            VAULT_STATUS_UNSEALED_AND_STANDBY,
        ):
            client.sys.submit_unseal_keys(keys)
        clients.append(client)

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    for client in clients:
        response = client.sys.read_health_status()
        assert response.status_code in (VAULT_STATUS_ACTIVE, VAULT_STATUS_UNSEALED_AND_STANDBY)


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    ops_test: OpsTest, build_and_deploy, deploy_grafana_agent
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:cos-agent",
        relation2=f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
        )

@pytest.mark.abort_on_fail
async def test_given_tls_certificates_pki_relation_when_integrate_then_status_is_active(
    ops_test: OpsTest, build_and_deploy, deploy_self_signed_certificates_operator
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:tls-certificates-pki",
        relation2=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
        status="active",
        timeout=1000,
    )

@pytest.mark.abort_on_fail
async def test_given_vault_pki_relation_when_integrate_then_cert_is_provided(
    ops_test: OpsTest, build_and_deploy, deploy_self_signed_certificates_operator, deploy_tls_certificates_requirer_operator
):
    assert ops_test.model
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:vault-pki",
        relation2=f"{VAULT_PKI_REQUIRER_APPLICATION_NAME}:certificates"
        )
    await ops_test.model.wait_for_idle(
            apps=[APP_NAME, VAULT_PKI_REQUIRER_APPLICATION_NAME],
            status="active",
            timeout=1000,
        )
    action_output = await run_get_certificate_action(ops_test)
    assert action_output["certificate"] is not None
    assert action_output["ca-certificate"] is not None
    assert action_output["csr"] is not None
