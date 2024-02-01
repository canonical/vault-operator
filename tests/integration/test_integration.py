#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import hvac
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


VAULT_STATUS_ACTIVE = 200
VAULT_STATUS_UNSEALED_AND_STANDBY = 429
VAULT_STATUS_NOT_INITIALIZED = 501
VAULT_STATUS_SEALED = 503


async def validate_vault_status(
    expected_vault_status_code: int, ops_test: OpsTest, vault_client: hvac.Client
):
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="blocked",
            timeout=1000,
        )
    response = vault_client.sys.read_health_status()
    assert response.status_code == expected_vault_status_code


async def get_leader(app: Application) -> Unit:
    leader = None
    for unit in app.units:
        assert isinstance(unit, Unit)
        if await unit.is_leader_from_status():
            leader = unit
            break
    assert isinstance(leader, Unit)
    return leader


@pytest.fixture(scope="module")
@pytest.mark.abort_on_fail
async def build_and_deploy(ops_test: OpsTest):
    """Build the charm-under-test and deploy it."""
    charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(
        charm,
        application_name=APP_NAME,
        trust=True,
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
async def test_given_charm_deployed_when_vault_initialized_and_unsealed_and_authorized_then_status_is_active(
    ops_test: OpsTest,
):
    """Test that Vault is active and running correctly after Vault is initialized, unsealed and authorized."""
    assert ops_test.model
    app = ops_test.model.applications[APP_NAME]
    assert isinstance(app, Application)
    leader = await get_leader(app)

    leader_ip = leader.public_address
    vault_endpoint = f"http://{leader_ip}:8200"
    # TODO: Use certs in "verify" when added in charm.
    client = hvac.Client(url=vault_endpoint, verify=False)
    await validate_vault_status(VAULT_STATUS_NOT_INITIALIZED, ops_test, client)

    init_output = client.sys.initialize(secret_shares=1, secret_threshold=1)
    keys = init_output["keys"]
    root_token = init_output["root_token"]
    await validate_vault_status(VAULT_STATUS_SEALED, ops_test, client)
    client.sys.submit_unseal_keys(keys)
    await validate_vault_status(VAULT_STATUS_ACTIVE, ops_test, client)
    # Run authorize-charm action
    await leader.run_action("authorize-charm", token=root_token)
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
        )


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_deployed_when_relate_to_grafana_agent_then_status_is_active(
    ops_test: OpsTest, build_and_deploy, deploy_grafana_agent
):
    assert ops_test.model
    await ops_test.model.integrate(
        APP_NAME,
        GRAFANA_AGENT_APPLICATION_NAME,
    )
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            timeout=1000,
        )
