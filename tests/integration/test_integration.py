#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
from pathlib import Path

import hvac  # type: ignore[import-untyped]
import pytest
import yaml
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
PEER_RELATION_NAME = "vault-peers"


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
async def test_given_charm_build_when_deploy_then_status_active(
    ops_test: OpsTest, build_and_deploy
):
    assert ops_test.model
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
        relation1=f"{APP_NAME}:cos-agent",
        relation2=f"{GRAFANA_AGENT_APPLICATION_NAME}:cos-agent",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )


@pytest.mark.abort_on_fail
async def test_given_charm_deployed_and_active_when_vault_status_checked_then_vault_returns_200_or_429(
    ops_test: OpsTest,
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )
    unit_ip = ops_test.model.units.get(f"{APP_NAME}/0").public_address
    vault_endpoint = f"http://{unit_ip}:8200"
    # TODO: Use certs in "verify" when added in charm.
    client = hvac.Client(url=vault_endpoint, verify=False)
    response = client.sys.read_health_status()
    # We accept both 200 and 429 because based on Vault's documentation:
    # 200: {{Description: "initialized, unsealed, and active"}}
    # 429: {{Description: "unsealed and standby"}}
    # 472: {{Description: "data recovery mode replication secondary and active"}}
    # 501: {{Description: "not initialized"}}
    # 503: {{Description: "sealed"}}
    # TODO: remove 501 when charm initializes vault.
    assert response.status_code in (200, 429, 501)
