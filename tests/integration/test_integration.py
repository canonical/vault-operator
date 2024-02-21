#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import os
from os.path import abspath
from pathlib import Path

import hvac  # type: ignore[import-untyped]
import pytest
import yaml
from juju.unit import Unit
from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
GRAFANA_AGENT_APPLICATION_NAME = "grafana-agent"
PEER_RELATION_NAME = "vault-peers"
SELF_SIGNED_CERTIFICATES_APPLICATION_NAME = "self-signed-certificates"


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
        trust=True,
        channel="beta",
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
async def test_given_certificates_provider_is_related_when_vault_status_checked_then_vault_returns_200_or_429(
    ops_test: OpsTest, build_and_deploy, deploy_self_signed_certificates_operator
):
    """To test that Vault is actually running when the charm is active."""
    assert ops_test.model
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )
    await ops_test.model.integrate(
        relation1=f"{SELF_SIGNED_CERTIFICATES_APPLICATION_NAME}:certificates",
        relation2=f"{APP_NAME}:tls-certificates-access",
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, SELF_SIGNED_CERTIFICATES_APPLICATION_NAME],
        status="active",
        timeout=1000,
    )
    unit_ip = ops_test.model.units.get(f"{APP_NAME}/0").public_address
    vault_endpoint = f"https://{unit_ip}:8200"
    action_output = await run_get_ca_certificate_action(ops_test)
    ca_certificate = action_output["ca-certificate"]
    with open("ca_file.txt", mode="w+") as ca_file:
        ca_file.write(ca_certificate)
    client = hvac.Client(url=vault_endpoint, verify=abspath(ca_file.name))
    response = client.sys.read_health_status()
    # We accept both 200 and 429 because based on Vault's documentation:
    # 200: {{Description: "initialized, unsealed, and active"}}
    # 429: {{Description: "unsealed and standby"}}
    # 472: {{Description: "data recovery mode replication secondary and active"}}
    # 501: {{Description: "not initialized"}}
    # 503: {{Description: "sealed"}}
    # TODO: remove 501 when charm initializes vault.
    assert response.status_code in (200, 429, 501)
    os.remove("ca_file.txt")
