"""Functional tests for the EIP-712 V2 clear-signing protocol.

V2 delivers the whole typed message in two one-shot TLV payloads — EIP712_SCHEMA then
EIP712_VALUES — before a bare SIGN command triggers the review.

The signature check is the meaningful assertion here: the expected address is recovered from a
hash that eth_account computes independently from the same JSON, so it only matches if the
app's schema parsing, value tree and hashing all agree with the EIP-712 standard.

V2 has no field descriptors yet, so every message is displayed raw. That is blind signing, so
the setting has to be enabled and the review carries a warning page.
"""

import fnmatch
import json
import os
from pathlib import Path

import client.response_parser as ResponseParser
import pytest
from client.client import EthAppClient
from client.eip712 import json_to_tlv
from client.settings import SettingID, settings_toggle
from client.status_word import StatusWord
from client.utils import recover_message
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavigateWithScenario

BIP32_PATH = "m/44'/60'/0'/0/0"
OTHER_BIP32_PATH = "m/44'/60'/1'/0/0"


def input_files() -> list[str]:
    json_path = f"{os.path.dirname(__file__)}/eip712_input_files"
    return sorted(file.path for file in os.scandir(json_path) if fnmatch.fnmatch(file.name, "*-data.json"))


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    if "input_file" in metafunc.fixturenames:
        metafunc.parametrize(
            "input_file",
            [pytest.param(Path(f), id="-".join(Path(f).stem.split("-")[:-1])) for f in input_files()],
        )


def load(input_file: Path) -> dict:
    with open(input_file, encoding="utf-8") as file:
        return json.load(file)


def get_wallet_addr(app_client: EthAppClient, bip32_path: str = BIP32_PATH) -> bytes:
    with app_client.get_public_addr(display=False, bip32_path=bip32_path):
        pass
    _, addr, _ = ResponseParser.pk_addr(app_client.response().data)
    return addr


def enable_blind_signing(scenario_navigator: NavigateWithScenario) -> None:
    settings_toggle(
        scenario_navigator.backend.device,
        scenario_navigator.navigator,
        [SettingID.BLIND_SIGNING],
    )


def sign_and_approve(
    scenario_navigator: NavigateWithScenario,
    data: dict,
    bip32_path: str = BIP32_PATH,
) -> tuple[int, int, int]:
    """Deliver the message, approve the review, and return the (v, r, s) signature."""
    app_client = EthAppClient(scenario_navigator.backend)

    json_to_tlv.process_data(app_client, data, bip32_path)
    with app_client.eip712_v2_sign():
        # a raw display always warns about blind signing
        scenario_navigator.review_approve_with_warning(do_comparison=False, nb_warnings=1)
    return ResponseParser.signature(app_client.response().data)


def test_eip712_v2_sign(scenario_navigator: NavigateWithScenario, input_file: Path):
    """The app must derive the reference EIP-712 hash for every known typed message."""
    enable_blind_signing(scenario_navigator)
    data = load(input_file)
    vrs = sign_and_approve(scenario_navigator, data)
    assert get_wallet_addr(EthAppClient(scenario_navigator.backend)) == recover_message(data, vrs)


def test_eip712_v2_derivation_path(scenario_navigator: NavigateWithScenario):
    """The signing key must come from the path carried by EIP712_VALUES, not a default one."""
    enable_blind_signing(scenario_navigator)
    data = load(Path(input_files()[0]))
    vrs = sign_and_approve(scenario_navigator, data, OTHER_BIP32_PATH)
    addr = get_wallet_addr(EthAppClient(scenario_navigator.backend), OTHER_BIP32_PATH)
    assert addr == recover_message(data, vrs)


def test_eip712_v2_reject(scenario_navigator: NavigateWithScenario):
    """Rejecting the review must not produce a signature."""
    enable_blind_signing(scenario_navigator)
    app_client = EthAppClient(scenario_navigator.backend)

    json_to_tlv.process_data(app_client, load(Path(input_files()[0])), BIP32_PATH)
    with pytest.raises(ExceptionRAPDU) as e:
        with app_client.eip712_v2_sign():
            scenario_navigator.review_reject_with_warning(do_comparison=False)
    assert e.value.status == StatusWord.SWO_CONDITIONS_NOT_SATISFIED


def test_eip712_v2_blind_signing_disabled(scenario_navigator: NavigateWithScenario):
    """Without the blind signing setting, a raw message must be refused rather than displayed."""
    app_client = EthAppClient(scenario_navigator.backend)

    json_to_tlv.process_data(app_client, load(Path(input_files()[0])), BIP32_PATH)
    with pytest.raises(ExceptionRAPDU) as e:
        with app_client.eip712_v2_sign():
            pass
    assert e.value.status == StatusWord.SWO_INCORRECT_DATA


def test_eip712_v2_values_without_schema(scenario_navigator: NavigateWithScenario):
    """Values sent before any schema must be refused."""
    app_client = EthAppClient(scenario_navigator.backend)

    payload = json_to_tlv.values_from_json(load(Path(input_files()[0])), BIP32_PATH).serialize()
    with pytest.raises(ExceptionRAPDU) as e:
        app_client.eip712_v2_send_values(payload)
    assert e.value.status == StatusWord.SWO_COMMAND_NOT_ALLOWED


def test_eip712_v2_sign_without_values(scenario_navigator: NavigateWithScenario):
    """Signing before a message has been delivered must be refused."""
    app_client = EthAppClient(scenario_navigator.backend)

    response = app_client.eip712_v2_send_schema(
        json_to_tlv.schema_from_json(load(Path(input_files()[0]))).serialize()
    )
    assert response.status == StatusWord.SWO_SUCCESS

    with pytest.raises(ExceptionRAPDU) as e:
        with app_client.eip712_v2_sign():
            pass
    assert e.value.status == StatusWord.SWO_COMMAND_NOT_ALLOWED


def test_eip712_v2_sign_twice(scenario_navigator: NavigateWithScenario):
    """A second signature must not be obtainable from an already consumed message."""
    enable_blind_signing(scenario_navigator)
    sign_and_approve(scenario_navigator, load(Path(input_files()[0])))

    app_client = EthAppClient(scenario_navigator.backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with app_client.eip712_v2_sign():
            pass
    assert e.value.status == StatusWord.SWO_COMMAND_NOT_ALLOWED
