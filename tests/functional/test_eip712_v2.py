"""Functional tests for the EIP-712 V2 clear-signing protocol.

V2 delivers the whole typed message in two one-shot TLV payloads — EIP712_SCHEMA then
EIP712_VALUES — before a bare SIGN command triggers the signature.

The signature check is the meaningful assertion here: the expected address is recovered from a
hash that eth_account computes independently from the same JSON, so it only matches if the
app's schema parsing, value tree and hashing all agree with the EIP-712 standard.
"""

import fnmatch
import json
import os
from pathlib import Path

import client.response_parser as ResponseParser
import pytest
from client.client import EthAppClient
from client.eip712 import json_to_tlv
from client.status_word import StatusWord
from client.utils import recover_message
from ragger.backend import BackendInterface
from ragger.error import ExceptionRAPDU

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


@pytest.fixture(name="app_client")
def app_client_fixture(backend: BackendInterface) -> EthAppClient:
    return EthAppClient(backend)


def get_wallet_addr(app_client: EthAppClient, bip32_path: str = BIP32_PATH) -> bytes:
    with app_client.get_public_addr(display=False, bip32_path=bip32_path):
        pass
    _, addr, _ = ResponseParser.pk_addr(app_client.response().data)
    return addr


def load(input_file: Path) -> dict:
    with open(input_file, encoding="utf-8") as file:
        return json.load(file)


def test_eip712_v2_sign(app_client: EthAppClient, input_file: Path):
    """The app must derive the reference EIP-712 hash for every known typed message."""
    data = load(input_file)
    vrs = json_to_tlv.sign(app_client, data, BIP32_PATH)
    assert get_wallet_addr(app_client) == recover_message(data, vrs)


def test_eip712_v2_derivation_path(app_client: EthAppClient):
    """The signing key must come from the path carried by EIP712_VALUES, not a default one."""
    data = load(Path(input_files()[0]))
    vrs = json_to_tlv.sign(app_client, data, OTHER_BIP32_PATH)
    assert get_wallet_addr(app_client, OTHER_BIP32_PATH) == recover_message(data, vrs)


def test_eip712_v2_values_without_schema(app_client: EthAppClient):
    """Values naming struct types that were never declared must be refused."""
    data = load(Path(input_files()[0]))
    payload = json_to_tlv.values_from_json(data, BIP32_PATH).serialize()
    with pytest.raises(ExceptionRAPDU) as e:
        app_client.eip712_v2_send_values(payload)
    assert e.value.status == StatusWord.SWO_INCORRECT_DATA


def test_eip712_v2_sign_without_values(app_client: EthAppClient):
    """Signing before a message has been delivered must be refused."""
    data = load(Path(input_files()[0]))
    response = app_client.eip712_v2_send_schema(json_to_tlv.schema_from_json(data).serialize())
    assert response.status == StatusWord.SWO_SUCCESS

    with pytest.raises(ExceptionRAPDU) as e:
        with app_client.eip712_v2_sign():
            pass
    assert e.value.status == StatusWord.SWO_COMMAND_NOT_ALLOWED


def test_eip712_v2_sign_twice(app_client: EthAppClient):
    """A second signature must not be obtainable from an already consumed message."""
    json_to_tlv.sign(app_client, load(Path(input_files()[0])), BIP32_PATH)

    with pytest.raises(ExceptionRAPDU) as e:
        with app_client.eip712_v2_sign():
            pass
    assert e.value.status == StatusWord.SWO_COMMAND_NOT_ALLOWED
