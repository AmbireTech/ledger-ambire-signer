# Functional tests for the ERC-8056 "token multiplier" (UI multiplier) feature.
#
# ERC-8056 lets a token expose a `uiMultiplier()` (18-decimals fixed point,
# 1e18 == 1.0x) so a stock-split-like rescale can happen without moving tokens:
# on-chain amounts stay raw, only the *displayed* amount is multiplied.
#
# On the device the multiplier is delivered as a LedgerPKI-signed descriptor
# (PROVIDE_TOKEN_MULTIPLIER APDU, anti-replay via GET_CHALLENGE). Once stored,
# it scales the amount shown during clear-signing. Two clear-signing paths feed
# off the same store and are both covered here:
#   - the legacy internal ERC-20 plugin (automatic on transfer/approve);
#   - the Generic Transaction Parser (GTP / GCS), via a TOKEN_AMOUNT field.

import json

import pytest
from web3 import Web3

from ragger.error import ExceptionRAPDU
from ragger.backend import BackendInterface
from ragger.navigator.navigation_scenario import NavigateWithScenario

from constants import ABIS_FOLDER
from fields_utils import get_all_paths
from test_sign import common as common_tx, BIP32_PATH
from test_gcs import compute_inst_hash

import client.response_parser as ResponseParser
from client.client import EthAppClient, SignMode
from client.status_word import StatusWord
from client.utils import get_selector_from_data
from client.gcs import (
    Field,
    ParamRaw,
    ParamTokenAmount,
    Value,
    TypeFamily,
    DataPath,
    ContainerPath,
    TxInfo,
)
from client.token_multiplier import TokenMultiplier, UI_MULTIPLIER_ONE

# =============================================================================
# TX signing constants (shared across tests)
# =============================================================================

# Same token values as the ERC-20 functional tests (USDC mainnet).
# Reusing them lets the identity (1.0x no-op) case of test_token_multiplier_erc20
# compare against the plain transfer's golden snapshots (test_name="test_transfer_erc20").
TOKEN_ADDR = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
TOKEN_TICKER = "USDC"
TOKEN_DECIMALS = 6
TOKEN_CHAIN_ID = 1

RECIPIENT = bytes.fromhex("d8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

# A 10x split: a raw transfer of N tokens must be shown as 10*N tokens.
MULTIPLIER_10X = 10 * UI_MULTIPLIER_ONE


# =============================================================================
# Test helpers
# =============================================================================


def _build_transfer_tx(amount_raw_units: int) -> dict:
    """Build an EIP-1559 ERC-20 `transfer(RECIPIENT, amount_raw_units)` tx."""
    with open(f"{ABIS_FOLDER}/erc20.json", encoding="utf-8") as file:
        contract = Web3().eth.contract(abi=json.load(file), address=None)
    data = contract.encode_abi("transfer", [RECIPIENT, amount_raw_units])
    return {
        "chainId": TOKEN_CHAIN_ID,
        "nonce": 1337,
        "maxPriorityFeePerGas": Web3.to_wei(0, "gwei"),
        "maxFeePerGas": Web3.to_wei(2.55, "gwei"),
        "gas": 94548,
        "to": TOKEN_ADDR,
        "value": Web3.to_wei(0, "ether"),
        "data": data,
    }


def _get_challenge(app_client: EthAppClient) -> int:
    """Fetch a fresh anti-replay challenge from the device."""
    return ResponseParser.challenge(app_client.get_challenge().data)


def _provide_multiplier(
    app_client: EthAppClient, multiplier: int, challenge: int = None
):
    """Build, sign (test PKI) and send a token multiplier descriptor.

    When @challenge is None a fresh one is fetched right before (the device
    consumes/rolls it as soon as the descriptor is verified). Passing an
    explicit @challenge lets tests exercise the anti-replay rejection.
    """
    if challenge is None:
        challenge = _get_challenge(app_client)
    descriptor = TokenMultiplier(
        challenge=challenge,
        address=TOKEN_ADDR,
        chain_id=TOKEN_CHAIN_ID,
        multiplier=multiplier,
    ).serialize()
    return app_client.provide_token_multiplier(descriptor)


# =============================================================================
# Legacy internal ERC-20 plugin path (transfer/approve handled automatically)
# =============================================================================


@pytest.mark.parametrize(
    "multiplier, snapshot_name",
    [
        # 10x split: a raw transfer of 10 USDC must display as 100 USDC.
        pytest.param(MULTIPLIER_10X, "test_token_multiplier_erc20", id="10x"),
        # Identity 1.0x is a no-op: the amount stays the raw 10 USDC, so we reuse
        # the plain transfer's snapshots to prove the rendering is byte-for-byte
        # identical to the no-multiplier case.
        pytest.param(UI_MULTIPLIER_ONE, "test_transfer_erc20", id="identity"),
    ],
)
def test_token_multiplier_erc20(
    scenario_navigator: NavigateWithScenario, multiplier: int, snapshot_name: str
):
    """A 10 USDC transfer rendered through the legacy ERC-20 plugin, scaled by
    the provided UI multiplier (100 USDC at 10x, 10 USDC at the 1.0x no-op)."""
    app_client = EthAppClient(scenario_navigator.backend)
    # The token must be known (CAL) for the amount to carry a ticker/decimals.
    app_client.provide_token_metadata(
        TOKEN_TICKER, TOKEN_ADDR, TOKEN_DECIMALS, TOKEN_CHAIN_ID
    )
    response = _provide_multiplier(app_client, multiplier)
    assert response.status == StatusWord.SWO_SUCCESS

    tx_params = _build_transfer_tx(10 * pow(10, TOKEN_DECIMALS))
    common_tx(scenario_navigator, tx_params, snapshot_name)


def test_token_multiplier_wrong_challenge(backend: BackendInterface):
    """A descriptor carrying a stale/forged challenge must be rejected."""
    app_client = EthAppClient(backend)
    app_client.provide_token_metadata(
        TOKEN_TICKER, TOKEN_ADDR, TOKEN_DECIMALS, TOKEN_CHAIN_ID
    )
    # Roll a real challenge on the device, then send the descriptor with a
    # flipped one: it no longer matches what the device expects.
    challenge = _get_challenge(app_client)
    challenge = ~challenge & 0xFFFFFFFF
    with pytest.raises(ExceptionRAPDU) as err:
        _provide_multiplier(app_client, MULTIPLIER_10X, challenge)
    assert err.value.status == StatusWord.SWO_INCORRECT_DATA


# =============================================================================
# Generic Transaction Parser (GTP / GCS) path, via a TOKEN_AMOUNT field
# =============================================================================


def test_token_multiplier_gtp(scenario_navigator: NavigateWithScenario):
    """Same 10x rescale, but through the generic parser instead of the plugin.

    The transfer is clear-signed with explicit GCS field descriptors: a
    TOKEN_AMOUNT field (amount = the `_value` calldata param, token = the tx
    destination contract) and a raw recipient address. The multiplier must
    scale the TOKEN_AMOUNT screen (10 USDC -> 100 USDC) exactly like the
    legacy plugin does.
    """
    backend = scenario_navigator.backend
    app_client = EthAppClient(backend)

    tx_params = _build_transfer_tx(10 * pow(10, TOKEN_DECIMALS))

    # 1) Store the transaction (GTP two-phase signing: STORE then START_FLOW).
    with app_client.sign(BIP32_PATH, tx_params, mode=SignMode.STORE):
        pass

    # 2) Describe how to render the calldata.
    param_paths = get_all_paths(f"{ABIS_FOLDER}/erc20.json", "transfer")
    fields = [
        Field(
            1,
            "Send",
            ParamTokenAmount(
                1,
                # amount: the uint256 `_value` parameter of transfer()
                Value(
                    1,
                    TypeFamily.UINT,
                    type_size=32,
                    data_path=DataPath(1, param_paths["_value"]),
                ),
                # token: the contract being called (tx destination)
                token=Value(
                    1,
                    TypeFamily.ADDRESS,
                    container_path=ContainerPath.TO,
                ),
            ),
        ),
        Field(
            1,
            "To",
            ParamRaw(
                1,
                Value(
                    1,
                    TypeFamily.ADDRESS,
                    data_path=DataPath(1, param_paths["_to"]),
                ),
            ),
        ),
    ]

    tx_info = TxInfo(
        1,
        tx_params["chainId"],
        tx_params["to"],
        get_selector_from_data(tx_params["data"]),
        compute_inst_hash(fields),
        "transfer",
    )
    app_client.provide_transaction_info(tx_info.serialize())

    # 3) Provide the token metadata (ticker/decimals) and the signed multiplier.
    app_client.provide_token_metadata(
        TOKEN_TICKER, TOKEN_ADDR, TOKEN_DECIMALS, TOKEN_CHAIN_ID
    )
    response = _provide_multiplier(app_client, MULTIPLIER_10X)
    assert response.status == StatusWord.SWO_SUCCESS

    # 4) Provide the field descriptors and run the review flow.
    for field in fields:
        app_client.provide_transaction_field_desc(field.serialize())

    with app_client.sign(mode=SignMode.START_FLOW):
        scenario_navigator.review_approve(test_name=scenario_navigator.test_name)
