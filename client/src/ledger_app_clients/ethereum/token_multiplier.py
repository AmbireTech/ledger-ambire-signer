from typing import Optional
from ragger.pki import SigningPartner
from ragger.tlv import TlvSerializable, LedgerCommonFieldTag
from .signing_partners import TOKEN_MULTIPLIER


# ERC-8056 UI multiplier scaling: 1e18 == 1.0x.
UI_MULTIPLIER_DECIMALS = 18
UI_MULTIPLIER_ONE = 10**UI_MULTIPLIER_DECIMALS


class TokenMultiplier(TlvSerializable):
    """ERC-8056 signed token multiplier descriptor.

    The multiplier is an 18-decimals fixed-point value (1e18 == 1.0x), exactly
    as returned by the token's ``uiMultiplier()``. The signer key and algorithm
    are not part of the payload: with LedgerPKI they are carried by the
    certificate (resolved via key_usage), like proxy_info.
    """

    challenge: int
    address: bytes
    chain_id: int
    multiplier: int
    signature: Optional[bytes]

    def __init__(
        self,
        challenge: int,
        address: bytes,
        chain_id: int,
        multiplier: int,
        signature: Optional[bytes] = None,
        signer: SigningPartner = TOKEN_MULTIPLIER,
    ):
        self.challenge = challenge
        self.address = address
        self.chain_id = chain_id
        self.multiplier = multiplier
        self.signature = signature
        self._signer = signer

    def serialize(self) -> bytes:
        payload = bytearray()
        payload += self.serialize_field(LedgerCommonFieldTag.STRUCTURE_TYPE, 0x27)
        payload += self.serialize_field(LedgerCommonFieldTag.VERSION, 1)
        payload += self.serialize_field(LedgerCommonFieldTag.CHALLENGE, self.challenge)
        payload += self.serialize_field(LedgerCommonFieldTag.ADDRESS, self.address)
        payload += self.serialize_field(LedgerCommonFieldTag.CHAIN_ID, self.chain_id)
        # uint256 big-endian, minimal length (the device reads it via convertUint256BE)
        # TODO: replace with proper tag when available in ragger
        payload += self.serialize_field(0x30, self.multiplier)
        sig = self.signature
        if sig is None:
            sig = self._signer.sign(bytes(payload))
        payload += self.serialize_field(LedgerCommonFieldTag.DER_SIGNATURE, sig)
        return bytes(payload)
