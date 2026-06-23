from enum import IntEnum
from typing import Optional

from ragger.bip import pack_derivation_path

from .tlv import TlvSerializable, FieldTag


class AddressBookResponseType(IntEnum):
    TYPE_REGISTER_IDENTITY = 0x2d
    TYPE_EDIT_CONTACT_NAME = 0x2e
    TYPE_REGISTER_LEDGER_ACCOUNT = 0x2f
    TYPE_EDIT_LEDGER_ACCOUNT = 0x30
    TYPE_EDIT_IDENTIFIER = 0x31
    TYPE_EDIT_SCOPE = 0x32
    TYPE_PROVIDE_CONTACT = 0x33
    TYPE_PROVIDE_LEDGER_ACCOUNT_CONTACT = 0x34


class AddressBookSubCommand(IntEnum):
    SUB_CMD_REGISTER_IDENTITY = 0x01
    SUB_CMD_EDIT_CONTACT_NAME = 0x02
    SUB_CMD_EDIT_IDENTIFIER = 0x03
    SUB_CMD_EDIT_SCOPE = 0x04
    SUB_CMD_REGISTER_LEDGER_ACCOUNT = 0x11
    SUB_CMD_EDIT_LEDGER_ACCOUNT = 0x12
    SUB_CMD_PROVIDE_CONTACT = 0x20
    SUB_CMD_PROVIDE_LEDGER_ACCOUNT_CONTACT = 0x21


GROUP_HANDLE_LENGTH = 64  # group_handle = gid(32) | MAC(K_group, gid)(32)
GID_SIZE = 32  # first half of group_handle, used in HMAC messages
HMAC_PROOF_LENGTH = 32
CONTACT_NAME_MAX_LENGTH = 32  # CONTACT_NAME_LENGTH(33) - 1 null terminator
SCOPE_MAX_LENGTH = 32         # SCOPE_LENGTH(33) - 1 null terminator
DEFAULT_BIP32_PATH = "m/44'/60'/0'/0/0"
DEFAULT_CONTACT_NAME = "Alice"
DEFAULT_CHAIN_ID = 1  # Ethereum Mainnet
DEFAULT_SCOPE = "Eth Address 1"
DEFAULT_ADDRESS = bytes.fromhex("6b175474e89094c44da98b954eedeac495271d0f")
DEFAULT_ACCOUNT_NAME = "ETH main address"


class AddressBookCommand(TlvSerializable):
    """Base class for every Address Book sub-command.

    Each sub-command is its own TlvSerializable: it carries the data and knows
    how to serialize() itself into a TLV payload, exactly like TrustedName or
    ProxyInfo. The `subcommand` class attribute selects the APDU P1; the APDU
    encapsulation (CLA/INS, P1, P2 chunking) is handled app-side in
    CommandBuilder.provide_address_book() / EthAppClient.provide_address_book().
    """
    subcommand: AddressBookSubCommand
    struct_type: AddressBookResponseType


class RegisterIdentity(AddressBookCommand):
    """Register Identity sub-command (P1=0x01, struct type 0x2d)."""
    subcommand = AddressBookSubCommand.SUB_CMD_REGISTER_IDENTITY
    struct_type = AddressBookResponseType.TYPE_REGISTER_IDENTITY

    def __init__(self,
                 address: bytes,
                 contact_name: str = DEFAULT_CONTACT_NAME,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID,
                 scope: str = DEFAULT_SCOPE,
                 group_handle: Optional[bytes] = None,
                 hmac_proof: Optional[bytes] = None) -> None:
        """
        Args:
            address: Unique address for the contact (e.g. 20-byte Ethereum address)
            contact_name: Name of the contact (max 32 chars, printable ASCII)
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
            scope: Scope/namespace for the address (max 32 chars)
            group_handle: Optional 64-byte group handle to link this address to an existing group
            hmac_proof: Optional HMAC_NAME required when group_handle is provided
        """
        self.address = address
        self.contact_name = contact_name
        self.derivation_path = derivation_path
        self.chain_id = chain_id
        self.scope = scope
        self.group_handle = group_handle
        self.hmac_proof = hmac_proof

    def serialize(self) -> bytes:
        assert self.contact_name and len(self.contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert len(self.address) > 0, "Identifier is required"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"
        assert (self.group_handle is None) == (self.hmac_proof is None), \
            "group_handle and hmac_proof must be provided together"
        if self.group_handle is not None:
            assert len(self.group_handle) == GROUP_HANDLE_LENGTH, \
                f"group_handle must be {GROUP_HANDLE_LENGTH} bytes"
        if self.hmac_proof is not None:
            assert len(self.hmac_proof) == HMAC_PROOF_LENGTH, \
                f"hmac_proof must be {HMAC_PROOF_LENGTH} bytes"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.SCOPE, self.scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.ACCOUNT_IDENTIFIER, self.address)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        if self.group_handle is not None:
            payload += self.serialize_field(FieldTag.GROUP_HANDLE, self.group_handle)
        if self.hmac_proof is not None:
            payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_proof)
        return payload


class EditContactName(AddressBookCommand):
    """Edit Contact Name sub-command (P1=0x02, struct type 0x2e).

    Only needs group_handle + names + path + HMAC_NAME — no address, scope,
    or network required (HMAC_NAME covers only gid + name).
    """
    subcommand = AddressBookSubCommand.SUB_CMD_EDIT_CONTACT_NAME
    struct_type = AddressBookResponseType.TYPE_EDIT_CONTACT_NAME

    def __init__(self,
                 old_contact_name: str,
                 new_contact_name: str,
                 hmac_proof: bytes,
                 group_handle: bytes,
                 derivation_path: str = DEFAULT_BIP32_PATH) -> None:
        """
        Args:
            old_contact_name: Current (old) name of the contact
            new_contact_name: New name to assign to the contact
            hmac_proof: HMAC_NAME from the original Register Identity response
            group_handle: 64-byte group handle received from the Register Identity response
            derivation_path: BIP32 path used to derive the HMAC key on device
        """
        self.old_contact_name = old_contact_name
        self.new_contact_name = new_contact_name
        self.hmac_proof = hmac_proof
        self.group_handle = group_handle
        self.derivation_path = derivation_path

    def serialize(self) -> bytes:
        assert self.old_contact_name and len(self.old_contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Previous contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert self.new_contact_name and len(self.new_contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"New contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert len(self.group_handle) == GROUP_HANDLE_LENGTH, \
            f"group_handle must be {GROUP_HANDLE_LENGTH} bytes"
        assert self.derivation_path, "Derivation path is required"
        assert len(self.hmac_proof) == HMAC_PROOF_LENGTH, f"HMAC_PROOF must be {HMAC_PROOF_LENGTH} bytes"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.new_contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.PREVIOUS_CONTACT_NAME, self.old_contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.GROUP_HANDLE, self.group_handle)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_proof)
        return payload


class EditIdentifier(AddressBookCommand):
    """Edit Identifier sub-command (P1=0x03, struct type 0x31, multi-chunk)."""
    subcommand = AddressBookSubCommand.SUB_CMD_EDIT_IDENTIFIER
    struct_type = AddressBookResponseType.TYPE_EDIT_IDENTIFIER

    def __init__(self,
                 new_address: bytes,
                 hmac_proof: bytes,
                 hmac_rest: bytes,
                 group_handle: bytes,
                 old_address: bytes = DEFAULT_ADDRESS,
                 contact_name: str = DEFAULT_CONTACT_NAME,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID,
                 scope: str = DEFAULT_SCOPE) -> None:
        """
        Args:
            new_address: New address bytes (e.g. 20-byte Ethereum address)
            hmac_proof: HMAC_NAME from the original Register Identity response
            hmac_rest: HMAC_REST from the original Register Identity response
            group_handle: 64-byte group handle received from the Register Identity response
            old_address: Current (old) address bytes
            contact_name: Name of the contact (unchanged, for display)
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
            scope: Scope/namespace for the address (unchanged)
        """
        self.new_address = new_address
        self.hmac_proof = hmac_proof
        self.hmac_rest = hmac_rest
        self.group_handle = group_handle
        self.old_address = old_address
        self.contact_name = contact_name
        self.derivation_path = derivation_path
        self.chain_id = chain_id
        self.scope = scope

    def serialize(self) -> bytes:
        assert self.contact_name and len(self.contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert len(self.group_handle) == GROUP_HANDLE_LENGTH, f"group_handle must be {GROUP_HANDLE_LENGTH} bytes"
        assert len(self.new_address) > 0, "New address is required"
        assert len(self.old_address) > 0, "Old address is required"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"
        assert len(self.hmac_proof) == HMAC_PROOF_LENGTH, f"HMAC_PROOF must be {HMAC_PROOF_LENGTH} bytes"
        assert len(self.hmac_rest) == HMAC_PROOF_LENGTH, f"HMAC_REST proof must be {HMAC_PROOF_LENGTH} bytes"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.SCOPE, self.scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.ACCOUNT_IDENTIFIER, self.new_address)
        payload += self.serialize_field(FieldTag.PREVIOUS_IDENTIFIER, self.old_address)
        payload += self.serialize_field(FieldTag.GROUP_HANDLE, self.group_handle)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_proof)
        payload += self.serialize_field(FieldTag.HMAC_REST, self.hmac_rest)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload


class EditScope(AddressBookCommand):
    """Edit Scope sub-command (P1=0x04, struct type 0x32, multi-chunk)."""
    subcommand = AddressBookSubCommand.SUB_CMD_EDIT_SCOPE
    struct_type = AddressBookResponseType.TYPE_EDIT_SCOPE

    def __init__(self,
                 old_scope: str,
                 new_scope: str,
                 hmac_proof: bytes,
                 hmac_rest: bytes,
                 group_handle: bytes,
                 address: bytes = DEFAULT_ADDRESS,
                 contact_name: str = DEFAULT_CONTACT_NAME,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID) -> None:
        """
        Args:
            old_scope: Current (old) scope of the contact
            new_scope: New scope to assign to the contact
            hmac_proof: HMAC_NAME from the original Register Identity response
            hmac_rest: HMAC_REST from the original Register Identity response
            group_handle: 64-byte group handle received from the Register Identity response
            address: Raw address bytes (e.g. 20-byte Ethereum address)
            contact_name: Name of the contact (unchanged, for display)
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
        """
        self.old_scope = old_scope
        self.new_scope = new_scope
        self.hmac_proof = hmac_proof
        self.hmac_rest = hmac_rest
        self.group_handle = group_handle
        self.address = address
        self.contact_name = contact_name
        self.derivation_path = derivation_path
        self.chain_id = chain_id

    def serialize(self) -> bytes:
        assert self.contact_name and len(self.contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert len(self.group_handle) == GROUP_HANDLE_LENGTH, f"group_handle must be {GROUP_HANDLE_LENGTH} bytes"
        assert self.old_scope and len(self.old_scope) <= SCOPE_MAX_LENGTH, \
            f"Previous scope required (max {SCOPE_MAX_LENGTH} chars)"
        assert self.new_scope and len(self.new_scope) <= SCOPE_MAX_LENGTH, \
            f"New scope required (max {SCOPE_MAX_LENGTH} chars)"
        assert len(self.address) > 0, "Identifier is required"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"
        assert len(self.hmac_proof) == HMAC_PROOF_LENGTH, f"HMAC_PROOF must be {HMAC_PROOF_LENGTH} bytes"
        assert len(self.hmac_rest) == HMAC_PROOF_LENGTH, f"HMAC_REST proof must be {HMAC_PROOF_LENGTH} bytes"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.SCOPE, self.new_scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.ACCOUNT_IDENTIFIER, self.address)
        payload += self.serialize_field(FieldTag.PREVIOUS_SCOPE, self.old_scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.GROUP_HANDLE, self.group_handle)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_proof)
        payload += self.serialize_field(FieldTag.HMAC_REST, self.hmac_rest)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload


class RegisterLedgerAccount(AddressBookCommand):
    """Register Ledger Account sub-command (P1=0x11, struct type 0x2f)."""
    subcommand = AddressBookSubCommand.SUB_CMD_REGISTER_LEDGER_ACCOUNT
    struct_type = AddressBookResponseType.TYPE_REGISTER_LEDGER_ACCOUNT

    def __init__(self,
                 contact_name: str = DEFAULT_ACCOUNT_NAME,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID) -> None:
        """
        Args:
            contact_name: Name for this contact
            derivation_path: BIP32 derivation path as string (e.g., "m/44'/60'/0'/0/0")
            chain_id: Chain ID for the network
        """
        self.contact_name = contact_name
        self.derivation_path = derivation_path
        self.chain_id = chain_id

    def serialize(self) -> bytes:
        assert self.contact_name and len(self.contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload


class EditLedgerAccount(AddressBookCommand):
    """Edit Ledger Account sub-command (P1=0x12, struct type 0x30)."""
    subcommand = AddressBookSubCommand.SUB_CMD_EDIT_LEDGER_ACCOUNT
    struct_type = AddressBookResponseType.TYPE_EDIT_LEDGER_ACCOUNT

    def __init__(self,
                 new_account_name: str,
                 hmac_proof: bytes,
                 old_account_name: str = DEFAULT_ACCOUNT_NAME,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID) -> None:
        """
        Args:
            new_account_name: New name to assign to the account
            hmac_proof: HMAC Proof of Registration from the previous registration
            old_account_name: Current name of the account
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id: Chain ID for the network
        """
        self.new_account_name = new_account_name
        self.hmac_proof = hmac_proof
        self.old_account_name = old_account_name
        self.derivation_path = derivation_path
        self.chain_id = chain_id

    def serialize(self) -> bytes:
        assert self.old_account_name and len(self.old_account_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Old account name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert self.new_account_name and len(self.new_account_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"New account name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"
        assert len(self.hmac_proof) == HMAC_PROOF_LENGTH, f"HMAC proof must be {HMAC_PROOF_LENGTH} bytes"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.new_account_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.PREVIOUS_CONTACT_NAME, self.old_account_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_proof)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        return payload


class ProvideContact(AddressBookCommand):
    """Provide Contact sub-command (P1=0x20, struct type 0x33, multi-chunk).

    Delivers a previously registered contact to the device so that the
    application can substitute the contact name for the raw address during
    transaction review. No UI is displayed; the device responds with 9000.
    """
    subcommand = AddressBookSubCommand.SUB_CMD_PROVIDE_CONTACT
    struct_type = AddressBookResponseType.TYPE_PROVIDE_CONTACT

    def __init__(self,
                 address: bytes,
                 group_handle: bytes,
                 hmac_name: bytes,
                 hmac_rest: bytes,
                 contact_name: str = DEFAULT_CONTACT_NAME,
                 scope: str = DEFAULT_SCOPE,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID) -> None:
        """
        Args:
            address:         Raw 20-byte Ethereum address
            group_handle:    64-byte group handle from the Register Identity response
            hmac_name:       HMAC_PROOF (32 B) from the Register Identity response
            hmac_rest:       HMAC_REST  (32 B) from the Register Identity response
            contact_name:    Human-readable name bound to the address
            scope:           Scope/namespace for the address (e.g. "Eth Address 1")
            derivation_path: BIP32 path used to derive the HMAC key on device
            chain_id:        Chain ID for the network
        """
        self.address = address
        self.group_handle = group_handle
        self.hmac_name = hmac_name
        self.hmac_rest = hmac_rest
        self.contact_name = contact_name
        self.scope = scope
        self.derivation_path = derivation_path
        self.chain_id = chain_id

    def serialize(self) -> bytes:
        assert self.contact_name and len(self.contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert self.scope and len(self.scope) <= SCOPE_MAX_LENGTH, \
            f"Scope required (max {SCOPE_MAX_LENGTH} chars)"
        assert len(self.address) > 0, "Address is required"
        assert len(self.group_handle) == GROUP_HANDLE_LENGTH, \
            f"group_handle must be {GROUP_HANDLE_LENGTH} bytes"
        assert len(self.hmac_name) == HMAC_PROOF_LENGTH, \
            f"HMAC_PROOF must be {HMAC_PROOF_LENGTH} bytes"
        assert len(self.hmac_rest) == HMAC_PROOF_LENGTH, \
            f"HMAC_REST must be {HMAC_PROOF_LENGTH} bytes"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.SCOPE, self.scope.encode('utf-8'))
        payload += self.serialize_field(FieldTag.ACCOUNT_IDENTIFIER, self.address)
        payload += self.serialize_field(FieldTag.GROUP_HANDLE, self.group_handle)
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_name)
        payload += self.serialize_field(FieldTag.HMAC_REST, self.hmac_rest)
        return payload


class ProvideLedgerAccountContact(AddressBookCommand):
    """Provide Ledger Account Contact sub-command (P1=0x21, struct type 0x34, multi-chunk).

    Unlike an Identity contact (P1=0x20), a Ledger Account contact has no external
    address, no group_handle, no hmac_rest, and no scope: the device derives the
    address internally from the derivation_path and verifies authenticity via
    hmac_proof (the HMAC Proof of Registration from RegisterLedgerAccount).
    """
    subcommand = AddressBookSubCommand.SUB_CMD_PROVIDE_LEDGER_ACCOUNT_CONTACT
    struct_type = AddressBookResponseType.TYPE_PROVIDE_LEDGER_ACCOUNT_CONTACT

    def __init__(self,
                 hmac_proof: bytes,
                 contact_name: str = DEFAULT_ACCOUNT_NAME,
                 derivation_path: str = DEFAULT_BIP32_PATH,
                 chain_id: int = DEFAULT_CHAIN_ID) -> None:
        """
        Args:
            hmac_proof:      32-byte HMAC proof from the Register Ledger Account response
            contact_name:    Human-readable account name
            derivation_path: BIP32 path used to derive the address and the HMAC key
            chain_id:        Chain ID for the network
        """
        self.hmac_proof = hmac_proof
        self.contact_name = contact_name
        self.derivation_path = derivation_path
        self.chain_id = chain_id

    def serialize(self) -> bytes:
        assert self.contact_name and len(self.contact_name) <= CONTACT_NAME_MAX_LENGTH, \
            f"Contact name required (max {CONTACT_NAME_MAX_LENGTH} chars)"
        assert len(self.hmac_proof) == HMAC_PROOF_LENGTH, \
            f"hmac_proof must be {HMAC_PROOF_LENGTH} bytes"
        assert self.derivation_path, "Derivation path is required"
        assert self.chain_id > 0, "Chain ID must be greater than 0"

        path_bytes = pack_derivation_path(self.derivation_path)

        payload: bytes = self.serialize_field(FieldTag.STRUCT_TYPE, self.struct_type)
        payload += self.serialize_field(FieldTag.STRUCT_VERSION, 1)
        payload += self.serialize_field(FieldTag.CONTACT_NAME, self.contact_name.encode('utf-8'))
        payload += self.serialize_field(FieldTag.DERIVATION_PATH, path_bytes)
        payload += self.serialize_field(FieldTag.CHAIN_ID, self.chain_id)
        payload += self.serialize_field(FieldTag.BLOCKCHAIN_FAMILY, 1)  # Ethereum
        payload += self.serialize_field(FieldTag.HMAC_PROOF, self.hmac_proof)
        return payload
