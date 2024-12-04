#!/usr/bin/env python3
import os
import struct
import uuid
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# constants
BCHOC_FILE_PATH = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
AES_KEY = b"R0chLi4uLi4uLi4="  
BLOCK_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_SIZE = struct.calcsize(BLOCK_FORMAT)
REMOVAL_STATES = ["DISPOSED", "DESTROYED", "RELEASED"]

# passwords
PASSWORDS = {
    "CREATOR": "C67C",
    "POLICE": "P80P",
    "ANALYST": "A65A",
    "LAWYER": "L76L",
    "EXECUTIVE": "E69E"
}

def encrypt_value(value):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    if isinstance(value, uuid.UUID):
        padded_value = value.bytes.ljust(32, b"\0")
    elif isinstance(value, int):
        try:
            padded_value = value.to_bytes(4, 'big').ljust(32, b"\0")
        except OverflowError:
            print(f"Error: Item ID {value} is out of range (must be 0 to 4294967295)")
            exit(1)
    else:
        padded_value = value.ljust(32, b"\0")
    
    return encryptor.update(padded_value)

def decrypt_value(encrypted_value):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_value)

def create_initial_block():
    """
    Creates the genesis block with placeholder values.
    """
    placeholder_case_id = b'0' * 32
    placeholder_evidence_id = b'0' * 32
    state = b'INITIAL' + b'\0' * 5
    data_payload = b'Initial block\x00'
    data_length = len(data_payload)
    initial_block = struct.pack(
        BLOCK_FORMAT,
        b'\0' * 32,           # prev_hash (32 null bytes)
        0.0,                  # timestamp
        placeholder_case_id,  # case_id (32 null bytes)
        placeholder_evidence_id,           # evidence_id (32 null bytes)
        state,  # state (12 bytes, padded)
        b'\0' * 12,           # creator (12 null bytes)
        b'\0' * 12,           # owner (12 null bytes)
        data_length           # data_length (0)
    ) + data_payload         # data_payload (empty)

    with open(BCHOC_FILE_PATH, "wb") as f:
        f.write(initial_block)

def get_blocks():
    if not os.path.exists(BCHOC_FILE_PATH):
        create_initial_block()

    blocks = []
    with open(BCHOC_FILE_PATH, "rb") as f:
        while True:
            block_header = f.read(BLOCK_SIZE)
            if not block_header:
                break  # EOF
            if len(block_header) < BLOCK_SIZE:
                raise ValueError("Invalid block header length in blockchain file.")
            fields = struct.unpack(BLOCK_FORMAT, block_header)
            data_length = fields[7]
            data = f.read(data_length)
            if len(data) < data_length:
                raise ValueError("Invalid block data length in blockchain file.")
            blocks.append((block_header, data))
    return blocks

def init():
    if os.path.exists(BCHOC_FILE_PATH):
        try:
            blocks = get_blocks()
            if len(blocks) == 0:
                raise ValueError("Blockchain file is empty.")
            # Optionally, verify the first block is the initial block
            print("Blockchain file found with INITIAL block.")
        except Exception as e:
            print(f"Error: Invalid blockchain file. {str(e)}")
            exit(1)
    else:
        create_initial_block()
        print("Blockchain file not found. Created INITIAL block.")

def show_cases():
    blocks = get_blocks()
    unique_cases = set()

    for i, (block_header, _) in enumerate(blocks):
        _, _, encrypted_case_id, _, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_case_id = decrypt_value(encrypted_case_id)

        if i == 0:
            continue

        try:
            case_uuid = uuid.UUID(bytes=decrypted_case_id[:16])
            unique_cases.add(case_uuid)
        except ValueError:
            continue

    if unique_cases: # merge entire statement
        #print("Unique case IDs in the blockchain:")
        for case_id in unique_cases:
            print(f"{case_id}") #remove dash PASS FOR 059
    else:
        print("No cases found in the blockchain.")

def show_items(case_id): # merge entire funciton
    blocks = get_blocks()
    encrypted_case_id = encrypt_value(uuid.UUID(case_id))
    unique_items = set() 

    for block_header, _ in blocks:
        _, _, curr_case_id, evidence_id_enc, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if curr_case_id == encrypted_case_id:
            decrypted_item_id = decrypt_value(evidence_id_enc)
            try:
                item_id = int.from_bytes(decrypted_item_id.strip(b"\0"), "big")
                unique_items.add(item_id)
            except ValueError:
                continue

    if unique_items:
        #print(f"Items associated with case {case_id}:")
        for item_id in sorted(unique_items):
            print(f"{item_id}") # remove dash PASS 060
    else:
        print(f"No items found for case {case_id}.")

def show_history(item_id, password, num_entries=None, reverse=False):
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)

    blocks = get_blocks()
    history = []

    for block_header, _ in blocks:
        prev_hash, timestamp, case_id_enc, evidence_id_enc, state, creator, owner, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_evidence_id = decrypt_value(evidence_id_enc)
        evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
        
        if evidence_item_id == item_id:
            decrypted_case_id = decrypt_value(case_id_enc)
            decrypted_state = state.strip(b"\0").decode()
            decrypted_creator = creator.strip(b"\0").decode()
            decrypted_owner = owner.strip(b"\0").decode()
            
            history.append({
                "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                "case_id": uuid.UUID(bytes=decrypted_case_id[:16]),
                "state": decrypted_state,
                "creator": decrypted_creator,
                "owner": decrypted_owner
            })

    if reverse:
        history = history[::-1]

    if num_entries is not None:
        history = history[:num_entries]

    if history:
        for record in history:
            print(f"Case: {record['case_id']}")
            print(f"Item: {item_id}")
            print(f"Action: {record['state']}")
            print(f"Time: {record['timestamp']}")
            print()
    else:
        print(f"No history found for item {item_id}.")

def get_item_latest_state(blocks, item_id):
    latest_state = None
    case_id_enc = None
    
    for block_header, _ in blocks:
        _, _, curr_case_id_enc, evidence_id_enc, state, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_evidence_id = decrypt_value(evidence_id_enc)
        evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
        if evidence_item_id == item_id:
            latest_state = state.strip(b"\0").decode()
            case_id_enc = curr_case_id_enc
    
    return latest_state, case_id_enc

def add(case_id, item_ids, creator, password):
    if password != PASSWORDS["CREATOR"]:
        print("Invalid password")
        exit(1)
    
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        print("Error: Invalid UUID format")
        exit(1)
    
    blocks = get_blocks()
    existing_item_ids = set()
    
    # Get existing items
    for block_header, _ in blocks:
        _, _, _, evidence_id_enc, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if evidence_id_enc != b"\0" * 32:
            decrypted_evidence_id = decrypt_value(evidence_id_enc)
            evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
            existing_item_ids.add(evidence_item_id)
    
    # Check for duplicates
    for item_id in item_ids:
        if item_id in existing_item_ids:
            print(f"Error: Item ID {item_id} already exists in blockchain")
            exit(1)
    
    prev_block_header, prev_block_data = blocks[-1]
    
    # Adding items
    for item_id in item_ids:
        encrypted_item_id = encrypt_value(item_id)
        prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
        timestamp = datetime.now(timezone.utc).timestamp()
        encrypted_case_id = encrypt_value(case_uuid)
        
        block_data = b"New evidence"
        data_length = len(block_data)
        block_header = struct.pack(
            BLOCK_FORMAT,
            prev_hash,
            timestamp,
            encrypted_case_id,
            encrypted_item_id,
            b"CHECKEDIN\0\0\0",
            creator.encode().ljust(12, b"\0"),
            b"\0" * 12,
            data_length
        )
        new_block = block_header + block_data
        
        with open(BCHOC_FILE_PATH, "ab") as f:
            f.write(new_block)
        
        # Update prev_block_header and prev_block_data
        prev_block_header = block_header
        prev_block_data = block_data
        
        print(f"Added item: {item_id}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

def checkout(item_id, password):
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    
    blocks = get_blocks()
    latest_state, case_id_enc = get_item_latest_state(blocks, item_id)
    
    if latest_state is None or latest_state in REMOVAL_STATES:
        print(f"Error: Item {item_id} not found")
        exit(1)
    
    if latest_state != "CHECKEDIN":
        print(f"Error: Item {item_id} is not in CHECKEDIN state")
        exit(1)
    
    prev_block_header, prev_block_data = blocks[-1]
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
    timestamp = datetime.now(timezone.utc).timestamp()
    
    encrypted_item_id = encrypt_value(item_id)
    
    checkout_block = struct.pack(
        BLOCK_FORMAT,
        prev_hash,
        timestamp,
        case_id_enc,
        encrypted_item_id,
        b"CHECKEDOUT\0\0",
        b"\0" * 12,
        b"\0" * 12,
        len(b"Checked out")
    ) + b"Checked out"
    
    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(checkout_block)
    
    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id_enc)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Checked out item: {item_id}")
    print("Status: CHECKEDOUT")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

def checkin(item_id, password):
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    
    blocks = get_blocks()
    latest_state, case_id_enc = get_item_latest_state(blocks, item_id)
    
    if latest_state is None or latest_state in REMOVAL_STATES:
        print(f"Error: Item {item_id} not found")
        exit(1)
    
    if latest_state != "CHECKEDOUT":
        print(f"Error: Item {item_id} is not in CHECKEDOUT state")
        exit(1)
    
    prev_block_header, prev_block_data = blocks[-1]
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
    timestamp = datetime.now(timezone.utc).timestamp()
    
    encrypted_item_id = encrypt_value(item_id)
    
    checkin_block = struct.pack(
        BLOCK_FORMAT,
        prev_hash,
        timestamp,
        case_id_enc,
        encrypted_item_id,
        b"CHECKEDIN\0\0\0",
        b"\0" * 12,
        b"\0" * 12,
        len(b"Checked in")
    ) + b"Checked in"
    
    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(checkin_block)
    
    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id_enc)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Checked in item: {item_id}")
    print("Status: CHECKEDIN")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

def remove(item_id, reason, owner_info, password):
    if password != PASSWORDS["CREATOR"]:
        print("Invalid password")
        exit(1)

    if reason not in REMOVAL_STATES:
        print("Error: Invalid reason for removal")
        exit(1)

    # Removed the owner_info check

    blocks = get_blocks()
    latest_state, case_id_enc = get_item_latest_state(blocks, item_id)

    if latest_state is None or latest_state in REMOVAL_STATES:
        print(f"Error: Item {item_id} not found")
        exit(1)

    if latest_state != "CHECKEDIN":
        print(f"Error: Item {item_id} must be in CHECKEDIN state to remove")
        exit(1)

    # Retrieve the original creator
    creator = None
    for block_header, _ in blocks:
        _, _, _, evidence_id_enc, _, creator_bytes, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_evidence_id = decrypt_value(evidence_id_enc)
        evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
        if evidence_item_id == item_id:
            creator = creator_bytes.strip(b"\0").decode()
            break  # Found the initial 'add' block

    if creator is None:
        print(f"Error: Creator not found for item {item_id}")
        exit(1)

    prev_block_header, prev_block_data = blocks[-1]
    data_payload = b""
    data_length = 0

    # Map password to role
    role = None
    for key, value in PASSWORDS.items():
        if value == password:
            role = key
            break
    if role is None:
        print("Invalid password")
        exit(1)

    # Set 'owner' to the user's role
    owner = role.encode().ljust(12, b"\0")

    timestamp = datetime.now(timezone.utc).timestamp()
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()

    encrypted_item_id = encrypt_value(item_id)

    block_header = struct.pack(
        BLOCK_FORMAT,
        prev_hash,
        timestamp,
        case_id_enc,
        encrypted_item_id,
        reason.encode().ljust(12, b"\0"),
        creator.encode().ljust(12, b"\0"),
        owner,
        data_length
    )
    new_block = block_header + data_payload

    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(new_block)

    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id_enc)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Removed item: {item_id}")
    print(f"Reason: {reason}")
    if owner_info:
        print(f"Owner: {owner_info}")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

def verify():
    blocks = get_blocks()
    if not blocks:
        print("No transactions found.")
        return
    
    print(f"Transactions in blockchain: {len(blocks)}")
    state = "CLEAN"
    
    prev_hash = None
    item_states = {}
    block_hashes = set()
    
    for index, (block_header, block_data) in enumerate(blocks):
        block_content = block_header + block_data
        curr_hash = hashlib.sha256(block_content).digest()
        
        if curr_hash in block_hashes:
            state = "ERROR"
            print(f"State of blockchain: {state}")
            print(f"Bad block: {curr_hash.hex()}")
            print("Duplicate block found.")
            exit(1)
        block_hashes.add(curr_hash)
        
        prev_block_hash, timestamp, case_id_enc, evidence_id_enc, state_bytes, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        
        if index == 0:
            prev_hash = curr_hash
            continue
        
        expected_prev_hash = hashlib.sha256(blocks[index - 1][0] + blocks[index - 1][1]).digest()
        if prev_block_hash != expected_prev_hash:
            state = "ERROR"
            print(f"State of blockchain: {state}")
            print(f"Bad block: {curr_hash.hex()}")
            print("Parent block hash mismatch.")
            exit(1)
        
        decrypted_evidence_id = decrypt_value(evidence_id_enc)
        item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), "big")
        action = state_bytes.strip(b"\0").decode()
        
        if action not in ["CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]:
            state = "ERROR"
            print(f"State of blockchain: {state}")
            print(f"Bad block: {curr_hash.hex()}")
            print(f"Invalid action: {action}")
            exit(1)
        
        if item_id not in item_states:
            if action != "CHECKEDIN":
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print(f"Bad block: {curr_hash.hex()}")
                print(f"Invalid initial action for item {item_id}: {action}")
                exit(1)
            item_states[item_id] = action
        else:
            prev_state = item_states[item_id]
            if prev_state == "CHECKEDIN" and action == "CHECKEDIN":
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print(f"Bad block: {curr_hash.hex()}")
                print(f"Item {item_id} already CHECKEDIN")
                exit(1)
            if prev_state == "CHECKEDOUT" and action == "CHECKEDOUT":
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print(f"Bad block: {curr_hash.hex()}")
                print(f"Item {item_id} already CHECKEDOUT")
                exit(1)
            if prev_state in REMOVAL_STATES:
                state = "ERROR"
                print(f"State of blockchain: {state}")
                print(f"Bad block: {curr_hash.hex()}")
                print(f"Action after removal on item {item_id}")
                exit(1)
            item_states[item_id] = action
        
        prev_hash = curr_hash
    
    print(f"State of blockchain: {state}")

def validate_item_id(value):
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid item ID {value}")
    if ivalue < 0 or ivalue > 0xFFFFFFFF:
        raise argparse.ArgumentTypeError(f"Item ID {value} is out of range (must be 0 to 4294967295)")
    return ivalue

if __name__ == "__main__":
    import argparse
    # Argument Parser
    parser = argparse.ArgumentParser(description="Blockchain Chain of Custody Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Init command
    parser_init = subparsers.add_parser("init", help="Initialize the blockchain with a genesis block.")

    # Add command
    parser_add = subparsers.add_parser("add", help="Add new items to a specific case.")
    parser_add.add_argument("-c", "--case_id", required=True, type=str, help="The case ID to associate items with.")
    parser_add.add_argument("-i", "--item_ids", required=True, type=validate_item_id, action='append', help="List of item IDs to add.")
    parser_add.add_argument("-g", "--creator", required=True, type=str, help="The creator of the items.")
    parser_add.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Checkout command
    parser_checkout = subparsers.add_parser("checkout", help="Checkout an item.")
    parser_checkout.add_argument("-i", "--item_id", required=True, type=validate_item_id, help="The ID of the item to checkout.")
    parser_checkout.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Checkin command
    parser_checkin = subparsers.add_parser("checkin", help="Checkin an item.")
    parser_checkin.add_argument("-i", "--item_id", required=True, type=validate_item_id, help="The ID of the item to checkin.")
    parser_checkin.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Remove command
    parser_remove = subparsers.add_parser("remove", help="Remove an item from further action.")
    parser_remove.add_argument("-i", "--item_id", required=True, type=validate_item_id, help="The ID of the item to remove.")
    parser_remove.add_argument("-y", "--why", required=True, type=str, help="Reason for removal.")
    parser_remove.add_argument("-o", "--owner", type=str, help="Owner information if reason is RELEASED.")
    parser_remove.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Verify command
    parser_verify = subparsers.add_parser("verify", help="Verify the integrity of the blockchain.")

    # Show command
    parser_show = subparsers.add_parser("show", help="Show blockchain information.")
    parser_show.add_argument("show_command", choices=["cases", "items", "history"], help="What to show.")
    parser_show.add_argument("-c", "--case_id", type=str, help="Case ID for filtering items.")
    parser_show.add_argument("-i", "--item_id", type=validate_item_id, help="Item ID to display history for.")
    parser_show.add_argument("-p", "--password", type=str, help="Password for authentication.")
    parser_show.add_argument("-n", "--num_entries", type=int, help="Number of entries to display.")
    parser_show.add_argument("-r", "--reverse", action="store_true", help="Display in reverse order.")

    args = parser.parse_args()

    try:
        if args.command == "init":
            init()
        elif args.command == "add":
            add(args.case_id, args.item_ids, args.creator, args.password)
        elif args.command == "checkout":
            checkout(args.item_id, args.password)
        elif args.command == "checkin":
            checkin(args.item_id, args.password)
        elif args.command == "remove":
            remove(args.item_id, args.why.upper(), args.owner, args.password)
        elif args.command == "verify":
            verify()
        elif args.command == "show":
            if args.show_command == "cases":
                show_cases()
            elif args.show_command == "items" and args.case_id: #remove and password #merge this fix
                show_items(args.case_id) #remove password
            #elif args.show_command == "history" and args.item_id and args.password:
                #show_history(args.item_id, args.password, args.num_entries, args.reverse)
            elif args.show_command == "history" and args.password:
                show_history(item_id=args.item_id, password=args.password, num_entries=args.num_entries, reverse=args.reverse)

            else:
                print("Error: Missing required arguments for 'show' command.")
                parser.print_help()
                exit(1)
        else:
            parser.print_help()
            exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)
