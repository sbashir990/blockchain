#!/usr/bin/env python3
import os
import struct
import uuid
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Constants
BCHOC_FILE_PATH = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
AES_KEY = b"R0chLi4uLi4uLi4="
BLOCK_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_SIZE = struct.calcsize(BLOCK_FORMAT)

def encrypt_value(value):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    if isinstance(value, uuid.UUID):
        padded_value = value.bytes.ljust(32, b"\0")
    elif isinstance(value, int):
        padded_value = value.to_bytes(4, 'big').ljust(32, b"\0")
    else:
        padded_value = value.ljust(32, b"\0")
    
    return encryptor.update(padded_value)

def decrypt_value(encrypted_value):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_value)

def create_initial_block():
    """
    Creates the genesis block with a clearly invalid case_id to avoid misinterpretation.
    """
    placeholder_case_id = b"\0" * 32
    initial_block = struct.pack(
        BLOCK_FORMAT,
        b"0" * 32,  # prev_hash
        0,          # timestamp
        placeholder_case_id,  # case_id (invalid placeholder)
        b"0" * 32,  # evidence_id
        b"INITIAL\0\0\0\0\0",  # state
        b"\0" * 12, # creator
        b"\0" * 12, # owner
        14          # data_length
    ) + b"Initial block\0"
    
    with open(BCHOC_FILE_PATH, "wb") as f:
        f.write(initial_block)

def get_blocks():
    if not os.path.exists(BCHOC_FILE_PATH):
        create_initial_block()
    
    blocks = []
    with open(BCHOC_FILE_PATH, "rb") as f:
        while True:
            block_header = f.read(BLOCK_SIZE)
            if not block_header or len(block_header) < BLOCK_SIZE:
                break
            
            fields = struct.unpack(BLOCK_FORMAT, block_header)
            data = f.read(fields[7])
            blocks.append((block_header, data))
    return blocks

def init():
    """
    Initializes the blockchain by creating the genesis block if it doesn't exist.
    """
    if os.path.exists(BCHOC_FILE_PATH):
        print("Blockchain file found with INITIAL block.")
    else:
        create_initial_block()
        print("Blockchain file not found. Created INITIAL block.")

def show_cases():
    """
    Displays all unique case IDs in the blockchain.
    """
    blocks = get_blocks()
    unique_cases = set()

    for i, (block_header, _) in enumerate(blocks):
        _, _, encrypted_case_id, _, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_case_id = decrypt_value(encrypted_case_id)

        # Skip the genesis block (first block)
        if i == 0:
            continue

        try:
            # Convert decrypted case_id bytes to UUID
            case_uuid = uuid.UUID(bytes=decrypted_case_id[:16])
            unique_cases.add(case_uuid)
        except ValueError:
            # Skip invalid UUIDs
            continue

    if unique_cases:
        print("Unique case IDs in the blockchain:")
        for case_id in unique_cases:
            print(f"- {case_id}")
    else:
        print("No cases found in the blockchain.")

def show_items(case_id, password):
    """
    Displays all items associated with a specific case ID.
    """
    if password != "C67C":  # Replace with appropriate password validation if required.
        print("Invalid password")
        exit(1)

    blocks = get_blocks()
    encrypted_case_id = encrypt_value(uuid.UUID(case_id))
    unique_items = set()  # Use a set to avoid duplicates

    for block_header, _ in blocks:
        _, _, curr_case_id, evidence_id, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if curr_case_id == encrypted_case_id:
            decrypted_item_id = decrypt_value(evidence_id)
            try:
                # Convert decrypted_item_id to integer
                item_id = int.from_bytes(decrypted_item_id.strip(b"\0"), "big")
                unique_items.add(item_id)  # Add to the set
            except ValueError:
                continue

    if unique_items:
        print(f"Items associated with case {case_id}:")
        for item_id in sorted(unique_items):  # Sort for consistent output
            print(f"- {item_id}")
    else:
        print(f"No items found for case {case_id}.")

def show_history(item_id, password):
    """
    Displays the history of actions performed on a specific item.
    """
    if password != "C67C":  # Replace with appropriate password validation if required.
        print("Invalid password")
        exit(1)

    blocks = get_blocks()
    encrypted_item_id = encrypt_value(item_id)
    history = []

    for block_header, _ in blocks:
        prev_hash, timestamp, case_id, evidence_id, state, creator, owner, _ = struct.unpack(BLOCK_FORMAT, block_header)
        
        if evidence_id == encrypted_item_id:
            decrypted_case_id = decrypt_value(case_id)
            decrypted_state = state.strip(b"\0").decode()
            decrypted_creator = creator.strip(b"\0").decode()
            
            history.append({
                "timestamp": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                "case_id": uuid.UUID(bytes=decrypted_case_id[:16]),
                "state": decrypted_state,
                "creator": decrypted_creator
            })

    if history:
        print(f"History for item {item_id}:")
        for record in history:
            print(f"- Timestamp: {record['timestamp']}")
            print(f"  Case ID: {record['case_id']}")
            print(f"  State: {record['state']}")
            print(f"  Creator: {record['creator']}")
    else:
        print(f"No history found for item {item_id}.")

def get_item_latest_state(blocks, encrypted_item_id):
    latest_state = None
    case_id = None
    
    for block_header, _ in blocks:
        _, _, curr_case_id, evidence_id, state, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if evidence_id == encrypted_item_id:
            latest_state = state.strip(b"\0")
            case_id = curr_case_id
    
    return latest_state, case_id

def add(case_id, item_ids, creator, password):
    if password != "C67C":
        print("Invalid password")
        exit(1)
    
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        print("Error: Invalid UUID format")
        exit(1)
    
    blocks = get_blocks()
    existing_items = set()
    
    # Collect existing items
    for block_header, _ in blocks:
        _, _, _, evidence_id, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if evidence_id != b"0" * 32:
            existing_items.add(evidence_id)
    
    # Check for duplicates
    for item_id in item_ids:
        encrypted_item_id = encrypt_value(item_id)
        if encrypted_item_id in existing_items:
            print(f"Error: Item ID {item_id} already exists in blockchain")
            exit(1)
    
    # Add all items
    for item_id in item_ids:
        encrypted_item_id = encrypt_value(item_id)
        prev_block_header, prev_block_data = blocks[-1]
        prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
        timestamp = datetime.now(timezone.utc).timestamp()
        encrypted_case_id = encrypt_value(case_uuid)
        
        new_block = struct.pack(
            BLOCK_FORMAT,
            prev_hash,
            timestamp,
            encrypted_case_id,
            encrypted_item_id,
            b"CHECKEDIN\0\0\0",
            creator.encode().ljust(12, b"\0"),
            b"\0" * 12,
            len(b"New evidence")
        ) + b"New evidence"
        
        with open(BCHOC_FILE_PATH, "ab") as f:
            f.write(new_block)
        
        print(f"Added item: {item_id}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

def checkout(item_id, password):
    if password != "A65A":
        print("Invalid password")
        exit(1)
    
    blocks = get_blocks()
    encrypted_item_id = encrypt_value(item_id)
    
    latest_state, case_id = get_item_latest_state(blocks, encrypted_item_id)
    
    if latest_state is None:
        print(f"Error: Item {item_id} not found")
        exit(1)
    
    if latest_state != b"CHECKEDIN":
        print(f"Error: Item {item_id} is not in CHECKEDIN state")
        exit(1)
    
    prev_block_header, prev_block_data = blocks[-1]
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
    timestamp = datetime.now(timezone.utc).timestamp()
    
    checkout_block = struct.pack(
        BLOCK_FORMAT,
        prev_hash,
        timestamp,
        case_id,
        encrypted_item_id,
        b"CHECKEDOUT\0\0",
        b"\0" * 12,
        b"\0" * 12,
        len(b"Checked out")
    ) + b"Checked out"
    
    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(checkout_block)
    
    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Checked out item: {item_id}")
    print("Status: CHECKEDOUT")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

def checkin(item_id, password):
    if password != "P80P":
        print("Invalid password")
        exit(1)
    
    blocks = get_blocks()
    encrypted_item_id = encrypt_value(item_id)
    
    latest_state, case_id = get_item_latest_state(blocks, encrypted_item_id)
    
    if latest_state is None:
        print(f"Error: Item {item_id} not found")
        exit(1)
    
    if latest_state != b"CHECKEDOUT":
        print(f"Error: Item {item_id} is not in CHECKEDOUT state")
        exit(1)
    
    prev_block_header, prev_block_data = blocks[-1]
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
    timestamp = datetime.now(timezone.utc).timestamp()
    
    checkin_block = struct.pack(
        BLOCK_FORMAT,
        prev_hash,
        timestamp,
        case_id,
        encrypted_item_id,
        b"CHECKEDIN\0\0\0",
        b"\0" * 12,
        b"\0" * 12,
        len(b"Checked in")
    ) + b"Checked in"
    
    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(checkin_block)
    
    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Checked in item: {item_id}")
    print("Status: CHECKEDIN")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")

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
    parser_add.add_argument("-i", "--item_ids", required=True, type=int, nargs="+", help="List of item IDs to add.")
    parser_add.add_argument("-g", "--creator", required=True, type=str, help="The creator of the items.")
    parser_add.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Checkout command
    parser_checkout = subparsers.add_parser("checkout", help="Checkout an item.")
    parser_checkout.add_argument("-i", "--item_id", required=True, type=int, help="The ID of the item to checkout.")
    parser_checkout.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Checkin command
    parser_checkin = subparsers.add_parser("checkin", help="Checkin an item.")
    parser_checkin.add_argument("-i", "--item_id", required=True, type=int, help="The ID of the item to checkin.")
    parser_checkin.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Show command
    parser_show = subparsers.add_parser("show", help="Show blockchain information.")
    parser_show.add_argument("--cases", action="store_true", help="List all unique case IDs.")
    parser_show.add_argument("--items", action="store_true", help="List all items for a specific case ID.")
    parser_show.add_argument("--history", action="store_true", help="Show the history of a specific item.")
    parser_show.add_argument("-c", "--case_id", type=str, help="Case ID for filtering items.")
    parser_show.add_argument("-i", "--item_id", type=int, help="Item ID to display history for.")
    parser_show.add_argument("-p", "--password", type=str, help="Password for authentication.")

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
        elif args.command == "show":
            if args.cases:
                show_cases()
            elif args.items and args.case_id and args.password:
                show_items(args.case_id, args.password)
            elif args.history and args.item_id and args.password:
                show_history(args.item_id, args.password)
            else:
                print("Error: Missing required arguments for 'show' command.")
                parser.print_help()
        else:
            parser.print_help()
            exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)
