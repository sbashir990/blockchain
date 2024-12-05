#!/usr/bin/env python3
import os
import struct
import uuid
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#This is the blockchain and how it has the file path 
BCHOC_FILE_PATH = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
AES_KEY = b"R0chLi4uLi4uLi4="  
BLOCK_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_SIZE = struct.calcsize(BLOCK_FORMAT) #block size
REMOVAL_STATES = ["DISPOSED", "DESTROYED", "RELEASED"] #this is the removal states 

#here is the password for the blockchain that can be used along with it 
PASSWORDS = {
    "CREATOR": "C67C",
    "POLICE": "P80P",
    "ANALYST": "A65A",
    "LAWYER": "L76L",
    "EXECUTIVE": "E69E"
}
#encrypt_value is used to take the data and follow steps necessary to complete the cipher 
def encrypt_value(value):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    #take the value and uuid to equate it to padded_value
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
    #return the encryption
    return encryptor.update(padded_value)

#next is decrypt value 
def decrypt_value(encrypted_value):

    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_value)
    #return the unencrypted data

def create_initial_block():
    #creates place holder for the block and all the values 
    placeholder_case_id = b'0' * 32
    placeholder_evidence_id = b'0' * 32
    state = b'INITIAL' + b'\0' * 5
    data_payload = b'Initial block\x00'
    data_length = len(data_payload)
    timestamp = datetime.now(timezone.utc).timestamp()  # Set to current time
    #have the timestamp
    initial_block = struct.pack(
        BLOCK_FORMAT,
        b'\0' * 32,          
        timestamp,                  
        placeholder_case_id, 
        placeholder_evidence_id,           
        state, 
        b'\0' * 12,       
        b'\0' * 12,         
        data_length          
    ) + data_payload         
    #with open BCHOC FILE PATH
    with open(BCHOC_FILE_PATH, "wb") as f:
        f.write(initial_block)

def get_blocks():
    #if the os path exists
    if not os.path.exists(BCHOC_FILE_PATH):
        create_initial_block()
    #create initial block
    blocks = []#set the block
    with open(BCHOC_FILE_PATH, "rb") as f:
        while True:
            block_header = f.read(BLOCK_SIZE)
            if not block_header:
                break  
            if len(block_header) < BLOCK_SIZE:
                raise ValueError("Invalid block header length in blockchain file.")
            fields = struct.unpack(BLOCK_FORMAT, block_header)
            data_length = fields[7]
            data = f.read(data_length)
            if len(data) < data_length:
                raise ValueError("Invalid block data length in blockchain file.")
            blocks.append((block_header, data))
            #return block
    return blocks

def init():#init method
    if os.path.exists(BCHOC_FILE_PATH):
        try: #os.path.exists get the file path 
            blocks = get_blocks()
            if len(blocks) == 0:
                raise ValueError("Blockchain file is empty.")
            
            print("Blockchain file found with INITIAL block.")
        except Exception as e:
            print(f"Error: Invalid blockchain file. {str(e)}")
            exit(1)
    else:
        create_initial_block() #create the block if not found 
        print("Blockchain file not found. Created INITIAL block.")

def show_cases(): #show cases to get the blocks and unique case is a hash set 
    blocks = get_blocks()
    unique_cases = set()

    for i, (block_header, _) in enumerate(blocks):
        _, _, encrypted_case_id, _, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_case_id = decrypt_value(encrypted_case_id)
        #check if i is equal to 0 if so continue 
        if i == 0:
            continue

        try:
            case_uuid = uuid.UUID(bytes=decrypted_case_id[:16])
            unique_cases.add(case_uuid)
        except ValueError:
            continue #continue and pass incase of value error 

    if unique_cases:
       #if unique case print the case else block not found 
        for case_id in unique_cases:
            print(f"{case_id}") 
    else:
        print("No cases found in the blockchain.")

def show_items(case_id): 
    blocks = get_blocks()
    encrypted_case_id = encrypt_value(uuid.UUID(case_id))
    unique_items = set() 
    #this is the for block header in blocks 
    for block_header, _ in blocks:
        _, _, curr_case_id, evidence_id_enc, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if curr_case_id == encrypted_case_id:
            decrypted_item_id = decrypt_value(evidence_id_enc)
            try: #try the conversion from bytes to int 
                item_id = int.from_bytes(decrypted_item_id.strip(b"\0"), "big")
                unique_items.add(item_id)
            except ValueError:
                continue #continue value error 

    if unique_items:
        #if unique items 
        for item_id in sorted(unique_items):
            print(f"{item_id}")  #for item id 
    else: #else they can not find the case 
        print(f"No items found for case {case_id}.")

#def show_history - 
def show_history(item_id=None, case_id=None, password=None, num_entries=None, reverse=False):
    if password not in PASSWORDS.values(): #if password is not the password exit 1
        print("Invalid password")
        exit(1)
    #blocks is get blocks
    blocks = get_blocks()
    history = [] #history block 


    case_uuid_filter = None
    if case_id is not None:
        try:#try the case uuid filter
            case_uuid_filter = uuid.UUID(case_id)
        except ValueError: #except valueerror 
            print(f"Error: Invalid case ID format: {case_id}")
            exit(1) #exit 1

    for index, (block_header, _) in enumerate(blocks):
        prev_hash, timestamp, case_id_enc, evidence_id_enc, state, creator, owner, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_state = state.strip(b"\0").decode() #this is the decrypted state, creator, owner
        decrypted_creator = creator.strip(b"\0").decode()
        decrypted_owner = owner.strip(b"\0").decode()

        if index == 0: #if index == 0 
    
            case_uuid = uuid.UUID(int=0)
            evidence_item_id = 0
        else: #else its decrypted case id and evidence id 
            decrypted_case_id = decrypt_value(case_id_enc)
            decrypted_evidence_id = decrypt_value(evidence_id_enc)

            try: #case uuid evidence_item_id 
                case_uuid = uuid.UUID(bytes=decrypted_case_id[:16])
                evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
            except ValueError: #valueerror 
                continue  

        action = decrypted_state #action dt record timestamp
        dt = datetime.fromtimestamp(timestamp, timezone.utc)
        record_timestamp = dt.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
        if record_timestamp.endswith('+0000'):
            record_timestamp = record_timestamp[:-5] + '+00:00'
            #include entry is true 
        include_entry = True
        #if item id is not None and evidence item id is not item id 
        if item_id is not None and evidence_item_id != item_id:
            include_entry = False
        if case_uuid_filter is not None and case_uuid != case_uuid_filter:
            include_entry = False
        #if include entry history append 
        if include_entry:
            history.append({
                "timestamp": record_timestamp,
                "timestamp_dt": dt,
                "case_id": case_uuid,
                "item_id": evidence_item_id,
                "state": action,
                "creator": decrypted_creator,
                "owner": decrypted_owner
            })
    history.sort(key=lambda x: x['timestamp_dt'])
    #sort the history using lambda 
    if reverse:
        history = history[::-1]
    #if reserve history = history [::-1]
    if num_entries is not None:
        #history = history [:num_entries ]
        history = history[:num_entries]

    if history:
        for record in history:
            print(f"Case: {record['case_id']}")
            print(f"Item: {record['item_id']}")
            print(f"Action: {record['state']}")
            print(f"Time: {record['timestamp']}")
            print() #if history: case, item, action, time


#def get item latest state
def get_item_latest_state(blocks, item_id):
    latest_state = None
    case_id_enc = None
    #set to none 
    for block_header, _ in reversed(blocks): #blockheader, in reversed
        _, _, curr_case_id_enc, evidence_id_enc, state, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_evidence_id_bytes = decrypt_value(evidence_id_enc)
        if len(decrypted_evidence_id_bytes) < 4:
            continue  
        evidence_item_id = int.from_bytes(decrypted_evidence_id_bytes[:4], 'big')
        if evidence_item_id == item_id:
            latest_state = state.strip(b"\0").decode()
            case_id_enc = curr_case_id_enc
            break  
    #return latest state, case id enc
    return latest_state, case_id_enc

#this is the add 
def add(case_id, item_ids, creator, password):
    if password != PASSWORDS["CREATOR"]:
        print("Invalid password")
        exit(1)
    #try the case id and get the value error 
    try:
        case_uuid = uuid.UUID(case_id)
    except ValueError:
        print("Error: Invalid UUID format")
        exit(1)
    #blocks = getblocks 
    blocks = get_blocks()
    existing_item_ids = set()
    
    
    for block_header, _ in blocks:
        _, _, _, evidence_id_enc, _, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        if evidence_id_enc != b"\0" * 32:
            decrypted_evidence_id = decrypt_value(evidence_id_enc)
            evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
            existing_item_ids.add(evidence_item_id)
    
   #for item id 
    for item_id in item_ids:
        if item_id in existing_item_ids:
            print(f"Error: Item ID {item_id} already exists in blockchain")
            exit(1)
    #prev block header, prev block data is blocks[-1]
    prev_block_header, prev_block_data = blocks[-1]
    
    
    for item_id in item_ids:
        encrypted_item_id = encrypt_value(item_id)
        prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
        timestamp = datetime.now(timezone.utc).timestamp()
        encrypted_case_id = encrypt_value(case_uuid)
        #block data = new evidence
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
        ) #new block 
        new_block = block_header + block_data
        
        with open(BCHOC_FILE_PATH, "ab") as f:
            f.write(new_block)
        
        #previous block header and data sent to equal 
        prev_block_header = block_header
        prev_block_data = block_data
        
        print(f"Added item: {item_id}")
        print("Status: CHECKEDIN")
        print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")
#checkout item id, password
def checkout(item_id, password):
    #if password not password 
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    #role is none 
    role = None
    for key, value in PASSWORDS.items():
        if value == password:
            role = key
            break
        #break 
    
    blocks = get_blocks()
    latest_state, case_id_enc = get_item_latest_state(blocks, item_id)
    #get blocks latest state 
    if latest_state is None or latest_state in REMOVAL_STATES:
        print(f"Error: Item {item_id} not found")
        exit(1) #exit 1 
    
    if latest_state != "CHECKEDIN":
        print(f"Error: Item {item_id} is not in CHECKEDIN state")
        exit(1)
    #if latest_state not checked in
    prev_block_header, prev_block_data = blocks[-1]
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
    timestamp = datetime.now(timezone.utc).timestamp()
    #encrypted item id is encrypted value 
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
    #with open  
    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(checkout_block)
    
    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id_enc)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Checked out item: {item_id}")
    print("Status: CHECKEDOUT")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")
#checked in items and id 
def checkin(item_id, password):
    if password not in PASSWORDS.values():
        print("Invalid password")
        exit(1)
    #here is exit 1 
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
    #have the block check in created 
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
#def remove is passwor not passwords creator 
def remove(item_id, reason, owner_info, password):
    if password != PASSWORDS["CREATOR"]:
        print("Invalid password")
        exit(1)
    # if reason not in removal states 
    if reason not in REMOVAL_STATES:
        print("Error: Invalid reason for removal")
        exit(1)#exit 1

    

    blocks = get_blocks()
    latest_state, case_id_enc = get_item_latest_state(blocks, item_id)
    #if latest_state is none or latest_state in removal states 
    if latest_state is None or latest_state in REMOVAL_STATES:
        print(f"Error: Item {item_id} not found")
        exit(1)

    if latest_state != "CHECKEDIN":
        print(f"Error: Item {item_id} must be in CHECKEDIN state to remove")
        exit(1)
    #exit 1 
    
    creator = None #here is the creator none 
    for block_header, _ in blocks:
        _, _, _, evidence_id_enc, _, creator_bytes, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        decrypted_evidence_id = decrypt_value(evidence_id_enc) #block header stuct 
        evidence_item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), 'big')
        if evidence_item_id == item_id:
            creator = creator_bytes.strip(b"\0").decode()
            break  

    if creator is None:
        print(f"Error: Creator not found for item {item_id}")
        exit(1)

    prev_block_header, prev_block_data = blocks[-1]
    data_payload = b"" #data playload 
    data_length = 0

    
    role = None #none is role 
    for key, value in PASSWORDS.items():
        if value == password:
            role = key #role is key 
            break
    if role is None:
        print("Invalid password")
        exit(1) #exit 1 

    owner = role.encode().ljust(12, b"\0")

    timestamp = datetime.now(timezone.utc).timestamp()
    prev_hash = hashlib.sha256(prev_block_header + prev_block_data).digest()
    #timestamp is datatime 
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
    ) #new block is header and payload 
    new_block = block_header + data_payload

    with open(BCHOC_FILE_PATH, "ab") as f:
        f.write(new_block)
    #decrypt case id 
    decrypted_case_id = uuid.UUID(bytes=decrypt_value(case_id_enc)[:16])
    print(f"Case: {decrypted_case_id}")
    print(f"Removed item: {item_id}")
    print(f"Reason: {reason}")
    if owner_info:
        print(f"Owner: {owner_info}")
    print(f"Time of action: {datetime.now(timezone.utc).isoformat()}")
#define the verification of blocks and get the blocks 
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
    #for index, (block header, block data)  in enumerate(blocks)
    for index, (block_header, block_data) in enumerate(blocks):
        block_content = block_header + block_data
        curr_hash = hashlib.sha256(block_content).digest()
        #if curr_hash in block_hashes
        if curr_hash in block_hashes:
            state = "ERROR"
            print(f"State of blockchain: {state}")
            print(f"Bad block: {curr_hash.hex()}")
            print("Duplicate block found.")
            exit(1) 
            #add
        block_hashes.add(curr_hash)
        #hash timestamp, caseid enc evidence id enc stata bytes 
        prev_block_hash, timestamp, case_id_enc, evidence_id_enc, state_bytes, _, _, _ = struct.unpack(BLOCK_FORMAT, block_header)
        
        if index == 0:
            prev_hash = curr_hash
            continue
        #this is the continuation if index is 0 
        expected_prev_hash = hashlib.sha256(blocks[index - 1][0] + blocks[index - 1][1]).digest()
        if prev_block_hash != expected_prev_hash:
            state = "ERROR"
            print(f"State of blockchain: {state}")
            print(f"Bad block: {curr_hash.hex()}")
            print("Parent block hash mismatch.")
            exit(1)
        #decrypt the evidence id = decrypt value
        decrypted_evidence_id = decrypt_value(evidence_id_enc)
        item_id = int.from_bytes(decrypted_evidence_id.strip(b"\0"), "big")
        action = state_bytes.strip(b"\0").decode()
        
        if action not in ["CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"]:
            state = "ERROR"
            print(f"State of blockchain: {state}")
            print(f"Bad block: {curr_hash.hex()}")
            print(f"Invalid action: {action}")
            exit(1)
        # if item id not in item states 
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
        #prev hash is current hash 
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

#main method 
if __name__ == "__main__":
    import argparse
    # Argument passer 
    parser = argparse.ArgumentParser(description="Blockchain Chain of Custody Tool")
    subparsers = parser.add_subparsers(dest="command")
    #parser init for subparsers and add 
    parser_init = subparsers.add_parser("init", help="Initialize the blockchain with a genesis block.")

    # Add 
    parser_add = subparsers.add_parser("add", help="Add new items to a specific case.")
    parser_add.add_argument("-c", "--case_id", required=True, type=str, help="The case ID to associate items with.")
    parser_add.add_argument("-i", "--item_ids", required=True, type=validate_item_id, action='append', help="List of item IDs to add.")
    parser_add.add_argument("-g", "--creator", required=True, type=str, help="The creator of the items.")
    parser_add.add_argument("-p", "--password", required=True, type=str, help="Password for authentication.")

    # Checkout 
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
#this will try to pass the commands into the different functions for blockchain
    try:
        if args.command == "init":
            init()
            #elif is add the arguments to use 
        elif args.command == "add":
            add(args.case_id, args.item_ids, args.creator, args.password)
        elif args.command == "checkout":

            checkout(args.item_id, args.password)
        elif args.command == "checkin":
            checkin(args.item_id, args.password)
        elif args.command == "remove":
            remove(args.item_id, args.why.upper(), args.owner, args.password)
        elif args.command == "verify":
            verify() #verification
        elif args.command == "show":
            if args.show_command == "cases":
                show_cases() #show cases 
            elif args.show_command == "items" and args.case_id: 
                show_items(args.case_id) 
            elif args.show_command == "history" and args.password:
                show_history(item_id=args.item_id, case_id=args.case_id, password=args.password, num_entries=args.num_entries, reverse=args.reverse)
                #show history 
            else:
                print("Error: Missing required arguments for 'show' command.")
                parser.print_help()
                exit(1) #exit 1 
        else:
            parser.print_help() #print help exit 1 
            exit(1) 
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)#exception as exit 1
