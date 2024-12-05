Project Name: Blockchain Chain of Custody Tool
Group Name: Canvas - Group 30
Members:
    - Ahmed Hejazi Kilani, ASU ID: 1222742339, Email: ahejazik@asu.edu
    - Dylan Niemeyer, ASU ID: 1220629579, Email: dniemey1@asu.edu
    - Suleiman Bashir, ASU ID: 1215611410, Email: smbashir@asu.edu

Description:
This program implements a blockchain-based chain of custody tool for digital forensics. It allows users to:
    - Add, check in, and check out evidence.
    - Display cases, items, and history.
    - Remove items and verify the integrity of the blockchain.

Instructions to Run:
    - Extract the compressed file.
    - Run make in the terminal to create the bchoc executable.
    - Use the following commands to interact with the program:
        - bchoc init: Initializes the blockchain with a Genesis block.
        - bchoc add -c <case_id> -i <item_id> -g <creator> -p <password>: Adds evidence to the blockchain.
        - bchoc show cases: Displays all cases.
        - Additional commands are detailed in the source code.
