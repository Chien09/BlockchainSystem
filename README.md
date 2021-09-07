# BlockchainSystem

Blockchain System which utilizes 3 processes to verify or mine data blocks. Dummay data files provided "BlockInput0.txt", "BlockInput1.txt", and "BlockInput2.txt". 
Verified blocks will be appened onto a linked-list blockchain ledger and stored as persistence data as JSON format. JSON file will be produced. 
TCP protocol used for the 3 processes to communicate with each other via multicasting and updating verified blocks, as well as, sending public and private keys. 
Implemented cryptographic on hash data via public key and private key, along with multithread processes. 
