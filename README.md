# BlockchainSystem

Multithreaded Blockchain System which utilizes 3 processes, each process asynchronously verify or mine data blocks based on passed in dummy data. Dummy data files provided "BlockInput0.txt", "BlockInput1.txt", and "BlockInput2.txt". Process 0 will read in "BlockInput0.txt", Process 1 will read in "BlockInput1.txt", and Process 2 will read in "BlockInput2.txt". All processes will each create unverified blocks based on read dummy data and then multicast to other processes to be appened into a local unverified priority blocking queue. Each process will then compete to verify or mine blocks from the unverified priority blocking queue. 

Verified blocks will be appened onto a linked-list blockchain ledger and stored as persistence data in JSON format. JSON file will be produced when all the unverified blocks have been verified. 

TCP protocol used for the 3 processes to communicate with each other via multicasting and updating verified blocks, as well as, sending public and private keys for more security of data blocks. 
Implemented cryptographic on hash data via public key and private key, along with multithread processes. 

## Instructions to run the Multithreaded Blockchain System in "Blockchain.java" file

SAMPLE OUTPUT from Process 0: 

Chien-Liang Liu's Main Server Process 0 Up and running...

Starting up Message Server using 4610 listening for Multicast Messages...
Starting up PublicKey Server using 4710 listening for Multicast PublicKeys...
Starting up UVB Server using 4820 listening for Multicast UVBs...
Starting up BlockChainLedger Server using 4930 listening for Multicast updated Blockchain...

Got Message: Hello multicast message from Process 0 up and running

Got Message: Hello multicast message from Process 1 up and running

Got Public Key from process 0

Got Message: Hello multicast message from Process 2 up and running

Got Public Key from process 1

GOT updated Blockchain from process 0 -> Dummy Block 0.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 0 -> Dummy Block 0

Got Public Key from process 2

----------------------------------------------------------------------------------------------
Reading data input files for creating UVBs (Unverified Blocks) and then multicast each UVB...

Got a UVB from Process: 0

Got a UVB from Process: 0

Got a UVB from Process: 1

Got a UVB from Process: 0

Got a UVB from Process: 2

Got a UVB from Process: 1

Got a UVB from Process: 0

Got a UVB from Process: 2

Got a UVB from Process: 1

Got a UVB from Process: 2

Got a UVB from Process: 1

Got a UVB from Process: 2

----------------------------------------------------------------------------------------------
UVBConsumer popping off UVBs from PriorityBlockingQueue to verify the UVBs (Apply Work)...

GOT updated Blockchain from process 0.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 0

GOT updated Blockchain from process 1.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 1

GOT updated Blockchain from process 2.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 2

GOT updated Blockchain from process 2.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 2

GOT updated Blockchain from process 1.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 1

GOT updated Blockchain from process 0.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 0

GOT updated Blockchain from process 1.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 1

GOT updated Blockchain from process 2.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 2

GOT updated Blockchain from process 0.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 0

GOT updated Blockchain from process 2.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 2

GOT updated Blockchain from process 1.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 1

GOT updated Blockchain from process 0.
--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: 0

COMPLETED!!! NO MORE UVBs (Unverified Blocks) TO BE VERIFIED!!!!!
