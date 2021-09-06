/*--------------------------------------------------------
1. Name & Date: Chien-Liang Liu , Date Completed: March 3, 2021

2. Java Version: build 10.0.2+13 (Java 10)

3. Compile Project in command line or ternimal instructions:
> javac -cp "gson-2.8.2.jar" Blockchain.java

4. Instructions to run this program:
First Compile the Blockchain.java then do the following below in separate command prompt (shell) or ternimals
FOR Windows: 
> java -cp ".;gson-2.8.2.jar" Blockchain 0
> java -cp ".;gson-2.8.2.jar" Blockchain 1
> java -cp ".;gson-2.8.2.jar" Blockchain 2

FOR MAC:
> java -cp ".:gson-2.8.2.jar" Blockchain 0
> java -cp ".:gson-2.8.2.jar" Blockchain 1
> java -cp ".:gson-2.8.2.jar" Blockchain 2

OR simply use MasterScript.bat (Windows) 

5. List of files needed for running the program.
 a. Blockchain.java (need to compile this first)
 b. gson-2.8.2.jar
 c. BlockInput0.txt
 d. BlockInput1.txt
 e. BLockInput2.txt

6. Notes:
-When each Server Process 0,1,2 finishes processing the UVBs meaning the PriorityBlockingQueue is empty, the console will print the last print
"COMPLETED!!! NO MORE UVBs (Unverified Blocks) TO BE VERIFIED!!!!!". To notify that the program is finished.

REFERENCES:
Applied some codes are from Professor Clark Elliott's Utility programs.
And website references supplied.
https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
https://dzone.com/articles/generate-random-alpha-numeric

----------------------------------------------------------*/
//imports for using the gson-2.8.2.jar, able to use GSON
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken; //this for the Token used for template when reading from JSON file

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.PriorityBlockingQueue;

//Main Class to run the whole BlockChain Program
public class Blockchain {
    static String serverName = "localhost";
    static int Process_Number; //to store the current Process running this server either 0,1,2
    static int Number_Of_Processes = 3; //number of Processes that will be Multicast message to (including self)
    static KeyPair keyPair; //for storing KeyPair for current Server Process either 0,1,2
    static Key_Object PublicKey_Object = new Key_Object(); //for storing public keys from other Server processes 0,1,2 including self
    static LinkedList<Block> BlockChain_Ledger = new LinkedList<Block>(); //storing the verified Blocks, the local Blockchain Ledger for each server process 0,1,2

    //Storing the UVBs (unverified Blocks), final so it doesn't get pointed to another stack
    final PriorityBlockingQueue<Block> UVB_PriorityQue = new PriorityBlockingQueue<Block>(20, BlockTimeStampComparator);

    //Using custom comparator for the PriorityBlockingQue order stack based on ordering of timestamp for the UVBs
    public static Comparator<Block> BlockTimeStampComparator = new Comparator<Block>()
    {
        @Override
        public int compare(Block b1, Block b2)
        {
            String s1 = b1.getTime_Stamp();
            String s2 = b2.getTime_Stamp();
            if (s1 == s2) {return 0;}
            if (s1 == null) {return -1;}
            if (s2 == null) {return 1;}
            return s1.compareTo(s2);
        }
    };

    //These are tokens for reading the data files "BlockInput[0 to 2].txt" so the token is to know where data are in the read line
    //In other words the tokens are the indexes
    private static final int iFNAME = 0; //first name
    private static final int iLNAME = 1; //Last name
    private static final int iDOB = 2; //Birth day
    private static final int iSSNUM = 3; //SSN num
    private static final int iDIAG = 4;  //Illness
    private static final int iTREAT = 5; //how to treat the disease
    private static final int iRX = 6; //medicine

    //Running the whole program via creating another object Blockchain, because to prevent potential static variables referencing issues.
    //So using another method to do the running of the program which is "runProgram" rather than this main method
    public static void main(String[] args) {
        Blockchain NewObject_Execution = new Blockchain();
        NewObject_Execution.runProgram(args);
    }

    //running the whole blockchain program
    public void runProgram(String args[]){

        //Taking in argument input (either 0,1,2) from console when first running this program
        if (args.length < 1) Process_Number = 0; //default
        else if (args[0].equals("0")) Process_Number = 0; //if argument 0
        else if (args[0].equals("1")) Process_Number = 1; //if argument 1
        else if (args[0].equals("2")) Process_Number = 2; //if argument 2
        else Process_Number = 0; //for default if argument is other than 0 or 1 or 2

        System.out.println("Chien-Liang Liu's Main Server Process " + Process_Number + " Up and running...\n");

        //ONLY applies to Server Process number 0
        //Add the created Dummy Block 0 first to the Linked-List BlockChain Ledger if Server Processes Number is 0
        //And write the Linked-List BlockChain Ledger into JSON format file
        if(Process_Number == 0){
            BlockChain_Ledger.add(createDummyBlock());
            //System.out.println("\nDummy Block 0 added to Linked-List BlockChain Ledger (Process 0)!\n");

            //Write Linked-List BLockChain Ledger into JSON file
            //creating Gson for converting Java Objects into JSON
            Gson gson = new GsonBuilder().setPrettyPrinting().create();

            //Convert Linked-List Blockchain Ledger to JSON format and then writing the JSON into a file saving to disk
            try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
                gson.toJson(BlockChain_Ledger, writer);
            } catch (IOException e) {e.printStackTrace();}
        }

        //set the ports up based on the Process_Number input from command line (used for Server Sockets and to multicast)
        //Each Server Process (0,1,2) will have multiple ports
        new Ports().setPort();

        //start up the MessageServer to listen and receive incoming messages from other server process 0,1,2 (including self)
        new Thread(new MessageServer()).start();

        //start up the PublicKeyServer to listen and receive incoming Public Keys from other server process 0,1,2 (including self)
        new Thread(new PublicKeyServer()).start();

        //start up the UVBServer to listen and receive incoming UVBs from other server process 0,1,2 (including self)
        //passing in the PriorityBlockingQue to add the UVB multicast received
        new Thread(new UVBServer(UVB_PriorityQue)).start();

        //start up the BlockChainLedgerServer to listen and receive incoming Updated BlockChain Ledger in JSON format from other server process 0,1,2 (including self)
        //to update the local Linked-List BlockChain Ledger for each Server Process 0,1,2 and the actual JSON file BlockChain Ledger
        new Thread(new BlockChainLedgerServer()).start();

        //Apply sleeping for waiting other servers to settle or start up
        try { Thread.sleep(6000); } catch (Exception e){}

        //send the multicast message to make sure all server process 0,1,2 are up and running
        SendMessage();

        //Apply sleeping to wait until all Hello Multicast messages are received or settled for each server process 0,1,2
        try { Thread.sleep(1500); } catch (Exception e) {}

        //Generate KeyPair then convert the PublicKey to string to multicast
        try {
            //Generate KeyPair (Public key/Private key)
            keyPair = generateKeyPair(999);

            //Retrieve Public Key which is in byte
            byte[] byte_PublicKey = keyPair.getPublic().getEncoded();

            //Converting Public Key into String using Base64
            String String_PublicKey = Base64.getEncoder().encodeToString(byte_PublicKey);
            //System.out.println("\nThe generated Public Key in String form for this Server Process " + Process_Number + " is: " + String_PublicKey + "\n");

            //send the multicast PublicKey in string form
            SendPublicKey(String_PublicKey);

        }catch (Exception e){ e.printStackTrace();}

        //Apply sleeping to wait until all Public Key Multicast messages are received or settled for each server process 0,1,2
        try { Thread.sleep(4000); } catch (Exception e) {}

        //ONLY multicast the first updated Linked-List Blockchain Ledger which includes the verified Dummy Block to other Server Process 1 and 2, if Server Process number is 0
        if(Process_Number == 0) {
            SendDummyBlockChainLedger(); //multicast Linked-List Blockchain ledger
        }

        //Apply sleeping to wait until all Multicast Linked-List Blockchain Ledger includes the Dummy Block are received or settled for each server process 0,1,2
        try { Thread.sleep(1500); } catch (Exception e) {}

        //send the multicast UVBs which are generated through reading data files
        SendUVB();

        //Apply sleeping to wait until all Multicast UVBs are received or settled for each server process 0,1,2
        try { Thread.sleep(9000); } catch (Exception e) {}

        System.out.println("\n----------------------------------------------------------------------------------------------");
        System.out.println("UVBConsumer popping off UVBs from PriorityBlockingQueue to verify the UVBs (Apply Work)...");
        //Apply sleep to wait until messages are received or settled for each server process 0,1,2
        try { Thread.sleep(3000); } catch (Exception e) {}

        //start up the UVBConsumer to process the UVBs in the PriorityBlockingQue to apply work to verify the UVBs
        //then Multicast the updated Linked-List Blockchain Ledger with the newly added Verified Block to other server process 0,1,2. BlockchainLedgerServerWorker will update the
        //local Linked-List BlockChain ledger for each Process 0,1,2 and finally update the actual JSON file ledger by Process 0
        new Thread(new UVBConsumer(UVB_PriorityQue)).start();
    }

    //method to create the dummy first block (Block 0) to be added to the BlockChain Ledger
    //Note: We need to create the DummyBlock only in one Server Process either 0,1,2 then send it to others because the Winning Hash can be different if each
    //Server Process makes their own Dummy Block 0
    public Block createDummyBlock(){
        Block DummyBlock = new Block();

        DummyBlock.setBlock_ID(UUID.randomUUID().toString()); //set Block ID using UUID
        DummyBlock.setBlock_Number("0"); //setting block number

        //Create TimeStamp for Dummy Block
        Date date = new Date();
        String TimeStamp_String = String.format("%1$s %2$tF.%2$tT", "", date); //To format data
        DummyBlock.setTime_Stamp(TimeStamp_String);

        //Set Data
        DummyBlock.setFirstName("Captain");
        DummyBlock.setLastName("Thailand");
        DummyBlock.setDateOfBirth("1782.04.21");
        DummyBlock.setSSN_Number("555-555-555");
        DummyBlock.setIllness("Corruption");
        DummyBlock.setRx_Medication("Democracy");

        //Set Dummy fake Previous Hash
        DummyBlock.setPrevious_Hash("tu283jfnv09308u3934k2lnjfhio2002988u5y454okjrpnete439349");

        //Preparing for the THREE ELEMENTS to be added for applying work
        //this string includes Previous Hash and Block data, RandomSeed will be added later when applying work
        String DummyBlock_Data = DummyBlock.getPrevious_Hash() + DummyBlock.getSSN_Number() + DummyBlock.getIllness() + DummyBlock.getRx_Medication();

        //Applying work to verify block
        try {
            //Setting and Limiting duration of work applied to solving puzzle
            for (int i = 1; i < 30; i++) {
                String Random_Seed = RandomSeed_Generator(8); //generate random seed to solve puzzle
                String THREE_ELEMENT = DummyBlock_Data + Random_Seed; //the THREE ELEMENTS

                //Hash Value to do work on which includes "THREE ELEMENTS" (Previous_Hash + Current Block Data + Random Seed)
                String Hash_Value = Hash_SHA256(THREE_ELEMENT);

                //APPLYING WORK
                int Work_Number = Integer.parseInt(Hash_Value.substring(0, 4), 16); // Grab the first few of the hash to be from 0000 - FFFF
                if (!(Work_Number < 20000)){  //Keep working if greater than 20000
                    //DO nothing so keep working
                }
                if (Work_Number < 20000){ //OH puzzle solved less than 20000
                    DummyBlock.setRandomSeed(Random_Seed); //set the winning random seed
                    DummyBlock.setCurrent_Hash(Hash_Value); //set the winning hash, which is the Proof-of-Work and that block is verified
                    break; //stop the loop cause puzzle solved
                }
            }
        }
        catch(Exception e){
            e.printStackTrace();
        }

        //return the verified DummyBlock
        return DummyBlock;
    }


    //Method for generating RandomSeed input as how many
    public String RandomSeed_Generator(int count){
        //bases characters for generating RandomSeed
        final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        //Build the random seed
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }

    //Method to apply hash SHA-256 algorithm encryption
    //But will need to combine first with "THREE ELEMENTS" which includes Previous_Hash + Data + Random Seed as the string input
    public String Hash_SHA256(String THREE_ELEMENTS){

        try {
            //Create hash from Block Data using SHA-256 algorithm
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(THREE_ELEMENTS.getBytes());
            byte byteData[] = md.digest();

            //Converting byte to hexadecimal
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }

            //this is the result from encryption using hash SHA-256
            String Hashed_String = sb.toString();

            return Hashed_String;
        }

        catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    //Multicast message to other server process 0, 1, 2 including self
    //to make sure Server Process 0, 1, 2 are up
    public void SendMessage(){
        Socket sock; // for socket
        PrintStream toServer; //for getting output stream
        try{
            //sending message to all server process 0,1,2 including self
            for(int i = 0; i< Number_Of_Processes; i++){
                sock = new Socket(serverName, Ports.MessageServerPort_Base + i); //setting up the socket according to Server Process Port
                toServer = new PrintStream(sock.getOutputStream()); //out stream for sending to Server
                toServer.println("Hello multicast message from Process " + Blockchain.Process_Number + " up and running"); //send message to other server including self
                toServer.flush(); //clearing Stream, due to stream maybe queued up
                sock.close();
            }
        }catch (Exception e) {e.printStackTrace ();}
    }

    //method for generating keypair depending on input
    public KeyPair generateKeyPair(long seed) throws Exception {
        //Apply RSA encryption for generating key pairs
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        rng.setSeed(seed);

        //size of key
        keyGenerator.initialize(1024, rng);

        return (keyGenerator.generateKeyPair());
    }

    //Multicast public key and Server Process Number to other server process 0,1,2 including self
    public void SendPublicKey(String Public_Key){
        Socket sock;
        PrintStream toServer; //for getting output stream
        try{
            //sending message to all servers including self
            for(int i = 0; i< Number_Of_Processes; i++){
                sock = new Socket(serverName, Ports.PublicKeyServerPort_Base + i); //setting up the socket according to Server Process Port
                toServer = new PrintStream(sock.getOutputStream()); //out stream for sending to Server
                toServer.println(Integer.toString(Process_Number)); //first send message is Server Process Number
                toServer.println(Public_Key); //second send message is the Process's public key
                toServer.flush(); //clearing Stream, due to stream maybe queued up
                sock.close();
            }
        }catch (Exception e) {e.printStackTrace();}
    }

    //Multicast the Linked-List Blockchain Ledger which includes the dummy block to other server process 0,1,2 including self so they can update
    //their local Linked-List Blockchain ledger
    //Note: We need to create the DummyBlock only in one Server Process either 0,1,2 then send it to others because the Winning Hash can be different if each
    //Server Process makes their own Dummy Block 0
    public void SendDummyBlockChainLedger(){
        Socket sock;
        PrintStream toServer; //for getting output stream

        //creating Gson for converting Linked-List Blockchain into JSON format
        Gson gson = new Gson();

        //the JSON String format of the Linked-List Blockchain
        String JSON_BlockChain = gson.toJson(BlockChain_Ledger);

        try{
            //sending JSON Blockchain to all servers including self
            for(int i = 0; i< Number_Of_Processes; i++){
                sock = new Socket(serverName, Ports.BlockChainLedgerServerPort_Base + i); //setting up the socket according to Server Process Port
                toServer = new PrintStream(sock.getOutputStream()); //out stream for sending to Server
                toServer.println(Integer.toString(Process_Number) + " -> Dummy Block 0"); //first send message to Server of the Process Number that is receiving the message from
                toServer.println(JSON_BlockChain); //second send message which is the JSON String format of Linked-List Blockchain
                toServer.flush(); //clearing Stream, due to stream maybe queued up
                sock.close();
            }
        }catch (Exception e) {e.printStackTrace();}
    }


    //Read the data input file depending on Process number 0,1,2
    //Create the UVBs from reading data from file
    //Multicast UVBs to other server process 0,1,2 including self so they can update their own PriorityBlockingQueue
    public void SendUVB(){
        //storing file name to read from
        String FILE_NAME;

        //Retrieve file for reading depending on the Process_Number
        //Process 0 -> file "BlockInput0.txt", Process 1 -> "BlockInput1.txt", Process 2 -> "BlockInput2.txt"
        switch (Process_Number) {
            case 1:
                FILE_NAME = "BlockInput1.txt";
                break; //break out of switch
            case 2:
                FILE_NAME = "BlockInput2.txt";
                break; //break out of switch
            default:
                FILE_NAME = "BlockInput0.txt";
                break; //break out of switch
        }

        System.out.println("\n----------------------------------------------------------------------------------------------");
        System.out.println("Reading data input files for creating UVBs (Unverified Blocks) and then multicast each UVB...");

        //Now we are going to create the UVBs from reading the data from the FILE_NAME
        try {
            //Buffer to read the contents of file
            BufferedReader br = new BufferedReader(new FileReader(FILE_NAME));

            //Token for matching the read in content
            String[] tokens = new String[10];

            //Storing a line of content read from file
            String ReadLine;

            //Keep reading from file until null
            while ((ReadLine = br.readLine()) != null) {

                //Create Unverified Block to store read in data
                Block UVB = new Block();

                //Setting the BLock ID
                UVB.setBlock_ID(UUID.randomUUID().toString());

                //Applying sleeping so that timestamp is different (doesn't overlap) for each UVB
                try { Thread.sleep(2000); } catch (InterruptedException e) { }

                //Create TimeStamp
                Date date = new Date();
                String TimeStamp_String = String.format("%1$s %2$tF.%2$tT", "", date); //To format date

                //Setting the TimeStamp
                UVB.setTime_Stamp(TimeStamp_String);

                //Setting Block Data based on Tokens
                tokens = ReadLine.split(" +");
                UVB.setFirstName(tokens[iFNAME]);
                UVB.setLastName(tokens[iLNAME]);
                UVB.setSSN_Number(tokens[iSSNUM]);
                UVB.setDateOfBirth(tokens[iDOB]);
                UVB.setIllness(tokens[iDIAG]);
                UVB.setTreatment(tokens[iTREAT]);
                UVB.setRx_Medication(tokens[iRX]);

                //Implementing Digital Signature to Data ONLY on "SSN_Number"----------------------------------------------------------
                //first apply SHA256 hash algorithm on the data "SSN_Number"
                String hash_SSN = Hash_SHA256(UVB.getSSN_Number()); //this is the hash
                UVB.setHash_SSN(hash_SSN); //storing the Hash_SSN for UVBConsumer use to unsign or verify the digital signature
                try{
                    //To sign the hash_SSN with the Private Key
                    byte[] Signed_digitalSignature = signData(hash_SSN.getBytes(), keyPair.getPrivate());

                    //set the process number that signed the digital signature so that we can unsigned or verify it with that Process's Public Key in UVBConsumer when applying work
                    UVB.setProcess_SignedData(Integer.toString(Process_Number));

                    //convert the Signed_digitalSignature into String and save it to UVB
                    UVB.setDigital_Signature(Base64.getEncoder().encodeToString(Signed_digitalSignature));

                } catch (Exception e) {
                    e.printStackTrace();
                }
                //------------------------------------------------------------------------------------------------------------------

                //Going to multicast the UVB to other server process 0,1,2 including self so can update the UVB PriorityBlockingQueue
                Socket sock;
                PrintStream toServer; //for getting output stream

                //creating Gson for converting Block object into JSON format
                Gson gson = new Gson();

                //the JSON String format of the Dummy Block 0
                String JSON_UVB = gson.toJson(UVB);
                try{
                    //sending UVB to all servers including self
                    for(int i = 0; i< Number_Of_Processes; i++){
                        sock = new Socket(serverName, Ports.UVBServerPort_Base + i); //setting up the socket according to Server Process Port
                        toServer = new PrintStream(sock.getOutputStream()); //out stream for sending to Server
                        toServer.println(Integer.toString(Process_Number)); //first send message to Server of the Process Number that is receiving the message from
                        toServer.println(JSON_UVB); //second send message which is the JSON String format of UVB
                        toServer.flush(); //clearing Stream, due to stream maybe queued up
                        sock.close();
                    }
                }catch (Exception e) {e.printStackTrace ();}

            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //method to sign or encrypt hash using Private Key for digital signature
    public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(data);
        return (signer.sign());
    }
}


//Block to implement "Serializable" so it can be passed via output stream message to another Server Processes
class Block implements Serializable {
    String Block_ID; //using UUID
    String Block_Number;
    String Time_Stamp;
    String FirstName; //data
    String LastName; //data
    String DateOfBirth; //data
    String SSN_Number; //data
    String Illness; //data
    String Treatment; //data
    String Rx_Medication; //data
    String Previous_Hash; //data
    String RandomSeed; //This is the winning RandomSeed for passing the work
    String Current_Winning_Hash; //Work has been applied Proof-of Work
    String Hash_SSN; //used for signing and unsigning
    String Digital_Signature; //storing the digital signature of signing the SSN_Number by Private Key
    String Process_SignedData; //Process Number that implemented the digital signature on the UVB using PrivateKey


    //Below all Getters & Setters
    public String getBlock_ID(){
        return Block_ID;
    }

    public void setBlock_ID(String Block_ID){
        this.Block_ID = Block_ID;
    }

    public String getBlock_Number(){
        return Block_Number;
    }

    public void setBlock_Number(String Block_Number){
        this.Block_Number = Block_Number;
    }

    public String getTime_Stamp(){
        return Time_Stamp;
    }

    public void setTime_Stamp(String Time_Stamp){
        this.Time_Stamp = Time_Stamp;
    }

    public String getFirstName() {
        return FirstName;
    }

    public void setFirstName (String FN){
        this.FirstName = FN;
    }

    public String getLastName() {
        return LastName;
    }

    public void setLastName (String LN){
        this.LastName = LN;
    }

    public String getSSN_Number() {
        return SSN_Number;
    }

    public void setSSN_Number (String SSN){
        this.SSN_Number = SSN;
    }

    public String getDateOfBirth() {
        return DateOfBirth;
    }

    public void setDateOfBirth (String DOB){
        this.DateOfBirth = DOB;
    }

    public String getIllness (){
        return Illness;
    }

    public void setIllness (String I){
        this.Illness = I;
    }

    public String getTreatment() {
        return Treatment;
    }

    public void setTreatment (String Treatment){
        this.Treatment = Treatment;
    }

    public String getRx_Medication() {
        return Rx_Medication;
    }

    public void setRx_Medication (String Rx) {
        this.Rx_Medication = Rx;
    }

    public String getPrevious_Hash(){
        return Previous_Hash;
    }

    public void setPrevious_Hash(String Previous_Hash){
        this.Previous_Hash = Previous_Hash;
    }

    public String getRandomSeed(){
        return RandomSeed;
    }

    public void setRandomSeed(String RandomSeed){
        this.RandomSeed = RandomSeed;
    }

    public String getCurrent_Hash(){
        return Current_Winning_Hash;
    }

    public void setCurrent_Hash(String Current_Hash){
        this.Current_Winning_Hash = Current_Hash;
    }

    public String getHash_SSN(){
        return Hash_SSN;
    }

    public void setHash_SSN(String hashSSN){
        this.Hash_SSN = hashSSN;
    }

    public String getDigital_Signature(){
        return this.Digital_Signature;
    }

    public void setDigital_Signature(String Signed_Data){
        this.Digital_Signature = Signed_Data;
    }

    public String getProcess_SignedData(){
        return this.Process_SignedData;
    }

    public void setProcess_SignedData(String Process_Number){
        this.Process_SignedData = Process_Number;
    }
}


//class storing Ports and setting up Ports based on Process_Number
class Ports{
    //Port for Receiving Messages -> Hello, to make sure Server Process 0, 1, 2 are up and running
    public static int MessageServerPort_Base = 4610; //this would be the default Server Process 0 port

    //Port for Receiving Public Key
    public static int PublicKeyServerPort_Base = 4710; //this would be the default Server Process 0 port

    //Port for Receiving UVB (Unverified Block)
    public static int UVBServerPort_Base = 4820; //this would be the default Server Process 0 port

    //Port for Receiving updated Linked-List Blockchain to update the local BlockChain
    public static int BlockChainLedgerServerPort_Base = 4930; //this would be the default Server Process 0 port

    //For custom port depending on Server Process 0,1,2
    public static int MessageServerPort;
    public static int UVBServerPort;
    public static int BlockChainLedgerServerPort;
    public static int PublicKeyServerPort;

    //method to set Port depending on the Process_Number
    public void setPort(){
        //If the Process_Number is 0 then port is 4610, if 1 then port is 4611, if 2 then port is 4612
        MessageServerPort = MessageServerPort_Base + (Blockchain.Process_Number * 1);

        //If the Process_Number is 0 then port is 4710, if 1 then port is 4711, if 2 then port is 4712
        PublicKeyServerPort = PublicKeyServerPort_Base + (Blockchain.Process_Number * 1);

        //If the Process_Number is 0 then port is 4820, if 1 then port is 4821, if 2 then port is 4822
        UVBServerPort = UVBServerPort_Base + (Blockchain.Process_Number * 1);

        //If the Process_Number is 0 then port is 4930, if 1 then port is 4931, if 2 then port is 4932
        BlockChainLedgerServerPort = BlockChainLedgerServerPort_Base + (Blockchain.Process_Number * 1);
    }
}

//class storing each Process 0,1,2 Public Key
class Key_Object{

    //For storing the Public Keys for the 3 Server Processes 0,1,2
    //index 0 -> Process 0's public key, index 1 -> Process 1's public key, index 2 -> Process 2's public key
    PublicKey[] Public_Key_List = new PublicKey[3];

    //Setter Used if Process Number is 0
    public void setPublic_Key_List_Index0(PublicKey PK){
        this.Public_Key_List[0] = PK;
    }

    //Getter Used if Process Number is 0
    public PublicKey getPublic_Key_Index0(){
        return this.Public_Key_List[0];
    }

    //Setter Used if Process Number is 1
    public void setPublic_Key_List_Index1(PublicKey PK){
        this.Public_Key_List[1] = PK;
    }

    //Getter Used if Process Number is 1
    public PublicKey getPublic_Key_Index1(){
        return this.Public_Key_List[1];
    }

    //Setter Used if Process Number is 2
    public void setPublic_Key_List_Index2(PublicKey PK){
        this.Public_Key_List[2] = PK;
    }

    //Getter Used if Process Number is 2
    public PublicKey getPublic_Key_Index2(){
        return this.Public_Key_List[2];
    }

}


//Create Message Server for listening incoming sockets to retrieve multicast message
//to make sure that Server Process 0, 1, 2 are up and running
class MessageServer implements Runnable{

    public void run(){
        int que_len = 5; //Max que socket to process, if greater throw in bin
        Socket MessageSock; //for getting socket
        System.out.println("Starting up Message Server using " + Ports.MessageServerPort + " listening for Multicast Messages...");
        try{
            ServerSocket Server_Socket = new ServerSocket(Ports.MessageServerPort, que_len); //create Server Socket on Port with max que
            while (true) { //keep looping and listening
                MessageSock = Server_Socket.accept(); //waiting for incoming socket or got it
                new MessageWorker (MessageSock).start(); //start thread to read Multicast Message from socket
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}


//worker class to read in or process the Multicast Message
class MessageWorker extends Thread{
    Socket MessageSock; //storing reference socket

    //constructor
    MessageWorker(Socket s){
        MessageSock = s;
    }

    public void run(){
        try{
            //Get reference for input stream from socket
            BufferedReader in = new BufferedReader(new InputStreamReader(MessageSock.getInputStream()));
            String dataMessage = in.readLine(); //read in Message
            System.out.println("\nGot Message: " + dataMessage);
            MessageSock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}

//Create PublicKey Server for listening to incoming sockets to retrieve multicast public keys
class PublicKeyServer implements Runnable{
    public void run(){
        int que_len = 6; //Max que socket to process, if greater throw in bin
        Socket Key_socket; //for getting socket
        System.out.println("Starting up PublicKey Server using " + Ports.PublicKeyServerPort + " listening for Multicast PublicKeys...");
        try{
            ServerSocket Server_Socket = new ServerSocket(Ports.PublicKeyServerPort, que_len); //create Server Socket on Port with max que
            while (true) { //keep looping
                Key_socket = Server_Socket.accept(); //waiting for incoming socket or got it
                new PublicKeyWorker (Key_socket).start(); //start thread to read Multicast PublicKeys from socket
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}

//worker class to read in or process the Multicast Public Key
class PublicKeyWorker extends Thread{
    Socket Key_socket; //storing reference for socket

    //constructor
    PublicKeyWorker(Socket s){
        Key_socket = s;
    }

    public void run(){

        try{
            //Get reference for input stream from socket
            BufferedReader in = new BufferedReader(new InputStreamReader(Key_socket.getInputStream()));
            String dataProcessNumber = in.readLine(); //first read in Message is the Process Number
            String dataPublicKey = in.readLine (); //second read in Message is the Public Key
            System.out.println("\nGot Public Key from process " + dataProcessNumber);

            //Converting the Public Key String back into Public Key Object format
            //Converting Public Key String back into byte form
            byte[] byte_PublicKey = Base64.getDecoder().decode(dataPublicKey);
            try {
                //For restoring or recreating the Public Key object back from byte
                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(byte_PublicKey);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                PublicKey Restored_PublicKey = keyFactory.generatePublic(pubSpec); //this is the Restored Public Key Object

                //Storing the Public Key based which process number
                int Tmp_ProcessNumber = Integer.parseInt(dataProcessNumber);
                if(Tmp_ProcessNumber == 0) {
                    Blockchain.PublicKey_Object.setPublic_Key_List_Index0(Restored_PublicKey); //Process 0 storing at index 0
                }
                else if(Tmp_ProcessNumber == 1){
                    Blockchain.PublicKey_Object.setPublic_Key_List_Index1(Restored_PublicKey); //Process 1 storing at index 1
                }
                else {   //Tmp_ProcessNumber == 2
                    Blockchain.PublicKey_Object.setPublic_Key_List_Index2(Restored_PublicKey); //Process 2 storing at index 2
                }

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }

            Key_socket.close();
        } catch (IOException x){x.printStackTrace();}
    }
}


//Create BlockChain Server for listening to incoming sockets to retrieve Multicast updated Linked-List Blockchain in JSON format
class BlockChainLedgerServer implements Runnable{
    public void run(){
        int que_len = 8; //Max que socket to process, if greater throw in bin
        Socket BC_socket; //for getting socket
        System.out.println("Starting up BlockChainLedger Server using " + Ports.BlockChainLedgerServerPort + " listening for Multicast updated Blockchain...");
        try{
            ServerSocket Server_Socket = new ServerSocket(Ports.BlockChainLedgerServerPort, que_len); //create Server Socket on Port with max que
            while (true) { //keep looping and listening
                BC_socket = Server_Socket.accept(); //waiting for incoming socket or got it
                new BlockChainLedgerServerWorker (BC_socket).start(); //start thread to read or process Multicast updated Blockchain JSON format from socket
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}


//worker class to read in to process the Multicast updated Blockchain JSON format and
//updated it to local Linked-List BlockChain ledger
//Also Server Process 0 will update the actual JSON file Blockchain Ledger each time a new updated Blockchain is received
class BlockChainLedgerServerWorker extends Thread{
    Socket BC_Socket; //storing reference socket

    //constructor
    BlockChainLedgerServerWorker(Socket s){
        BC_Socket = s;
    }

    public void run(){

        //creating Gson for converting JSON format back into Linked-List Blockchain
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        try{
            //Get reference for input stream from socket
            BufferedReader in = new BufferedReader(new InputStreamReader(BC_Socket.getInputStream()));
            String dataProcessNumber = in.readLine(); //first read in Message is the Process Number
            System.out.println("\nGOT updated Blockchain from process " + dataProcessNumber + ".");

            String dataJSON_Blockchain = in.readLine(); //second read in Message is the JSON format Blockchain ledger

            //Temporary Linked-List to store the read in updated Blockchain Ledger
            LinkedList<Block> New_Blockchain = new LinkedList<>();

            //Recreating the updated Linked-List Blockchain object from JSON String
            //Using a token template For taking the JSON string objects and converting into Block Objects and put it into Linked-List
            New_Blockchain = gson.fromJson(dataJSON_Blockchain, new TypeToken<LinkedList<Block>>(){}.getType());

            //replace the local Blockchain with the new updated one
            Blockchain.BlockChain_Ledger = New_Blockchain;

            System.out.println("--NEW BLOCKCHAIN UPDATED-- Blockchain from Process: " + dataProcessNumber);

            //for debugging purposes to see size of BlockChain Ledger
            //System.out.println(Blockchain.BlockChain_Ledger.size());

            //for debugging purpose
            //Block tmpBlock = Blockchain.BlockChain_Ledger.getLast();
            //System.out.println("Most Recent Verified Block number and name: " + tmpBlock.getBlock_Number() + ", " + tmpBlock.getFirstName() + " " + tmpBlock.getLastName());

            //Update the actual BlockChain Ledger for the JSON file ONLY if Server Process is 0
            if(Blockchain.Process_Number == 0){
                //WRITE the updated Blockchain to JSON file
                //Convert Linked-List Blockchain Ledger to JSON format and then writing the JSON into a file saving to disk
                try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
                    gson.toJson(Blockchain.BlockChain_Ledger, writer);
                } catch (IOException e) {e.printStackTrace();}
            }

            BC_Socket.close();
        } catch (IOException x){x.printStackTrace();}
    }
}


//Create UVBServer for listening to incoming sockets to retrieve multicast UVB in JSON format
class UVBServer implements Runnable{
    PriorityBlockingQueue UVB_PQ; //storing reference of PriorityBlockingQueue

    //constructor
    UVBServer(PriorityBlockingQueue UVB_PriorityQue){
        UVB_PQ = UVB_PriorityQue;
    }

    public void run(){
        int que_len = 8; //Max que socket to process, if greater throw in bin
        Socket UVBSock; //for getting socket
        System.out.println("Starting up UVB Server using " + Ports.UVBServerPort + " listening for Multicast UVBs...");
        try{
            ServerSocket Server_Socket = new ServerSocket(Ports.UVBServerPort, que_len); //create Server Socket on Port with max que
            while (true) { //keep looping
                UVBSock = Server_Socket.accept(); //waiting for incoming socket or got it
                new UVBServerWorker (UVBSock, UVB_PQ).start(); //start thread to read Multicast UVB from socket
            }
        }catch (IOException ioe) {System.out.println(ioe);}
    }
}


//worker class to read in or process the Multicast UVBs adding into PriorityBlockingQueue
class UVBServerWorker extends Thread{
    Socket UVBSock; //storing reference socket
    PriorityBlockingQueue UVB_PQ; //storing reference of PriorityBlockingQueue

    //constructor
    UVBServerWorker(Socket s, PriorityBlockingQueue UVB_PQ){
        UVBSock = s;
        this.UVB_PQ = UVB_PQ;
    }

    public void run(){

        //creating Gson for converting JSON format back into Block object
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        try{
            //Get reference for input stream from socket
            BufferedReader in = new BufferedReader(new InputStreamReader(UVBSock.getInputStream()));
            String dataProcessNumber = in.readLine(); //first read in Message is the Process Number
            System.out.println("\nGot a UVB from Process: " + dataProcessNumber);

            String dataJSON_UVB = in.readLine(); //second read in Message is the JSON String format of UVB

            //Recreating Block object from JSON String
            Block UVB_Block = gson.fromJson(dataJSON_UVB, Block.class);

            //adding UVB block into PriorityBlockingQueue
            UVB_PQ.add(UVB_Block);

            //for debugging purposes
            //System.out.println("UVB Block FirstName & LastName: " + UVB_Block.getFirstName() + " " + UVB_Block.getLastName() + "\nTimeStamp is: " + UVB_Block.getTime_Stamp());

            UVBSock.close();
        } catch (IOException x){x.printStackTrace();}
    }
}


//create UVBConsumer to pop off UVBs from the PriorityBlockingQueue and apply work to verify the block
class UVBConsumer implements Runnable{
    PriorityBlockingQueue UVB_PQue; //storing reference of UVB PriorityBLockingQue
    Block tmpBlock; //used for storing UVB to process on when popping off the UVB PriorityBLockingQue

    //for counting block number and then added to the Block
    int Block_Number = 1;

    //used for determining if a block is verified through work, meaning puzzle solved if TRUE
    boolean Block_Verification = false;

    //constructor
    UVBConsumer(PriorityBlockingQueue UVB_PQ){
        this.UVB_PQue = UVB_PQ;
    }

    public void run(){

        try {
            //keep looping to process verifying UVB from the UVB PriorityBlockingQue
            while (true) {

                //if there is no more UVBs in the PriorityBlockingQueue
                if(UVB_PQue.isEmpty()){
                    System.out.println("\nCOMPLETED!!! NO MORE UVBs (Unverified Blocks) TO BE VERIFIED!!!!!");
                }

                //popping off a UVB from PriorityBlockingQue
                tmpBlock = (Block) UVB_PQue.take();

                //setting Block Number
                tmpBlock.setBlock_Number(Integer.toString(Block_Number));

                //getting the Previous Block hash
                String Previous_Block_Hash = returnPreviousBlockHash(Block_Number);
                //setting previous block hash
                tmpBlock.setPrevious_Hash(Previous_Block_Hash);

                //increment Block Number for next UVB to be verified
                Block_Number++;

                //----------------------------------------------------------------------------------------------------------------------------------------------
                //Verify or unsign the digital signature before continuing
                String Process_Num_Signed = tmpBlock.getProcess_SignedData(); //getting the process number that signed the digital signature so we can retrieve the public key from that process
                PublicKey PK = returnPublicKey(Process_Num_Signed); //method to get the correct Public Key based on Process Number

                //Converting digital_Signature back into byte[] for verifying
                String digital_signature = tmpBlock.getDigital_Signature();
                byte[] DigitalSignature = Base64.getDecoder().decode(digital_signature); //this is the digital signature back in byte form

                boolean Verified_DigitalSignature = verifySig(tmpBlock.getHash_SSN().getBytes(), PK, DigitalSignature);

                //for debugging purposes
                //System.out.println(Verified_DigitalSignature);

                //---------------------------------------------------------------------------------------------------------------------------------------------------

                //will pass if digital signature is verified -> TRUE, so continue processing UVB to apply work
                if(Verified_DigitalSignature){
                    //Preparing for the THREE ELEMENTS to be added for applying work
                    //this string includes Previous Hash and Block data, RandomSeed will be added later when applying work
                    String Block_PreviousH_Data = tmpBlock.getPrevious_Hash() + tmpBlock.getSSN_Number() + tmpBlock.getIllness() + tmpBlock.getRx_Medication();

                    //Applying work to verify block and getting the Proof-of-work if puzzle solved including Winning Random Seed
                    //Array index 0 is Winning Random Seed and index 1 is Winning Hash
                    String[] Work_ResultsTmp = ApplyWORK(Block_PreviousH_Data);

                    //Checking to see if the block has been verified, meaning Apply work puzzle is solved
                    if (Block_Verification == true) {
                        //This Block has been Verified !!!!!!!!!!
                        tmpBlock.setRandomSeed(Work_ResultsTmp[0]); //setting winning Random Seed
                        tmpBlock.setCurrent_Hash(Work_ResultsTmp[1]); //Setting Winning Hash which will be the Proof-of-work for this block

                        //changing back to false for other blocks to be verified
                        Block_Verification = false;

                        //add the Verified Block to the local Linked-List Blockchain
                        Blockchain.BlockChain_Ledger.add(tmpBlock);

                        //Multicast the updated Blockchain to other server process 0,1,2 including self, the message will be received by the BlockChainLedgerServer
                        Socket sock;
                        PrintStream toServer; //for getting output stream

                        //creating Gson for converting Linked-List Blockchain into JSON format
                        Gson gson = new Gson();

                        //the JSON String format Linked-List Blockchain
                        String JSON_Updated_BC = gson.toJson(Blockchain.BlockChain_Ledger);

                        try {
                            //sending multicast JSON format updated Blockchain to all server process 0,1,2 including self
                            for (int i = 0; i < Blockchain.Number_Of_Processes; i++) {
                                sock = new Socket(Blockchain.serverName, Ports.BlockChainLedgerServerPort_Base + i); //setting up the socket according to Server Process Port
                                toServer = new PrintStream(sock.getOutputStream()); //out stream for sending to Server
                                toServer.println(Integer.toString(Blockchain.Process_Number)); //first send message to Server of the Process Number that is receiving the message from
                                toServer.println(JSON_Updated_BC); //second send message which is the JSON String format Blockchain
                                toServer.flush(); //clearing Stream, due to stream maybe queued up
                                sock.close();
                            }

                            //sleep for the printing to settle and the Linked-List Blockchain ledger and the JSON file Blockchain ledger to be updated before moving on to next UVB to work on
                            try { Thread.sleep(6500); } catch (Exception e) { e.printStackTrace(); }

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
                else{
                    //Verification of digital signature was not successful so cannot continue the work for this UVB
                    //if it comes in here means something wrong with the keys/digital signature
                    System.out.println("Digital Signature did not get verified!!!!!!!!!!!!");
                }

            }

        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    //method for iterating the linklist to grab the previous block hash information for inputting into new Block to be verified
    public String returnPreviousBlockHash(int Current_Block_Number){

        //Getting the previous block to retrieve it's Winning Hash or Current_Hash
        int Previous_Block_Number = Current_Block_Number - 1;

        //For storing the Previous_Hash from previous Block
        String Previous_Hash = "";

        //iterating through the linklist to find the matching Block Number
        Iterator<Block> iterator = Blockchain.BlockChain_Ledger.iterator();
        Block tmpBlock;
        while(iterator.hasNext()){
            tmpBlock = iterator.next();
            if(tmpBlock.getBlock_Number().equals(Integer.toString(Previous_Block_Number))){ //contains the same Block Number
                Previous_Hash = tmpBlock.getCurrent_Hash(); //retrieve hash
                break; //stop the loop
            }
        }

        return Previous_Hash;
    }

    //method to retrieve the correct Public Key based on the Process number that signed it with it's Private Key
    public PublicKey returnPublicKey(String Process_Number){

        //storing the correct public key
        PublicKey PK_tmp;

        //retrieve Public Key based on which Process Number
        if(Process_Number.equals("0")){
            PK_tmp = Blockchain.PublicKey_Object.getPublic_Key_Index0(); //index 0 -> Process 0's Public Key
        }
        else if(Process_Number.equals("1")){
            PK_tmp = Blockchain.PublicKey_Object.getPublic_Key_Index1();//index 1 -> Process 1's Public Key
        }
        else{ //if(Process_Number.equals("2"))
            PK_tmp = Blockchain.PublicKey_Object.getPublic_Key_Index2(); //index 2 -> Process 2's Public Key
        }

        return PK_tmp;
    }

    //Method to verify the signed digital signature using Public Key to open
    public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initVerify(key);
        signer.update(data);

        return (signer.verify(sig));
    }

    //method to apply WORK returning results in an Array if verified
    public String[] ApplyWORK(String DataAndPreviousHash){
        //For Storing Winning RandomSeed at index 0 and Winning Hash at index 1 to return
        String[] Results = new String[2];

        try {
            //Setting and limiting duration of work applied to solving puzzle
            for (int i = 1; i < 30; i++) {

                //CHECKING to see if this current UVB is already verified or not, each loop!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                //--------------------------------------------------------------------------------------------------------------------------------

                //used for determining if there is the same block that is already verified in the linked-list BlockChain Ledger
                boolean Same_Block = false; //TRUE means there is duplicate or same block present

                //Iterating over the Linked-List Blockchain to check for the same block
                Iterator<Block> iterator = Blockchain.BlockChain_Ledger.iterator();
                Block tmp_b;
                while(iterator.hasNext()){
                    tmp_b = iterator.next();

                    if(tmpBlock.getBlock_ID().equals(tmp_b.getBlock_ID())){
                        //System.out.println("FOUND SAME BLOCK");
                        Same_Block = true; //yes same block found
                        break; // stop the loop cause Verified block already exist in the BlockChain Ledger Linked-List
                    }
                }
                //--------------------------------------------------------------------------------------------------------------------------------

                //If there is no same verified block in the BlockChain Ledger linked-list, then keep Applying work
                if(!Same_Block) {

                    String Random_Seed = RandomSeed_Generator(8); //generate random seed to solve puzzle
                    String THREE_ELEMENT = DataAndPreviousHash + Random_Seed;

                    //Hash Value to do work on which includes "THREE ELEMENTS" (Previous_Hash + Current Block Data + Random Seed)
                    String Hash_Value = Hash_SHA256(THREE_ELEMENT);

                    //APPLYING WORK
                    int Work_Number = Integer.parseInt(Hash_Value.substring(0, 4), 16); // Grab the first few of the hash to be from 0000 and FFFF
                    if (!(Work_Number < 20000)){  //Keep working if greater than 20000
                        //Do nothing so keep working
                    }
                    if (Work_Number < 20000){ //OH puzzle solved less than 20000
                        Results[0] = Random_Seed; //winning random seed
                        Results[1] = Hash_Value; //winning Hash, this will be used as Proof-of-Work on the block
                        Block_Verification = true; //changing to true, means that we verified this block by solving the puzzle
                        break; //stop the loop cause puzzle solved
                    }

                    //Apply sleeping to fake work time
                    try { Thread.sleep(1500); } catch (Exception e){ e.printStackTrace();}

                }
                else{
                    Block_Verification = false; //set to false making sure to not to proceed with this UVB block
                    break; //stop this for-loop to apply work because the current UVB has already been verified so move onto the next UVB in the Whileloop
                }

            }
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return Results;
    }

    //Method to apply hash SHA-256 algorithm encryption
    //But will need to combine first with "THREE ELEMENTS" including Previous_Hash + Data + Random Seed as the pass in String to this method
    public String Hash_SHA256(String THREE_ELEMENTS){

        try {
            //Create hash from Block Data using SHA-256 algorithm
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(THREE_ELEMENTS.getBytes());
            byte byteData[] = md.digest();

            //Converting byte to hexadecimal
            StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }

            //this is the result from encryption using hash SHA-256
            String Hashed_String = sb.toString();

            return Hashed_String;
        }

        catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    //Method for generating RandomSeed input as how many
    public String RandomSeed_Generator(int count){
        //bases characters for generating RandomSeed
        final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        //Build the random seed
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }
}

