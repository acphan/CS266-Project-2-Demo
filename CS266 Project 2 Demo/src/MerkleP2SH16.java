import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

public class MerkleP2SH16 {

	public static void main(String [] args) throws Exception
	  {
		// Start timer and record memory
		long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
	  	long time1 = System.nanoTime();

	  	// Hash script
	  	ScriptHashOut hashedScript = new ScriptHashOut();
	  	
	  	// Put into string format
	  	String hashNode1 = hashedScript.hashScript();
	  	String hashNode2 = hashedScript.hashScript();
	  	String hashNode3 = hashedScript.hashScript();
	  	String hashNode4 = hashedScript.hashScript();
	  	String hashNode5 = hashedScript.hashScript();
	  	String hashNode6 = hashedScript.hashScript();
	  	String hashNode7 = hashedScript.hashScript();
	  	String hashNode8 = hashedScript.hashScript();
		String hashNode9 = hashedScript.hashScript();
	  	String hashNode10 = hashedScript.hashScript();
	  	String hashNode11 = hashedScript.hashScript();
	  	String hashNode12 = hashedScript.hashScript();
	  	String hashNode13 = hashedScript.hashScript();
	  	String hashNode14 = hashedScript.hashScript();
	  	String hashNode15 = hashedScript.hashScript();
	  	String hashNode16 = hashedScript.hashScript();
	  
	  	// Put hashed nodes in list for merkle tree
	    List<String> merkleNodes = new ArrayList<String>();
	    merkleNodes.add(hashNode1);
	    merkleNodes.add(hashNode2);
	    merkleNodes.add(hashNode3);
	    merkleNodes.add(hashNode4);
	    merkleNodes.add(hashNode5);
	    merkleNodes.add(hashNode6);
	    merkleNodes.add(hashNode7);
	    merkleNodes.add(hashNode8);
	    merkleNodes.add(hashNode9);
	    merkleNodes.add(hashNode10);
	    merkleNodes.add(hashNode11);
	    merkleNodes.add(hashNode12);
	    merkleNodes.add(hashNode13);
	    merkleNodes.add(hashNode14);
	    merkleNodes.add(hashNode15);
	    merkleNodes.add(hashNode16);
	    
	    // Create Merkle Tree and print out root
	    MerkleTree treeOne = new MerkleTree(merkleNodes);
	    treeOne.mTree();
	    System.out.println("root : " + treeOne.getRoot());
	    System.out.println();

	    // Test merkle tree authentication correctly - same nodes/path
	    System.out.println("Same nodes and path test");
	    String checkNode1 = hashNode1;
	    
	    String checkNode2 = getHash(checkNode1 + hashNode2);
	    String checkNode3 = getHash(hashNode3 + hashNode4);
	    String checkNode4 = getHash(hashNode5 + hashNode6);
	    String checkNode5 = getHash(hashNode7 + hashNode8);
	    String checkNode6 = getHash(hashNode9 + hashNode10);
	    String checkNode7 = getHash(hashNode11 + hashNode12);
	    String checkNode8 = getHash(hashNode13 + hashNode14);
	    String checkNode9 = getHash(hashNode15 + hashNode16);
	    
	    String checkNode10 = getHash(checkNode2 + checkNode3);
	    String checkNode11 = getHash(checkNode4 + checkNode5);
	    String checkNode12 = getHash(checkNode6 + checkNode7);
	    String checkNode13 = getHash(checkNode8 + checkNode9);
	    
	    String checkNode14 = getHash(checkNode10 + checkNode11);
	    String checkNode15 = getHash(checkNode12 + checkNode13);
	    
	    String checkNodeFinal = getHash(checkNode14 + checkNode15);
	    System.out.println((checkNodeFinal));

	    checkHash(treeOne, checkNodeFinal, checkNode1);
	    System.out.println();
	    
	    System.out.println("Different node and same path test");
	    String hashNode1DN = getHash("This is a different node.");
	    String checkNode1DN = hashNode1DN;
	    
	    String checkNode2DN = getHash(checkNode1DN + hashNode2);
	    String checkNode3DN = getHash(hashNode3 + hashNode4);
	    String checkNode4DN = getHash(hashNode5 + hashNode6);
	    String checkNode5DN = getHash(hashNode7 + hashNode8);
	    String checkNode6DN = getHash(hashNode9 + hashNode10);
	    String checkNode7DN = getHash(hashNode11 + hashNode12);
	    String checkNode8DN = getHash(hashNode13 + hashNode14);
	    String checkNode9DN = getHash(hashNode15 + hashNode16);
	    
	    String checkNode10DN = getHash(checkNode2DN + checkNode3DN);
	    String checkNode11DN = getHash(checkNode4DN + checkNode5DN);
	    String checkNode12DN = getHash(checkNode6DN + checkNode7DN);
	    String checkNode13DN = getHash(checkNode8DN + checkNode9DN);
	    
	    String checkNode14DN = getHash(checkNode10DN + checkNode11DN);
	    String checkNode15DN = getHash(checkNode12DN + checkNode13DN);
	    
	    String checkNodeFinalDN = getHash(checkNode14DN + checkNode15DN);
	    System.out.println((checkNodeFinalDN));
	 
	    checkHash(treeOne, checkNodeFinalDN, checkNode1DN);
	    System.out.println();
	    
	    System.out.println("Same nodes and different path test");
	    String checkNode1DP = hashNode1;
	    
	    String checkNode2DP = getHash(checkNode1DP + hashNode2);
	    String checkNode3DP = getHash(hashNode3 + hashNode4);
	    String checkNode4DP = getHash(hashNode5 + hashNode6);
	    String checkNode5DP = getHash(hashNode8 + hashNode7);
	    String checkNode6DP = getHash(hashNode9 + hashNode10);
	    String checkNode7DP = getHash(hashNode11 + hashNode12);
	    String checkNode8DP = getHash(hashNode13 + hashNode14);
	    String checkNode9DP = getHash(hashNode15 + hashNode16);
	    
	    String checkNode10DP = getHash(checkNode2DP + checkNode3DP);
	    String checkNode11DP = getHash(checkNode4DP + checkNode5DP);
	    String checkNode12DP = getHash(checkNode6DP + checkNode7DP);
	    String checkNode13DP = getHash(checkNode8DP + checkNode9DP);
	    
	    String checkNode14DP = getHash(checkNode10DP + checkNode11DP);
	    String checkNode15DP = getHash(checkNode12DP + checkNode13DP);
	    
	    String checkNodeFinalDP = getHash(checkNode14DP + checkNode15DP);
	    System.out.println((checkNodeFinalDP));

	    checkHash(treeOne, checkNodeFinalDP, checkNode1DP);
	    System.out.println();
	    
	    // Get time it takes to perform the tests
	    long time2 = System.nanoTime();
	    long timeTaken = time2 - time1;
	    System.out.println("Time Taken: " + timeTaken + " nanoseconds.");
	    System.out.println();
	    
	    // Get memory usage for tests
	    long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
	    long actualMemUsed=afterUsedMem-beforeUsedMem;
	    System.out.println("Memory Used: " + actualMemUsed + " bytes.");
	  }
	
	 // Get hash value of messages to be placed into merkle tree nodes
	  public static String getHash(String str) {
	      byte[] cipher_byte;
	      try{
	          MessageDigest md = MessageDigest.getInstance("SHA-256");
	          md.update(str.getBytes());
	          cipher_byte = md.digest();
	          StringBuilder sb = new StringBuilder(2 * cipher_byte.length);
	          for(byte b: cipher_byte) {
	            sb.append(String.format("%02x", b&0xff) );
	          }
	          return sb.toString();
	      } catch (Exception e) {
	              e.printStackTrace();
	      }
	      
	      return "";
	  }
	
	 // Compare merkle tree root and node final hash as well as script hashes
	  public static void checkHash (MerkleTree tree, String checkNodeFinal, String usedNode) throws Exception
	  {
		  ScriptHashOut checkScript = new ScriptHashOut();

		   if ((tree.getRoot().compareTo(checkNodeFinal) == 0) && (checkScript.hashScript().compareTo(usedNode) == 0))
		    {
		    	System.out.println("Accept the node. Continue.");
		    }
		    else
		    {
		    	System.out.println("Do not accept.");
		    }
		   
	  }

}
