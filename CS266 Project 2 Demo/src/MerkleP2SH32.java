import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

public class MerkleP2SH32 {

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
	  	String hashNode17 = hashedScript.hashScript();
	  	String hashNode18 = hashedScript.hashScript();
	  	String hashNode19 = hashedScript.hashScript();
	  	String hashNode20 = hashedScript.hashScript();
	  	String hashNode21 = hashedScript.hashScript();
	  	String hashNode22 = hashedScript.hashScript();
	  	String hashNode23 = hashedScript.hashScript();
	  	String hashNode24 = hashedScript.hashScript();
		String hashNode25 = hashedScript.hashScript();
	  	String hashNode26 = hashedScript.hashScript();
	  	String hashNode27 = hashedScript.hashScript();
	  	String hashNode28 = hashedScript.hashScript();
	  	String hashNode29 = hashedScript.hashScript();
	  	String hashNode30 = hashedScript.hashScript();
	  	String hashNode31 = hashedScript.hashScript();
	  	String hashNode32 = hashedScript.hashScript();
	  
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
	    merkleNodes.add(hashNode17);
	    merkleNodes.add(hashNode18);
	    merkleNodes.add(hashNode19);
	    merkleNodes.add(hashNode20);
	    merkleNodes.add(hashNode21);
	    merkleNodes.add(hashNode22);
	    merkleNodes.add(hashNode23);
	    merkleNodes.add(hashNode24);
	    merkleNodes.add(hashNode25);
	    merkleNodes.add(hashNode26);
	    merkleNodes.add(hashNode27);
	    merkleNodes.add(hashNode28);
	    merkleNodes.add(hashNode29);
	    merkleNodes.add(hashNode30);
	    merkleNodes.add(hashNode31);
	    merkleNodes.add(hashNode32);
	    
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
	    String checkNode10 = getHash(hashNode17 + hashNode18);
	    String checkNode11 = getHash(hashNode19 + hashNode20);
	    String checkNode12 = getHash(hashNode21 + hashNode22);
	    String checkNode13 = getHash(hashNode23 + hashNode24);
	    String checkNode14 = getHash(hashNode25 + hashNode26);
	    String checkNode15 = getHash(hashNode27 + hashNode28);
	    String checkNode16 = getHash(hashNode29 + hashNode30);
	    String checkNode17 = getHash(hashNode31 + hashNode32);
	    
	    String checkNode18 = getHash(checkNode2 + checkNode3);
	    String checkNode19 = getHash(checkNode4 + checkNode5);
	    String checkNode20 = getHash(checkNode6 + checkNode7);
	    String checkNode21 = getHash(checkNode8 + checkNode9);
	    String checkNode22 = getHash(checkNode10 + checkNode11);
	    String checkNode23 = getHash(checkNode12 + checkNode13);
	    String checkNode24 = getHash(checkNode14 + checkNode15);
	    String checkNode25 = getHash(checkNode16 + checkNode17);
	    
	    String checkNode26 = getHash(checkNode18 + checkNode19);
	    String checkNode27 = getHash(checkNode20 + checkNode21);
	    String checkNode28 = getHash(checkNode22 + checkNode23);
	    String checkNode29 = getHash(checkNode24 + checkNode25);
	    
	    String checkNode30 = getHash(checkNode26 + checkNode27);
	    String checkNode31 = getHash(checkNode28 + checkNode29);
	    
	    String checkNodeFinal = getHash(checkNode30 + checkNode31);
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
	    String checkNode10DN = getHash(hashNode17 + hashNode18);
	    String checkNode11DN = getHash(hashNode19 + hashNode20);
	    String checkNode12DN = getHash(hashNode21 + hashNode22);
	    String checkNode13DN = getHash(hashNode23 + hashNode24);
	    String checkNode14DN = getHash(hashNode25 + hashNode26);
	    String checkNode15DN = getHash(hashNode27 + hashNode28);
	    String checkNode16DN = getHash(hashNode29 + hashNode30);
	    String checkNode17DN = getHash(hashNode31 + hashNode32);
	    
	    String checkNode18DN = getHash(checkNode2DN + checkNode3DN);
	    String checkNode19DN = getHash(checkNode4DN + checkNode5DN);
	    String checkNode20DN = getHash(checkNode6DN + checkNode7DN);
	    String checkNode21DN = getHash(checkNode8DN + checkNode9DN);
	    String checkNode22DN = getHash(checkNode10DN + checkNode11DN);
	    String checkNode23DN = getHash(checkNode12DN + checkNode13DN);
	    String checkNode24DN = getHash(checkNode14DN + checkNode15DN);
	    String checkNode25DN = getHash(checkNode16DN + checkNode17DN);
	    
	    String checkNode26DN = getHash(checkNode18DN + checkNode19DN);
	    String checkNode27DN = getHash(checkNode20DN + checkNode21DN);
	    String checkNode28DN = getHash(checkNode22DN + checkNode23DN);
	    String checkNode29DN = getHash(checkNode24DN + checkNode25DN);
	    
	    String checkNode30DN = getHash(checkNode26DN + checkNode27DN);
	    String checkNode31DN = getHash(checkNode28DN + checkNode29DN);
	    
	    String checkNodeFinalDN = getHash(checkNode30DN + checkNode31DN);
	    System.out.println((checkNodeFinalDN));
	 
	    checkHash(treeOne, checkNodeFinalDN, checkNode1DN);
	    System.out.println();
	    
	    System.out.println("Same nodes and different path test");
	    String checkNode1DP = hashNode1;
	    
	    String checkNode2DP = getHash(checkNode1DP + hashNode2);
	    String checkNode3DP = getHash(hashNode3 + hashNode4);
	    String checkNode4DP = getHash(hashNode5 + hashNode6);
	    String checkNode5DP = getHash(hashNode7 + hashNode8);
	    String checkNode6DP = getHash(hashNode9 + hashNode10);
	    String checkNode7DP = getHash(hashNode11 + hashNode12);
	    String checkNode8DP = getHash(hashNode13 + hashNode14);
	    String checkNode9DP = getHash(hashNode15 + hashNode16);
	    String checkNode10DP = getHash(hashNode18 + hashNode17);
	    String checkNode11DP = getHash(hashNode19 + hashNode20);
	    String checkNode12DP = getHash(hashNode21 + hashNode22);
	    String checkNode13DP = getHash(hashNode23 + hashNode24);
	    String checkNode14DP = getHash(hashNode25 + hashNode26);
	    String checkNode15DP = getHash(hashNode27 + hashNode28);
	    String checkNode16DP = getHash(hashNode29 + hashNode30);
	    String checkNode17DP = getHash(hashNode31 + hashNode32);
	    
	    String checkNode18DP = getHash(checkNode2DP + checkNode3DP);
	    String checkNode19DP = getHash(checkNode4DP + checkNode5DP);
	    String checkNode20DP = getHash(checkNode6DP + checkNode7DP);
	    String checkNode21DP = getHash(checkNode8DP + checkNode9DP);
	    String checkNode22DP = getHash(checkNode10DP + checkNode11DP);
	    String checkNode23DP = getHash(checkNode12DP + checkNode13DP);
	    String checkNode24DP = getHash(checkNode14DP + checkNode15DP);
	    String checkNode25DP = getHash(checkNode16DP + checkNode17DP);
	    
	    String checkNode26DP = getHash(checkNode18DP + checkNode19DP);
	    String checkNode27DP = getHash(checkNode20DP + checkNode21DP);
	    String checkNode28DP = getHash(checkNode22DP + checkNode23DP);
	    String checkNode29DP = getHash(checkNode24DP + checkNode25DP);
	    
	    String checkNode30DP = getHash(checkNode26DP + checkNode27DP);
	    String checkNode31DP = getHash(checkNode28DP + checkNode29DP);
	    
	    String checkNodeFinalDP = getHash(checkNode30DP + checkNode31DP);
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
