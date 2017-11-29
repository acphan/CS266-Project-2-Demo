import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

public class MerkleP2SH {

	public static void main(String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException
	  {
		// Start timer and record memory
		long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
	  	long time1 = System.nanoTime();

	  	// Hash script
	  	ScriptHashOut hashedScript = new ScriptHashOut();

	  	// Put into string format
	  	String hashNode1 = hashedScript.toString();
	  	String hashNode2 = hashedScript.toString();
	  	String hashNode3 = hashedScript.toString();
	  	String hashNode4 = hashedScript.toString();
	  	String hashNode5 = hashedScript.toString();
	  	String hashNode6 = hashedScript.toString();
	  	String hashNode7 = hashedScript.toString();
	  	String hashNode8 = hashedScript.toString();
	  
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
	    
	    // Create Merkle Tree and print out root
	    MerkleTree treeOne = new MerkleTree(merkleNodes);
	    treeOne.mTree();
	    System.out.println("root : " + treeOne.getRoot());
	    System.out.println();
	    
	    // For every node, generate key pair
	    Script newScript = new Script();
	    newScript.setPubKeyList(newScript.multisign(treeOne.getNodeCount()));
	    
	    
	    

	    // Test merkle tree authentication correctly - same nodes/path
	    System.out.println("Same nodes and path test");
	    String checkNode1 = hashNode1;
	    
	    String checkNode2 = getHash(checkNode1 + hashNode2);
	    String checkNode3 = getHash(hashNode3 + hashNode4);
	    String checkNode4 = getHash(hashNode5 + hashNode6);
	    String checkNode5 = getHash(hashNode7 + hashNode8);
	    
	    String checkNode6 = getHash(checkNode2 + checkNode3);
	    String checkNode7 = getHash(checkNode4 + checkNode5);
	    
	    String checkNodeFinal = getHash(checkNode6 + checkNode7);
	    System.out.println((checkNodeFinal));

	    checkHash(treeOne, checkNodeFinal, checkNode1);
	    System.out.println();
	    
	    // Test merkle tree authentication wrong - changed node, same path
	    System.out.println("Different node and same path test");
	    String hashNode1DN = getHash("This is a different node.");
	    String checkNode1DN = hashNode1DN;
	    
	    String checkNode2DN = getHash(checkNode1DN + hashNode2);
	    String checkNode3DN = getHash(hashNode3 + hashNode4);
	    String checkNode4DN = getHash(hashNode5 + hashNode6);
	    String checkNode5DN = getHash(hashNode7 + hashNode8);
	    
	    String checkNode6DN = getHash(checkNode2DN + checkNode3DN);
	    String checkNode7DN = getHash(checkNode4DN + checkNode5DN);
	    
	    String checkNodeFinalDN = getHash(checkNode6DN + checkNode7DN);
	    System.out.println((checkNodeFinalDN));
	    
	    checkHash(treeOne, checkNodeFinalDN, checkNode1DN);
	    System.out.println();
	    
	    
	    // Test merkle tree authentication wrong - same nodes, changed path
	    System.out.println("Same nodes and different path test");
	    String checkNode1DP = hashNode1;
	    
	    String checkNode2DP = getHash(checkNode1DP + hashNode2);
	    String checkNode3DP = getHash(hashNode3 + hashNode4);
	    String checkNode4DP = getHash(hashNode5 + hashNode6);
	    String checkNode5DP = getHash(hashNode7 + hashNode8);
	    
	    String checkNode6DP = getHash(checkNode3DP + checkNode2DP);
	    String checkNode7DP = getHash(checkNode4DP + checkNode5DP);
	    
	    String checkNodeFinalDP = getHash(checkNode6DP + checkNode7DP);
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
	
	 // Compare merkle tree root and node final hash
	  public static void checkHash (MerkleTree tree, String checkNodeFinal, String usedNode)
	  {
		  ScriptHashOut checkScript = new ScriptHashOut();
		  String checkScriptString = checkScript.toString();

		   if ((tree.getRoot().compareTo(checkNodeFinal) == 0) && (checkScriptString.compareTo(usedNode) == 0))
		    {
		    	System.out.println("Accept the node. Continue.");
		    }
		    else
		    {
		    	System.out.println("Do not accept.");
		    }
		   
	  }

}
