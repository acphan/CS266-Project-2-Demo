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
	    
	    //Check node
	    String checkedNode1 = hashNode1;
	    ScriptHashOut nodeScriptHash = new ScriptHashOut();
	    
	    
	    
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

}
