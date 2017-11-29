import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class RunMerkle16 {

  public static void main(String [] args) 
  {
	long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
  	long time1 = System.nanoTime();
  	
  	String node1 = "Sample message to be encrypted.";
  	String node2 = "This is a test.";
  	String node3 = "This is the third node.";
  	String node4 = "We are in class CS266.";
  	String node5 = "Random message.";
  	String node6 = "This is not a test.";
  	String node7 = "This is one of the nodes.";
  	String node8 = "We are in Fall 2017.";
	String node9 = "Another message to be encrypted.";
  	String node10 = "This is not really a test.";
  	String node11 = "This is one of the 16 nodes.";
  	String node12 = "We are in semester Fall 2017.";
  	String node13 = "Truly a hidden message.";
  	String node14 = "Hello there.";
  	String node15 = "How are you today.";
  	String node16 = "Last node of this test.";
  	
  	String hashNode1 = getHash(node1);
  	String hashNode2 = getHash(node2);
  	String hashNode3 = getHash(node3);
  	String hashNode4 = getHash(node4);
  	String hashNode5 = getHash(node5);
  	String hashNode6 = getHash(node6);
  	String hashNode7 = getHash(node7);
  	String hashNode8 = getHash(node8);
  	String hashNode9 = getHash(node9);
  	String hashNode10 = getHash(node10);
  	String hashNode11 = getHash(node11);
  	String hashNode12 = getHash(node12);
  	String hashNode13 = getHash(node13);
  	String hashNode14 = getHash(node14);
  	String hashNode15 = getHash(node15);
  	String hashNode16 = getHash(node16);
  	
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
     
    MerkleTree treeOne = new MerkleTree(merkleNodes);
    treeOne.mTree();
    System.out.println("root : " + treeOne.getRoot());
    System.out.println();
    
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

    checkHashRoot(treeOne, checkNodeFinal);
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
 
    checkHashRoot(treeOne, checkNodeFinalDN);
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

    checkHashRoot(treeOne, checkNodeFinalDP);
    System.out.println();
    
    long time2 = System.nanoTime();
    long timeTaken = time2 - time1;
    System.out.println("Time Taken: " + timeTaken + " nanoseconds.");
    System.out.println();
    
    long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
    long actualMemUsed=afterUsedMem-beforeUsedMem;
    System.out.println("Memory Used: " + actualMemUsed + " bytes.");
  }
  
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
  
  public static void checkHashRoot (MerkleTree tree, String checkNodeFinal)
  {
	   if (tree.getRoot().equals(checkNodeFinal))
	    {
	    	System.out.println("Accept the node, the hash and root are equal. Continue.");
	    }
	    else
	    {
	    	System.out.println("Hash and root are not equal. Do not accept.");
	    }
	   
  }
}