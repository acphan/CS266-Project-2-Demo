import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class RunMerkle32 {

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
  	String node17 = "Sample message to be encrypted.";
  	String node18 = "This is a test.";
  	String node19 = "This is the third node.";
  	String node20 = "We are in class CS266.";
  	String node21 = "Random message.";
  	String node22 = "This is not a test.";
  	String node23 = "This is one of the nodes.";
  	String node24 = "We are in Fall 2017.";
	String node25 = "Another message to be encrypted.";
  	String node26 = "This is not really a test.";
  	String node27 = "This is one of the 16 nodes.";
  	String node28 = "We are in semester Fall 2017.";
  	String node29 = "Truly a hidden message.";
  	String node30 = "Hello there.";
  	String node31 = "How are you today.";
  	String node32 = "Last node of this test.";
  	
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
  	String hashNode17 = getHash(node17);
  	String hashNode18 = getHash(node18);
  	String hashNode19 = getHash(node19);
  	String hashNode20 = getHash(node20);
  	String hashNode21 = getHash(node21);
  	String hashNode22 = getHash(node22);
  	String hashNode23 = getHash(node23);
  	String hashNode24 = getHash(node24);
  	String hashNode25 = getHash(node25);
  	String hashNode26 = getHash(node26);
  	String hashNode27 = getHash(node27);
  	String hashNode28 = getHash(node28);
  	String hashNode29 = getHash(node29);
  	String hashNode30 = getHash(node30);
  	String hashNode31 = getHash(node31);
  	String hashNode32 = getHash(node32);
  	
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
 
    checkHashRoot(treeOne, checkNodeFinalDN);
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