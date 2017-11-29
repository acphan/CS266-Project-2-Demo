import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

public class MerkleTree {

  List<String> nodes;

  String root;

  public MerkleTree(List<String> nodeList) 
  {
    this.nodes = nodeList;
    root = "";
  }

  public void mTree() {
    
    List<String> tempNodes = new ArrayList<String>();
    
    for (int i = 0; i < this.nodes.size(); i++) 
    {
    	tempNodes.add(this.nodes.get(i));
    }
    
    List<String> updatedList = getUpdate(tempNodes);
    
    while (updatedList.size() != 1) 
    {
    	updatedList = getUpdate(updatedList);
    }
    
    this.root = updatedList.get(0);
  }

  private List<String> getUpdate(List<String> tempNodes) {
    
    List<String> updatedList = new ArrayList<String>();
    int index = 0;
    
    while (index < tempNodes.size())
    {

      String left = tempNodes.get(index);
      index++;

      String right = "";
      if (index != tempNodes.size()) 
      {
        right = tempNodes.get(index);
      }

      String hashValue = getHash(left + right);
      updatedList.add(hashValue);
      index++;
      
    }
    
    return updatedList;
  }

  public String getHash(String str) 
  {
        byte[] cipher_byte;
        
        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(str.getBytes());
            cipher_byte = md.digest();
            StringBuilder sb = new StringBuilder(2 * cipher_byte.length);
            
            for(byte b: cipher_byte) 
            {
              sb.append(String.format("%02x", b&0xff) );
            }
            return sb.toString();
        } catch (Exception e) {
                e.printStackTrace();
        }
        
        return "";
  }

  public String getRoot() 
  {
    return this.root;
  }
  
  public int getNodeCount()
  {
	  return this.nodes.size();
  }
    
}