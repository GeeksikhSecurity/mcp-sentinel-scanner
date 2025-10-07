import java.io.*;
import java.sql.*;

public class Main {
    private static final String API_KEY = "sk-1234567890abcdef"; // Hardcoded secret
    
    public static void main(String[] args) throws Exception {
        String userInput = args[0];
        
        // Command injection
        Runtime.getRuntime().exec("echo " + userInput);
        
        // SQL injection
        String query = "SELECT * FROM users WHERE id = '" + userInput + "'";
        
        // Path traversal
        File file = new File("../../../etc/passwd");
        
        // Deserialization
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject();
    }
}

class TestClass {
    private static final String MOCK_SECRET = "test-secret-123456789";
    
    public void testMethod() {
        // Test context
        assert true;
    }
}