import org.example.VirusSignatureDatabase;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.List;

public class VirusSignatureDatabaseTest {
    VirusSignatureDatabase db = new VirusSignatureDatabase();

    @Test
    public void testAddVirusSignature() {
        String result = db.addVirusSignature("Trojan", "hash123", "Trojan horse virus");
        assertEquals("Signature Trojan added successfully.", result);
    }

    @Test
    public void testRemoveVirusSignature() {
        db.addVirusSignature("Trojan", "hash123", "Trojan horse virus");
        String result = db.removeVirusSignature("Trojan");
        assertEquals("Signature Trojan removed successfully.", result);
    }

    @Test
    public void testCheckFileForVirus() {
        db.addVirusSignature("Trojan", "hash123", "Trojan horse virus");
        String result = db.checkFileForVirus("hash123");
        assertEquals("File is infected with virus: Trojan", result);
    }

    @Test
    public void testListAllVirusSignatures() {
        db.addVirusSignature("Trojan", "hash123", "Trojan horse virus");
        List<String> signatures = db.listAllVirusSignatures();
        assertEquals(Arrays.asList("Trojan"), signatures);
    }

    @Test
    public void testIsSignatureInDatabase() {
        db.addVirusSignature("Trojan", "hash123", "Trojan horse virus");
        boolean exists = db.isSignatureInDatabase("Trojan");
        assertTrue(exists);
    }
}
