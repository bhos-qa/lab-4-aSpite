package org.example;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class VirusSignatureDatabase {
    private static final Logger LOGGER = Logger.getLogger(VirusSignatureDatabase.class.getName());

    // Database represented by lists
    private final List<String> signatureNames;
    private final List<String> signatureHashes;
    private final List<String> signatureDetails;

    public VirusSignatureDatabase() {
        this.signatureNames = new ArrayList<>();
        this.signatureHashes = new ArrayList<>();
        this.signatureDetails = new ArrayList<>();
    }

    // 1. Add a virus signature with duplicate check
    public String addVirusSignature(String signatureName, String hash, String details) {
        if (signatureNames.contains(signatureName)) {
            return "Signature with this name already exists.";
        }
        signatureNames.add(signatureName);
        signatureHashes.add(hash);
        signatureDetails.add(details);
        return "Signature " + signatureName + " added successfully.";
    }

    // 2. Remove a virus signature
    public String removeVirusSignature(String signatureName) {
        int index = signatureNames.indexOf(signatureName);
        if (index == -1) {
            return "Signature " + signatureName + " not found.";
        }
        signatureNames.remove(index);
        signatureHashes.remove(index);
        signatureDetails.remove(index);
        return "Signature " + signatureName + " removed successfully.";
    }

    // 3. Update a virus signature (e.g., updating hash or details)
    public String updateVirusSignature(String signatureName, String newHash, String newDetails) {
        int index = signatureNames.indexOf(signatureName);
        if (index == -1) {
            return "Signature " + signatureName + " not found.";
        }
        signatureHashes.set(index, newHash);
        signatureDetails.set(index, newDetails);
        return "Signature " + signatureName + " updated.";
    }

    // 4. Check if a file is infected by comparing its hash with the database
    public String checkFileForVirus(String fileHash) {
        int index = signatureHashes.indexOf(fileHash);
        if (index == -1) {
            return "File is clean.";
        }
        return "File is infected with virus: " + signatureNames.get(index);
    }

    // 5. List all virus signatures in the database
    public List<String> listAllVirusSignatures() {
        return new ArrayList<>(signatureNames);
    }

    // 6. Check if a specific virus signature exists in the database
    public boolean isSignatureInDatabase(String signatureName) {
        return signatureNames.contains(signatureName);
    }

    // 7. Get details of a virus signature
    public String getSignatureDetails(String signatureName) {
        int index = signatureNames.indexOf(signatureName);
        if (index == -1) {
            return "Signature not found.";
        }
        return "Signature: " + signatureName + ", Hash: " + signatureHashes.get(index) + ", Details: " + signatureDetails.get(index);
    }

    // 8. Simulate scanning the system for viruses by checking file hashes
    public String scanSystem(List<String> fileHashes) {
        List<String> infectedFiles = new ArrayList<>();
        for (String fileHash : fileHashes) {
            if (signatureHashes.contains(fileHash)) {
                int index = signatureHashes.indexOf(fileHash);
                infectedFiles.add("File is infected with virus: " + signatureNames.get(index));
            }
        }
        return infectedFiles.isEmpty() ? "System is clean." : String.join("\n", infectedFiles);
    }

    // 9. Import new virus signatures
    public String importVirusSignatures(List<String> newSignatures, List<String> newHashes, List<String> newDetails) {
        int importedCount = 0;
        for (int i = 0; i < newSignatures.size(); i++) {
            if (!signatureNames.contains(newSignatures.get(i))) {
                signatureNames.add(newSignatures.get(i));
                signatureHashes.add(newHashes.get(i));
                signatureDetails.add(newDetails.get(i));
                importedCount++;
            }
        }
        return "Imported " + importedCount + " new signatures.";
    }

    // 10. Export all virus signatures
    public List<String> exportVirusSignatures() {
        List<String> exportedSignatures = new ArrayList<>();
        for (int i = 0; i < signatureNames.size(); i++) {
            exportedSignatures.add("Signature: " + signatureNames.get(i) + ", Hash: " + signatureHashes.get(i) + ", Details: " + signatureDetails.get(i));
        }
        return exportedSignatures;
    }

    // Method that interacts with the database and is vulnerable to SQL injection
    public String findSignatureByName(String signatureName) {
        String result = "Signature not found.";
        try (Connection conn = DriverManager.getConnection("jdbc:postgresql://localhost:5432/signature_db", "postgres", "postgres")) {
            Statement stmt = conn.createStatement();

            // Vulnerability: Unsanitized user input directly used in the query
            String query = "SELECT * FROM signatures WHERE name = '" + signatureName + "'";
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                result = "Signature: " + rs.getString("name") + ", Hash: " + rs.getString("hash");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Database error occurred while finding signature by name", e);

        }
        return result;
    }
}
