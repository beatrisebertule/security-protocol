package terminal.test;

import java.security.*;
import java.util.List;

import terminal.common.ByteUtil;
import terminal.common.CryptoUtil;
import terminal.common.ProtocolConstants;
import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.backend.Customer;

public class InfrastructureTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== Infrastructure Tests ===\n");

        testByteUtil();
        testCryptoSignVerify();
        testCertificateRoundtrip();
        testPinHash();
        testBackendInit();
        testVehicleCustomerManagement();
        testAssignmentToken();
        testProtocolConstants();

        System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
        if (failed > 0) System.exit(1);
    }

    // --- ByteUtil tests ---

    private static void testByteUtil() {
        System.out.println("-- ByteUtil --");

        // toHex / fromHex roundtrip
        byte[] original = new byte[] { 0x00, 0x0A, (byte) 0xFF, 0x7F };
        String hex = ByteUtil.toHex(original);
        byte[] decoded = ByteUtil.fromHex(hex);
        assertArrayEquals("toHex/fromHex roundtrip", original, decoded);

        // Known value
        assertEquals("toHex known", "000AFF7F", hex);

        // concat
        byte[] a = new byte[] { 0x01, 0x02 };
        byte[] b = new byte[] { 0x03, 0x04 };
        byte[] c = ByteUtil.concat(a, b);
        assertArrayEquals("concat", new byte[] { 0x01, 0x02, 0x03, 0x04 }, c);

        // shortToBytes / bytesToShort
        short val = (short) 0x1234;
        byte[] sb = ByteUtil.shortToBytes(val);
        assertEquals("shortToBytes[0]", 0x12, sb[0] & 0xFF);
        assertEquals("shortToBytes[1]", 0x34, sb[1] & 0xFF);
        short back = ByteUtil.bytesToShort(sb, 0);
        assertEquals("bytesToShort roundtrip", val, back);

        // Edge: zero
        byte[] zero = ByteUtil.shortToBytes((short) 0);
        assertEquals("short zero", (short) 0, ByteUtil.bytesToShort(zero, 0));
    }

    // --- CryptoUtil sign/verify ---

    private static void testCryptoSignVerify() throws Exception {
        System.out.println("-- CryptoUtil sign/verify --");

        KeyPair kp = CryptoUtil.generateECKeyPair();
        assertNotNull("generateECKeyPair", kp);
        assertNotNull("public key", kp.getPublic());
        assertNotNull("private key", kp.getPrivate());

        byte[] data = "test data for signing".getBytes();
        byte[] signature = CryptoUtil.sign(kp.getPrivate(), data);
        assertNotNull("sign returns bytes", signature);
        assertTrue("signature non-empty", signature.length > 0);

        boolean valid = CryptoUtil.verify(kp.getPublic(), data, signature);
        assertTrue("verify valid sig", valid);

        // Tamper data
        byte[] tampered = "tampered data".getBytes();
        boolean invalid = CryptoUtil.verify(kp.getPublic(), tampered, signature);
        assertTrue("verify tampered fails", !invalid);

        // Wrong key
        KeyPair kp2 = CryptoUtil.generateECKeyPair();
        boolean wrongKey = CryptoUtil.verify(kp2.getPublic(), data, signature);
        assertTrue("verify wrong key fails", !wrongKey);

        // Encode/decode public key roundtrip
        byte[] encoded = CryptoUtil.encodeECPublicKey(kp.getPublic());
        assertEquals("encoded pubkey length", 65, encoded.length);
        assertEquals("encoded pubkey prefix", 0x04, encoded[0] & 0xFF);

        PublicKey decoded = CryptoUtil.decodeECPublicKey(encoded);
        // Verify with decoded key
        boolean decodedValid = CryptoUtil.verify(decoded, data, signature);
        assertTrue("verify with decoded pubkey", decodedValid);
    }

    // --- Certificate TLV ---

    private static void testCertificateRoundtrip() throws Exception {
        System.out.println("-- Certificate TLV --");

        KeyPair masterKP = CryptoUtil.generateECKeyPair();
        KeyPair cardKP = CryptoUtil.generateECKeyPair();

        byte[] cardId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] cardPubEncoded = CryptoUtil.encodeECPublicKey(cardKP.getPublic());

        byte[] cert = CryptoUtil.createCertificate(cardId, cardPubEncoded, masterKP.getPrivate());
        assertNotNull("createCertificate", cert);
        assertTrue("cert non-empty", cert.length > 0);

        // Parse roundtrip
        byte[][] parts = CryptoUtil.parseCertificate(cert);
        assertArrayEquals("cert subjectId", cardId, parts[0]);
        assertArrayEquals("cert pubkey", cardPubEncoded, parts[1]);
        assertTrue("cert sig non-empty", parts[2].length > 0);

        // Verify with master public key
        boolean valid = CryptoUtil.verifyCertificate(cert, masterKP.getPublic());
        assertTrue("verifyCertificate valid", valid);

        // Verify with wrong key fails
        KeyPair wrongKP = CryptoUtil.generateECKeyPair();
        boolean invalid = CryptoUtil.verifyCertificate(cert, wrongKP.getPublic());
        assertTrue("verifyCertificate wrong key fails", !invalid);

        // Extract public key from cert
        PublicKey extracted = CryptoUtil.extractPublicKeyFromCert(cert);
        assertNotNull("extractPublicKeyFromCert", extracted);
        // Verify signing with original key, verifying with extracted
        byte[] testData = "test".getBytes();
        byte[] sig = CryptoUtil.sign(cardKP.getPrivate(), testData);
        assertTrue("extracted key verifies", CryptoUtil.verify(extracted, testData, sig));
    }

    // --- PIN hash ---

    private static void testPinHash() throws Exception {
        System.out.println("-- PIN hash --");

        byte[] hash1 = CryptoUtil.hashPin("1234");
        assertEquals("hash length", 32, hash1.length);

        byte[] hash2 = CryptoUtil.hashPin("1234");
        assertArrayEquals("deterministic hash", hash1, hash2);

        byte[] hash3 = CryptoUtil.hashPin("5678");
        assertTrue("different PINs different hash", !java.util.Arrays.equals(hash1, hash3));
    }

    // --- BackendSystem init ---

    private static void testBackendInit() throws Exception {
        System.out.println("-- BackendSystem init --");

        BackendSystem.reset();
        BackendSystem backend = BackendSystem.getInstance();
        backend.init();

        assertNotNull("master public key", backend.getMasterPublicKey());
        byte[] mpkEncoded = backend.getMasterPublicKeyEncoded();
        assertEquals("MPK encoded length", 65, mpkEncoded.length);

        assertNotNull("terminal key pair", backend.getTerminalKeyPair());
        assertNotNull("terminal certificate", backend.getTerminalCertificate());

        // Terminal certificate verifiable with MPK
        boolean valid = CryptoUtil.verifyCertificate(backend.getTerminalCertificate(), backend.getMasterPublicKey());
        assertTrue("terminal cert valid", valid);

        // signCertificate for a card
        KeyPair cardKP = CryptoUtil.generateECKeyPair();
        byte[] cardId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] cardPubEncoded = CryptoUtil.encodeECPublicKey(cardKP.getPublic());
        byte[] cardCert = backend.signCertificate(cardId, cardPubEncoded);
        assertTrue("card cert verifiable", CryptoUtil.verifyCertificate(cardCert, backend.getMasterPublicKey()));
    }

    // --- Vehicle/Customer management ---

    private static void testVehicleCustomerManagement() throws Exception {
        System.out.println("-- Vehicle/Customer management --");

        BackendSystem.reset();
        BackendSystem backend = BackendSystem.getInstance();
        backend.init();

        // Register vehicles
        byte[] v1Id = new byte[] { 0x01, 0x00, 0x00, 0x01 };
        byte[] v2Id = new byte[] { 0x01, 0x00, 0x00, 0x02 };
        backend.registerVehicle(v1Id, "AB-123-CD");
        backend.registerVehicle(v2Id, "EF-456-GH");

        List<Vehicle> available = backend.getAvailableVehicles();
        assertEquals("2 vehicles available", 2, available.size());

        // Register customer
        byte[] custId = new byte[] { (byte) 0xC0, 0x01 };
        backend.registerCustomer(custId, "Alice");
        Customer cust = backend.getCustomer(custId);
        assertNotNull("customer registered", cust);
        assertEquals("customer name", "Alice", cust.getName());
        assertEquals("initial mileage", 0, cust.getOutstandingMileage());
        assertTrue("not blocked", !cust.isBlocked());

        // Link card
        byte[] cardId = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        backend.linkCardToCustomer(custId, cardId);
        assertArrayEquals("card linked", cardId, cust.getCardId());

        // Assign vehicle
        backend.assignVehicle(v1Id, custId);
        assertEquals("1 vehicle available after assign", 1, backend.getAvailableVehicles().size());
        Vehicle v1 = backend.getVehicle(v1Id);
        assertTrue("v1 not available", !v1.isAvailable());

        // Release vehicle
        backend.releaseVehicle(v1Id);
        assertEquals("2 available after release", 2, backend.getAvailableVehicles().size());

        // Mileage + payment
        backend.addMileageToCustomer(custId, 150);
        assertEquals("mileage added", 150, cust.getOutstandingMileage());
        backend.processPayment(custId);
        assertEquals("mileage cleared", 0, cust.getOutstandingMileage());

        // Block
        backend.blockCustomer(custId);
        assertTrue("customer blocked", cust.isBlocked());
    }

    // --- Assignment token (sigma4) ---

    private static void testAssignmentToken() throws Exception {
        System.out.println("-- Assignment token (sigma4) --");

        BackendSystem.reset();
        BackendSystem backend = BackendSystem.getInstance();
        backend.init();

        // Simulate sigma3 (card signature over vehicle request)
        KeyPair cardKP = CryptoUtil.generateECKeyPair();
        byte[] cardPubEncoded = CryptoUtil.encodeECPublicKey(cardKP.getPublic());
        byte[] requestData = new byte[] { 0x01, 0x02, 0x03 }; // simulated vehicle request
        byte[] sigma3 = CryptoUtil.sign(cardKP.getPrivate(), requestData);

        // Backend signs sigma4
        byte[] sigma4 = backend.signAssignmentToken(sigma3, cardPubEncoded);
        assertNotNull("sigma4 created", sigma4);
        assertTrue("sigma4 non-empty", sigma4.length > 0);

        // Parse sigma4
        byte[][] parts = BackendSystem.parseAssignmentToken(sigma4);
        assertArrayEquals("sigma4 contains sigma3", sigma3, parts[0]);
        assertArrayEquals("sigma4 contains pkc", cardPubEncoded, parts[1]);
        assertTrue("sigma4 sig non-empty", parts[2].length > 0);

        // Verify sigma4
        boolean valid = backend.verifyAssignmentToken(sigma4);
        assertTrue("sigma4 verifiable", valid);

        // Tamper sigma4 - flip a byte in sigma3 portion
        byte[] tampered = sigma4.clone();
        tampered[5] ^= 0xFF;
        boolean invalid = backend.verifyAssignmentToken(tampered);
        assertTrue("tampered sigma4 fails", !invalid);
    }

    // --- ProtocolConstants match AppletConstants ---

    private static void testProtocolConstants() {
        System.out.println("-- ProtocolConstants --");

        // Spot-check key values match
        assertEquals("CLA", 0x00, ProtocolConstants.CLA_RENTAL);
        assertEquals("STATE_BLANK", 0x00, ProtocolConstants.STATE_BLANK);
        assertEquals("STATE_ASSIGNED", 0x03, ProtocolConstants.STATE_ASSIGNED);
        assertEquals("INS_GET_STATE", 0x70, ProtocolConstants.INS_GET_STATE & 0xFF);
        assertEquals("INS_PERSONALIZE_KEYS", 0x10, ProtocolConstants.INS_PERSONALIZE_KEYS & 0xFF);
        assertEquals("SW_WRONG_STATE", 0x6A80, ProtocolConstants.SW_WRONG_STATE & 0xFFFF);
        assertEquals("SW_PIN_LOCKED", 0x6A82, ProtocolConstants.SW_PIN_LOCKED & 0xFFFF);
        assertEquals("NONCE_LENGTH", 16, ProtocolConstants.NONCE_LENGTH);
        assertEquals("EC_PUB_KEY_LENGTH", 65, ProtocolConstants.EC_PUB_KEY_LENGTH);
    }

    // --- Test helpers ---

    private static void assertTrue(String name, boolean condition) {
        if (condition) {
            System.out.println("  PASS: " + name);
            passed++;
        } else {
            System.out.println("  FAIL: " + name);
            failed++;
        }
    }

    private static void assertEquals(String name, Object expected, Object actual) {
        if (expected.equals(actual)) {
            System.out.println("  PASS: " + name);
            passed++;
        } else {
            System.out.println("  FAIL: " + name + " (expected=" + expected + ", actual=" + actual + ")");
            failed++;
        }
    }

    private static void assertEquals(String name, int expected, int actual) {
        if (expected == actual) {
            System.out.println("  PASS: " + name);
            passed++;
        } else {
            System.out.println("  FAIL: " + name + " (expected=" + expected + ", actual=" + actual + ")");
            failed++;
        }
    }

    private static void assertNotNull(String name, Object obj) {
        assertTrue(name + " not null", obj != null);
    }

    private static void assertArrayEquals(String name, byte[] expected, byte[] actual) {
        assertTrue(name, java.util.Arrays.equals(expected, actual));
    }
}
