import Foundation
import Testing
@testable import SwiftKyber

final class SwiftKyberTests {
    
    
    /// Convenience to produce random data of a given length.
    private func randomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }
    
    @Test
    func testKeyPairGeneration() {
        #expect(throws: Never.self, performing: {
            let keyPair = try Kyber1024.KeyAgreement.PrivateKey()
            
            #expect(keyPair.publicKey.rawRepresentation.count == kyber1024PublicKeyLength, "Public key length is incorrect")
            #expect(keyPair.rawRepresentation.count == kyber1024PrivateKeyLength, "Secret key length is incorrect")
        })
    }
    
    // Test: Encapsulation
    @Test
    func testEncapsulation() {
        #expect(throws: Never.self, performing: {
            let keyPair = try Kyber1024.KeyAgreement.PrivateKey()
            let publicKey = keyPair.publicKey
            
            let (ciphertext, sharedSecret) = try publicKey.encapsulate()
            
            #expect(ciphertext.count == kyber1024CiphertextLength, "Ciphertext length is incorrect")
            #expect(sharedSecret.bytes.count == kyber1024SharedSecretLength, "Shared secret length is incorrect")
        })
    }
    
    // Test: Decapsulation
    @Test
    func testDecapsulation() {
        #expect(throws: Never.self, performing: {
            let keyPair = try Kyber1024.KeyAgreement.PrivateKey()
            let publicKey = keyPair.publicKey
            
            let capsule = try publicKey.encapsulate()
            
            #expect(capsule.sharedSecret.bytes.count == kyber1024SharedSecretLength, "Shared secret length is incorrect")
        })
    }
    
    // Test: Shared Secret Calculation from Key Agreement (Bob's Decapsulation)
    @Test
    func testSharedSecretFromKeyAgreement() {
        #expect(throws: Never.self, performing: {
            // Generate Alice's keypair
            let aliceKeyPair = try Kyber1024.KeyAgreement.PrivateKey()
            let alicePublicKey = aliceKeyPair.publicKey
            let (ciphertext, _) = try alicePublicKey.encapsulate()
            
            // Generate Bob's keypair
            let bobKeyPair = try Kyber1024.KeyAgreement.PrivateKey()
            // Bob decapsulates to obtain the shared secret
            let bobSharedSecret = try bobKeyPair.sharedSecret(from: ciphertext)
            
            #expect(bobSharedSecret.bytes.count == kyber1024SharedSecretLength, "Shared secret length is incorrect")
        })
    }
    
    @Test
    /// Generates a fresh key‑pair, lets the *public* key encapsulate, and
    /// uses the matching *private* key to decapsulate.
    func testEncapDecapRoundTrip() throws {
        #expect(throws: Never.self, performing: {
            // Bob is the recipient: he generates a private / public key pair.
            let bobPriv = try Kyber1024.KeyAgreement.PrivateKey()
            let bobPub  = bobPriv.publicKey
            print(bobPriv)
            print(bobPub)
            // Alice (the sender) takes Bob's public key and encapsulates.
            let (ciphertext, aliceSecret) = try bobPub.encapsulate()
            
            // Bob receives the ciphertext and decapsulates it.
            let bobSecret = try bobPriv.sharedSecret(from: ciphertext)
            
            // ① Both parties must get 32‑byte shared secrets.
            #expect(aliceSecret.bytes.count ==
                    kyber1024SharedSecretLength)
            #expect(bobSecret.bytes.count ==
                    kyber1024SharedSecretLength)
            
            // ② Secrets must be identical.
            #expect(aliceSecret == bobSecret,
                    "Alice and Bob derived different shared secrets")
        })
    }
    
    @Test
    /// Attempt to decapsulate a ciphertext with the **wrong** private key
    /// — must throw.
    func testDecapsulationWithWrongKeyThrows() throws {
            let bobPriv = try Kyber1024.KeyAgreement.PrivateKey()
               let bobPub  = bobPriv.publicKey

               let malloryPriv = try Kyber1024.KeyAgreement.PrivateKey()

               let (ciphertext, expectedSecret) = try bobPub.encapsulate()
               let wrongSecret = try malloryPriv.sharedSecret(from: ciphertext)
            #expect(expectedSecret != wrongSecret)
    }
    
    @Test
    /// Supplying a malformed (shortened) ciphertext must throw.
    func testMalformedCiphertextThrows() throws {
        #expect(throws: Error.self, performing: {
            let bobPriv = try Kyber1024.KeyAgreement.PrivateKey()
            
            // Build an invalid, truncated ciphertext.
            let badCiphertext = Data(repeating: 0,
                                     count: Int(kyber1024CiphertextLength) - 10)
            _ = try bobPriv.sharedSecret(from: badCiphertext)
        })
    }

    enum Errors: Error {
        case malformed, mismatched
    }
}
