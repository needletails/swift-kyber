//
//  SwiftKyber.swift
//  swift-kyber
//
//  Created by Cole M on 4/24/25.
//
import Foundation
import CLibOQS

public let kyber1024PublicKeyLength: Int32 = OQS_KEM_kyber_1024_length_public_key
public let kyber1024PrivateKeyLength: Int32 = OQS_KEM_kyber_1024_length_secret_key
public let kyber1024CiphertextLength: Int32 = OQS_KEM_kyber_1024_length_ciphertext
public let kyber1024SharedSecretLength: Int32 = OQS_KEM_kyber_1024_length_shared_secret
public let kyber1024KeypairSeedLength: Int32 = OQS_KEM_kyber_1024_length_keypair_seed

public enum Kyber1024: Sendable {}

extension Kyber1024 {
    
    public enum KeyAgreement: Sendable {
        
        public struct PrivateKey: Sendable {
            
            
            public let publicKey: PublicKey
            // secret‑key bytes (OQS_KEM_kyber_1024_length_secret_key)
            public let rawRepresentation: Data
            
            public init() throws {
                let pkLen = Int(OQS_KEM_kyber_1024_length_public_key)
                let skLen = Int(OQS_KEM_kyber_1024_length_secret_key)
                
                let pkPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: pkLen)
                let skPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: skLen)
                defer {
                    pkPtr.deallocate()
                    skPtr.deallocate()
                }
                
                let status = OQS_KEM_kyber_1024_keypair(pkPtr, skPtr)
                try OQSStatus(status.rawValue).throwIfError()
                
                self.rawRepresentation = Data(bytes: skPtr, count: skLen)
                self.publicKey = PublicKey(rawRepresentation: Data(bytes: pkPtr, count: pkLen))
            }
            
            /// Re‑creates a private key from raw secret‑key bytes
            /// (e.g. after decoding from storage).
            public init<Bytes: DataProtocol>(rawRepresentation: Bytes) throws {
                guard rawRepresentation.count == Int(OQS_KEM_kyber_1024_length_secret_key) else {
                    throw KyberError.invalidKeySize
                }
                self.rawRepresentation = Data(rawRepresentation)
                // Need the public key as well – liboqs cannot derive it from sk,
                // so the caller must supply it separately.
                throw KyberError.publicKeyRequired
            }
            
            /// Decapsulate **Alice’s ciphertext** to get the shared secret.
            public func sharedSecret(from ciphertext: Data) throws -> SharedSecret {
                try Kyber1024.sharedSecret(ciphertext: ciphertext,
                                           secretKey: rawRepresentation)
            }
        }
        
        public struct PublicKey: Sendable {
            
            // raw public‑key bytes (OQS_KEM_kyber_1024_length_public_key)
            public let rawRepresentation: Data
            
            public init(rawRepresentation: Data) {
                self.rawRepresentation = rawRepresentation
            }
            
            /// Alice uses Bob’s *public* key to produce `(ciphertext, sharedSecret)`.
            public func encapsulate() throws -> (ciphertext: Data, sharedSecret: SharedSecret) {
                try Kyber1024.encapsulate(to: rawRepresentation)
            }
        }
    }
    
    public struct SharedSecret: Sendable, Equatable {
        fileprivate let rawRepresentation: Data          // 32 bytes
        
        /// Returns the 32 raw secret bytes – use with care.
        public var bytes: Data { rawRepresentation }
    }
}

extension Kyber1024 {
    
    /// liboqs status wrapper → throws on error
    private struct OQSStatus {
        let value: Int32
        init(_ v: Int32) { self.value = v }
        func throwIfError(file: StaticString = #file, line: UInt = #line) throws {
            guard value == OQS_SUCCESS.rawValue else { throw KyberError(from: value) }
        }
    }
    
    static func encapsulate(to pk: Data) throws -> (Data, SharedSecret) {
        
        precondition(pk.count == Int(OQS_KEM_kyber_1024_length_public_key))
        
        let ctLen = Int(OQS_KEM_kyber_1024_length_ciphertext)
        let ssLen = Int(OQS_KEM_kyber_1024_length_shared_secret)
        
        let ctPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: ctLen)
        let ssPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: ssLen)
        
        defer {
            ctPtr.deallocate()
            ssPtr.deallocate()
        }
        
        let status = pk.withUnsafeBytes { pkBuf in
            OQS_KEM_kyber_1024_encaps(ctPtr, ssPtr,
                                      pkBuf.bindMemory(to: UInt8.self).baseAddress!)
        }
        try OQSStatus(status.rawValue).throwIfError()
        
        return (Data(bytes: ctPtr, count: ctLen),
                SharedSecret(rawRepresentation: Data(bytes: ssPtr, count: ssLen)))
    }
    
    static func sharedSecret(ciphertext: Data,
                             secretKey: Data) throws -> SharedSecret {
        
        // Validate ciphertext length
        guard ciphertext.count == Int(OQS_KEM_kyber_1024_length_ciphertext) else {
            throw KyberError.invalidCiphertextLength
        }
        
        let ssLen = Int(OQS_KEM_kyber_1024_length_shared_secret)
        let ssPtr = UnsafeMutablePointer<UInt8>.allocate(capacity: ssLen)
        
        defer {
            ssPtr.deallocate()
        }
        
        let status = ciphertext.withUnsafeBytes { ctBuf in
            secretKey.withUnsafeBytes { skBuf in
                OQS_KEM_kyber_1024_decaps(ssPtr,
                                          ctBuf.bindMemory(to: UInt8.self).baseAddress!,
                                          skBuf.bindMemory(to: UInt8.self).baseAddress!)
            }
        }
        try OQSStatus(status.rawValue).throwIfError()
        
        return SharedSecret(rawRepresentation: Data(bytes: ssPtr, count: ssLen))
    }
}

extension Kyber1024.KeyAgreement.PrivateKey: Codable {
    private enum CodingKeys: String, CodingKey {
        case rawRepresentation
        case publicKey
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rawRepresentation, forKey: .rawRepresentation)
        try container.encode(publicKey, forKey: .publicKey)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let raw = try container.decode(Data.self, forKey: .rawRepresentation)
        let pub = try container.decode(Kyber1024.KeyAgreement.PublicKey.self, forKey: .publicKey)
        self.rawRepresentation = raw
        self.publicKey = pub
    }
}

extension Kyber1024.KeyAgreement.PublicKey: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawRepresentation)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(Data.self)
        self.init(rawRepresentation: raw)
    }
}

extension Kyber1024.SharedSecret: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawRepresentation)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(Data.self)
        self.init(rawRepresentation: raw)
    }
}

extension Kyber1024.KeyAgreement.PublicKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension Kyber1024.KeyAgreement.PrivateKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation &&
        lhs.publicKey == rhs.publicKey
    }
}


public enum KyberError: LocalizedError, Sendable {
    case unspecified
    case externalOpenSSL
    case invalidKeySize
    case publicKeyRequired
    case invalidCiphertextLength
    case unknownStatus(Int32)
    
    init(from status: Int32) {
        switch status {
        case OQS_ERROR.rawValue:
            self = .unspecified
        case OQS_EXTERNAL_LIB_ERROR_OPENSSL.rawValue:
            self = .externalOpenSSL
        default:
            self = .unknownStatus(status)
        }
    }
    
    public var errorDescription: String? {
        switch self {
        case .unspecified: return "liboqs encountered an unspecified error."
        case .externalOpenSSL: return "liboqs failed due to an underlying OpenSSL error."
        case .invalidKeySize: return "Key bytes have the wrong length."
        case .publicKeyRequired: return "Re‑creating a private key requires the matching public key."
        case .invalidCiphertextLength: return "Ciphertext has the wrong length."
        case .unknownStatus(let s): return "liboqs returned an unrecognized status (\(s))."
        }
    }
}
