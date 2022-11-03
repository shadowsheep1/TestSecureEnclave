//
//  ViewController.swift
//  TestSecureEnclave
//
//  Created by Fabio Bombardi on 01/11/22.
//

import UIKit
import CryptoKit

class ViewController: UIViewController {
    private let tag = "com.example.keys.mykey".data(using: .utf8)!
    private let keyType = kSecAttrKeyTypeECSECPrimeRandom
    private let keySizeInBits = 256
    
    // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_keychain
    private func checkPrivateKeyExistance() throws -> SecKey? {
        let getQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: keyType,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(getQuery as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw NSError(domain: "Error retrieving private key alias \(tag)", code: 42, userInfo: nil)
        }
        let key = item as! SecKey
        return key
    }
    
    private func generatePrivateKey() throws -> SecKey? {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage, // signing and verification
            &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        let attributes: NSDictionary = [
            kSecAttrKeyType: keyType,
            kSecAttrKeySizeInBits: keySizeInBits,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: tag,
                kSecAttrAccessControl: access
            ]
        ]
        
        guard let key = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return key
    }
    
    // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave
    private func testSecureEnclave() {
        var privateKey: SecKey?
        if let key = try? checkPrivateKeyExistance() {
            privateKey = key
        } else {
            privateKey = try? generatePrivateKey()
        }
        
        guard let privateKey = privateKey,
              let publicKey = SecKeyCopyPublicKey(privateKey) else { return }
        print("PublicKey: \(publicKey)")
        let jwk = jwkRepresentation(publicKey)
        let jwkJsonString = try! String(data: JSONEncoder().encode(jwk), encoding: .utf8)!
        print("JWT: \(jwkJsonString)")
        let signAlgorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, signAlgorithm) else {
            print("Error: unsupported sign algorithm: \(signAlgorithm)")
            return
        }
        print("OK: supported sign algorithm: \(signAlgorithm)")
        let sampleMessage = "Lorem ipsum bubulo bibi!"
        let sampleData = Data(sampleMessage.utf8)
        guard let signature = signSampleData(sampleData, privateKey, signAlgorithm) else { return }
        let signatureBase64 = signature.base64EncodedString()
        print("Sample signature: \(signatureBase64)")
        if verifySampleData(sampleData, signature, publicKey, signAlgorithm) {
            print("OK: sample data verified!")
        }
    }
   
    private func verifySampleData(
        _ message: Data,
        _ digest: Data,
        _ publicKey: SecKey,
        _ signAlgorithm: SecKeyAlgorithm
    ) -> Bool {
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(
            publicKey,
            signAlgorithm,
            message as CFData,
            digest as CFData,
            &error
        ) else {
            print("Verification error: \(error!.takeRetainedValue())")
            return false
        }
        return true
    }
    
    private func signSampleData(
        _ message: Data,
        _ privateKey: SecKey,
        _ signAlgorithm: SecKeyAlgorithm
    ) -> Data? {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            signAlgorithm,
            message as CFData,
            &error
        ) as Data? else {
            print("\(String(describing: error?.takeRetainedValue()))")
            return nil
        }
        return signature
    }
    
    private func jwkRepresentation(_ publicKey: SecKey) -> [String:String]? {
        // For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y
        // https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation
        if let publicKeyExtneralRepresentation = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data {
            var publicKeyBytes: [UInt8] = []
            publicKeyBytes = Array(publicKeyExtneralRepresentation)
            print(publicKeyBytes.map({String(format: "%02X", $0)}).joined(separator: ""))
            // base64url encoding of the octet string representation of the coordinate
            let xOctets = publicKeyBytes[1...32]
            let yOctets = publicKeyBytes[33...64]
            let xHexString = publicKeyBytes[1...32].map({ String(format: "%02X", $0)}).joined(separator: "")
            let yHexString = publicKeyBytes[33...64].map({ String(format: "%02X", $0)}).joined(separator: "")
            let y = String(decoding: Data(yOctets).base64EncodedData(), as: UTF8.self).base64URLEscaped()
            let x = String(decoding: Data(xOctets).base64EncodedData(), as: UTF8.self).base64URLEscaped()
            print("x \(x) of octetString \(xHexString)")
            print("y \(y) of octetString \(yHexString)")
            // https://www.rfc-editor.org/rfc/rfc7517
            // https://www.rfc-editor.org/rfc/rfc7518.html#page-6
            let jwk: [String:String]  = [
                "kty":"EC",
                "crv":"P-256",
                "x":"\(x)",
                "y":"\(y)"
            ]
            return jwk
        }
        return [:]
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        print("SecureEnclave Available = \(SecureEnclave.isAvailable)")
        testSecureEnclave()
    }
    
    @IBAction func goAction(_ sender: Any) {
        testSecureEnclave()
    }
}

// https://github.com/vapor/core/blob/main/Sources/Core/Data+Base64URL.swift
extension String {
    /// Converts a base64-url encoded string to a base64 encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public func base64URLUnescaped() -> String {
        let replaced = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        /// https://stackoverflow.com/questions/43499651/decode-base64url-to-base64-swift
        let padding = replaced.count % 4
        if padding > 0 {
            return replaced + String(repeating: "=", count: 4 - padding)
        } else {
            return replaced
        }
    }
    
    /// Converts a base64 encoded string to a base64-url encoded string.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    public func base64URLEscaped() -> String {
        return replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
