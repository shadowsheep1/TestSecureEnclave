//
//  ViewController.swift
//  TestSecureEnclave
//
//  Created by Fabio Bombardi on 01/11/22.
//

import UIKit
import CryptoKit

class ViewController: UIViewController {
    @IBOutlet weak var keySelector: UISegmentedControl!
    
    private var keyConfig: KeyConfig = .ec
    private enum KeyConfig: Int, CaseIterable {
        case ec, rsa
        
        func keyTagString() -> String {
            switch self {
            case .ec:
                return "com.example.keys.mykey.ec"
            case .rsa:
                return "com.example.keys.mykey.rsa"
            }
        }
        
        func keyTag() -> Data {
            keyTagString().data(using: .utf8)!
        }
        
        func keyType() -> CFString {
            switch self {
            case .ec:
                return kSecAttrKeyTypeECSECPrimeRandom
            case .rsa:
                return kSecAttrKeyTypeRSA
            }
        }
        
        func keySizeInBits() -> Int {
            switch self {
            case .ec:
                return 256
            case .rsa:
                return 2048
            }
        }
        
        func keySignAlgorithm() -> SecKeyAlgorithm {
            switch self {
            case .ec:
                return .ecdsaSignatureMessageX962SHA256
            case .rsa:
                // https://www.encryptionconsulting.com/overview-of-rsassa-pss/
                return .rsaSignatureMessagePSSSHA256
            }
        }
    }
    
    private func privateKeyKeychainQuery() -> [String : Any] {
        return [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyConfig.keyTag(),
            kSecAttrKeyType as String: keyConfig.keyType(),
            kSecReturnRef as String: true
        ]
    }
    
    private func removeKeyFromKeychain() throws {
        let status = SecItemDelete(privateKeyKeychainQuery() as CFDictionary)
        guard status == errSecSuccess else {
            print("Key error: \(status)")
            throw NSError(domain: "Error removing private key alias \(keyConfig.keyTagString())", code: 42, userInfo: nil)
        }
        print("Cleaned private key alias \(keyConfig.keyTagString())!")
    }
    
    // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_keychain
    private func checkPrivateKeyExistance() throws -> SecKey? {
        let getQuery = privateKeyKeychainQuery()
        var item: CFTypeRef?
        let status = SecItemCopyMatching(getQuery as CFDictionary, &item)
        guard status == errSecSuccess else {
            print("Key error: \(status)")
            throw NSError(domain: "Error retrieving private key alias \(keyConfig.keyTagString())", code: 42, userInfo: nil)
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
            // https://learning.oreilly.com/library/view/ios-components-and/9780133086898/ch18lev2sec7.html#ch18lev2sec7
            print("Key generation error! \(String(describing: error)))")
            throw error!.takeRetainedValue() as Error
        }
        
        // https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values
        let attributes: NSMutableDictionary = [
            kSecAttrKeyType: keyConfig.keyType(),
            kSecAttrKeySizeInBits: keyConfig.keySizeInBits(),
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: keyConfig.keyTag(),
                kSecAttrAccessControl: access
            ]
        ]
        
        if keyConfig == .ec {
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
        }
        //if keyConfig == .rsa {
        //    attributes[kSecAttrKeyClass] = kSecAttrKeyClassPrivate
        //}
        
        guard let key = SecKeyCreateRandomKey(attributes, &error) else {
            print("Key generation error: \(String(describing: error))")
            throw error!.takeRetainedValue() as Error
        }
        return key
    }
    
    // https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave
    private func testSecureEnclave() {
        print("KEY TAG: \(keyConfig.keyTagString())")
        var privateKey: SecKey?
        // Erase all content and settings from emulator to start brand new.
        if let key = try? checkPrivateKeyExistance() {
            privateKey = key
        } else {
            privateKey = try? generatePrivateKey()
        }
        
        guard let privateKey = privateKey,
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return
        }
        if let privateKeyExtneralRepresentation = SecKeyCopyExternalRepresentation(privateKey, nil) {
            print("private key: \(privateKeyExtneralRepresentation)")
        }
        print("PublicKey: \(publicKey)")
        if keyConfig == .ec {
            let jwk = jwkRepresentation(publicKey)
            let jwkJsonString = try! String(data: JSONEncoder().encode(jwk), encoding: .utf8)!
            print("JWT: \(jwkJsonString)")
        }
        let signAlgorithm: SecKeyAlgorithm = keyConfig.keySignAlgorithm()
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, signAlgorithm) else {
            print("Error: unsupported sign algorithm: \(signAlgorithm)")
            return
        }
        print("OK: supported sign algorithm: \(signAlgorithm)")
        let sampleMessage = "Lorem ipsum bubulo bibi!"
        let sampleData = Data(sampleMessage.utf8)
        print("Sample data sha256 base64: \(SHA256.hash(data: sampleData).data.base64EncodedString())")
        print("Sample data base64 \(sampleData.base64EncodedString())")
        print("Sample data (bin): \(sampleData.map({String(format: "0x%02X ", $0)}).joined(separator: ""))")
        guard let signature = signSampleData(sampleData, privateKey, signAlgorithm) else { return }
        // https://easy64.org/decode-base64-to-file/
        print("Sample signature (bin): \(signature.map({String(format: "0x%02X ", $0)}).joined(separator: ""))")
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
            print("Verification error: \(String(describing: error)))")
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
    
    // https://stackoverflow.com/questions/69258967/convert-ecpublickeyseckey-to-pem-string-in-swift
    private func printAns1Pem(_ publicKeyData: Data) {
        let ecHeader: [UInt8] = [
            /* sequence          */ 0x30, 0x59,
                                    /* |-> sequence      */ 0x30, 0x13,
                                    /* |---> ecPublicKey */ 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // (ANSI X9.62 public key type)
                                    /* |---> prime256v1  */ 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, // (ANSI X9.62 named elliptic curve)
                                    /* |-> bit headers   */ 0x07, 0x03, 0x42, 0x00
        ]
        
        var asn1 = Data()
        asn1.append(Data(ecHeader))
        asn1.append(publicKeyData as Data)
        let encoded = asn1.base64EncodedString(options: .lineLength64Characters)
        let pemString = "-----BEGIN PUBLIC KEY-----\r\n\(encoded)\r\n-----END PUBLIC KEY-----\r\n"
        print(pemString)
    }
    
    private func jwkRepresentation(_ publicKey: SecKey) -> [String:String]? {
        // For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y
        // https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation
        if let publicKeyExtneralRepresentation = SecKeyCopyExternalRepresentation(publicKey, nil) as? Data {
            printAns1Pem(publicKeyExtneralRepresentation)
            var publicKeyBytes: [UInt8] = []
            publicKeyBytes = Array(publicKeyExtneralRepresentation)
            print(publicKeyBytes.map({String(format: "%02X", $0)}).joined(separator: ""))
            //publicKeyBytes.forEach({print("\($0)")})
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
    }
    
    @IBAction func goAction(_ sender: Any) {
        testSecureEnclave()
    }
    
    @IBAction func keyTypeValueChanged(_ sender: Any) {
        keyConfig = KeyConfig(rawValue: keySelector.selectedSegmentIndex) ?? .ec
    }
    
    @IBAction func removeKeyAction(_ sender: Any) {
        try? removeKeyFromKeychain()
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

extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }
    
    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}
