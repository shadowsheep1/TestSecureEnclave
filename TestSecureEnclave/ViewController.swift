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
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        print("SecureEnclave Available = \(SecureEnclave.isAvailable)")
        testSecureEnclave()
    }
    
    
}

