//
//  File.swift
//  
//
//  Created by mim Armand on 9/18/24.
//

import Foundation
import SwiftJWT

public class GCPAuthenticator {

    // MARK: - Service Account Structure

    struct ServiceAccount: Codable {
        let type: String
        let project_id: String
        let private_key_id: String
        let private_key: String
        let client_email: String
        let client_id: String
        let auth_uri: String
        let token_uri: String
        let auth_provider_x509_cert_url: String
        let client_x509_cert_url: String
        let universe_domain: String?
    }

    // MARK: - Error Definitions

    public enum GCPAuthError: Error {
        case invalidServiceAccountJSON
        case jwtCreationFailed
        case tokenRequestFailed
        case invalidTokenResponse
        case urlCreationFailed
    }

    // MARK: - Properties

    private let serviceAccount: ServiceAccount
    private var accessToken: String?
    private var tokenExpiration: Date?

    // MARK: - Initializer

    /// Initializes the authenticator with service account JSON data.
    /// - Parameter serviceAccountJSONData: The JSON data of the service account key.
    public init(serviceAccountJSONData: Data) throws {
        let decoder = JSONDecoder()
        do {
            self.serviceAccount = try decoder.decode(ServiceAccount.self, from: serviceAccountJSONData)
        } catch {
            throw GCPAuthError.invalidServiceAccountJSON
        }
    }

    // MARK: - Access Token Retrieval

    /// Retrieves an access token for the specified scope.
    /// - Parameters:
    ///   - scope: The scope for which the token is requested.
    ///   - completion: Completion handler with the result.
    public func getAccessToken(scope: String, completion: @escaping (Result<String, Error>) -> Void) {
        // Check if the token is still valid
        if let token = accessToken, let expiration = tokenExpiration, Date() < expiration {
            completion(.success(token))
            return
        }

        do {
            // Create a JWT
            let jwt = try createJWT(scope: scope)
            // Exchange JWT for an access token
            requestAccessToken(jwt: jwt, completion: completion)
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - JWT Creation

    private func createJWT(scope: String) throws -> String {
        let header = Header(kid: serviceAccount.private_key_id)

        // JWT Claims
        struct Claims: Claims {
            let iss: String // Issuer
            let scope: String
            let aud: String // Audience
            let exp: Date   // Expiration
            let iat: Date   // Issued at
        }

        let iat = Date()
        let exp = iat.addingTimeInterval(3600) // Token valid for 1 hour

        let claims = Claims(
            iss: serviceAccount.client_email,
            scope: scope,
            aud: serviceAccount.token_uri,
            exp: exp,
            iat: iat
        )

        var jwt = JWT(header: header, claims: claims)

        // Prepare the private key
        let privateKeyPEM = serviceAccount.private_key

        guard let privateKeyData = privateKeyPEM.data(using: .utf8) else {
            throw GCPAuthError.jwtCreationFailed
        }

        // Sign the JWT
        let signer = JWTSigner.rs256(privateKey: privateKeyData)
        do {
            let signedJWT = try jwt.sign(using: signer)
            return signedJWT
        } catch {
            throw GCPAuthError.jwtCreationFailed
        }
    }

    // MARK: - Access Token Request

    private func requestAccessToken(jwt: String, completion: @escaping (Result<String, Error>) -> Void) {
        guard let url = URL(string: serviceAccount.token_uri) else {
            completion(.failure(GCPAuthError.urlCreationFailed))
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let bodyComponents = [
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt
        ]
        let bodyString = bodyComponents.map { "\($0)=\($1)" }.joined(separator: "&")
        request.httpBody = bodyString.data(using: .utf8)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        // Send the request
        let task = URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            // Handle errors
            guard let data = data, error == nil else {
                completion(.failure(error ?? GCPAuthError.tokenRequestFailed))
                return
            }

            do {
                // Parse the response
                if let tokenResponse = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
                   let accessToken = tokenResponse["access_token"] as? String,
                   let expiresIn = tokenResponse["expires_in"] as? Double {

                    // Cache the token and expiration
                    self?.accessToken = accessToken
                    self?.tokenExpiration = Date().addingTimeInterval(expiresIn)
                    completion(.success(accessToken))
                } else {
                    completion(.failure(GCPAuthError.invalidTokenResponse))
                }
            } catch {
                completion(.failure(GCPAuthError.invalidTokenResponse))
            }
        }
        task.resume()
    }
}

