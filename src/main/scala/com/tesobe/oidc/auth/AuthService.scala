/*
 * Copyright (c) 2025 TESOBE
 *
 * This file is part of OBP-OIDC.
 *
 * OBP-OIDC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * OBP-OIDC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC. If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc.auth

import com.tesobe.oidc.models.{User, OidcError, OidcClient, ObpConsent}

/** Authentication service trait defining the contract for user authentication
  * and client validation in the OIDC provider.
  */
trait AuthService[F[_]] {

  /** Authenticate a user by username and password Returns the user information
    * if authentication succeeds
    */
  def authenticate(
      username: String,
      password: String,
      provider: String
  ): F[Either[OidcError, User]]

  /** Get user information by subject ID
    */
  def getUserById(sub: String): F[Option[User]]

  /** Get user information by subject ID and provider.
    * When a provider is available, this can use the OBP API
    * (GET /obp/v6.0.0/users/provider/PROVIDER/username/USERNAME)
    * instead of requiring a database connection.
    */
  def getUserBySubAndProvider(sub: String, provider: String): F[Option[User]]

  /** Read a Consent from OBP-API (GET /obp/v7.0.0/oidc/consents/CONSENT_ID).
    * The consent callback uses this record, not the browser's callback parameters,
    * to decide whether to issue a code and for which user. None when the consent
    * does not exist or OBP-API cannot be reached.
    */
  def getConsent(consentId: String): F[Option[ObpConsent]]

  /** Get available authentication providers
    */
  def getAvailableProviders(): F[List[String]]

  /** Validate that a client_id and redirect_uri combination is valid
    */
  def validateClient(clientId: String, redirectUri: String): F[Boolean]

  /** Authenticate a client by client_id and client_secret Returns the client
    * information if authentication succeeds
    */
  def authenticateClient(
      clientId: String,
      clientSecret: String
  ): F[Either[OidcError, OidcClient]]

  /** Find a client by client ID (which maps to key_c in database)
    */
  def findClientByClientIdThatIsKey(clientId: String): F[Option[OidcClient]]

  /** Find an admin client by client ID (which maps to key_c in database, with
    * write access)
    */
  def findAdminClientByClientIdThatIsKey(
      clientId: String
  ): F[Option[OidcClient]]

  /** List all registered clients
    */
  def listClients(): F[Either[OidcError, List[OidcClient]]]

}
