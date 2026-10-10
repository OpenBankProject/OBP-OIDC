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

import cats.effect.IO
import cats.syntax.either._
import com.tesobe.oidc.models.{ObpConsent, User, OidcError, OidcClient}

/** Mock authentication service for TESTING PURPOSES ONLY This service should
  * never be used in production or offered as an option to users.
  *
  * `consents` stands in for OBP-API's consent records (GET /obp/v7.0.0/oidc/consents/CONSENT_ID).
  */
class MockAuthService(consents: Map[String, ObpConsent] = Map.empty) extends AuthService[IO] {

  // Test users for testing only
  private val users = Map(
    "alice123" -> User(
      sub = "alice123",
      username = "alice123",
      password = "secret123456",
      name = Some("Alice Smith"),
      email = Some("alice@example.com"),
      email_verified = Some(true),
      provider = Some("obp-test")
    ),
    "bob12345" -> User(
      sub = "bob12345",
      username = "bob12345",
      password = "password456789",
      name = Some("Bob Jones"),
      email = Some("bob@example.com"),
      email_verified = Some(true),
      provider = Some("obp-test")
    ),
    "charlie1" -> User(
      sub = "charlie1",
      username = "charlie1",
      password = "test789012",
      name = Some("Charlie Brown"),
      email = Some("charlie@example.com"),
      email_verified = Some(true),
      provider = Some("obp-test")
    )
  )

  def authenticate(
      username: String,
      password: String,
      provider: String
  ): IO[Either[OidcError, User]] = IO {
    users.get(username) match {
      case Some(user)
          if user.password == password && user.provider.contains(provider) =>
        user.asRight[OidcError]
      case Some(user) if user.password == password =>
        OidcError("access_denied", Some("Invalid provider")).asLeft[User]
      case Some(_) =>
        OidcError("access_denied", Some("Invalid password")).asLeft[User]
      case None =>
        OidcError("access_denied", Some("User not found")).asLeft[User]
    }
  }

  def getUserById(sub: String): IO[Option[User]] = IO {
    users.values.find(_.sub == sub)
  }

  def getUserBySubAndProvider(sub: String, provider: String): IO[Option[User]] = IO {
    users.values.find(u => u.sub == sub && u.provider.contains(provider))
  }

  def getConsent(consentId: String): IO[Option[ObpConsent]] = IO {
    consents.get(consentId)
  }

  def getAvailableProviders(): IO[List[String]] = IO {
    List("obp-test", "test-provider")
  }

  // Exact match against the registered redirect_uris, as HybridAuthService does, so tests of
  // redirect_uri handling exercise the real rule.
  def validateClient(clientId: String, redirectUri: String): IO[Boolean] =
    findClientByClientIdThatIsKey(clientId).map(_.exists(_.redirect_uris.contains(redirectUri)))

  def findClientByClientIdThatIsKey(clientId: String): IO[Option[OidcClient]] =
    IO {
      // Mock implementation for testing
      Some(
        OidcClient(
          client_id = clientId,
          client_secret = Some("test-secret"),
          client_name = "Test Client",
          consumer_id = "test-consumer",
          redirect_uris = registeredRedirectUris(clientId),
          grant_types = List("authorization_code"),
          response_types = List("code"),
          scopes = List("openid", "profile", "email")
        )
      )
    }

  // "legacy-client" stands for a Consumer saved before OBP-API checked redirect URLs: its stored
  // entries break RedirectUriRules and must never be used, even though they are registered.
  private def registeredRedirectUris(clientId: String): List[String] =
    if (clientId == "legacy-client") List("javascript:alert(1)", "http://public.example/cb")
    else List("https://example.com/callback")

  def findAdminClientByClientIdThatIsKey(
      clientId: String
  ): IO[Option[OidcClient]] =
    findClientByClientIdThatIsKey(clientId)

  def authenticateClient(
      clientId: String,
      clientSecret: String
  ): IO[Either[OidcError, OidcClient]] = IO {
    // Mock implementation for testing
    if (clientSecret == "test-secret") {
      Right(
        OidcClient(
          client_id = clientId,
          client_secret = Some(clientSecret),
          client_name = "Test Client",
          consumer_id = "test-consumer",
          redirect_uris = List("https://example.com/callback"),
          grant_types = List("authorization_code", "client_credentials"),
          response_types = List("code"),
          scopes = List("openid", "profile", "email")
        )
      )
    } else {
      Left(OidcError("invalid_client", Some("Invalid client credentials")))
    }
  }

  def listClients(): IO[Either[OidcError, List[OidcClient]]] = IO {
    Right(
      List(
        OidcClient(
          client_id = "test-client",
          client_secret = Some("test-secret"),
          client_name = "Test Client",
          consumer_id = "test-consumer",
          redirect_uris = List("https://example.com/callback"),
          grant_types = List("authorization_code"),
          response_types = List("code"),
          scopes = List("openid", "profile", "email")
        )
      )
    )
  }
}

object MockAuthService {
  def apply(): MockAuthService = new MockAuthService()
  def apply(consents: Map[String, ObpConsent]): MockAuthService = new MockAuthService(consents)
}
