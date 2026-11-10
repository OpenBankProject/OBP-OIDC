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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc.endpoints

import cats.effect.{IO, Ref}
import cats.effect.unsafe.implicits.global
import com.tesobe.oidc.auth.{CodeService, MockAuthService}
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.models._
import com.tesobe.oidc.ratelimit.{InMemoryRateLimitService, RateLimitConfig}
import com.tesobe.oidc.stats.StatsService
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.implicits._
import org.http4s.server.Router
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.typelevel.ci.CIString

/** A client whose OBP Consumer sets grant types gets tokens only for those, and a client without
  * authorization_code cannot start a login. A client whose Consumer sets none works as before.
  */
class ClientGrantTypesTest extends AnyFlatSpec with Matchers {

  private val redirectUri = "https://example.com/callback" // registered in MockAuthService

  private val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase = DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  private def createApp: IO[HttpApp[IO]] =
    for {
      authService <- IO(MockAuthService())
      codeService <- CodeService(testConfig)
      jwtService <- JwtService(testConfig)
      statsService <- StatsService()
      rateLimitService <- InMemoryRateLimitService(RateLimitConfig())
      consentChallengesRef <- Ref.of[IO, Map[String, ConsentChallenge]](Map.empty)
      pendingAuthorizationsRef <- Ref.of[IO, Map[String, PendingAuthorization]](Map.empty)
      authEndpoint = AuthEndpoint(authService, codeService, statsService, rateLimitService, testConfig, jwtService, consentChallengesRef, pendingAuthorizationsRef)
      tokenEndpoint = TokenEndpoint(authService, codeService, jwtService, testConfig, statsService)
    } yield Router("/" -> authEndpoint.routes, "/" -> tokenEndpoint.routes).orNotFound

  private def token(app: HttpApp[IO], fields: (String, String)*): (Status, String) =
    (for {
      response <- app(Request[IO](Method.POST, uri"/obp-oidc/token").withEntity(UrlForm(fields: _*)))
      body <- response.as[String]
    } yield (response.status, body)).unsafeRunSync()

  private def authorize(app: HttpApp[IO], clientId: String): Response[IO] =
    app(Request[IO](Method.GET, Seq("response_type" -> "code", "client_id" -> clientId, "redirect_uri" -> redirectUri,
      "scope" -> "openid", "state" -> "s1").foldLeft(uri"/obp-oidc/auth")((uri, kv) => uri.withQueryParam(kv._1, kv._2))))
      .unsafeRunSync()

  "A client-credentials-only client" should "not be able to start a person's login" in {
    val app = createApp.unsafeRunSync()
    val response = authorize(app, "cc-only-client")
    response.status should be(Status.SeeOther)
    val location = response.headers.get(CIString("Location")).map(_.head.value).getOrElse(fail("no redirect"))
    location should startWith(redirectUri)
    location should include("error=unauthorized_client")
  }

  it should "not be issued tokens by the authorization_code or refresh_token grant" in {
    val app = createApp.unsafeRunSync()
    val (codeStatus, codeBody) = token(app, "grant_type" -> "authorization_code", "code" -> "any", "redirect_uri" -> redirectUri,
      "client_id" -> "cc-only-client", "client_secret" -> "test-secret")
    codeStatus should be(Status.BadRequest)
    codeBody should include("unauthorized_client")

    val (refreshStatus, refreshBody) = token(app, "grant_type" -> "refresh_token", "refresh_token" -> "any", "client_id" -> "cc-only-client")
    refreshStatus should be(Status.BadRequest)
    refreshBody should include("unauthorized_client")
  }

  "A client without client_credentials" should "not be issued a client-credentials token" in {
    val app = createApp.unsafeRunSync()
    val (status, body) = token(app, "grant_type" -> "client_credentials", "client_id" -> "people-only-client", "client_secret" -> "test-secret")
    status should be(Status.BadRequest)
    body should include("unauthorized_client")
  }

  it should "still let people log in" in {
    val app = createApp.unsafeRunSync()
    authorize(app, "people-only-client").status should be(Status.Ok)
  }

  "A client whose Consumer sets no grant types" should "let people log in as before" in {
    val app = createApp.unsafeRunSync()
    authorize(app, "test-client").status should be(Status.Ok)
  }

  it should "not be refused a client-credentials token for its grant types" in {
    val app = createApp.unsafeRunSync()
    val (_, body) = token(app, "grant_type" -> "client_credentials", "client_id" -> "test-client", "client_secret" -> "test-secret")
    body should not include "unauthorized_client"
  }
}
