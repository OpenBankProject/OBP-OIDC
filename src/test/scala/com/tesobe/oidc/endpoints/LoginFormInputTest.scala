/*
 * Copyright (c) 2026 TESOBE
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

package com.tesobe.oidc.endpoints

import cats.effect.{IO, Ref}
import cats.effect.unsafe.implicits.global
import com.tesobe.oidc.auth.{CodeService, MockAuthService}
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.models._
import com.tesobe.oidc.ratelimit.{InMemoryRateLimitService, RateLimitConfig, RateLimitService}
import com.tesobe.oidc.stats.StatsService
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.implicits._
import org.http4s.server.Router
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.typelevel.ci.CIString

/** POST /auth with credentials that existing users may have: a short username, a short password.
  * Input the form check refuses is handled like a wrong password: the same pending request is shown
  * again with the same message, and the attempt counts towards rate limiting.
  */
class LoginFormInputTest extends AnyFlatSpec with Matchers {

  private val clientId = "test-client"
  private val registeredRedirectUri = "https://example.com/callback" // registered in MockAuthService

  // A user created before OBP-API had a password policy: 7-character username, short password.
  private val shortUsername = "kim1234"
  private val shortPassword = "pw1"
  private val provider = "obp-test"

  private val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase = DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  /** MockAuthService plus the short-credential user, counting every call to authenticate. */
  private class CountingAuthService(calls: Ref[IO, Int]) extends MockAuthService() {
    private val shortUser = User(
      sub = shortUsername,
      username = shortUsername,
      password = shortPassword,
      name = Some("Kim Lee"),
      email = Some("kim@example.com"),
      email_verified = Some(true),
      provider = Some(provider)
    )

    override def authenticate(username: String, password: String, provider: String): IO[Either[OidcError, User]] =
      calls.update(_ + 1) *> {
        if (username == shortUsername)
          IO.pure(
            if (password == shortUser.password && shortUser.provider.contains(provider)) Right(shortUser)
            else Left(OidcError("access_denied", Some("Invalid password")))
          )
        else super.authenticate(username, password, provider)
      }
  }

  /** The real rate limiter, also remembering which username each failed attempt was recorded for. */
  private class RecordingRateLimitService(underlying: RateLimitService[IO], failed: Ref[IO, List[String]])
      extends RateLimitService[IO] {
    def checkAndRecordFailedAttempt(ip: String, username: String): IO[Either[String, Unit]] =
      failed.update(_ :+ username) *> underlying.checkAndRecordFailedAttempt(ip, username)
    def recordSuccessfulLogin(ip: String, username: String): IO[Unit] = underlying.recordSuccessfulLogin(ip, username)
    def isBlocked(ip: String, username: String): IO[Boolean] = underlying.isBlocked(ip, username)
    def checkRegistrationAttempt(ip: String): IO[Either[String, Unit]] = underlying.checkRegistrationAttempt(ip)
    def cleanup(): IO[Unit] = underlying.cleanup()
  }

  private case class TestApp(app: HttpApp[IO], authCalls: Ref[IO, Int], failedAttempts: Ref[IO, List[String]])

  private def createApp: IO[TestApp] =
    for {
      authCalls <- Ref.of[IO, Int](0)
      failedAttempts <- Ref.of[IO, List[String]](Nil)
      authService = new CountingAuthService(authCalls)
      codeService <- CodeService(testConfig)
      jwtService <- JwtService(testConfig)
      statsService <- StatsService()
      realRateLimit <- InMemoryRateLimitService(RateLimitConfig())
      rateLimitService = new RecordingRateLimitService(realRateLimit, failedAttempts)
      consentChallengesRef <- Ref.of[IO, Map[String, ConsentChallenge]](Map.empty)
      pendingAuthorizationsRef <- Ref.of[IO, Map[String, PendingAuthorization]](Map.empty)
      authEndpoint = AuthEndpoint(authService, codeService, statsService, rateLimitService, testConfig, jwtService, consentChallengesRef, pendingAuthorizationsRef)
    } yield TestApp(Router("/" -> authEndpoint.routes).orNotFound, authCalls, failedAttempts)

  private val authorizeUri: Uri =
    uri"/obp-oidc/auth"
      .withQueryParam("response_type", "code")
      .withQueryParam("client_id", clientId)
      .withQueryParam("redirect_uri", registeredRedirectUri)
      .withQueryParam("scope", "openid")
      .withQueryParam("state", "s1")

  private def authRequestIdIn(body: String): Option[String] =
    "name=\"auth_request_id\" value=\"([^\"]+)\"".r.findFirstMatchIn(body).map(_.group(1))

  /** Open the login form and return the auth_request_id it carries and the binding cookie it sets. */
  private def openLoginForm(app: HttpApp[IO]): IO[(String, ResponseCookie)] =
    for {
      response <- app(Request[IO](Method.GET, authorizeUri))
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      val authRequestId = authRequestIdIn(body).getOrElse(fail("no auth_request_id in the login form"))
      val cookie = response.cookies.find(_.name == s"obp_oidc_auth_$authRequestId").getOrElse(fail("no binding cookie"))
      (authRequestId, cookie)
    }

  private def submit(app: HttpApp[IO], opened: (String, ResponseCookie), fields: (String, String)*): IO[Response[IO]] =
    app(
      Request[IO](Method.POST, uri"/obp-oidc/auth")
        .withEntity(UrlForm((("auth_request_id" -> opened._1) +: fields): _*))
        .addCookie(opened._2.name, opened._2.content)
    )

  private def credentials(username: String, password: String): Seq[(String, String)] =
    Seq("username" -> username, "password" -> password, "provider" -> provider)

  private def assertCodeSentToRegisteredUri(response: Response[IO]): Unit = {
    response.status should be(Status.SeeOther)
    val location = Uri.unsafeFromString(response.headers.get(CIString("Location")).map(_.head.value).getOrElse(fail("no redirect")))
    location.copy(query = Query.empty).renderString should be(registeredRedirectUri)
    location.query.params.get("code") should be(defined)
  }

  "POST /auth" should "sign in a user with a 7-character username and a short password" in {
    (for {
      t <- createApp
      opened <- openLoginForm(t.app)
      response <- submit(t.app, opened, credentials(shortUsername, shortPassword): _*)
      failed <- t.failedAttempts.get
    } yield {
      assertCodeSentToRegisteredUri(response)
      failed should be(empty)
    }).unsafeRunSync()
  }

  it should "show the same request again with 'Incorrect username/password' for a 7-character username with a wrong password" in {
    (for {
      t <- createApp
      opened <- openLoginForm(t.app)
      response <- submit(t.app, opened, credentials(shortUsername, "wrong-password"): _*)
      body <- response.as[String]
      failed <- t.failedAttempts.get
    } yield {
      response.status should be(Status.Ok)
      body should include("Incorrect username/password")
      authRequestIdIn(body) should be(Some(opened._1))
      failed should be(List(shortUsername))
    }).unsafeRunSync()
  }

  it should "refuse a username longer than 100 characters without calling the authentication service" in {
    (for {
      t <- createApp
      opened <- openLoginForm(t.app)
      response <- submit(t.app, opened, credentials("a" * 101, shortPassword): _*)
      body <- response.as[String]
      authCalls <- t.authCalls.get
      failed <- t.failedAttempts.get
    } yield {
      response.status should be(Status.Ok)
      body should include("Incorrect username/password")
      body should not include ("a" * 101)
      authRequestIdIn(body) should be(Some(opened._1))
      authCalls should be(0)
      // Counted like a wrong password, under the username cut to the maximum length
      failed.map(_.length) should be(List(AuthEndpoint.MaxUsernameLength))
    }).unsafeRunSync()
  }

  it should "refuse an empty password without calling the authentication service and count the attempt" in {
    (for {
      t <- createApp
      opened <- openLoginForm(t.app)
      response <- submit(t.app, opened, credentials(shortUsername, ""): _*)
      body <- response.as[String]
      authCalls <- t.authCalls.get
      failed <- t.failedAttempts.get
    } yield {
      response.status should be(Status.Ok)
      body should include("Incorrect username/password")
      authCalls should be(0)
      failed should be(List(shortUsername))
    }).unsafeRunSync()
  }

  it should "keep the pending request usable after refused input, so the user can try again" in {
    (for {
      t <- createApp
      opened <- openLoginForm(t.app)
      refused <- submit(t.app, opened, credentials("a" * 101, shortPassword): _*)
      retry <- submit(t.app, opened, credentials(shortUsername, shortPassword): _*)
    } yield {
      refused.status should be(Status.Ok)
      assertCodeSentToRegisteredUri(retry)
    }).unsafeRunSync()
  }

  it should "answer 'Invalid form data' only when a field is missing from the submission" in {
    (for {
      t <- createApp
      opened <- openLoginForm(t.app)
      response <- submit(t.app, opened, "username" -> shortUsername, "provider" -> provider)
      body <- response.as[String]
      authCalls <- t.authCalls.get
    } yield {
      response.status should be(Status.BadRequest)
      body should include("Invalid form data")
      authCalls should be(0)
    }).unsafeRunSync()
  }
}
