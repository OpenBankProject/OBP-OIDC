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

package com.tesobe.oidc.endpoints

import cats.effect.{IO, Ref}
import cats.effect.unsafe.implicits.global
import cats.syntax.traverse._
import com.tesobe.oidc.auth.{CodeService, MockAuthService, RedirectUriRules}
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.models._
import com.tesobe.oidc.ratelimit.{InMemoryRateLimitService, RateLimitConfig}
import com.tesobe.oidc.stats.StatsService
import com.tesobe.oidc.tokens.JwtService
import io.circe.parser.decode
import org.http4s._
import org.http4s.implicits._
import org.http4s.server.Router
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers
import org.typelevel.ci.CIString

/** This suite checks that OBP-OIDC only ever sends a user, an authorization code or an error to a
  * redirect_uri registered for the client, and that the consent callback issues a code only for the
  * user and client of the consent as OBP-API records it. Each test acts out an attack and checks that
  * it fails.
  */
class RedirectAndConsentSecurityTest extends AnyFlatSpec with Matchers {

  private val clientId = "test-client"
  private val registeredRedirectUri = "https://example.com/callback" // registered in MockAuthService
  private val attackerRedirectUri = "https://evil.example/cb"

  private val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase = DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  // Consents as OBP-API would record them. All belong to alice123 unless stated otherwise.
  private val acceptedConsent = ObpConsent(
    consentId = "consent-ok",
    status = "ACCEPTED",
    consentRequestId = Some("consent-request-1"),
    consumerId = "consumer-1",
    clientId = Some(clientId),
    userId = "user-id-alice",
    username = "alice123",
    provider = "obp-test"
  )
  private val consents = List(
    acceptedConsent,
    acceptedConsent.copy(consentId = "consent-of-another-client", clientId = Some("another-client")),
    acceptedConsent.copy(consentId = "consent-from-another-request", consentRequestId = Some("consent-request-2")),
    acceptedConsent.copy(consentId = "consent-not-yet-accepted", status = "INITIATED"),
    acceptedConsent.copy(consentId = "uk-consent", status = "AUTHORISED", consentRequestId = None)
  ).map(c => c.consentId -> c).toMap

  private def createApp: IO[HttpApp[IO]] =
    for {
      authService <- IO(MockAuthService(consents))
      codeService <- CodeService(testConfig)
      jwtService <- JwtService(testConfig)
      statsService <- StatsService()
      rateLimitService <- InMemoryRateLimitService(RateLimitConfig())
      consentChallengesRef <- Ref.of[IO, Map[String, ConsentChallenge]](Map.empty)
      pendingAuthorizationsRef <- Ref.of[IO, Map[String, PendingAuthorization]](Map.empty)
      authEndpoint = AuthEndpoint(authService, codeService, statsService, rateLimitService, testConfig, jwtService, consentChallengesRef, pendingAuthorizationsRef)
      tokenEndpoint = TokenEndpoint(authService, codeService, jwtService, testConfig, statsService)
      userInfoEndpoint = UserInfoEndpoint(authService, jwtService)
    } yield Router("/" -> authEndpoint.routes, "/" -> tokenEndpoint.routes, "/" -> userInfoEndpoint.routes).orNotFound

  private def locationOf(response: Response[IO]): Option[String] =
    response.headers.get(CIString("Location")).map(_.head.value)

  private def authorizeUri(redirectUri: String, extra: (String, String)*): Uri =
    (Seq("response_type" -> "code", "client_id" -> clientId, "redirect_uri" -> redirectUri, "scope" -> "openid", "state" -> "s1") ++ extra)
      .foldLeft(uri"/obp-oidc/auth")((uri, kv) => uri.withQueryParam(kv._1, kv._2))

  /** Open the login form and return the auth_request_id it carries and the binding cookie it sets. */
  private def openLoginForm(app: HttpApp[IO]): IO[(String, ResponseCookie)] =
    for {
      response <- app(Request[IO](Method.GET, authorizeUri(registeredRedirectUri)))
      body <- response.as[String]
    } yield {
      response.status should be(Status.Ok)
      val authRequestId = "name=\"auth_request_id\" value=\"([^\"]+)\"".r
        .findFirstMatchIn(body).map(_.group(1)).getOrElse(fail("no auth_request_id in the login form"))
      val cookie = response.cookies.find(_.name == s"obp_oidc_auth_$authRequestId").getOrElse(fail("no binding cookie"))
      (authRequestId, cookie)
    }

  private def loginForm(fields: (String, String)*): UrlForm =
    UrlForm((Seq("username" -> "alice123", "password" -> "secret123456", "provider" -> "obp-test") ++ fields): _*)

  /** Start a consent flow at /auth and return the challenge id OBP-OIDC put in the Portal redirect. */
  private def startConsentFlow(app: HttpApp[IO], consentParam: (String, String)): IO[String] =
    for {
      response <- app(Request[IO](Method.GET, authorizeUri(registeredRedirectUri, consentParam, "bank_id" -> "bank-1")))
    } yield {
      response.status should be(Status.SeeOther)
      val portalUri = Uri.unsafeFromString(locationOf(response).getOrElse(fail("no redirect to the Portal")))
      val returnUri = Uri.unsafeFromString(portalUri.query.params.getOrElse("oidc_return_url", fail("no oidc_return_url")))
      returnUri.query.params.getOrElse("challenge", fail("no challenge"))
    }

  private def consentCallback(app: HttpApp[IO], params: (String, String)*): IO[Response[IO]] =
    app(Request[IO](Method.GET, params.foldLeft(uri"/obp-oidc/consent-callback")((uri, kv) => uri.withQueryParam(kv._1, kv._2))))

  /** Exchange a code and return the subject of the resulting access token, via the userinfo endpoint. */
  private def subjectForCode(app: HttpApp[IO], code: String): IO[String] =
    for {
      tokenResponse <- app(Request[IO](Method.POST, uri"/obp-oidc/token").withEntity(UrlForm(
        "grant_type" -> "authorization_code", "code" -> code, "redirect_uri" -> registeredRedirectUri,
        "client_id" -> clientId, "client_secret" -> "test-secret")))
      tokenBody <- tokenResponse.as[String]
      tokens = decode[TokenResponse](tokenBody).getOrElse(fail(s"token exchange failed: $tokenBody"))
      userInfoResponse <- app(Request[IO](Method.GET, uri"/obp-oidc/userinfo")
        .putHeaders(Header.Raw(CIString("Authorization"), s"Bearer ${tokens.access_token}")))
      userInfoBody <- userInfoResponse.as[String]
    } yield decode[UserInfo](userInfoBody).getOrElse(fail(s"userinfo failed: $userInfoBody")).sub

  private def assertDeniedToRegisteredUri(response: Response[IO]): Unit = {
    response.status should be(Status.SeeOther)
    val location = Uri.unsafeFromString(locationOf(response).getOrElse(fail("no redirect")))
    location.copy(query = Query.empty).renderString should be(registeredRedirectUri)
    location.query.params.get("error") should be(Some("access_denied"))
    location.query.params.get("code") should be(None)
  }

  // ----- GET /auth -----

  "GET /auth" should "show an error page, not redirect, when the redirect_uri is not registered" in {
    (for {
      app <- createApp
      response <- app(Request[IO](Method.GET, authorizeUri(attackerRedirectUri)))
    } yield {
      response.status should be(Status.BadRequest)
      locationOf(response) should be(None)
    }).unsafeRunSync()
  }

  it should "not redirect an unsupported response_type to an unregistered redirect_uri" in {
    (for {
      app <- createApp
      uri = authorizeUri(attackerRedirectUri).withQueryParam("response_type", "token")
      response <- app(Request[IO](Method.GET, uri))
    } yield {
      response.status should be(Status.BadRequest)
      locationOf(response) should be(None)
    }).unsafeRunSync()
  }

  it should "put no client_id or redirect_uri in the login form, only the request id" in {
    (for {
      app <- createApp
      response <- app(Request[IO](Method.GET, authorizeUri(registeredRedirectUri)))
      body <- response.as[String]
    } yield {
      body should include("name=\"auth_request_id\"")
      body should not include "name=\"redirect_uri\""
      body should not include "name=\"client_id\""
    }).unsafeRunSync()
  }

  // ----- POST /auth -----

  "POST /auth" should "refuse a forged form that names its own client and redirect_uri" in {
    (for {
      app <- createApp
      response <- app(Request[IO](Method.POST, uri"/obp-oidc/auth").withEntity(
        loginForm("client_id" -> clientId, "redirect_uri" -> attackerRedirectUri, "scope" -> "openid")))
    } yield {
      response.status should be(Status.BadRequest)
      locationOf(response) should be(None)
    }).unsafeRunSync()
  }

  it should "refuse a valid request id posted without its binding cookie (a form posted from another site)" in {
    (for {
      app <- createApp
      opened <- openLoginForm(app)
      response <- app(Request[IO](Method.POST, uri"/obp-oidc/auth").withEntity(loginForm("auth_request_id" -> opened._1)))
    } yield {
      response.status should be(Status.BadRequest)
      locationOf(response) should be(None)
    }).unsafeRunSync()
  }

  it should "send the code to the stored redirect_uri and ignore a redirect_uri added to the form" in {
    (for {
      app <- createApp
      opened <- openLoginForm(app)
      (authRequestId, cookie) = opened
      response <- app(Request[IO](Method.POST, uri"/obp-oidc/auth")
        .withEntity(loginForm("auth_request_id" -> authRequestId, "redirect_uri" -> attackerRedirectUri, "client_id" -> "another-client"))
        .addCookie(cookie.name, cookie.content))
    } yield {
      response.status should be(Status.SeeOther)
      val location = Uri.unsafeFromString(locationOf(response).getOrElse(fail("no redirect")))
      location.copy(query = Query.empty).renderString should be(registeredRedirectUri)
      location.query.params.get("code") should be(defined)
    }).unsafeRunSync()
  }

  it should "not accept the same request id twice once it has been used to sign in" in {
    (for {
      app <- createApp
      opened <- openLoginForm(app)
      (authRequestId, cookie) = opened
      post = Request[IO](Method.POST, uri"/obp-oidc/auth")
        .withEntity(loginForm("auth_request_id" -> authRequestId))
        .addCookie(cookie.name, cookie.content)
      first <- app(post)
      second <- app(Request[IO](Method.POST, uri"/obp-oidc/auth")
        .withEntity(loginForm("auth_request_id" -> authRequestId))
        .addCookie(cookie.name, cookie.content))
    } yield {
      first.status should be(Status.SeeOther)
      second.status should be(Status.BadRequest)
    }).unsafeRunSync()
  }

  // ----- GET /consent-callback -----

  "The consent callback" should "issue the code for the consent's own user, whatever username the URL names" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_request_id" -> "consent-request-1")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "ACCEPTED",
        "consent_id" -> "consent-ok", "username" -> "bob12345", "provider" -> "obp-test")
      location = Uri.unsafeFromString(locationOf(response).getOrElse(fail("no redirect")))
      code = location.query.params.getOrElse("code", fail(s"no code in $location"))
      subject <- subjectForCode(app, code)
    } yield {
      location.copy(query = Query.empty).renderString should be(registeredRedirectUri)
      subject should be("alice123")
    }).unsafeRunSync()
  }

  it should "refuse a consent that belongs to another client" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_request_id" -> "consent-request-1")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "ACCEPTED",
        "consent_id" -> "consent-of-another-client", "username" -> "alice123")
    } yield assertDeniedToRegisteredUri(response)).unsafeRunSync()
  }

  it should "refuse a consent that came from a different consent request" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_request_id" -> "consent-request-1")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "ACCEPTED",
        "consent_id" -> "consent-from-another-request", "username" -> "alice123")
    } yield assertDeniedToRegisteredUri(response)).unsafeRunSync()
  }

  it should "refuse a consent OBP-API does not record as accepted, even if the URL says ACCEPTED" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_request_id" -> "consent-request-1")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "ACCEPTED",
        "consent_id" -> "consent-not-yet-accepted", "username" -> "alice123")
    } yield assertDeniedToRegisteredUri(response)).unsafeRunSync()
  }

  it should "refuse a consent OBP-API does not know" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_request_id" -> "consent-request-1")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "ACCEPTED",
        "consent_id" -> "no-such-consent", "username" -> "alice123")
    } yield assertDeniedToRegisteredUri(response)).unsafeRunSync()
  }

  it should "refuse a different consent_id than the UK consent the flow was started for" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_id" -> "uk-consent")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "ACCEPTED",
        "consent_id" -> "consent-ok", "username" -> "alice123")
    } yield assertDeniedToRegisteredUri(response)).unsafeRunSync()
  }

  it should "issue a code for an authorised UK consent" in {
    (for {
      app <- createApp
      challenge <- startConsentFlow(app, "consent_id" -> "uk-consent")
      response <- consentCallback(app, "challenge" -> challenge, "consent_status" -> "AUTHORISED", "username" -> "alice123")
      location = Uri.unsafeFromString(locationOf(response).getOrElse(fail("no redirect")))
    } yield {
      location.copy(query = Query.empty).renderString should be(registeredRedirectUri)
      location.query.params.get("code") should be(defined)
    }).unsafeRunSync()
  }

  "GET /auth" should "refuse a registered redirect_uri that breaks the redirect rules, without redirecting" in {
    val result = (for {
      app <- createApp
      responses <- List("javascript:alert(1)", "http://public.example/cb").traverse { storedRedirectUri =>
        val uri = uri"/obp-oidc/auth"
          .withQueryParam("response_type", "code")
          .withQueryParam("client_id", "legacy-client")
          .withQueryParam("redirect_uri", storedRedirectUri)
          .withQueryParam("scope", "openid")
        app(Request[IO](Method.GET, uri))
      }
    } yield responses).unsafeRunSync()

    result.foreach { response =>
      response.status should be(Status.BadRequest)
      locationOf(response) should be(None)
    }
  }

  "RedirectUriRules" should "allow https, loopback http and reverse-domain app schemes" in {
    List(
      "https://a.com/cb",
      "http://localhost:5173/cb",
      "http://127.0.0.1:8080/cb",
      "http://[::1]:8080/cb",
      "com.example.app:/cb",
      "x-com.tesobe.helloobp.ios://callback"
    ).foreach { uri =>
      withClue(uri) { RedirectUriRules.problemWith(uri) should be(None) }
    }
  }

  it should "reject script schemes, wildcards, user information, fragments and public http" in {
    List(
      "javascript:alert(1)",
      "data:text/html,x",
      "vbscript:x",
      "file:///etc/passwd",
      "https://*.a.com/cb",
      "https://user@evil.com/cb",
      "https://a.com/cb#x",
      "http://example.com/cb",
      "myapp://callback",
      "www.example.com",
      "https:///cb",
      ""
    ).foreach { uri =>
      withClue(uri) { RedirectUriRules.problemWith(uri) should not be None }
    }
  }
}
