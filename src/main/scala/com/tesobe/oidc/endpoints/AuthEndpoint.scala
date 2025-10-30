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

import cats.effect.IO
import com.tesobe.oidc.auth.{AuthService, CodeService}
import com.tesobe.oidc.models.{OidcError}
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.Location
import org.slf4j.LoggerFactory
import com.tesobe.oidc.stats.StatsService

class AuthEndpoint(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    statsService: StatsService[IO]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  // Test logging immediately when class is created
  logger.info("🚀 AuthEndpoint created - logging is working!")
  println("🚀 AuthEndpoint created - logging is working!")

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    // Standalone testing page that does not require query parameters
    // Allows manual login verification without any external client/Portal
    case GET -> Root / "obp-oidc" / "test-login" =>
      showStandaloneLoginForm()

    case GET -> Root / "obp-oidc" / "auth" :?
        ResponseTypeQueryParamMatcher(responseType) +&
        ClientIdQueryParamMatcher(clientId) +&
        RedirectUriQueryParamMatcher(redirectUri) +&
        ScopeQueryParamMatcher(scope) +&
        StateQueryParamMatcher(state) +&
        NonceQueryParamMatcher(nonce) =>
      handleAuthorizationRequest(
        responseType,
        clientId,
        redirectUri,
        scope,
        state,
        nonce
      )

    case req @ POST -> Root / "obp-oidc" / "auth" =>
      req.as[UrlForm].flatMap(handleLoginSubmission)
  }

  // Query parameter matchers
  object ResponseTypeQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("response_type")
  object ClientIdQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("client_id")
  object RedirectUriQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("redirect_uri")
  object ScopeQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("scope")
  object StateQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("state")
  object NonceQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("nonce")

  private def handleAuthorizationRequest(
      responseType: String,
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String]
  ): IO[Response[IO]] = {

    // Validate request parameters
    if (responseType != "code") {
      val error = OidcError(
        "unsupported_response_type",
        Some("Only 'code' response type is supported"),
        state = state
      )
      redirectWithError(redirectUri, error)
    } else if (!scope.contains("openid")) {
      val error = OidcError(
        "invalid_scope",
        Some("'openid' scope is required"),
        state = state
      )
      redirectWithError(redirectUri, error)
    } else {
      // Validate client and redirect URI
      authService.validateClient(clientId, redirectUri).flatMap { isValid =>
        if (!isValid) {
          val error = OidcError(
            "invalid_client",
            Some("Invalid client_id or redirect_uri"),
            state = state
          )
          redirectWithError(redirectUri, error)
        } else {
          // Show login form
          showLoginForm(clientId, redirectUri, scope, state, nonce)
        }
      }
    }
  }

  private def handleLoginSubmission(form: UrlForm): IO[Response[IO]] = {
    val formData = form.values.view.mapValues(_.headOption.getOrElse("")).toMap

    for {
      _ <- IO(logger.info("🔥 LOGIN FORM SUBMISSION STARTED"))
      _ <- IO(println("🔥 LOGIN FORM SUBMISSION STARTED"))
      username <- IO.fromOption(formData.get("username"))(
        new RuntimeException("Missing username")
      )
      _ <- IO(logger.info(s"📋 Auth form submitted for username: '$username'"))
      _ <- IO(println(s"📋 Auth form submitted for username: '$username'"))
      password <- IO.fromOption(formData.get("password"))(
        new RuntimeException("Missing password")
      )
      _ <- IO(
        logger.debug(s"🔑 Password received (length: ${password.length})")
      )
      provider <- IO.fromOption(formData.get("provider"))(
        new RuntimeException("Missing provider")
      )
      _ <- IO(logger.info(s"🏢 Provider selected: '$provider'"))
      clientId <- IO.fromOption(formData.get("client_id"))(
        new RuntimeException("Missing client_id")
      )
      redirectUri <- IO.fromOption(formData.get("redirect_uri"))(
        new RuntimeException("Missing redirect_uri")
      )
      scope <- IO.fromOption(formData.get("scope"))(
        new RuntimeException("Missing scope")
      )
      state = formData.get("state")
      nonce = formData.get("nonce")

      _ <- IO(
        logger.info(
          s"🔄 Calling authentication service for username: '$username' with provider: '$provider'"
        )
      )
      response <- authenticateAndGenerateCode(
        username,
        password,
        provider,
        clientId,
        redirectUri,
        scope,
        state,
        nonce
      )
    } yield response
  }.handleErrorWith { error =>
    logger.error(
      s"💥 Error handling login submission: ${error.getMessage}",
      error
    )
    BadRequest("Invalid form data")
  }

  private def authenticateAndGenerateCode(
      username: String,
      password: String,
      provider: String,
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String]
  ): IO[Response[IO]] = {

    authService.authenticate(username, password, provider).flatMap {
      case Right(user) =>
        for {
          _ <- statsService.incrementLoginSuccess(username)
          code <- codeService
            .generateCode(clientId, redirectUri, user.sub, scope, state, nonce)
          response <- redirectWithCode(redirectUri, code, state)
        } yield response

      case Left(error) =>
        for {
          _ <- statsService.incrementLoginFailure(username, error.error)
          response <- redirectWithError(redirectUri, error.copy(state = state))
        } yield response
    }
  }

  private def showLoginForm(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String]
  ): IO[Response[IO]] = {

    for {
      providers <- authService.getAvailableProviders()
      clientOpt <- authService.findClientById(clientId)

      stateParam = state
        .map(s => s"""<input type="hidden" name="state" value="$s">""")
        .getOrElse("")
      nonceParam = nonce
        .map(n => s"""<input type="hidden" name="nonce" value="$n">""")
        .getOrElse("")

      providerOptions = providers
        .map { provider =>
          s"""<option value="$provider">$provider</option>"""
        }
        .mkString("\n            ")

      clientName = clientOpt.map(_.client_name).getOrElse("Unknown Client")
      consumerId = clientOpt.map(_.consumer_id).getOrElse("Unknown Consumer")

      html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login - OIDC Provider</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
          .form-group { margin-bottom: 15px; }
          label { display: block; margin-bottom: 5px; font-weight: bold; }
          input[type="text"], input[type="password"] {
            width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;
          }
          button {
            background: #007bff; color: white; padding: 10px 20px;
            border: none; border-radius: 4px; cursor: pointer; width: 100%;
          }
          button:hover { background: #0056b3; }
          .info { background: #f8f9fa; padding: 8px; border-radius: 4px; margin-bottom: 15px; font-size: 14px; }

        </style>
      </head>
      <body>
        <h2>Sign In</h2>
        <div class="info">
          <strong>Consumer ID:</strong> $consumerId<br>
          <strong>Client Name:</strong> $clientName<br>
          <strong>Client ID:</strong> $clientId<br>
          <strong>Requested Scopes:</strong> $scope
        </div>

        <form method="post" action="/obp-oidc/auth">
          <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
          </div>

          <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
          </div>

          <div class="form-group">
            <label for="provider">Authentication Provider:</label>
            <select id="provider" name="provider" required>
            $providerOptions
            </select>
          </div>

          <input type="hidden" name="client_id" value="$clientId">
          <input type="hidden" name="redirect_uri" value="$redirectUri">
          <input type="hidden" name="scope" value="$scope">
          $stateParam
          $nonceParam

          <button type="submit">Sign In</button>
        </form>
      </body>
      </html>
    """

      response <- Ok(html).map(
        _.withContentType(
          org.http4s.headers.`Content-Type`(MediaType.text.html)
        )
      )
    } yield response
  }

  /**
    * Renders a standalone testing page that allows users to input all
    * parameters and submit directly to /obp-oidc/auth.
    * This is useful to verify the login flow without any external Portal.
    */
  private def showStandaloneLoginForm(): IO[Response[IO]] = {
    for {
      providers <- authService.getAvailableProviders()

      providerOptions = providers
        .map { provider =>
          s"""<option value=\"$provider\">$provider</option>"""
        }
        .mkString("\n            ")

      html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>OBP-OIDC Test Login</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 520px; margin: 40px auto; padding: 20px; }
          .form-group { margin-bottom: 14px; }
          label { display: block; margin-bottom: 6px; font-weight: bold; }
          input[type=\"text\"], input[type=\"password\"] {
            width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;
          }
          select { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
          .row { display: grid; grid-template-columns: 1fr; gap: 10px; }
          button { background: #0a66ff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
          button:hover { background: #084ec2; }
          .hint { color: #666; font-size: 12px; margin-top: -6px; margin-bottom: 10px; }
          .box { background: #f7f7f7; border: 1px solid #eee; border-radius: 6px; padding: 12px; margin-bottom: 16px; }
          code { background: #eee; padding: 2px 4px; border-radius: 4px; }
        </style>
      </head>
      <body>
        <h2>OBP-OIDC Test Login</h2>
        <div class=\"box\">
          <div class=\"hint\">This form submits to <code>/obp-oidc/auth</code> and simulates an OAuth2 Authorization Code request.</div>
        </div>

        <form method=\"post\" action=\"/obp-oidc/auth\"> 
          <div class=\"form-group\">
            <label for=\"client_id\">Client ID</label>
            <input type=\"text\" id=\"client_id\" name=\"client_id\" placeholder=\"Required\" required>
          </div>

          <div class=\"form-group\">
            <label for=\"redirect_uri\">Redirect URI</label>
            <input type=\"text\" id=\"redirect_uri\" name=\"redirect_uri\" placeholder=\"https://oauth.pstmn.io/v1/callback\" required>
            <div class=\"hint\">Must be registered for the client. Postman callback is supported.</div>
          </div>

          <div class=\"form-group\">
            <label for=\"scope\">Scope</label>
            <input type=\"text\" id=\"scope\" name=\"scope\" value=\"openid email profile\" required>
          </div>

          <div class=\"row\">
            <div class=\"form-group\">
              <label for=\"state\">State (optional)</label>
              <input type=\"text\" id=\"state\" name=\"state\" placeholder=\"optional\"> 
            </div>
            <div class=\"form-group\">
              <label for=\"nonce\">Nonce (optional)</label>
              <input type=\"text\" id=\"nonce\" name=\"nonce\" placeholder=\"optional\"> 
            </div>
          </div>

          <div class=\"form-group\">
            <label for=\"username\">Username</label>
            <input type=\"text\" id=\"username\" name=\"username\" required>
          </div>

          <div class=\"form-group\">
            <label for=\"password\">Password</label>
            <input type=\"password\" id=\"password\" name=\"password\" required>
          </div>

          <div class=\"form-group\">
            <label for=\"provider\">Authentication Provider</label>
            <select id=\"provider\" name=\"provider\" required>
              $providerOptions
            </select>
          </div>

          <button type=\"submit\">Sign In</button>
        </form>

      </body>
      </html>
      """

      response <- Ok(html).map(
        _.withContentType(
          org.http4s.headers.`Content-Type`(MediaType.text.html)
        )
      )
    } yield response
  }

  private def redirectWithCode(
      redirectUri: String,
      code: String,
      state: Option[String]
  ): IO[Response[IO]] = {
    val stateParam = state.map(s => s"&state=$s").getOrElse("")
    val location = s"$redirectUri?code=$code$stateParam"
    SeeOther(Location(Uri.unsafeFromString(location)))
  }

  private def redirectWithError(
      redirectUri: String,
      error: OidcError
  ): IO[Response[IO]] = {
    val stateParam = error.state.map(s => s"&state=$s").getOrElse("")
    val descriptionParam = error.error_description
      .map(d => s"&error_description=${java.net.URLEncoder.encode(d, "UTF-8")}")
      .getOrElse("")
    val location =
      s"$redirectUri?error=${error.error}$descriptionParam$stateParam"
    SeeOther(Location(Uri.unsafeFromString(location)))
  }
}

object AuthEndpoint {
  def apply(
      authService: AuthService[IO],
      codeService: CodeService[IO],
      statsService: StatsService[IO]
  ): AuthEndpoint =
    new AuthEndpoint(authService, codeService, statsService)
}
