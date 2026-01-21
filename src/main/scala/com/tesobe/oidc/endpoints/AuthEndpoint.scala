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
import com.tesobe.oidc.ratelimit.RateLimitService
import com.tesobe.oidc.config.OidcConfig
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.Location
import org.slf4j.LoggerFactory
import com.tesobe.oidc.stats.StatsService

class AuthEndpoint(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    statsService: StatsService[IO],
    rateLimitService: RateLimitService[IO],
    config: OidcConfig
) {

  private val logger = LoggerFactory.getLogger(getClass)

  // Test logging immediately when class is created
  logger.info("🚀 AuthEndpoint created - logging is working!")
  println("🚀 AuthEndpoint created - logging is working!")

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    // Standalone testing page that does not require query parameters
    // Allows manual login verification without any external client/Portal
    // Only available in local development mode
    case GET -> Root / "obp-oidc" / "test-login"
        if config.localDevelopmentMode =>
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
      req
        .as[UrlForm]
        .flatMap(form => handleLoginSubmissionWithRequest(form, Some(req)))
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

    IO(
      logger.info(
        s"🔍 handleAuthorizationRequest called - responseType: $responseType, clientId: $clientId, redirectUri: $redirectUri, scope: $scope"
      )
    ) *>
      IO(
        println(
          s"🔍 handleAuthorizationRequest called - responseType: $responseType, clientId: $clientId, redirectUri: $redirectUri, scope: $scope"
        )
      ) *>
      // Validate request parameters
      (if (responseType != "code") {
         IO(logger.warn(s"❌ Unsupported response_type: $responseType")) *>
           IO(println(s"❌ Unsupported response_type: $responseType")) *> {
             val error = OidcError(
               "unsupported_response_type",
               Some("Only 'code' response type is supported"),
               state = state
             )
             redirectWithError(redirectUri, error)
           }
       } else if (!scope.contains("openid")) {
         IO(logger.warn(s"❌ Missing 'openid' scope: $scope")) *>
           IO(println(s"❌ Missing 'openid' scope: $scope")) *> {
             val error = OidcError(
               "invalid_scope",
               Some("'openid' scope is required"),
               state = state
             )
             redirectWithError(redirectUri, error)
           }
       } else {
         // Validate client and redirect URI
         IO(
           logger.info(s"✅ Response type and scope valid, validating client...")
         ) *>
           IO(
             println(s"✅ Response type and scope valid, validating client...")
           ) *>
           authService.validateClient(clientId, redirectUri).flatMap {
             isValid =>
               if (!isValid) {
                 IO(
                   logger.warn(
                     s"❌ Client validation failed for clientId: $clientId, redirectUri: $redirectUri"
                   )
                 ) *>
                   IO(
                     println(
                       s"❌ Client validation failed for clientId: $clientId, redirectUri: $redirectUri"
                     )
                   ) *> {
                     val error = OidcError(
                       "invalid_client",
                       Some("Invalid client_id or redirect_uri"),
                       state = state
                     )
                     redirectWithError(redirectUri, error)
                   }
               } else {
                 // Show login form
                 IO(
                   logger.info(s"✅ Client validated, showing login form...")
                 ) *>
                   IO(println(s"✅ Client validated, showing login form...")) *>
                   showLoginForm(clientId, redirectUri, scope, state, nonce)
               }
           }
       })
  }

  private def validateAuthInput(
      username: String,
      password: String,
      provider: String
  ): Either[String, (String, String, String)] = {
    if (username.isEmpty || username.trim.isEmpty)
      Left("Username cannot be empty")
    else if (username.length < 8)
      Left("Username must be at least 8 characters")
    else if (username.length > 100)
      Left("Username must not exceed 100 characters")
    else if (password.isEmpty)
      Left("Password cannot be empty")
    else if (password.length < 10)
      Left("Password must be at least 10 characters")
    else if (password.length > 512)
      Left("Password must not exceed 512 characters")
    else if (provider.isEmpty || provider.trim.isEmpty)
      Left("Provider cannot be empty")
    else if (provider.length < 5)
      Left("Provider must be at least 5 characters")
    else if (provider.length > 512)
      Left("Provider must not exceed 512 characters")
    else
      Right((username.trim, password, provider.trim))
  }

  private def handleLoginSubmission(form: UrlForm): IO[Response[IO]] = {
    handleLoginSubmissionWithRequest(form, None)
  }

  private def handleLoginSubmissionWithRequest(
      form: UrlForm,
      requestOpt: Option[Request[IO]]
  ): IO[Response[IO]] = {
    val formData = form.values.view.mapValues(_.headOption.getOrElse("")).toMap

    for {
      _ <- IO(logger.info("LOGIN FORM SUBMISSION STARTED"))
      _ <- IO(println("LOGIN FORM SUBMISSION STARTED"))

      // Extract IP address for rate limiting
      ip = requestOpt
        .flatMap(_.remoteAddr)
        .map(_.toString)
        .getOrElse("unknown")

      username <- IO.fromOption(formData.get("username"))(
        new RuntimeException("Missing username")
      )
      _ <- IO(
        logger.info(
          s"Auth form submitted for username: '$username' from IP: $ip"
        )
      )
      _ <- IO(
        println(
          s"Auth form submitted for username: '$username' from IP: $ip"
        )
      )

      password <- IO.fromOption(formData.get("password"))(
        new RuntimeException("Missing password")
      )
      _ <- IO(
        logger.debug(s"Password received (length: ${password.length})")
      )
      provider <- IO.fromOption(formData.get("provider"))(
        new RuntimeException("Missing provider")
      )
      _ <- IO(logger.info(s"Provider selected: '$provider'"))

      // Validate input lengths
      validatedInput <- IO
        .fromEither(
          validateAuthInput(username, password, provider).left.map(errorMsg =>
            new RuntimeException(errorMsg)
          )
        )
        .handleErrorWith { error =>
          IO(logger.warn(s"⚠️ Input validation failed: ${error.getMessage}")) *>
            IO(println(s"⚠️ Input validation failed: ${error.getMessage}")) *>
            IO.raiseError(error)
        }
      validUsername = validatedInput._1
      validPassword = validatedInput._2
      validProvider = validatedInput._3

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
          s"Calling authentication service for username: '$validUsername' with provider: '$validProvider'"
        )
      )

      // Perform authentication
      authResult <- authService.authenticate(
        validUsername,
        validPassword,
        validProvider
      )

      response <- authResult match {
        case Right(user) =>
          // Authentication successful - clear rate limit tracking
          rateLimitService.recordSuccessfulLogin(ip, validUsername) *>
            IO(
              logger.info(s"Authentication successful for user: ${user.sub}")
            ) *>
            authenticateAndGenerateCode(
              validUsername,
              validPassword,
              validProvider,
              clientId,
              redirectUri,
              scope,
              state,
              nonce
            )
        case Left(error) =>
          // Authentication failed - record failed attempt for rate limiting
          rateLimitService.checkAndRecordFailedAttempt(ip, validUsername) *>
            IO(
              logger.warn(
                s"Authentication failed for username: '$validUsername', error: ${error.error}"
              )
            ) *>
            showLoginForm(
              clientId,
              redirectUri,
              scope,
              state,
              nonce,
              Some("Incorrect username/password")
            )
      }
    } yield response
  }.handleErrorWith { error =>
    logger.error(
      s"Error handling login submission: ${error.getMessage}",
      error
    )
    BadRequest(s"Invalid form data: ${error.getMessage}")
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
      nonce: Option[String],
      errorMessage: Option[String] = None
  ): IO[Response[IO]] = {

    IO(logger.info(s"🔍 showLoginForm called for clientId: $clientId")) *>
      IO(println(s"🔍 showLoginForm called for clientId: $clientId")) *>
      (for {
        providers <- authService.getAvailableProviders()
        clientOpt <- authService.findClientByClientIdThatIsKey(clientId)

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

        // Format client name for production display: replace dashes with spaces and convert to proper case
        formattedClientName = clientName
          .replace("-", " ")
          .split(" ")
          .map(word =>
            if (word.isEmpty) ""
            else word.charAt(0).toUpper + word.substring(1).toLowerCase
          )
          .mkString(" ")
          .replace("Obp ", "OBP ")

        errorHtml = errorMessage
          .map(msg => s"""<div class="error">$msg</div>""")
          .getOrElse("")

        // Extract domain origin from redirect_uri for logo link
        logoLinkUrl =
          try {
            val uri = new java.net.URI(redirectUri)
            val port =
              if (uri.getPort > 0 && uri.getPort != 80 && uri.getPort != 443) {
                s":${uri.getPort}"
              } else {
                ""
              }
            s"${uri.getScheme}://${uri.getHost}${port}"
          } catch {
            case _: Exception =>
              redirectUri // Fallback to full redirect_uri if parsing fails
          }

        // Determine forgot password URL: use config setting or default to calling app + /forgot-password
        forgotPasswordLink = config.forgotPasswordUrl.getOrElse(
          s"$logoLinkUrl/forgot-password"
        )

        logoHtml = config.logoUrl match {
          case Some(url) =>
            s"""<div class="login-logo">
              <a href="$logoLinkUrl" title="Return to ${formattedClientName}">
                <img src="$url" alt="${config.logoAltText}">
              </a>
            </div>"""
          case None => ""
        }

        html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>Sign In - OBP OIDC Provider</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/static/css/main.css">
        <link rel="stylesheet" href="/static/css/forms.css">
      </head>
      <body class="form-page">
        <div class="login-container">
          $logoHtml
          <h2>Sign In</h2>
          <p class="subtitle">$formattedClientName is asking you to login</p>
          $errorHtml
          ${if (config.localDevelopmentMode) {
            s"""<div class="info">
            <strong>Consumer ID:</strong> $consumerId<br>
            <strong>Client Name:</strong> $clientName<br>
            <strong>Client ID:</strong> $clientId<br>
            <strong>Requested Scopes:</strong> $scope
          </div>"""
          } else {
            ""
          }}

          <form method="post" action="/obp-oidc/auth">
            <div class="form-group">
              <label for="username">Username</label>
              <input type="text" id="username" name="username" required autocomplete="username">
            </div>

            <div class="form-group">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" required autocomplete="current-password">
              <div style="text-align: right; margin-top: 0.5rem;">
                <a href="$forgotPasswordLink" style="font-size: 0.9rem; color: #0066cc; text-decoration: none;">Forgot password?</a>
              </div>
            </div>

            ${
          // Show dropdown if: multiple providers OR single provider in dev mode
          // Hide dropdown if: single provider in production mode
          if (providers.length > 1 || config.localDevelopmentMode) {
            s"""<div class="form-group">
              <label for="provider">Authentication Provider</label>
              <select id="provider" name="provider" required>
              $providerOptions
              </select>
            </div>"""
          } else if (providers.length == 1) {
            // Single provider in production: use hidden field
            s"""<input type="hidden" name="provider" value="${providers.head}">"""
          } else {
            // No providers - shouldn't happen but handle gracefully
            s"""<div class="form-group">
              <label for="provider">Authentication Provider</label>
              <select id="provider" name="provider" required>
              $providerOptions
              </select>
            </div>"""
          }}

            <input type="hidden" name="client_id" value="$clientId">
            <input type="hidden" name="redirect_uri" value="$redirectUri">
            <input type="hidden" name="scope" value="$scope">
            $stateParam
            $nonceParam

            <button type="submit">Sign In</button>
          </form>
        </div>
      </body>
      </html>
    """

        response <- Ok(html).map(
          _.withContentType(
            org.http4s.headers.`Content-Type`(MediaType.text.html)
          )
        )
        _ <- IO(logger.info(s"✅ Login form HTML generated successfully"))
        _ <- IO(println(s"✅ Login form HTML generated successfully"))
      } yield response).flatTap { resp =>
        IO(logger.info(s"✅ Login form response status: ${resp.status}")) *>
          IO(println(s"✅ Login form response status: ${resp.status}"))
      }
  }

  /** Renders a standalone testing page that allows users to input all
    * parameters and submit directly to /obp-oidc/auth. This is useful to verify
    * the login flow without any external Portal.
    */
  private def showStandaloneLoginForm(): IO[Response[IO]] = {
    for {
      providers <- authService.getAvailableProviders()

      providerOptions = providers
        .map { provider =>
          s"""<option value=\"$provider\">$provider</option>"""
        }
        .mkString("\n            ")

      // For test login, use configured forgot password URL or default to localhost
      forgotPasswordLink = config.forgotPasswordUrl.getOrElse(
        "http://localhost:5174/forgot-password"
      )

      html = s"""
      <!DOCTYPE html>
      <html>
      <head>
        <title>Test Login - OBP OIDC Provider</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/static/css/main.css">
        <link rel="stylesheet" href="/static/css/forms.css">
      </head>
      <body class="form-page">
        <div class="login-container-large">
          <h2>OBP-OIDC Test Login</h2>
          <p class=\"subtitle\">Development Testing Interface</p>
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
            <div style=\"text-align: right; margin-top: 0.5rem;\">
              <a href=\"$forgotPasswordLink\" style=\"font-size: 0.9rem; color: #0066cc; text-decoration: none;\">Forgot password?</a>
            </div>
          </div>

          <div class=\"form-group\">
            <label for=\"provider\">Authentication Provider</label>
            <select id=\"provider\" name=\"provider\" required>
              $providerOptions
            </select>
          </div>

            <button type=\"submit\">Sign In</button>
          </form>
        </div>
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
    val stateParam = state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("") // Code URL-encoding
    val location = s"$redirectUri?code=$code$stateParam"
    IO(println(s"🔄 Redirecting with code to: $location")) *>
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
      statsService: StatsService[IO],
      rateLimitService: RateLimitService[IO],
      config: OidcConfig
  ): AuthEndpoint =
    new AuthEndpoint(
      authService,
      codeService,
      statsService,
      rateLimitService,
      config
    )
}
