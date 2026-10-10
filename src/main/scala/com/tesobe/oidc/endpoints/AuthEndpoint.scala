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
import com.tesobe.oidc.auth.{AuthService, CodeService, RedirectUriRules}
import com.tesobe.oidc.endpoints.HtmlUtils.htmlEncode
import com.tesobe.oidc.models.{ConsentChallenge, ObpConsent, OidcError, PendingAuthorization, User}
import com.tesobe.oidc.ratelimit.RateLimitService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.tokens.JwtService
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.Location
import org.slf4j.LoggerFactory
import com.tesobe.oidc.stats.StatsService

import java.time.Instant
import java.util.UUID

class AuthEndpoint(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    statsService: StatsService[IO],
    rateLimitService: RateLimitService[IO],
    config: OidcConfig,
    jwtService: JwtService[IO],
    consentChallengesRef: Ref[IO, Map[String, ConsentChallenge]],
    pendingAuthorizationsRef: Ref[IO, Map[String, PendingAuthorization]]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  // Consent statuses OBP-API uses for a consent the user has approved: ACCEPTED (OBP),
  // AUTHORISED (UK Open Banking) and valid (Berlin Group).
  private val approvedConsentStatuses = Set("ACCEPTED", "AUTHORISED", "VALID")

  private def isApprovedConsentStatus(status: String): Boolean =
    approvedConsentStatuses.contains(status.toUpperCase)

  private val authRequestCookiePrefix = "obp_oidc_auth_"

  // Test logging immediately when class is created
  logger.info("AuthEndpoint created - logging is working!")
  println("AuthEndpoint created - logging is working!")

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
        NonceQueryParamMatcher(nonce) +&
        ConsentRequestIdQueryParamMatcher(consentRequestId) +&
        BankIdQueryParamMatcher(bankId) +&
        ConsentIdQueryParamMatcher(consentId) =>
      handleAuthorizationRequest(
        responseType,
        clientId,
        redirectUri,
        scope,
        state,
        nonce,
        consentRequestId,
        bankId,
        consentId
      )

    case req @ POST -> Root / "obp-oidc" / "auth" =>
      req
        .as[UrlForm]
        .flatMap(form => handleLoginSubmissionWithRequest(form, Some(req)))

    // Consent callback: Portal redirects here after user approves/denies consent
    case GET -> Root / "obp-oidc" / "consent-callback" :?
        ChallengeQueryParamMatcher(challengeId) +&
        ConsentIdCallbackQueryParamMatcher(consentId) +&
        ConsentStatusQueryParamMatcher(consentStatus) +&
        UsernameCallbackQueryParamMatcher(username) =>
      handleConsentCallback(challengeId, consentId, consentStatus, username)
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
  object ConsentRequestIdQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("consent_request_id")
  object BankIdQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("bank_id")
  object ConsentIdQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("consent_id")

  // Consent callback query parameter matchers
  object ChallengeQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("challenge")
  object ConsentIdCallbackQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("consent_id")
  object ConsentStatusQueryParamMatcher
      extends QueryParamDecoderMatcher[String]("consent_status")
  object UsernameCallbackQueryParamMatcher
      extends OptionalQueryParamDecoderMatcher[String]("username")

  private def handleAuthorizationRequest(
      responseType: String,
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      consentRequestId: Option[String] = None,
      bankId: Option[String] = None,
      consentId: Option[String] = None
  ): IO[Response[IO]] = {

    IO(
      logger.info(
        s"handleAuthorizationRequest called - responseType: $responseType, clientId: $clientId, redirectUri: $redirectUri, scope: $scope, consentRequestId: $consentRequestId, bankId: $bankId"
      )
    ) *>
      IO(
        println(
          s"handleAuthorizationRequest called - responseType: $responseType, clientId: $clientId, redirectUri: $redirectUri, scope: $scope"
        )
      ) *>
      // Validate the client and redirect URI before anything else. Until both are known to be
      // registered, redirect_uri is untrusted input: an error must be shown here, never sent to it
      // (RFC 6749 section 4.1.2.1), or this endpoint becomes an open redirect.
      validateClientAndRedirectUri(clientId, redirectUri).flatMap { isValid =>
        if (!isValid) {
          IO(logger.warn(s"Client validation failed for clientId: $clientId, redirectUri: $redirectUri")) *>
            showErrorPage(
              Status.BadRequest,
              "Invalid client",
              "The client_id is not known, or the redirect_uri is not registered for it."
            )
        } else if (responseType != "code" && responseType != "code id_token") {
          IO(logger.warn(s"Unsupported response_type: $responseType")) *>
            redirectWithError(
              redirectUri,
              OidcError("unsupported_response_type", Some("Supported response types: 'code', 'code id_token'"), state = state)
            )
        } else if (!scope.contains("openid")) {
          IO(logger.warn(s"Missing 'openid' scope: $scope")) *>
            redirectWithError(
              redirectUri,
              OidcError("invalid_scope", Some("'openid' scope is required"), state = state)
            )
        } else {
                 (consentRequestId, consentId) match {
                   case (Some(crId), _) =>
                     // OBP consent-request flow: skip login form, redirect straight to Portal.
                     // The user will authenticate on Portal (which does its own OAuth with OBP-OIDC).
                     IO(logger.info(s"Client validated, consent_request_id present — skipping login, redirecting to Portal...")) *>
                       redirectToPortalForConsent(clientId, redirectUri, scope, state, nonce, responseType, crId, bankId.getOrElse(""))
                   case (_, Some(cid)) =>
                     // UK Open Banking flow: the TPP has already lodged an account-access consent
                     // (status AWAITINGAUTHORISATION). Route the PSU to Portal to authenticate and
                     // approve it; Portal calls OBP-API to authorise the consent, then redirects back
                     // to /consent-callback so we mint a code bound to this consent_id.
                     IO(logger.info(s"Client validated, UK consent_id present ($cid) — redirecting to Portal for UK consent approval...")) *>
                       redirectToPortalForUKConsent(clientId, redirectUri, scope, state, nonce, responseType, cid, bankId.getOrElse(""))
                   case _ =>
                     // Normal flow: keep the validated request on the server and show the login form
                     IO(logger.info(s"Client validated, showing login form...")) *>
                       storePendingAuthorization(clientId, redirectUri, scope, state, nonce, responseType, consentId)
                         .flatMap(pending => showLoginForm(pending))
                 }
        }
      }
  }

  /** Keep a validated authorization request on the server while the user fills in the login form.
    * Expired requests are dropped on the way.
    */
  private def storePendingAuthorization(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String,
      consentId: Option[String]
  ): IO[PendingAuthorization] =
    for {
      id <- IO(UUID.randomUUID().toString)
      bindingToken <- IO(UUID.randomUUID().toString)
      now = Instant.now().getEpochSecond
      pending = PendingAuthorization(
        id = id,
        bindingToken = bindingToken,
        clientId = clientId,
        redirectUri = redirectUri,
        scope = scope,
        state = state,
        nonce = nonce,
        responseType = responseType,
        consentId = consentId,
        exp = now + config.codeExpirationSeconds
      )
      _ <- pendingAuthorizationsRef.update(all => all.filter(_._2.exp >= now) + (id -> pending))
    } yield pending

  /** The pending request named by the form's auth_request_id, if it exists, has not expired and the
    * browser sent back its binding cookie (a form posted from another site arrives without it).
    */
  private def findPendingAuthorization(
      authRequestId: String,
      requestOpt: Option[Request[IO]]
  ): IO[Option[PendingAuthorization]] =
    pendingAuthorizationsRef.get.map { all =>
      val now = Instant.now().getEpochSecond
      val cookieValue = requestOpt.flatMap(_.cookies.find(_.name == authRequestCookiePrefix + authRequestId)).map(_.content)
      all.get(authRequestId).filter(p => p.exp >= now && cookieValue.contains(p.bindingToken))
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
          IO(logger.warn(s"Input validation failed: ${error.getMessage}")) *>
            IO(println(s"Input validation failed: ${error.getMessage}")) *>
            IO.raiseError(error)
        }
      validUsername = validatedInput._1
      validPassword = validatedInput._2
      validProvider = validatedInput._3

      // The client, redirect_uri, scope, state, nonce and response_type come from the request that
      // GET /auth validated and stored, never from the posted form, which anyone can forge.
      pendingOpt <- formData.get("auth_request_id").filter(_.nonEmpty) match {
        case Some(authRequestId) => findPendingAuthorization(authRequestId, requestOpt)
        case None if config.localDevelopmentMode => pendingFromStandaloneTestForm(formData)
        case None => IO.pure(None)
      }

      response <- pendingOpt match {
        case None =>
          IO(logger.warn("Login form submitted without a valid pending authorization request")) *>
            showErrorPage(
              Status.BadRequest,
              "Sign-in expired",
              "This sign-in form has expired or was not opened by this server. Go back to the application and sign in again."
            )

        case Some(pending) =>
          for {
            _ <- IO(logger.info(s"Calling authentication service for username: '$validUsername' with provider: '$validProvider'"))
            authResult <- authService.authenticate(validUsername, validPassword, validProvider)
            response <- authResult match {
              case Right(user) =>
                // Authentication successful - clear rate limit tracking; the pending request is used up
                rateLimitService.recordSuccessfulLogin(ip, validUsername) *>
                  pendingAuthorizationsRef.update(_ - pending.id) *>
                  IO(logger.info(s"Authentication successful for user: ${user.sub}")) *>
                  generateCodeForUser(
                    user, pending.clientId, pending.redirectUri, pending.scope, pending.state, pending.nonce,
                    pending.responseType, consentId = pending.consentId
                  )
              case Left(error) =>
                // Authentication failed - record failed attempt for rate limiting, show the same request again
                rateLimitService.checkAndRecordFailedAttempt(ip, validUsername) *>
                  IO(
                    logger.warn(
                      s"Authentication failed for username: '$validUsername', provider: '$validProvider', error: ${error.error}, description: ${error.error_description.getOrElse("none")}"
                    )
                  ) *>
                  showLoginForm(pending, Some("Incorrect username/password"))
            }
          } yield response
      }
    } yield response
  }.handleErrorWith { error =>
    logger.error(
      s"Error handling login submission: ${error.getMessage}",
      error
    )
    BadRequest("Invalid form data. Please try again.")
  }

  /** The standalone test page (/obp-oidc/test-login, local development mode only) posts the client
    * and redirect_uri itself rather than going through GET /auth. They are validated here exactly as
    * GET /auth would, so even in development a code is only ever issued for a registered redirect_uri.
    */
  private def pendingFromStandaloneTestForm(formData: Map[String, String]): IO[Option[PendingAuthorization]] =
    (formData.get("client_id"), formData.get("redirect_uri"), formData.get("scope")) match {
      case (Some(clientId), Some(redirectUri), Some(scope)) =>
        validateClientAndRedirectUri(clientId, redirectUri).flatMap {
          case true =>
            storePendingAuthorization(
              clientId,
              redirectUri,
              scope,
              formData.get("state").filter(_.nonEmpty),
              formData.get("nonce").filter(_.nonEmpty),
              formData.get("response_type").getOrElse("code"),
              consentId = None
            ).map(Some(_))
          case false => IO.pure(None)
        }
      case _ => IO.pure(None)
    }

  /** Store authorization state and redirect to Portal for consent approval.
    * No user authentication happens here — the user will authenticate on Portal.
    */
  private def redirectToPortalForConsent(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String,
      consentRequestId: String,
      bankId: String
  ): IO[Response[IO]] = {
    for {
      challengeId <- IO(UUID.randomUUID().toString)
      exp = Instant.now().plusSeconds(config.codeExpirationSeconds).getEpochSecond

      challenge = ConsentChallenge(
        challenge = challengeId,
        clientId = clientId,
        redirectUri = redirectUri,
        scope = scope,
        state = state,
        nonce = nonce,
        responseType = responseType,
        consentRequestId = Some(consentRequestId),
        consentId = None,
        bankId = bankId,
        exp = exp
      )

      _ <- consentChallengesRef.update(_ + (challengeId -> challenge))
      _ <- IO(logger.info(s"Created consent challenge: $challengeId for consent_request_id: $consentRequestId, redirecting to Portal"))

      // Build the OBP-OIDC consent callback URL that Portal will redirect back to
      oidcReturnUrl = s"${config.issuer}/consent-callback?challenge=${java.net.URLEncoder.encode(challengeId, "UTF-8")}"

      // Redirect to Portal's login page with consent params
      // Portal will authenticate the user (OBP-OIDC session may make this seamless),
      // then show the consent approval page
      portalUrl = s"${config.obpPortalBaseUrl}/login/obp-oidc" +
        s"?consent_request_id=${java.net.URLEncoder.encode(consentRequestId, "UTF-8")}" +
        s"&bank_id=${java.net.URLEncoder.encode(bankId, "UTF-8")}" +
        s"&oidc_return_url=${java.net.URLEncoder.encode(oidcReturnUrl, "UTF-8")}"

      _ <- IO(logger.info(s"Redirecting to Portal for consent: $portalUrl"))
      response <- SeeOther(Location(Uri.unsafeFromString(portalUrl)))
    } yield response
  }

  /** Store authorization state and redirect to Portal for UK Open Banking consent approval.
    *
    * Unlike the OBP consent-request flow, the UK consent already exists (the TPP lodged it
    * via POST /account-access-consents and passed its consent_id here). Portal authenticates
    * the PSU, calls OBP-API to authorise that consent (status → AUTHORISED, bound to the PSU),
    * then redirects back to /consent-callback where we mint the authorization code — so the
    * TPP's token carries the consent_id claim that OBP-API validates on data calls.
    */
  private def redirectToPortalForUKConsent(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String,
      consentId: String,
      bankId: String
  ): IO[Response[IO]] = {
    for {
      challengeId <- IO(UUID.randomUUID().toString)
      exp = Instant.now().plusSeconds(config.codeExpirationSeconds).getEpochSecond

      challenge = ConsentChallenge(
        challenge = challengeId,
        clientId = clientId,
        redirectUri = redirectUri,
        scope = scope,
        state = state,
        nonce = nonce,
        responseType = responseType,
        consentRequestId = None,
        consentId = Some(consentId),
        bankId = bankId,
        exp = exp
      )

      _ <- consentChallengesRef.update(_ + (challengeId -> challenge))
      _ <- IO(logger.info(s"Created consent challenge: $challengeId for UK consent_id: $consentId, redirecting to Portal"))

      oidcReturnUrl = s"${config.issuer}/consent-callback?challenge=${java.net.URLEncoder.encode(challengeId, "UTF-8")}"

      // Portal reads api_standard=UKOpenBanking to drive the UK approval page (which calls
      // OBP-API's consent authorise endpoint) instead of the OBP consent-request page.
      portalUrl = s"${config.obpPortalBaseUrl}/login/obp-oidc" +
        s"?consent_id=${java.net.URLEncoder.encode(consentId, "UTF-8")}" +
        s"&api_standard=UKOpenBanking" +
        s"&bank_id=${java.net.URLEncoder.encode(bankId, "UTF-8")}" +
        s"&oidc_return_url=${java.net.URLEncoder.encode(oidcReturnUrl, "UTF-8")}"

      _ <- IO(logger.info(s"Redirecting to Portal for UK consent: $portalUrl"))
      response <- SeeOther(Location(Uri.unsafeFromString(portalUrl)))
    } yield response
  }

  /** Handle the consent callback from Portal after user approves/denies consent.
    *
    * Everything on this URL comes through the browser, so none of it is trusted to decide who the code
    * is for. A consent_status other than an approved one ends the flow with access_denied. Otherwise the
    * consent is read from OBP-API and checked against the challenge (see verifyConsent); the user the
    * code is issued for is the consent's own user, never a username or provider on the URL.
    *
    * Two completion modes, chosen by whether Portal sends a `username` parameter (its value is ignored):
    *  - present: standard OIDC completion — mint an authorization code for the original client, bound
    *    to the consent_id, so the token exchange yields JWTs carrying the `consent_id` claim that OBP-API
    *    validates.
    *  - absent (legacy, e.g. Hola): redirect back to the client with `consent_status=ACCEPTED&consent_id=...`
    *    only — the client then uses Consent-Id + Consumer-Key headers against OBP-API, no OAuth code minted.
    *    The consent is verified first in this mode too.
    */
  private def handleConsentCallback(
      challengeId: String,
      consentIdParam: Option[String],
      consentStatus: String,
      usernameParam: Option[String]
  ): IO[Response[IO]] = {
    for {
      challenges <- consentChallengesRef.get
      response <- challenges.get(challengeId) match {
        case Some(challenge) =>
          // Consume the challenge (one-time use)
          consentChallengesRef.update(_ - challengeId) *> {
            val now = Instant.now().getEpochSecond
            if (challenge.exp < now) {
              IO(logger.warn(s"Consent challenge expired: $challengeId")) *>
                redirectWithError(challenge.redirectUri, OidcError("access_denied", Some("Consent challenge expired"), state = challenge.state))
            } else if (!isApprovedConsentStatus(consentStatus)) {
              IO(logger.info(s"Consent denied for challenge: $challengeId, status: $consentStatus")) *>
                redirectWithError(challenge.redirectUri, OidcError("access_denied", Some(s"User denied consent (status: $consentStatus)"), state = challenge.state))
            } else {
              verifyConsent(challenge, consentIdParam).flatMap {
                case Left(reason) =>
                  IO(logger.warn(s"Consent callback refused for challenge $challengeId: $reason")) *>
                    redirectWithError(challenge.redirectUri, OidcError("access_denied", Some("The consent could not be verified"), state = challenge.state))

                case Right(consent) if usernameParam.isEmpty =>
                  // Legacy completion: hand the verified consent_id back to the client.
                  val stateParam = challenge.state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("")
                  val location = s"${challenge.redirectUri}?consent_status=ACCEPTED&consent_id=${java.net.URLEncoder.encode(consent.consentId, "UTF-8")}$stateParam"
                  IO(logger.info(s"Consent ${consent.consentId} verified — legacy redirect with consent_id")) *>
                    SeeOther(Location(Uri.unsafeFromString(location)))

                case Right(consent) =>
                  authService.getUserBySubAndProvider(consent.username, consent.provider).flatMap {
                    case Some(user) =>
                      IO(logger.info(s"Consent ${consent.consentId} verified for user '${user.sub}' — issuing authorization code for client ${challenge.clientId}")) *>
                        generateCodeForUser(
                          user,
                          challenge.clientId,
                          challenge.redirectUri,
                          challenge.scope,
                          challenge.state,
                          challenge.nonce,
                          challenge.responseType,
                          Some(consent.consentId)
                        )
                    case None =>
                      IO(logger.warn(s"Consent ${consent.consentId}: user '${consent.username}' (provider '${consent.provider}') could not be resolved")) *>
                        redirectWithError(challenge.redirectUri, OidcError("access_denied", Some("The consent could not be verified"), state = challenge.state))
                  }
              }
            }
          }
        case None =>
          IO(logger.warn(s"Consent challenge not found: $challengeId")) *>
            BadRequest("Invalid or expired consent challenge.")
      }
    } yield response
  }

  /** Read the consent from OBP-API and check that it is the consent this challenge was started for:
    *  - UK flow: it is the consent_id the TPP passed to /auth (a different consent_id on the URL is refused);
    *    OBP flow: it came from the challenge's consent_request_id;
    *  - its status is an approved one;
    *  - it belongs to the challenge's client (its Consumer Key is the client_id).
    * Left carries the reason for the log; the browser only learns that verification failed.
    */
  private def verifyConsent(
      challenge: ConsentChallenge,
      consentIdParam: Option[String]
  ): IO[Either[String, ObpConsent]] = {
    val consentIdMismatch = (challenge.consentId, consentIdParam) match {
      case (Some(expected), Some(given)) => given != expected
      case _                             => false
    }
    challenge.consentId.orElse(consentIdParam) match {
      case _ if consentIdMismatch => IO.pure(Left(s"consent_id on the callback is not the challenge's consent ${challenge.consentId.getOrElse("")}"))
      case None                   => IO.pure(Left("no consent_id on the callback"))
      case Some(consentId) =>
        authService.getConsent(consentId).map {
          case None =>
            Left(s"consent $consentId not found in OBP-API (or OBP-API could not be reached)")
          case Some(consent) if !isApprovedConsentStatus(consent.status) =>
            Left(s"consent $consentId has status ${consent.status}")
          case Some(consent) if challenge.consentRequestId.exists(expected => !consent.consentRequestId.contains(expected)) =>
            Left(s"consent $consentId did not come from consent request ${challenge.consentRequestId.getOrElse("")}")
          case Some(consent) if !consent.clientId.contains(challenge.clientId) =>
            Left(s"consent $consentId belongs to client ${consent.clientId.getOrElse("(none)")}, not ${challenge.clientId}")
          case Some(consent) =>
            Right(consent)
        }
    }
  }

  /** Issue an authorization code for `user` and send it to `redirectUri`.
    * Every caller has validated the client and redirect_uri already; they are validated again here so
    * that no path, present or future, can issue a code for a redirect_uri that is not registered.
    */
  private def generateCodeForUser(
      user: User,
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String = "code",
      consentId: Option[String] = None
  ): IO[Response[IO]] =
    validateClientAndRedirectUri(clientId, redirectUri).flatMap {
      case false =>
        IO(logger.error(s"Refusing to issue a code: redirect_uri is not registered for client $clientId")) *>
          showErrorPage(Status.BadRequest, "Invalid client", "The client_id is not known, or the redirect_uri is not registered for it.")
      case true =>
        for {
          _ <- statsService.incrementLoginSuccess(user.username)
          code <- codeService
            .generateCode(clientId, redirectUri, user.sub, scope, state, nonce, user.provider, consentId)
          response <- responseType match {
            case "code id_token" =>
              for {
                idToken <- jwtService.generateHybridIdToken(user, clientId, code, state, nonce, consentId)
                resp <- redirectWithCodeAndIdToken(redirectUri, code, idToken, state)
              } yield resp
            case _ =>
              redirectWithCode(redirectUri, code, state)
          }
        } yield response
    }

  /** Rebuild the /obp-oidc/auth URL for the current request so an external page
    * (e.g. the Portal register page) can send the user back into the flow.
    */
  private def buildAuthorizeUrl(
      clientId: String,
      redirectUri: String,
      scope: String,
      state: Option[String],
      nonce: Option[String],
      responseType: String,
      consentId: Option[String]
  ): String = {
    def enc(v: String) = java.net.URLEncoder.encode(v, "UTF-8")
    val params = Seq(
      "response_type" -> Some(responseType),
      "client_id" -> Some(clientId),
      "redirect_uri" -> Some(redirectUri),
      "scope" -> Some(scope),
      "state" -> state,
      "nonce" -> nonce,
      "consent_id" -> consentId
    ).collect { case (k, Some(v)) => s"$k=${enc(v)}" }
    s"${config.issuer}/auth?${params.mkString("&")}"
  }

  /** Append return_to=<url> to a base URL, respecting any existing query string. */
  private def withReturnTo(baseUrl: String, returnTo: String): String = {
    val sep = if (baseUrl.contains("?")) "&" else "?"
    s"$baseUrl${sep}return_to=${java.net.URLEncoder.encode(returnTo, "UTF-8")}"
  }

  /** The origin (scheme://host[:port]) of an http or https URI, for the logo link back to the client.
    * Anything else — another scheme, or a value that does not parse — gives None, and no link is shown.
    */
  private def httpOrigin(uriString: String): Option[String] =
    scala.util.Try(new java.net.URI(uriString)).toOption.flatMap { uri =>
      Option(uri.getScheme).map(_.toLowerCase).filter(scheme => scheme == "https" || scheme == "http").flatMap { scheme =>
        Option(uri.getHost).filter(_.nonEmpty).map { host =>
          val port = if (uri.getPort > 0 && uri.getPort != 80 && uri.getPort != 443) s":${uri.getPort}" else ""
          s"$scheme://$host$port"
        }
      }
    }

  /** Show the login form for a validated, stored authorization request. The form carries only the
    * request's id; the matching binding cookie is set on the response (see PendingAuthorization).
    */
  private def showLoginForm(
      pending: PendingAuthorization,
      errorMessage: Option[String] = None
  ): IO[Response[IO]] = {
    val clientId = pending.clientId
    val redirectUri = pending.redirectUri
    val scope = pending.scope
    val state = pending.state
    val nonce = pending.nonce
    val responseType = pending.responseType
    val consentId = pending.consentId

    IO(logger.info(s"showLoginForm called for clientId: $clientId")) *>
      IO(println(s"showLoginForm called for clientId: $clientId")) *>
      (for {
        providers <- authService.getAvailableProviders()
        clientOpt <- authService.findClientByClientIdThatIsKey(clientId)

        providerOptions = providers
          .map { provider =>
            s"""<option value="${htmlEncode(provider)}">${htmlEncode(provider)}</option>"""
          }
          .mkString("\n            ")

        clientName = clientOpt.map(_.client_name).getOrElse("Unknown Client")
        consumerId = clientOpt.map(_.consumer_id).getOrElse("Unknown Consumer")

        // Format client name for production display: replace dashes with spaces and convert to proper case
        formattedClientName = htmlEncode(clientName
          .replace("-", " ")
          .split(" ")
          .map(word =>
            if (word.isEmpty) ""
            else word.charAt(0).toUpper + word.substring(1).toLowerCase
          )
          .mkString(" ")
          .replace("Obp ", "OBP "))

        errorHtml = errorMessage
          .map(msg => s"""<div class="error">${htmlEncode(msg)}</div>""")
          .getOrElse("")

        // Logo links back to the origin of the (validated) redirect_uri, only for http(s)
        logoLinkUrl = httpOrigin(redirectUri)

        forgotPasswordLink = s"${config.obpPortalBaseUrl}/forgot-password"

        // Register link: points at the Portal (or OIDC_REGISTRATION_URL) and carries the
        // current authorize URL as return_to so the Portal can send the user back into
        // the OAuth flow once the account exists.
        registerHtml = config.registrationUrl match {
          case Some(registrationUrl) =>
            val authorizeUrl = buildAuthorizeUrl(clientId, redirectUri, scope, state, nonce, responseType, consentId)
            val href = withReturnTo(registrationUrl, authorizeUrl)
            s"""<p class="register-prompt" style="text-align: center; margin-top: 1rem; font-size: 0.9rem;">
              Don't have an account?
              <a href="${htmlEncode(href)}" data-testid="register-link" style="color: #0066cc; text-decoration: none;">Register</a>
            </p>"""
          case None => ""
        }

        logoHtml = config.logoUrl match {
          case Some(url) =>
            val image = s"""<img src="${htmlEncode(url)}" alt="${htmlEncode(config.logoAltText)}">"""
            val linkedImage = logoLinkUrl match {
              case Some(origin) => s"""<a href="${htmlEncode(origin)}" title="Return to ${formattedClientName}">$image</a>"""
              case None => image
            }
            s"""<div class="login-logo">
              $linkedImage
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
            <strong>Consumer ID:</strong> ${htmlEncode(consumerId)}<br>
            <strong>Client Name:</strong> ${htmlEncode(clientName)}<br>
            <strong>Client ID:</strong> ${htmlEncode(clientId)}<br>
            <strong>Requested Scopes:</strong> ${htmlEncode(scope)}
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
            s"""<input type="hidden" name="provider" value="${htmlEncode(providers.head)}">"""
          } else {
            // No providers - shouldn't happen but handle gracefully
            s"""<div class="form-group">
              <label for="provider">Authentication Provider</label>
              <select id="provider" name="provider" required>
              $providerOptions
              </select>
            </div>"""
          }}

            <input type="hidden" name="auth_request_id" value="${htmlEncode(pending.id)}">

            <button type="submit">Sign In</button>
          </form>
          $registerHtml
        </div>
        <script>
          (function() {
            var sel = document.getElementById('provider');
            if (!sel) return;
            var saved = document.cookie.replace(/(?:(?:^|.*;\\s*)lastProvider\\s*=\\s*([^;]*).*$$)|^.*$$/, '$$1');
            if (saved) {
              for (var i = 0; i < sel.options.length; i++) {
                if (sel.options[i].value === decodeURIComponent(saved)) {
                  sel.selectedIndex = i;
                  break;
                }
              }
            }
            sel.addEventListener('change', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
            sel.form.addEventListener('submit', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
          })();
        </script>
      </body>
      </html>
    """

        response <- Ok(html).map(
          _.withContentType(
            org.http4s.headers.`Content-Type`(MediaType.text.html)
          ).addCookie(
            ResponseCookie(
              name = authRequestCookiePrefix + pending.id,
              content = pending.bindingToken,
              maxAge = Some(config.codeExpirationSeconds.toLong),
              path = Some("/obp-oidc"),
              sameSite = Some(SameSite.Lax),
              secure = config.issuer.startsWith("https://"),
              httpOnly = true
            )
          )
        )
        _ <- IO(logger.info(s"Login form HTML generated successfully"))
        _ <- IO(println(s"Login form HTML generated successfully"))
      } yield response).flatTap { resp =>
        IO(logger.info(s"Login form response status: ${resp.status}")) *>
          IO(println(s"Login form response status: ${resp.status}"))
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

      forgotPasswordLink = s"${config.obpPortalBaseUrl}/forgot-password"

      registerHtml = config.registrationUrl match {
        case Some(registrationUrl) =>
          s"""<p class=\"register-prompt\" style=\"text-align: center; margin-top: 1rem; font-size: 0.9rem;\">
              Don't have an account?
              <a href=\"${htmlEncode(registrationUrl)}\" data-testid=\"register-link\" style=\"color: #0066cc; text-decoration: none;\">Register</a>
            </p>"""
        case None => ""
      }

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
          $registerHtml
        </div>
        <script>
          (function() {
            var sel = document.getElementById('provider');
            if (!sel) return;
            var saved = document.cookie.replace(/(?:(?:^|.*;\\s*)lastProvider\\s*=\\s*([^;]*).*$$)|^.*$$/, '$$1');
            if (saved) {
              for (var i = 0; i < sel.options.length; i++) {
                if (sel.options[i].value === decodeURIComponent(saved)) {
                  sel.selectedIndex = i;
                  break;
                }
              }
            }
            sel.addEventListener('change', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
            sel.form.addEventListener('submit', function() {
              document.cookie = 'lastProvider=' + encodeURIComponent(sel.value) + ';path=/;max-age=31536000;SameSite=Lax';
            });
          })();
        </script>
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

  /** An error shown on this server instead of being sent to a redirect_uri, for requests whose client
    * or redirect_uri could not be trusted (RFC 6749 section 4.1.2.1).
    */
  /** This checks that the client is known, that redirect_uri is registered for it, and that redirect_uri
    * meets RedirectUriRules. A stored entry that breaks the rules (one saved before OBP-API checked them)
    * is treated as not registered, so it is never used as a redirect target.
    */
  private def validateClientAndRedirectUri(clientId: String, redirectUri: String): IO[Boolean] =
    RedirectUriRules.problemWith(redirectUri) match {
      case Some(problem) =>
        IO(logger.warn(s"Refusing redirect_uri for client $clientId: $problem")).as(false)
      case None =>
        authService.validateClient(clientId, redirectUri)
    }

  private def showErrorPage(status: Status, title: String, message: String): IO[Response[IO]] = {
    val html = s"""<!DOCTYPE html>
      <html>
      <head>
        <title>${htmlEncode(title)} - OBP OIDC Provider</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="/static/css/main.css">
        <link rel="stylesheet" href="/static/css/forms.css">
      </head>
      <body class="form-page">
        <div class="login-container">
          <h2 data-testid="error-title">${htmlEncode(title)}</h2>
          <div class="error" role="alert" data-testid="error-message">${htmlEncode(message)}</div>
        </div>
      </body>
      </html>"""
    IO.pure(
      Response[IO](status)
        .withEntity(html)
        .withContentType(org.http4s.headers.`Content-Type`(MediaType.text.html))
    )
  }

  private def redirectWithCode(
      redirectUri: String,
      code: String,
      state: Option[String]
  ): IO[Response[IO]] = {
    val stateParam = state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("") // Code URL-encoding
    val location = s"$redirectUri?code=$code$stateParam"
    IO(println(s"Redirecting with code to: $location")) *>
    SeeOther(Location(Uri.unsafeFromString(location)))
  }

  /** Redirect with both code and id_token in the fragment (hybrid flow).
    * Per OIDC Core 3.3.2.5, when response_type includes a token or id_token,
    * parameters MUST be returned in the URI fragment.
    */
  private def redirectWithCodeAndIdToken(
      redirectUri: String,
      code: String,
      idToken: String,
      state: Option[String]
  ): IO[Response[IO]] = {
    val stateParam = state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("")
    val location = s"$redirectUri#code=$code&id_token=$idToken$stateParam"
    IO(logger.info(s"Redirecting with code and id_token (hybrid flow) to: ${redirectUri}#code=...&id_token=...")) *>
    IO(println(s"Redirecting with code and id_token (hybrid flow)")) *>
    SeeOther(Location(Uri.unsafeFromString(location)))
  }

  private def redirectWithError(
      redirectUri: String,
      error: OidcError
  ): IO[Response[IO]] = {
    val stateParam = error.state.map(s => s"&state=${java.net.URLEncoder.encode(s, "UTF-8")}").getOrElse("")
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
      config: OidcConfig,
      jwtService: JwtService[IO],
      consentChallengesRef: Ref[IO, Map[String, ConsentChallenge]],
      pendingAuthorizationsRef: Ref[IO, Map[String, PendingAuthorization]]
  ): AuthEndpoint =
    new AuthEndpoint(
      authService,
      codeService,
      statsService,
      rateLimitService,
      config,
      jwtService,
      consentChallengesRef,
      pendingAuthorizationsRef
    )
}
