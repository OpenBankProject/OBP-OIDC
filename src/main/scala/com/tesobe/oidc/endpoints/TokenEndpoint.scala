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
import cats.syntax.all._
import com.tesobe.oidc.auth.{AuthService, CodeService}
import com.tesobe.oidc.models.{OidcError, TokenRequest, TokenResponse}
import com.tesobe.oidc.tokens.JwtService
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.stats.StatsService
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.typelevel.ci.CIString
import org.http4s.dsl.io._
import org.slf4j.LoggerFactory

class TokenEndpoint(
    authService: AuthService[IO],
    codeService: CodeService[IO],
    jwtService: JwtService[IO],
    config: OidcConfig,
    statsService: StatsService[IO]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ POST -> Root / "obp-oidc" / "token" =>
      println(
        s"🎫 DEBUG: TokenEndpoint route matched! ${req.method} ${req.uri}"
      )
      println(s"🎫 DEBUG: About to log with logger...")
      logger.info(s"🎫 Token endpoint called")
      logger.info(
        s"📋 Content-Type: ${req.headers.get[headers.`Content-Type`].map(_.mediaType).getOrElse("MISSING")}"
      )
      logger.info(
        s"🔗 Headers: ${req.headers.headers.map(h => s"${h.name}: ${h.value}").mkString(", ")}"
      )
      println(s"🎫 DEBUG: Logger calls completed, about to parse form...")

      req.as[UrlForm].attempt.flatMap {
        case Right(form) =>
          println(s"🎫 DEBUG: Form parsing successful")
          println(s"🎫 DEBUG: Form data: ${form.values}")
          handleTokenRequest(form)
        case Left(error) =>
          println(s"💥 DEBUG: Form parsing failed: ${error.getMessage}")
          logger
            .error(s"💥 Failed to parse form data: ${error.getMessage}", error)
          BadRequest(
            OidcError(
              "invalid_request",
              Some("Failed to parse form data")
            ).asJson
          )
      }

  }

  private def handleTokenRequest(form: UrlForm): IO[Response[IO]] = {
    println(s"🎫 DEBUG: handleTokenRequest called")
    val formData = form.values.view.mapValues(_.headOption.getOrElse("")).toMap
    println(s"🎫 DEBUG: formData created: ${formData}")

    logger.info(s"🎫 Token request received")
    logger.info(s"📋 Form data keys: ${formData.keys.mkString(", ")}")

    val grantType = formData.get("grant_type")
    val code = formData.get("code")
    val redirectUri = formData.get("redirect_uri")
    val clientId = formData.get("client_id")
    val refreshToken = formData.get("refresh_token")

    println(s"🎫 DEBUG: Grant type extracted: ${grantType}")
    logger.info(s"🔑 Grant type: ${grantType.getOrElse("MISSING")}")
    logger.info(s"🎟️ Code: ${code.map(_ => "PROVIDED").getOrElse("MISSING")}")
    logger.info(s"📍 Redirect URI: ${redirectUri.getOrElse("MISSING")}")
    logger.info(s"🆔 Client ID: ${clientId.getOrElse("MISSING")}")

    println(s"🎫 DEBUG: About to match on parameters")
    grantType match {
      case Some("authorization_code") =>
        (code, redirectUri, clientId) match {
          case (Some(authCode), Some(redirectUriValue), Some(clientIdValue)) =>
            println(s"🎫 DEBUG: Matched authorization_code case")
            logger.info(
              s"✅ Processing authorization_code grant for client: $clientIdValue"
            )
            logger.trace(
              s"About to call processAuthorizationCodeGrant"
            )
            val result = processAuthorizationCodeGrant(
              authCode,
              redirectUriValue,
              clientIdValue
            )
            logger.trace(
              s"processAuthorizationCodeGrant call completed"
            )
            result
          case _ =>
            println(
              s"🎫 DEBUG: Missing required parameters for authorization_code"
            )
            logger.warn(
              s"❌ Missing required parameters for authorization_code - code: ${code.isDefined}, redirect_uri: ${redirectUri.isDefined}, client_id: ${clientId.isDefined}"
            )
            BadRequest(
              OidcError(
                "invalid_request",
                Some("Missing required parameters for authorization_code grant")
              ).asJson
            )
        }
      case Some("refresh_token") =>
        (refreshToken, clientId) match {
          case (Some(refreshTokenValue), Some(clientIdValue)) =>
            println(s"🎫 DEBUG: Matched refresh_token case")
            logger.info(
              s"✅ Processing refresh_token grant for client: $clientIdValue"
            )
            processRefreshTokenGrant(refreshTokenValue, clientIdValue)
          case _ =>
            println(s"🎫 DEBUG: Missing required parameters for refresh_token")
            logger.warn(
              s"❌ Missing required parameters for refresh_token - refresh_token: ${refreshToken.isDefined}, client_id: ${clientId.isDefined}"
            )
            BadRequest(
              OidcError(
                "invalid_request",
                Some("Missing required parameters for refresh_token grant")
              ).asJson
            )
        }
      case Some(unsupportedGrant) =>
        println(
          s"🎫 DEBUG: Matched unsupported grant type case: '$unsupportedGrant'"
        )
        logger.warn(s"❌ Unsupported grant type: '$unsupportedGrant'")
        BadRequest(
          OidcError(
            "unsupported_grant_type",
            Some(s"Grant type '$unsupportedGrant' is not supported")
          ).asJson
        )
      case None =>
        println(s"🎫 DEBUG: Missing grant_type parameter")
        logger.warn(s"❌ Missing grant_type parameter")
        BadRequest(
          OidcError(
            "invalid_request",
            Some("Missing grant_type parameter")
          ).asJson
        )
    }
  }

  private def processAuthorizationCodeGrant(
      code: String,
      redirectUri: String,
      clientId: String
  ): IO[Response[IO]] = {

    logger.info(s"🔍 Validating authorization code for client: $clientId")
    logger.info(
      s"🔍 DEBUG: Code: ${code.take(8)}..., RedirectUri: $redirectUri"
    )
    logger.trace(
      s"About to call validateAndConsumeCode with code: ${code.take(8)}..."
    )
    codeService.validateAndConsumeCode(code, clientId, redirectUri).flatMap {
      case Right(authCode) =>
        logger.trace(
          s"Authorization code validation SUCCESS for user: ${authCode.sub}"
        )
        logger.info(s"✅ Authorization code validated for user: ${authCode.sub}")
        logger.info(
          s"🔍 DEBUG: AuthCode details - scope: ${authCode.scope}, nonce: ${authCode.nonce}"
        )
        // Get user information
        logger.trace(
          s"About to call getUserById for sub: ${authCode.sub}"
        )
        authService.getUserById(authCode.sub).flatMap {
          case Some(user) =>
            logger.trace(s"User FOUND: ${user.username}")
            logger.info(s"✅ User found: ${user.username}, generating tokens...")
            logger.info(
              s"🎯 DEBUG: About to generate tokens with azp claim set to clientId: $clientId"
            )
            logger.trace(
              s"Entering for comprehension for token generation"
            )
            for {
              // Generate tokens
              _ <- IO.pure(
                logger.trace(s"About to generate ID token")
              )
              _ <- IO.pure(
                logger.info(
                  s"🎫 DEBUG: Calling generateIdToken with clientId (azp): $clientId"
                )
              )
              idToken <- jwtService
                .generateIdToken(user, clientId, authCode.nonce)
              _ <- IO.pure(
                logger.trace(s"ID token generated successfully")
              )
              _ <- IO.pure(
                logger.info(
                  s"🎫 DEBUG: Calling generateAccessToken with clientId (azp): $clientId"
                )
              )
              accessToken <- jwtService
                .generateAccessToken(user, clientId, authCode.scope)
              _ <- IO.pure(
                logger.trace(
                  s"Access token generated successfully"
                )
              )
              _ <- IO.pure(
                logger.info(s"✅ DEBUG: Both tokens generated successfully")
              )

              // Track successful authorization code grant
              _ <- statsService
                .incrementAuthorizationCodeSuccess(clientId, user.username)

              // Generate refresh token (stateless JWT)
              refreshTokenJwt <- jwtService
                .generateRefreshToken(user, clientId, authCode.scope)

              // Create token response
              tokenResponse = TokenResponse(
                access_token = accessToken,
                token_type = "Bearer",
                expires_in = config.tokenExpirationSeconds,
                id_token = idToken,
                scope = authCode.scope,
                refresh_token = Some(refreshTokenJwt)
              )

              _ <- IO.pure(
                logger.trace(
                  s"Token response created, about to send OK response"
                )
              )
              _ <- IO.pure(
                logger
                  .info(s"🚀 DEBUG: Token response created, sending response")
              )
              response <- Ok(tokenResponse.asJson)
                .map(
                  _.withHeaders(
                    Header.Raw(CIString("Cache-Control"), "no-store"),
                    Header.Raw(CIString("Pragma"), "no-cache")
                  )
                )
              _ <- IO.pure(
                logger.trace(s"OK response created successfully")
              )

            } yield response

          case None =>
            logger.trace(
              s"User NOT FOUND for sub: ${authCode.sub}"
            )
            logger.warn(s"❌ User not found for sub: ${authCode.sub}")
            BadRequest(
              OidcError("invalid_grant", Some("User not found")).asJson
            )
        }

      case Left(error) =>
        logger.trace(
          s"Authorization code validation FAILED: ${error.error} - ${error.error_description
              .getOrElse("No description")}"
        )
        logger.warn(
          s"❌ Authorization code validation failed: ${error.error} - ${error.error_description
              .getOrElse("No description")}"
        )
        logger.info(
          s"🔍 DEBUG: This is why you don't see azp logging - code validation failed!"
        )
        // Track failed authorization code grant
        statsService
          .incrementAuthorizationCodeFailure(error.error)
          .flatMap(_ => BadRequest(error.asJson))
    }
  }

  private def processRefreshTokenGrant(
      refreshToken: String,
      clientId: String
  ): IO[Response[IO]] = {
    logger.info(s"🔄 Processing refresh token grant for client: $clientId")

    // Validate the refresh token JWT (stateless validation)
    jwtService.validateRefreshToken(refreshToken).flatMap {
      case Right(tokenClaims) =>
        logger
          .info(s"✅ Refresh token JWT validated for user: ${tokenClaims.sub}")

        // Check if client_id matches
        if (tokenClaims.client_id != clientId) {
          logger.warn(s"❌ Client ID mismatch in refresh token")
          BadRequest(
            OidcError("invalid_grant", Some("Client ID mismatch")).asJson
          )
        } else {
          // Get user information
          authService.getUserById(tokenClaims.sub).flatMap {
            case Some(user) =>
              logger.info(s"✅ User found for refresh: ${user.username}")

              for {
                // Generate new access token
                newAccessToken <- jwtService
                  .generateAccessToken(user, clientId, tokenClaims.scope)

                // Generate new refresh token (token rotation)
                newRefreshTokenJwt <- jwtService
                  .generateRefreshToken(user, clientId, tokenClaims.scope)

                // Create token response (no ID token for refresh grant)
                tokenResponse = TokenResponse(
                  access_token = newAccessToken,
                  token_type = "Bearer",
                  expires_in = config.tokenExpirationSeconds,
                  id_token = "", // Not included in refresh token response
                  scope = tokenClaims.scope,
                  refresh_token = Some(newRefreshTokenJwt)
                )

                _ <- IO.pure(
                  logger.info(
                    s"🎉 Refresh token successfully used for user: ${user.username}, client: $clientId - New tokens issued"
                  )
                )

                // Track successful refresh token usage
                _ <- statsService
                  .incrementRefreshTokenSuccess(clientId, user.username)

                response <- Ok(tokenResponse.asJson)
                  .map(
                    _.withHeaders(
                      Header.Raw(CIString("Cache-Control"), "no-store"),
                      Header.Raw(CIString("Pragma"), "no-cache")
                    )
                  )

              } yield response

            case None =>
              logger.warn(
                s"❌ User not found for refresh token: ${tokenClaims.sub}"
              )
              statsService
                .incrementRefreshTokenFailure("User not found")
                .flatMap(_ =>
                  BadRequest(
                    OidcError("invalid_grant", Some("User not found")).asJson
                  )
                )
          }
        }

      case Left(error) =>
        logger.warn(s"❌ Refresh token validation failed: ${error.error}")
        statsService
          .incrementRefreshTokenFailure(error.error)
          .flatMap(_ => BadRequest(error.asJson))
    }
  }
}

object TokenEndpoint {
  def apply(
      authService: AuthService[IO],
      codeService: CodeService[IO],
      jwtService: JwtService[IO],
      config: OidcConfig,
      statsService: StatsService[IO]
  ): TokenEndpoint =
    new TokenEndpoint(
      authService,
      codeService,
      jwtService,
      config,
      statsService
    )
}
