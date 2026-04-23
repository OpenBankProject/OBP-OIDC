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

import cats.effect.{IO, Ref, Resource}
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.{User, OidcError}
import io.circe.{Decoder, Encoder, Json}
import io.circe.generic.semiauto.{deriveDecoder, deriveEncoder}
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers._
import org.http4s.MediaType
import org.typelevel.ci._
import org.slf4j.LoggerFactory

import java.time.Instant

/** Request body for POST /obp/v6.0.0/users/verify-credentials
  */
case class VerifyCredentialsRequest(
    username: String,
    password: String,
    provider: String
)

object VerifyCredentialsRequest {
  implicit val encoder: Encoder[VerifyCredentialsRequest] = deriveEncoder
}

/** Response from POST /obp/v6.0.0/users/verify-credentials on success
  * Based on typical OBP-API user response structure
  */
case class VerifyCredentialsResponse(
    user_id: String,
    username: String,
    provider: String,
    email: Option[String],
    first_name: Option[String],
    last_name: Option[String],
    is_validated: Option[Boolean]
)

object VerifyCredentialsResponse {
  implicit val decoder: Decoder[VerifyCredentialsResponse] = deriveDecoder
}

/** DirectLogin response containing the token
  */
case class DirectLoginResponse(
    token: String
)

object DirectLoginResponse {
  implicit val decoder: Decoder[DirectLoginResponse] = deriveDecoder
}

/** Cached token with expiration tracking
  */
case class CachedToken(
    token: String,
    obtainedAt: Instant,
    // Tokens typically expire after some time, we'll refresh before that
    // Default OBP token lifetime is often 1 hour, we refresh after 50 minutes
    expiresAfterMinutes: Int = 50
) {
  def isExpired: Boolean = {
    val now = Instant.now()
    val expiresAt = obtainedAt.plusSeconds(expiresAfterMinutes * 60)
    now.isAfter(expiresAt)
  }
}

/** Service for verifying user credentials via OBP API endpoint
  */
class ObpApiCredentialsService(
    client: Client[IO],
    config: OidcConfig,
    tokenRef: Ref[IO, Option[CachedToken]]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Obtain a DirectLogin token using username/password
    */
  private[oidc] def obtainDirectLoginToken(): IO[Either[OidcError, String]] = {
    (config.obpApiUrl, config.obpApiUsername, config.obpApiPassword, config.obpApiConsumerKey) match {
      case (Some(baseUrl), Some(username), Some(password), Some(consumerKey)) =>
        val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/my/logins/direct"
        logger.info(s"Obtaining DirectLogin token from: $endpoint")

        val request = Request[IO](
          method = Method.POST,
          uri = Uri.unsafeFromString(endpoint)
        ).putHeaders(
          Header.Raw(
            ci"DirectLogin",
            s"""username="$username",password="$password",consumer_key="$consumerKey""""
          ),
          `Content-Type`(MediaType.application.json)
        )

        client
          .run(request)
          .use { response =>
            response.status match {
              case Status.Ok | Status.Created =>
                response.as[Json].flatMap { json =>
                  json.hcursor.get[String]("token") match {
                    case Right(token) =>
                      logger.info("Successfully obtained DirectLogin token")
                      // Cache the token
                      tokenRef.set(Some(CachedToken(token, Instant.now()))).map { _ =>
                        Right(token)
                      }
                    case Left(_) =>
                      logger.error(s"DirectLogin response missing token field: $json")
                      IO.pure(Left(OidcError(
                        "server_error",
                        Some("Invalid DirectLogin response: missing token")
                      )))
                  }
                }

              case Status.Unauthorized | Status.Forbidden =>
                response.as[String].flatMap { body =>
                  logger.error(s"DirectLogin authentication failed: $body")
                  IO.pure(Left(OidcError(
                    "server_error",
                    Some("OBP API authentication failed - check OBP_API_USERNAME, OBP_API_PASSWORD, and OBP_API_CONSUMER_KEY")
                  )))
                }

              case Status.NotFound =>
                response.as[String].flatMap { body =>
                  logger.error(s"DirectLogin endpoint not found (404): $body")
                  // Check if OBP-API is running at all by hitting /root
                  checkObpApiRoot(baseUrl).flatMap {
                    case Right(rootOk) if rootOk =>
                      logger.error("OBP-API is running but DirectLogin endpoint not found. Check if DirectLogin is enabled in OBP-API props.")
                      IO.pure(Left(OidcError(
                        "server_error",
                        Some("OBP-API is running but DirectLogin endpoint not found. Check if DirectLogin is enabled in OBP-API props (allow_direct_login=true)")
                      )))
                    case _ =>
                      logger.error(s"OBP-API not reachable at $baseUrl. Check OBP_API_URL and ensure OBP-API is running.")
                      IO.pure(Left(OidcError(
                        "server_error",
                        Some(s"OBP-API not reachable at $baseUrl. Check OBP_API_URL and ensure OBP-API is running.")
                      )))
                  }
                }

              case status =>
                response.as[String].flatMap { body =>
                  logger.error(s"DirectLogin request failed with status $status: $body")
                  IO.pure(Left(OidcError(
                    "server_error",
                    Some(s"Failed to obtain DirectLogin token: ${status.code}")
                  )))
                }
            }
          }
          .handleErrorWith { error =>
            logger.error(s"Error obtaining DirectLogin token: ${error.getMessage}", error)
            // Check if OBP-API is running at all
            config.obpApiUrl match {
              case Some(baseUrl) =>
                checkObpApiRoot(baseUrl).flatMap {
                  case Right(rootOk) if rootOk =>
                    IO.pure(Left(OidcError(
                      "server_error",
                      Some(s"OBP-API is running but failed to connect to DirectLogin: ${error.getMessage}")
                    )))
                  case _ =>
                    IO.pure(Left(OidcError(
                      "server_error",
                      Some(s"OBP-API not reachable at $baseUrl: ${error.getMessage}")
                    )))
                }
              case None =>
                IO.pure(Left(OidcError(
                  "server_error",
                  Some(s"Failed to connect to OBP API: ${error.getMessage}")
                )))
            }
          }

      case _ =>
        val missing = List(
          if (config.obpApiUrl.isEmpty) Some("OBP_API_URL") else None,
          if (config.obpApiUsername.isEmpty) Some("OBP_API_USERNAME") else None,
          if (config.obpApiPassword.isEmpty) Some("OBP_API_PASSWORD") else None,
          if (config.obpApiConsumerKey.isEmpty) Some("OBP_API_CONSUMER_KEY") else None
        ).flatten.mkString(", ")

        logger.error(s"Missing configuration for DirectLogin: $missing")
        IO.pure(Left(OidcError(
          "server_error",
          Some(s"Missing OBP API configuration: $missing")
        )))
    }
  }

  /** Get a valid token, refreshing if necessary
    */
  private def getValidToken(): IO[Either[OidcError, String]] = {
    tokenRef.get.flatMap {
      case Some(cached) if !cached.isExpired =>
        logger.debug("Using cached DirectLogin token")
        IO.pure(Right(cached.token))
      case _ =>
        logger.info("Token expired or not present, obtaining new token")
        obtainDirectLoginToken()
    }
  }

  /** Check if OBP-API is running by hitting the /root endpoint
    */
  private def checkObpApiRoot(baseUrl: String): IO[Either[String, Boolean]] = {
    val rootEndpoint = s"${baseUrl.stripSuffix("/")}/obp/v4.0.0/root"
    logger.info(s"Checking if OBP-API is reachable at: $rootEndpoint")

    val request = Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString(rootEndpoint)
    )

    client
      .run(request)
      .use { response =>
        response.status match {
          case Status.Ok =>
            logger.info(s"OBP-API is running at $baseUrl")
            IO.pure(Right(true))
          case status =>
            logger.warn(s"OBP-API /root returned status $status")
            IO.pure(Right(false))
        }
      }
      .handleErrorWith { error =>
        logger.warn(s"Failed to reach OBP-API at $rootEndpoint: ${error.getMessage}")
        IO.pure(Left(error.getMessage))
      }
  }

  /** Verify user credentials by calling POST /obp/v6.0.0/users/verify-credentials
    *
    * Requires:
    * - OBP_API_URL to be configured
    * - OBP_API_USERNAME (a user with CanVerifyUserCredentials role)
    * - OBP_API_PASSWORD
    * - OBP_API_CONSUMER_KEY
    */
  def verifyCredentials(
      username: String,
      password: String,
      provider: String
  ): IO[Either[OidcError, User]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured")
        IO.pure(
          Left(
            OidcError(
              "server_error",
              Some("OBP API URL not configured for credential verification")
            )
          )
        )

      case Some(baseUrl) =>
        // First get a valid token
        getValidToken().flatMap {
          case Left(error) => IO.pure(Left(error))
          case Right(token) =>
            val endpoint =
              s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/users/verify-credentials"
            logger.info(
              s"Verifying credentials via OBP API: $endpoint for user: $username, provider: $provider"
            )

            val requestBody = VerifyCredentialsRequest(
              username = username,
              password = password,
              provider = provider
            )

            val request = Request[IO](
              method = Method.POST,
              uri = Uri.unsafeFromString(endpoint)
            ).withEntity(requestBody.asJson)
              .putHeaders(
                Header.Raw(
                  ci"DirectLogin",
                  s"token=$token"
                ),
                `Content-Type`(MediaType.application.json)
              )

            client
              .run(request)
              .use { response =>
                response.status match {
                  case Status.Ok =>
                    response
                      .as[Json]
                      .flatMap { json =>
                        json.as[VerifyCredentialsResponse] match {
                          case Right(verifyResponse) =>
                            logger.info(
                              s"Credentials verified successfully via OBP API for user: $username"
                            )
                            val user = User(
                              sub = verifyResponse.username,
                              username = verifyResponse.username,
                              password = "", // Never expose password
                              name = for {
                                first <- verifyResponse.first_name
                                last <- verifyResponse.last_name
                              } yield s"$first $last".trim,
                              email = verifyResponse.email,
                              email_verified = verifyResponse.is_validated,
                              provider = Some(verifyResponse.provider)
                            )
                            IO.pure(Right(user))

                          case Left(error) =>
                            logger.error(
                              s"Failed to parse OBP API response: ${error.getMessage}"
                            )
                            IO.pure(
                              Left(
                                OidcError(
                                  "server_error",
                                  Some(
                                    s"Invalid response from credential verification endpoint"
                                  )
                                )
                              )
                            )
                        }
                      }

                  case Status.Unauthorized =>
                    // Token might have expired, clear cache and report error
                    // The user's credentials are invalid
                    logger.warn(
                      s"Credential verification failed for user: $username - invalid credentials or expired token"
                    )
                    // Check if it's a token issue by looking at the response
                    response.as[String].flatMap { body =>
                      if (body.contains("token") || body.contains("Token")) {
                        // Token expired, clear cache for next attempt
                        tokenRef.set(None).map { _ =>
                          Left(OidcError(
                            "server_error",
                            Some("OBP API token expired, please retry")
                          ))
                        }
                      } else {
                        IO.pure(Left(OidcError(
                          "invalid_grant",
                          Some("Invalid username or password")
                        )))
                      }
                    }

                  case Status.Forbidden =>
                    logger.warn(
                      s"Credential verification forbidden for user: $username"
                    )
                    IO.pure(
                      Left(
                        OidcError(
                          "invalid_grant",
                          Some("Invalid username or password")
                        )
                      )
                    )

                  case Status.BadRequest =>
                    response.as[Json].flatMap { json =>
                      val errorMsg = json.hcursor
                        .get[String]("message")
                        .getOrElse("Bad request")
                      logger.warn(
                        s"Credential verification returned bad request: $errorMsg"
                      )
                      IO.pure(
                        Left(
                          OidcError(
                            "invalid_grant",
                            Some(errorMsg)
                          )
                        )
                      )
                    }

                  case status =>
                    response.as[String].flatMap { body =>
                      logger.error(
                        s"Unexpected response from OBP API: status=$status, body=$body"
                      )
                      IO.pure(
                        Left(
                          OidcError(
                            "server_error",
                            Some(
                              s"Credential verification failed with status: ${status.code}"
                            )
                          )
                        )
                      )
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(
                  s"Error calling OBP API verify-credentials endpoint: ${error.getMessage}",
                  error
                )
                IO.pure(
                  Left(
                    OidcError(
                      "server_error",
                      Some(s"Failed to connect to OBP API: ${error.getMessage}")
                    )
                  )
                )
              }
        }
    }
  }

  /** Get available authentication providers by calling GET /obp/v6.0.0/providers
    */
  def getProviders(): IO[List[String]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured for fetching providers")
        println("Cannot fetch providers: OBP_API_URL is not configured")
        IO.pure(List.empty)

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) =>
            logger.error(s"Failed to get token for providers endpoint: ${error.error}")
            println(s"Cannot fetch providers: failed to obtain DirectLogin token: ${error.error_description.getOrElse(error.error)}")
            IO.pure(List.empty)
          case Right(token) =>
            val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/providers"
            logger.info(s"Fetching providers from OBP API: $endpoint")

            val request = Request[IO](
              method = Method.GET,
              uri = Uri.unsafeFromString(endpoint)
            ).putHeaders(
              Header.Raw(ci"DirectLogin", s"token=$token")
            )

            client
              .run(request)
              .use { response =>
                response.status match {
                  case Status.Ok =>
                    response.as[Json].map { json =>
                      logger.info(s"OBP API providers response JSON: $json")
                      println(s"OBP API providers response JSON: $json")
                      json.hcursor.get[List[String]]("providers") match {
                        case Right(providers) =>
                          logger.info(s"Got ${providers.size} providers from OBP API: ${providers.mkString(", ")}")
                          println(s"Got ${providers.size} providers from OBP API: ${providers.mkString(", ")}")
                          providers
                        case Left(decodingFailure) =>
                          logger.warn(s"Unexpected providers response format (decode error: $decodingFailure): $json")
                          println(s"WARNING: Unexpected providers response format (decode error: $decodingFailure): $json")
                          List.empty
                      }
                    }
                  case status =>
                    response.as[String].flatMap { body =>
                      logger.error(s"Failed to fetch providers from OBP API ($status): $body")
                      println(s"OBP API GET /obp/v6.0.0/providers returned $status: $body")
                      println(s"   This error originates from the OBP-API server at ${config.obpApiUrl.getOrElse("unknown")}.")
                      println(s"   The login page will show no providers. Please check the OBP-API logs for more details.")
                      IO.pure(List.empty)
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(s"Error calling OBP API providers endpoint: ${error.getMessage}", error)
                println(s"Error calling OBP API GET /obp/v6.0.0/providers: ${error.getMessage}")
                IO.pure(List.empty)
              }
        }
    }
  }

  /** Get user by provider and username via OBP API.
    * Calls GET /obp/v6.0.0/users/provider/{PROVIDER}/username/{USERNAME}
    * Requires CanGetAnyUser role.
    */
  def getUserByProviderAndUsername(
      provider: String,
      username: String
  ): IO[Option[User]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured for user lookup")
        IO.pure(None)

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) =>
            logger.error(s"Failed to get token for user lookup: ${error.error}")
            IO.pure(None)
          case Right(token) =>
            // Use http4s URI `/` operator to properly percent-encode path segments
            // (provider can be a URL like "http://127.0.0.1:8080" which contains slashes)
            val uri = Uri.unsafeFromString(s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/users/provider") / provider / "username" / username
            logger.info(s"Looking up user via OBP API: $uri")

            val request = Request[IO](
              method = Method.GET,
              uri = uri
            ).putHeaders(
              Header.Raw(ci"DirectLogin", s"token=$token")
            )

            client
              .run(request)
              .use { response =>
                response.status match {
                  case Status.Ok =>
                    response.as[Json].flatMap { json =>
                      val cursor = json.hcursor
                      val user = for {
                        userId <- cursor.get[String]("user_id")
                        uname <- cursor.get[String]("username")
                        email = cursor.get[String]("email").toOption
                        prov <- cursor.get[String]("provider")
                      } yield User(
                        sub = uname,
                        username = uname,
                        password = "",
                        name = None,
                        email = email,
                        email_verified = Some(true),
                        provider = Some(prov)
                      )
                      user match {
                        case Right(u) =>
                          logger.info(s"User found via OBP API: ${u.username}")
                          IO.pure(Some(u))
                        case Left(err) =>
                          logger.error(s"Failed to parse user response: ${err.getMessage}")
                          IO.pure(None)
                      }
                    }
                  case status =>
                    response.as[String].flatMap { body =>
                      logger.warn(s"User lookup via OBP API: GET $uri returned $status: $body")
                      IO.pure(None)
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(
                  s"Error calling OBP API user lookup: ${error.getMessage}",
                  error
                )
                IO.pure(None)
              }
        }
    }
  }
}

/** Response structure for entitlements check */
case class EntitlementInfo(
    role_name: String,
    bank_id: String
)

object EntitlementInfo {
  implicit val decoder: Decoder[EntitlementInfo] = deriveDecoder
}

case class EntitlementsResponse(
    list: List[EntitlementInfo]
)

object EntitlementsResponse {
  implicit val decoder: Decoder[EntitlementsResponse] = deriveDecoder
}

object ObpApiCredentialsService {

  private val logger = LoggerFactory.getLogger(getClass)
  private val RequiredRole = "CanVerifyUserCredentials"

  /** Result of checking required roles, including per-role status. */
  case class RoleCheckResult(
      userRoles: Set[String],
      requiredRoles: List[String]
  ) {
    def roleStatus(role: String): Boolean = userRoles.contains(role)
    def missing: List[String] = requiredRoles.filterNot(userRoles.contains)
    def allPresent: Boolean = missing.isEmpty
  }

  /** Check that the OBP API user has all the specified required roles.
    * Returns Right with RoleCheckResult if entitlements could be fetched
    * (even if some roles are missing), or Left with error message if
    * the check itself failed.
    * Callers should inspect RoleCheckResult.allPresent to decide whether to abort.
    */
  def checkRequiredRoles(
      config: OidcConfig,
      requiredRoles: List[String]
  ): IO[Either[String, RoleCheckResult]] = {
    val username = config.obpApiUsername.getOrElse("unknown")
    val baseUrl = config.obpApiUrl.getOrElse("unknown")

    EmberClientBuilder.default[IO].build.use { httpClient =>
      for {
        tokenRefLocal <- Ref.of[IO, Option[CachedToken]](None)
        service = new ObpApiCredentialsService(httpClient, config, tokenRefLocal)
        tokenResult <- service.obtainDirectLoginToken()
        result <- tokenResult match {
          case Left(error) =>
            IO.pure(Left(
              s"Cannot check roles: OBP API connection failed: ${error.error_description.getOrElse(error.error)}"
            ))
          case Right(token) =>
            val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/my/entitlements"
            logger.info(s"Checking required roles at: $endpoint")

            val request = Request[IO](
              method = Method.GET,
              uri = Uri.unsafeFromString(endpoint)
            ).putHeaders(
              Header.Raw(ci"DirectLogin", s"token=$token")
            )

            httpClient
              .run(request)
              .use { response =>
                response.status match {
                  case Status.Ok =>
                    response.as[Json].map { json =>
                      val userRoles = json.hcursor.get[List[EntitlementInfo]]("list") match {
                        case Right(entitlements) => entitlements.map(_.role_name).toSet
                        case Left(_) => Set.empty[String]
                      }
                      Right(RoleCheckResult(userRoles, requiredRoles))
                    }
                  case status =>
                    response.as[String].map { body =>
                      Left(s"Failed to check entitlements (HTTP $status): $body")
                    }
                }
              }
              .handleErrorWith { error =>
                IO.pure(Left(s"Error checking entitlements: ${error.getMessage}"))
              }
        }
      } yield result
    }
  }

  /** Create an ObpApiCredentialsService with http4s Ember client
    */
  def create(config: OidcConfig): Resource[IO, ObpApiCredentialsService] = {
    for {
      client <- EmberClientBuilder.default[IO].build
      tokenRef <- Resource.eval(Ref.of[IO, Option[CachedToken]](None))
      _ <- Resource.eval(IO(logger.info("Created ObpApiCredentialsService with Ember HTTP client")))
    } yield new ObpApiCredentialsService(client, config, tokenRef)
  }

  /** Test the OBP API connection by attempting to obtain a DirectLogin token
    * and checking if the user has the CanVerifyUserCredentials role.
    */
  def testConnection(config: OidcConfig): IO[Either[String, String]] = {
    val username = config.obpApiUsername.getOrElse("unknown")
    val baseUrl = config.obpApiUrl.getOrElse("unknown")

    EmberClientBuilder.default[IO].build.use { client =>
      for {
        tokenRefLocal <- Ref.of[IO, Option[CachedToken]](None)
        service = new ObpApiCredentialsService(client, config, tokenRefLocal)
        tokenResult <- service.obtainDirectLoginToken()
        result <- tokenResult match {
          case Left(error) =>
            IO.pure(Left(s"OBP API connection failed: ${error.error_description.getOrElse(error.error)}"))
          case Right(token) =>
            // Check for CanVerifyUserCredentials role
            checkUserRole(client, baseUrl, token).map {
              case Right(hasRole) =>
                val roleStatus = if (hasRole) {
                  s"User has $RequiredRole role"
                } else {
                  s"WARNING: User does NOT have $RequiredRole role"
                }
                Right(
                  s"OBP API credential verification connection successful. " +
                    s"Connected to $baseUrl as $username. $roleStatus"
                )
              case Left(roleError) =>
                Right(
                  s"OBP API credential verification connection successful. " +
                    s"Connected to $baseUrl as $username. " +
                    s"WARNING: Could not verify $RequiredRole role: $roleError"
                )
            }
        }
      } yield result
    }
  }

  /** Check if the current user has the CanVerifyUserCredentials role
    */
  private def checkUserRole(
      client: Client[IO],
      baseUrl: String,
      token: String
  ): IO[Either[String, Boolean]] = {
    val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/my/entitlements"
    logger.debug(s"Checking user entitlements at: $endpoint")

    val request = Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString(endpoint)
    ).putHeaders(
      Header.Raw(ci"DirectLogin", s"token=$token")
    )

    client
      .run(request)
      .use { response =>
        response.status match {
          case Status.Ok =>
            response.as[Json].map { json =>
              // Try to parse as EntitlementsResponse, or look for role in list
              val hasRole = json.hcursor.get[List[EntitlementInfo]]("list") match {
                case Right(entitlements) =>
                  entitlements.exists(_.role_name == RequiredRole)
                case Left(_) =>
                  // Try alternative structure - just look for the role name in the JSON
                  json.toString.contains(RequiredRole)
              }
              Right(hasRole)
            }
          case status =>
            response.as[String].map { body =>
              logger.warn(s"Failed to check entitlements: $status - $body")
              Left(s"HTTP $status")
            }
        }
      }
      .handleErrorWith { error =>
        logger.warn(s"Error checking entitlements: ${error.getMessage}")
        IO.pure(Left(error.getMessage))
      }
  }
}
