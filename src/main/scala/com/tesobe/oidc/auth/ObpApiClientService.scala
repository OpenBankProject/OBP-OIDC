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
import com.tesobe.oidc.models.{OidcClient, OidcError}
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

/** Request body for POST /obp/v6.0.0/oidc/clients/verify
  */
case class VerifyClientRequest(
    client_id: String,
    client_secret: String
)

object VerifyClientRequest {
  implicit val encoder: Encoder[VerifyClientRequest] = deriveEncoder
}

/** Response from POST /obp/v6.0.0/oidc/clients/verify
  */
case class VerifyClientResponse(
    valid: Boolean,
    client_id: Option[String],
    consumer_id: Option[String],
    redirect_uris: Option[List[String]]
)

object VerifyClientResponse {
  implicit val decoder: Decoder[VerifyClientResponse] = deriveDecoder
}

/** Response from GET /obp/v6.0.0/oidc/clients/CLIENT_ID
  */
case class GetClientResponse(
    client_id: String,
    client_name: String,
    consumer_id: String,
    redirect_uris: List[String],
    enabled: Boolean
)

object GetClientResponse {
  implicit val decoder: Decoder[GetClientResponse] = deriveDecoder
}

/** Single consumer from GET /obp/v6.0.0/management/consumers response
  */
case class ConsumerJson(
    consumer_id: String,
    app_name: String,
    consumer_key: String,
    redirect_url: String,
    enabled: Boolean,
    created: Option[String]
)

object ConsumerJson {
  implicit val decoder: Decoder[ConsumerJson] = deriveDecoder
}

/** Response from GET /obp/v6.0.0/management/consumers
  */
case class ConsumersResponse(
    consumers: List[ConsumerJson]
)

object ConsumersResponse {
  implicit val decoder: Decoder[ConsumersResponse] = deriveDecoder
}

/** Request body for POST /obp/v5.1.0/management/consumers
  */
case class CreateConsumerRequest(
    app_name: String,
    app_type: String,
    description: String,
    developer_email: String,
    redirect_url: String,
    enabled: Boolean,
    company: String
)

object CreateConsumerRequest {
  implicit val encoder: Encoder[CreateConsumerRequest] = deriveEncoder
}

/** Response from POST /obp/v5.1.0/management/consumers
  */
case class CreateConsumerResponse(
    consumer_id: String,
    consumer_key: String,
    consumer_secret: String,
    app_name: String,
    app_type: String,
    description: String,
    developer_email: String,
    redirect_url: String,
    enabled: Boolean,
    company: String
)

object CreateConsumerResponse {
  implicit val decoder: Decoder[CreateConsumerResponse] = deriveDecoder
}

/** Service for verifying OIDC clients via OBP API endpoint
  *
  * This service calls POST /obp/v6.0.0/oidc/clients/verify to verify
  * client credentials instead of accessing the consumer database directly.
  */
class ObpApiClientService(
    client: Client[IO],
    config: OidcConfig,
    tokenRef: Ref[IO, Option[CachedToken]]
) {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Obtain a DirectLogin token using username/password
    * Reuses the same approach as ObpApiCredentialsService
    */
  private[auth] def obtainDirectLoginToken(): IO[Either[OidcError, String]] = {
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
                      logger.info("Successfully obtained DirectLogin token for client verification")
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
                  ObpApiCredentialsService.checkObpApiRoot(client, baseUrl).flatMap {
                    case Right(200) =>
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
                ObpApiCredentialsService.checkObpApiRoot(client, baseUrl).flatMap {
                  case Right(200) =>
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
        logger.debug("Using cached DirectLogin token for client verification")
        IO.pure(Right(cached.token))
      case _ =>
        logger.info("Token expired or not present, obtaining new token")
        obtainDirectLoginToken()
    }
  }

  /** Verify client credentials by calling POST /obp/v6.0.0/oidc/clients/verify
    *
    * Requires:
    * - OBP_API_URL to be configured
    * - OBP_API_USERNAME (a user with CanGetOidcClient role)
    * - OBP_API_PASSWORD
    * - OBP_API_CONSUMER_KEY
    */
  def verifyClient(
      clientId: String,
      clientSecret: String
  ): IO[Either[OidcError, OidcClient]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured")
        IO.pure(
          Left(
            OidcError(
              "server_error",
              Some("OBP API URL not configured for client verification")
            )
          )
        )

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) => IO.pure(Left(error))
          case Right(token) =>
            val endpoint =
              s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/oidc/clients/verify"
            val maskedSecret = if (clientSecret.length <= 4) "****"
              else clientSecret.take(2) + "*" * (clientSecret.length - 4) + clientSecret.takeRight(2)
            logger.info(
              s"Verifying client via OBP API: $endpoint for client_id: $clientId"
            )
            logger.info(
              s"Client secret being sent: length=${clientSecret.length}, masked=$maskedSecret"
            )

            val requestBody = VerifyClientRequest(
              client_id = clientId,
              client_secret = clientSecret
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
                        json.as[VerifyClientResponse] match {
                          case Right(verifyResponse) if verifyResponse.valid =>
                            logger.info(
                              s"Client verified successfully via OBP API for client_id: $clientId"
                            )
                            val oidcClient = OidcClient(
                              client_id = verifyResponse.client_id.getOrElse(clientId),
                              client_secret = Some(clientSecret), // Don't expose, but keep for internal use
                              consumer_id = verifyResponse.consumer_id.getOrElse(""),
                              client_name = "", // Not returned by API
                              redirect_uris = verifyResponse.redirect_uris.getOrElse(List.empty),
                              grant_types = List("authorization_code", "refresh_token"),
                              response_types = List("code"),
                              scopes = List("openid", "profile", "email"),
                              token_endpoint_auth_method = "client_secret_basic",
                              created_at = None
                            )
                            IO.pure(Right(oidcClient))

                          case Right(verifyResponse) =>
                            // valid = false
                            logger.warn(
                              s"Client verification failed via OBP API for client_id: $clientId (valid=false)"
                            )
                            IO.pure(
                              Left(
                                OidcError(
                                  "invalid_client",
                                  Some("Invalid client credentials")
                                )
                              )
                            )

                          case Left(error) =>
                            logger.error(
                              s"Failed to parse OBP API response: ${error.getMessage}"
                            )
                            IO.pure(
                              Left(
                                OidcError(
                                  "server_error",
                                  Some("Invalid response from client verification endpoint")
                                )
                              )
                            )
                        }
                      }

                  case Status.Unauthorized =>
                    // Token might have expired, clear cache and report error
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
                          "invalid_client",
                          Some("Client verification unauthorized")
                        )))
                      }
                    }

                  case Status.Forbidden =>
                    response.as[String].flatMap { body =>
                      logger.error(s"OBP API returned 403 Forbidden for client verification: $body")
                      IO.pure(
                        Left(
                          OidcError(
                            "server_error",
                            Some(body)
                          )
                        )
                      )
                    }

                  case Status.NotFound =>
                    logger.warn(
                      s"Client not found via OBP API: $clientId"
                    )
                    IO.pure(
                      Left(
                        OidcError(
                          "invalid_client",
                          Some("Client not found")
                        )
                      )
                    )

                  case Status.BadRequest =>
                    response.as[Json].flatMap { json =>
                      val errorMsg = json.hcursor
                        .get[String]("message")
                        .getOrElse("Bad request")
                      logger.warn(
                        s"Client verification returned bad request: $errorMsg"
                      )
                      IO.pure(
                        Left(
                          OidcError(
                            "invalid_request",
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
                            Some(s"Client verification failed with status: ${status.code}")
                          )
                        )
                      )
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(
                  s"Error calling OBP API verify-client endpoint: ${error.getMessage}",
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

  /** Find client by client_id (without verifying secret)
    * Used for authorization endpoint to check redirect_uri
    * Calls GET /obp/v6.0.0/oidc/clients/CLIENT_ID
    */
  /** List all consumers via OBP API
    * Calls GET /obp/v6.0.0/management/consumers
    */
  def listClients(): IO[Either[OidcError, List[OidcClient]]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured")
        IO.pure(Left(OidcError("server_error", Some("OBP_API_URL is not configured"))))

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) =>
            IO.pure(Left(error))
          case Right(token) =>
            val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/management/consumers"
            logger.info(s"Listing consumers via OBP API: $endpoint")

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
                    response.as[String].flatMap { rawBody =>
                      logger.info(s"OBP API consumers response (raw): $rawBody")
                      io.circe.parser.parse(rawBody) match {
                        case Right(json) =>
                          json.as[ConsumersResponse] match {
                            case Right(consumersResp) =>
                              val clients = consumersResp.consumers.map { c =>
                                OidcClient(
                                  client_id = c.consumer_key,
                                  client_secret = None,
                                  consumer_id = c.consumer_id,
                                  client_name = c.app_name,
                                  redirect_uris = c.redirect_url.split("[,\\s]+").map(_.trim).filter(_.nonEmpty).toList,
                                  grant_types = List("authorization_code", "refresh_token"),
                                  response_types = List("code"),
                                  scopes = List("openid", "profile", "email"),
                                  token_endpoint_auth_method = "client_secret_basic",
                                  created_at = c.created
                                )
                              }
                              logger.info(s"Found ${clients.size} consumers via OBP API")
                              IO.pure(Right(clients))
                            case Left(error) =>
                              logger.error(s"Failed to parse consumers response: ${error.getMessage}. Raw body: $rawBody")
                              IO.pure(Left(OidcError("server_error", Some(s"Failed to parse OBP API response: $rawBody"))))
                          }
                        case Left(parseError) =>
                          logger.error(s"OBP API returned non-JSON response: $rawBody")
                          IO.pure(Left(OidcError("server_error", Some(s"OBP API returned non-JSON: $rawBody"))))
                      }
                    }

                  case _ =>
                    response.as[String].flatMap { body =>
                      logger.error(s"OBP API returned ${response.status} for consumer listing: $body")
                      IO.pure(Left(OidcError("server_error", Some(body))))
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(s"Error listing consumers via OBP API: ${error.getMessage}", error)
                IO.pure(Left(OidcError("server_error", Some(s"Failed to connect to OBP API: ${error.getMessage}"))))
              }
        }
    }
  }

  /** Create a consumer via OBP API
    * Calls POST /obp/v5.1.0/management/consumers
    * Requires CanCreateConsumer role on the DirectLogin user
    */
  def createConsumer(oidcClient: OidcClient): IO[Either[OidcError, OidcClient]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured")
        IO.pure(Left(OidcError("server_error", Some("OBP_API_URL is not configured"))))

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) => IO.pure(Left(error))
          case Right(token) =>
            val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v5.1.0/management/consumers"
            logger.info(s"Creating consumer via OBP API: $endpoint for app_name: ${oidcClient.client_name}")

            val requestBody = CreateConsumerRequest(
              app_name = oidcClient.client_name,
              app_type = "Confidential",
              description = s"OIDC client for ${oidcClient.client_name}",
              developer_email = "admin@tesobe.com",
              redirect_url = oidcClient.redirect_uris.mkString(","),
              enabled = true,
              company = "TESOBE"
            )

            val request = Request[IO](
              method = Method.POST,
              uri = Uri.unsafeFromString(endpoint)
            ).withEntity(requestBody.asJson)
              .putHeaders(
                Header.Raw(ci"DirectLogin", s"token=$token"),
                `Content-Type`(MediaType.application.json)
              )

            client.run(request)
              .use { response =>
                response.status match {
                  case Status.Created | Status.Ok =>
                    response.as[String].flatMap { rawBody =>
                      logger.info(s"OBP API create consumer response: $rawBody")
                      io.circe.parser.parse(rawBody) match {
                        case Right(json) =>
                          json.as[CreateConsumerResponse] match {
                            case Right(consumerResp) =>
                              logger.info(s"Successfully created consumer via OBP API: ${consumerResp.app_name} (consumer_id: ${consumerResp.consumer_id})")
                              val createdClient = OidcClient(
                                client_id = consumerResp.consumer_key,
                                client_secret = Some(consumerResp.consumer_secret),
                                consumer_id = consumerResp.consumer_id,
                                client_name = consumerResp.app_name,
                                redirect_uris = consumerResp.redirect_url.split("[,\\s]+").map(_.trim).filter(_.nonEmpty).toList,
                                grant_types = List("authorization_code", "refresh_token"),
                                response_types = List("code"),
                                scopes = List("openid", "profile", "email"),
                                token_endpoint_auth_method = "client_secret_basic",
                                created_at = None
                              )
                              IO.pure(Right(createdClient))
                            case Left(error) =>
                              logger.error(s"Failed to parse create consumer response: ${error.getMessage}. Raw body: $rawBody")
                              IO.pure(Left(OidcError("server_error", Some(s"Failed to parse OBP API response: $rawBody"))))
                          }
                        case Left(parseError) =>
                          logger.error(s"OBP API returned non-JSON response: $rawBody")
                          IO.pure(Left(OidcError("server_error", Some(s"OBP API returned non-JSON: $rawBody"))))
                      }
                    }

                  case Status.Unauthorized =>
                    response.as[String].flatMap { body =>
                      if (body.contains("token") || body.contains("Token")) {
                        tokenRef.set(None).map { _ =>
                          Left(OidcError("server_error", Some("OBP API token expired, please retry")))
                        }
                      } else {
                        logger.error(s"OBP API returned 401 for consumer creation: $body")
                        IO.pure(Left(OidcError("server_error", Some(body))))
                      }
                    }

                  case Status.Forbidden =>
                    response.as[String].flatMap { body =>
                      logger.error(s"OBP API returned 403 Forbidden for consumer creation: $body. Ensure the DirectLogin user has the CanCreateConsumer role.")
                      IO.pure(Left(OidcError("server_error", Some(body))))
                    }

                  case status =>
                    response.as[String].flatMap { body =>
                      logger.error(s"OBP API returned ${status} for consumer creation: $body")
                      IO.pure(Left(OidcError("server_error", Some(body))))
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(s"Error creating consumer via OBP API: ${error.getMessage}", error)
                IO.pure(Left(OidcError("server_error", Some(s"Failed to connect to OBP API: ${error.getMessage}"))))
              }
        }
    }
  }

  /** Find a consumer by app_name via OBP API
    * Uses listClients() and filters by app_name
    */
  def findConsumerByName(name: String): IO[Option[OidcClient]] = {
    listClients().map {
      case Right(clients) =>
        clients.find(_.client_name == name)
      case Left(error) =>
        logger.error(s"Failed to list clients when searching for '$name': ${error.error_description.getOrElse(error.error)}")
        None
    }
  }

  def findClient(clientId: String): IO[Option[OidcClient]] = {
    config.obpApiUrl match {
      case None =>
        logger.error("OBP_API_URL is not configured")
        IO.pure(None)

      case Some(baseUrl) =>
        getValidToken().flatMap {
          case Left(error) =>
            logger.error(s"Failed to get token for client lookup: ${error.error}")
            IO.pure(None)
          case Right(token) =>
            val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/oidc/clients/$clientId"
            logger.info(s"Looking up client via OBP API: $endpoint")

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
                    response.as[Json].flatMap { json =>
                      json.as[GetClientResponse] match {
                        case Right(clientResponse) =>
                          logger.info(s"Client found via OBP API: ${clientResponse.client_name}")
                          val oidcClient = OidcClient(
                            client_id = clientResponse.client_id,
                            client_secret = None, // Not returned by GET endpoint
                            consumer_id = clientResponse.consumer_id,
                            client_name = clientResponse.client_name,
                            redirect_uris = clientResponse.redirect_uris,
                            grant_types = List("authorization_code", "refresh_token"),
                            response_types = List("code"),
                            scopes = List("openid", "profile", "email"),
                            token_endpoint_auth_method = "client_secret_basic",
                            created_at = None
                          )
                          IO.pure(Some(oidcClient))
                        case Left(error) =>
                          logger.error(s"Failed to parse client response: ${error.getMessage}")
                          IO.pure(None)
                      }
                    }

                  case Status.NotFound =>
                    logger.warn(s"Client not found via OBP API: $clientId")
                    IO.pure(None)

                  case Status.Unauthorized =>
                    // Token might have expired
                    response.as[String].flatMap { body =>
                      if (body.contains("token") || body.contains("Token")) {
                        tokenRef.set(None).map { _ =>
                          logger.warn("Token expired during client lookup")
                          None
                        }
                      } else {
                        logger.warn(s"Unauthorized for client lookup: $clientId")
                        IO.pure(None)
                      }
                    }

                  case Status.Forbidden =>
                    response.as[String].flatMap { body =>
                      logger.error(s"OBP API returned 403 Forbidden for client lookup: $body")
                      IO.raiseError(new RuntimeException(body))
                    }

                  case status =>
                    response.as[String].flatMap { body =>
                      logger.error(s"Unexpected response from OBP API: status=$status, body=$body")
                      IO.pure(None)
                    }
                }
              }
              .handleErrorWith { error =>
                logger.error(s"Error looking up client via OBP API: ${error.getMessage}", error)
                IO.pure(None)
              }
        }
    }
  }
}

object ObpApiClientService {

  private val logger = LoggerFactory.getLogger(getClass)
  private val RequiredRole = "CanGetOidcClient"
  private val CreateConsumerRole = "CanCreateConsumer"

  /** Create an ObpApiClientService with http4s Ember client
    */
  def create(config: OidcConfig): Resource[IO, ObpApiClientService] = {
    for {
      client <- EmberClientBuilder.default[IO].build
      tokenRef <- Resource.eval(Ref.of[IO, Option[CachedToken]](None))
      _ <- Resource.eval(IO(logger.info("Created ObpApiClientService with Ember HTTP client")))
    } yield new ObpApiClientService(client, config, tokenRef)
  }

  /** Test the OBP API connection for client verification
    */
  def testConnection(config: OidcConfig): IO[Either[String, String]] = {
    val username = config.obpApiUsername.getOrElse("unknown")
    val baseUrl = config.obpApiUrl.getOrElse("unknown")

    EmberClientBuilder.default[IO].build.use { client =>
      for {
        tokenRefLocal <- Ref.of[IO, Option[CachedToken]](None)
        service = new ObpApiClientService(client, config, tokenRefLocal)
        tokenResult <- service.obtainDirectLoginToken()
        result <- tokenResult match {
          case Left(error) =>
            IO.pure(Left(s"OBP API connection failed for client verification: ${error.error_description.getOrElse(error.error)}"))
          case Right(token) =>
            // Check for CanGetOidcClient and CanCreateConsumer roles
            checkUserRoles(client, baseUrl, token).map {
              case Right(roleStatuses) =>
                Right(
                  s"OBP API client verification connection successful. " +
                    s"Connected to $baseUrl as $username. $roleStatuses"
                )
              case Left(roleError) =>
                Right(
                  s"OBP API client verification connection successful. " +
                    s"Connected to $baseUrl as $username. " +
                    s"WARNING: Could not verify roles: $roleError"
                )
            }
        }
      } yield result
    }
  }

  /** Check if the current user has the required roles (CanGetOidcClient, CanCreateConsumer)
    */
  private def checkUserRoles(
      client: Client[IO],
      baseUrl: String,
      token: String
  ): IO[Either[String, String]] = {
    val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v6.0.0/my/entitlements"
    logger.debug(s"Checking user entitlements at: $endpoint")

    val request = Request[IO](
      method = Method.GET,
      uri = Uri.unsafeFromString(endpoint)
    ).putHeaders(
      Header.Raw(ci"DirectLogin", s"token=$token")
    )

    val rolesToCheck = List(RequiredRole, CreateConsumerRole)

    client
      .run(request)
      .use { response =>
        response.status match {
          case Status.Ok =>
            response.as[Json].map { json =>
              val entitlements = json.hcursor.get[List[EntitlementInfo]]("list").getOrElse(List.empty)
              val statuses = rolesToCheck.map { role =>
                val hasRole = entitlements.exists(_.role_name == role) || json.toString.contains(role)
                if (hasRole) s"User has $role role"
                else s"WARNING: User does NOT have $role role"
              }
              Right(statuses.mkString(". "))
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
