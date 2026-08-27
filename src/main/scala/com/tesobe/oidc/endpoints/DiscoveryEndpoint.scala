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
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcConfiguration
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._

class DiscoveryEndpoint(config: OidcConfig) {

  /** The discovery document is served at every location a standards-following
    * client may look. For an issuer with a path component (https://host/obp-oidc):
    *
    *   - RFC 8414 inserts the well-known segment BETWEEN host and path:
    *       /.well-known/oauth-authorization-server/obp-oidc
    *       /.well-known/openid-configuration/obp-oidc
    *   - OIDC Discovery appends it AFTER the issuer path:
    *       /obp-oidc/.well-known/openid-configuration
    *   - Some OAuth clients also try the appended OAuth form:
    *       /obp-oidc/.well-known/oauth-authorization-server
    *
    * MCP clients (Claude Code SDK, OpenAI Codex) try the RFC 8414 forms first
    * and may fall back to guessed default endpoint paths if discovery fails,
    * so all four must resolve.
    */
  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    // OIDC Discovery: well-known appended to the issuer path
    case GET -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
      getConfiguration
    case HEAD -> Root / "obp-oidc" / ".well-known" / "openid-configuration" =>
      getConfigurationHead
    case GET -> Root / "obp-oidc" / ".well-known" / "oauth-authorization-server" =>
      getConfiguration
    case HEAD -> Root / "obp-oidc" / ".well-known" / "oauth-authorization-server" =>
      getConfigurationHead
    // RFC 8414: well-known inserted between host and issuer path
    case GET -> Root / ".well-known" / "oauth-authorization-server" / "obp-oidc" =>
      getConfiguration
    case HEAD -> Root / ".well-known" / "oauth-authorization-server" / "obp-oidc" =>
      getConfigurationHead
    case GET -> Root / ".well-known" / "openid-configuration" / "obp-oidc" =>
      getConfiguration
    case HEAD -> Root / ".well-known" / "openid-configuration" / "obp-oidc" =>
      getConfigurationHead
  }

  private def buildConfiguration: OidcConfiguration =
    OidcConfiguration(
      issuer = config.issuer,
      authorization_endpoint = s"${config.issuer}/auth",
      token_endpoint = s"${config.issuer}/token",
      userinfo_endpoint = s"${config.issuer}/userinfo",
      jwks_uri = s"${config.issuer}/jwks",
      revocation_endpoint = s"${config.issuer}/revoke",
      registration_endpoint = if (config.enableDynamicClientRegistration) Some(s"${config.issuer}/connect/register") else None,
      response_types_supported = List("code", "code id_token"),
      subject_types_supported = List("public"),
      id_token_signing_alg_values_supported = List("RS256"),
      scopes_supported = List("openid", "profile", "email"),
      token_endpoint_auth_methods_supported =
        List("client_secret_post", "client_secret_basic", "none"),
      claims_supported = List("sub", "name", "email", "email_verified", "consent_id"),
      grant_types_supported =
        List("authorization_code", "refresh_token", "client_credentials"),
      revocation_endpoint_auth_methods_supported =
        List("client_secret_post", "client_secret_basic")
    )

  private def getConfiguration: IO[Response[IO]] =
    Ok(buildConfiguration.asJson)

  private def getConfigurationHead: IO[Response[IO]] =
    // For HEAD requests, return OK with proper headers but no body
    Ok(buildConfiguration.asJson).map(_.withBodyStream(fs2.Stream.empty))
}

object DiscoveryEndpoint {
  def apply(config: OidcConfig): DiscoveryEndpoint = new DiscoveryEndpoint(
    config
  )
}
