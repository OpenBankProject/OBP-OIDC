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

package com.tesobe.oidc.config

import cats.effect.IO

case class ServerConfig(
    host: String,
    port: Int
)

case class DatabaseConfig(
    host: String,
    port: Int,
    database: String,
    username: String,
    password: String,
    maxConnections: Int = 10
)

case class OidcConfig(
    issuer: String,
    server: ServerConfig,
    database: DatabaseConfig,
    adminDatabase: DatabaseConfig,
    keyId: String = "oidc-key-1",
    tokenExpirationSeconds: Long = 3600, // 1 hour
    codeExpirationSeconds: Long = 600, // 10 minutes
    obpApiUrl: Option[String] = None,
    localDevelopmentMode: Boolean = false,
    logoUrl: Option[String] = Some(
      "https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png"
    ),
    logoAltText: String = "Open Bank Project",
    forgotPasswordUrl: Option[String] = None,
    enableDynamicClientRegistration: Boolean = false
)

object Config {

  def load: IO[OidcConfig] = IO {
    val host = sys.env.getOrElse("OIDC_HOST", "localhost")
    val port = sys.env.getOrElse("OIDC_PORT", "9000").toInt

    // Support external URLs for TLS terminating proxy
    val baseUrl = sys.env.get("OIDC_EXTERNAL_URL") match {
      case Some(externalUrl) =>
        // Remove trailing slash if present
        if (externalUrl.endsWith("/")) externalUrl.dropRight(1) else externalUrl
      case None =>
        // Fallback to internal URL construction
        val protocol = sys.env.getOrElse("OIDC_PROTOCOL", "http")
        s"$protocol://$host:$port"
    }
    val issuer = s"$baseUrl/obp-oidc"

    val dbConfig = DatabaseConfig(
      host = sys.env.getOrElse("DB_HOST", "localhost"),
      port = sys.env.getOrElse("DB_PORT", "5432").toInt,
      database = sys.env.getOrElse("DB_NAME", "sandbox"),
      username = sys.env.getOrElse("OIDC_USER_USERNAME", "oidc_user"),
      password = sys.env.getOrElse(
        "OIDC_USER_PASSWORD",
        "CHANGE_THIS_TO_A_VERY_STRONG_PASSWORD_2024!"
      ),
      maxConnections = sys.env.getOrElse("DB_MAX_CONNECTIONS", "10").toInt
    )

    val adminDbConfig = DatabaseConfig(
      host = sys.env
        .getOrElse("DB_HOST", "localhost"), // Same host as read-only database
      port = sys.env.getOrElse("DB_PORT", "5432").toInt,
      database =
        sys.env.getOrElse("DB_NAME", "sandbox"), // Same database as read-only
      username = sys.env.getOrElse("OIDC_ADMIN_USERNAME", "oidc_admin"),
      password = sys.env.getOrElse(
        "OIDC_ADMIN_PASSWORD",
        "CHANGE_THIS_TO_A_VERY_STRONG_ADMIN_PASSWORD_2024!"
      ),
      maxConnections = sys.env.getOrElse("DB_ADMIN_MAX_CONNECTIONS", "5").toInt
    )

    OidcConfig(
      issuer = issuer,
      server = ServerConfig(host, port),
      database = dbConfig,
      adminDatabase = adminDbConfig,
      keyId = sys.env.getOrElse("OIDC_KEY_ID", "oidc-key-1"),
      tokenExpirationSeconds =
        sys.env.getOrElse("OIDC_TOKEN_EXPIRATION", "3600").toLong,
      codeExpirationSeconds =
        sys.env.getOrElse("OIDC_CODE_EXPIRATION", "600").toLong,
      obpApiUrl = sys.env.get("OBP_API_URL"),
      localDevelopmentMode =
        sys.env.getOrElse("LOCAL_DEVELOPMENT_MODE", "false").toBoolean,
      logoUrl = sys.env
        .get("LOGO_URL")
        .flatMap(url => if (url.trim.isEmpty) None else Some(url))
        .orElse(
          Some(
            "https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png"
          )
        ),
      logoAltText = sys.env.getOrElse("LOGO_ALT_TEXT", "Open Bank Project"),
      forgotPasswordUrl = sys.env.get("FORGOT_PASSWORD_URL"),
      enableDynamicClientRegistration =
        sys.env.getOrElse("ENABLE_DYNAMIC_CLIENT_REGISTRATION", "false").toBoolean
    )
  }
}
