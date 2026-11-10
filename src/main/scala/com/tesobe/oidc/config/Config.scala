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

/** Credential verification method options */
sealed trait VerifyCredentialsMethod
object VerifyCredentialsMethod {
  case object ViaOidcUsersView extends VerifyCredentialsMethod
  case object ViaApiEndpoint extends VerifyCredentialsMethod
}

/** Client verification method options */
sealed trait VerifyClientMethod
object VerifyClientMethod {
  case object ViaDatabase extends VerifyClientMethod
  case object ViaApiEndpoint extends VerifyClientMethod
}

/** Provider listing method options */
sealed trait ListProvidersMethod
object ListProvidersMethod {
  case object ViaOidcUsersView extends ListProvidersMethod
  case object ViaApiEndpoint extends ListProvidersMethod
}

case class OidcConfig(
    issuer: String,
    server: ServerConfig,
    database: DatabaseConfig,
    adminDatabase: DatabaseConfig,
    keyId: String = "oidc-key-1",
    signingKeyPath: Option[String] = None, // PEM file for the RSA signing key; None = ephemeral per-startup key
    tokenExpirationSeconds: Long = 3600, // 1 hour
    codeExpirationSeconds: Long = 600, // 10 minutes
    obpApiUrl: Option[String] = None,
    localDevelopmentMode: Boolean = false,
    logoUrl: Option[String] = Some(
      "https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png"
    ),
    logoAltText: String = "Open Bank Project",
    obpPortalBaseUrl: String = "http://localhost:5174",
    registrationUrl: Option[String] = Some("http://localhost:5174/register"), // None = hide the Register link
    skipClientBootstrap: Boolean = false,
    enableDynamicClientRegistration: Boolean = true,
    useVerifyEndpoints: Boolean = true,
    obpApiUsername: Option[String] = None,
    obpApiPassword: Option[String] = None,
    obpApiConsumerKey: Option[String] = None,
    obpApiRetryMaxAttempts: Int = 60,
    obpApiRetryDelaySeconds: Int = 30
) {

  /** Derived method settings from useVerifyEndpoints */
  def verifyCredentialsMethod: VerifyCredentialsMethod =
    if (useVerifyEndpoints) VerifyCredentialsMethod.ViaApiEndpoint
    else VerifyCredentialsMethod.ViaOidcUsersView

  def verifyClientMethod: VerifyClientMethod =
    if (useVerifyEndpoints) VerifyClientMethod.ViaApiEndpoint
    else VerifyClientMethod.ViaDatabase

  def listProvidersMethod: ListProvidersMethod =
    if (useVerifyEndpoints) ListProvidersMethod.ViaApiEndpoint
    else ListProvidersMethod.ViaOidcUsersView

  /** Whether any configured method requires a database connection */
  /** Only the deprecated SQL view mode reads OBP-API's database. In endpoint mode, everything (users, clients and
    * the clients created at startup) goes through OBP-API's endpoints. */
  def needsDatabase: Boolean = !useVerifyEndpoints

  /** Warnings about deprecated settings in this configuration, shown in the log at startup and on the status page. */
  /** The OBP-API settings that endpoint mode needs but are not set. Empty when nothing is missing. */
  def missingObpApiSettings: List[String] =
    List(
      "OBP_API_URL" -> obpApiUrl,
      "OBP_API_USERNAME" -> obpApiUsername,
      "OBP_API_PASSWORD" -> obpApiPassword,
      "OBP_API_CONSUMER_KEY" -> obpApiConsumerKey
    ).collect { case (name, None) => name }

  def deprecationWarnings: List[String] =
    if (useVerifyEndpoints) Nil
    else List(OidcConfig.SqlViewAccessDeprecated)
}

object OidcConfig {
  val SqlViewAccessDeprecated: String =
    "OBP-OIDC is reading users and clients directly from SQL views in OBP-API's database " +
      "(v_oidc_users, v_oidc_clients and v_oidc_admin_clients). This is deprecated and will be removed in a future version. " +
      "Set USE_VERIFY_ENDPOINTS=true so that OBP-OIDC uses OBP-API's endpoints instead. " +
      "The views must be updated by hand whenever OBP-API changes, and they differ between database vendors, " +
      "so every upgrade is a risk."
}

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

    val obpPortalBaseUrl = {
      val url = sys.env.getOrElse("OBP_PORTAL_BASE_URL", "http://localhost:5174")
      if (url.endsWith("/")) url.dropRight(1) else url
    }

    val defaultPort = "5432"

    val dbConfig = DatabaseConfig(
      host = sys.env.getOrElse("DB_HOST", "localhost"),
      port = sys.env.getOrElse("DB_PORT", defaultPort).toInt,
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
      port = sys.env.getOrElse("DB_PORT", defaultPort).toInt,
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
      signingKeyPath = sys.env.get("OIDC_SIGNING_KEY_FILE").filter(_.trim.nonEmpty),
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
      obpPortalBaseUrl = obpPortalBaseUrl,
      registrationUrl = sys.env.get("OIDC_REGISTRATION_URL") match {
        case Some(url) if url.trim.isEmpty => None // explicitly disabled
        case Some(url)                     => Some(url.trim)
        case None                          => Some(s"$obpPortalBaseUrl/register")
      },
      skipClientBootstrap =
        sys.env.getOrElse("OIDC_SKIP_CLIENT_BOOTSTRAP", "false").toBoolean,
      enableDynamicClientRegistration =
        sys.env.getOrElse("ENABLE_DYNAMIC_CLIENT_REGISTRATION", "true").toBoolean,
      useVerifyEndpoints =
        sys.env.getOrElse("USE_VERIFY_ENDPOINTS", "true").toBoolean,
      obpApiUsername = sys.env.get("OBP_API_USERNAME"),
      obpApiPassword = sys.env.get("OBP_API_PASSWORD"),
      obpApiConsumerKey = sys.env.get("OBP_API_CONSUMER_KEY"),
      obpApiRetryMaxAttempts = sys.env.getOrElse("OBP_API_RETRY_MAX_ATTEMPTS", "60").toInt,
      obpApiRetryDelaySeconds = sys.env.getOrElse("OBP_API_RETRY_DELAY_SECONDS", "30").toInt
    )
  }
}
