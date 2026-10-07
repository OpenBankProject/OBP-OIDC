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

package com.tesobe.oidc.bootstrap

import cats.effect.IO
import cats.implicits._
import com.tesobe.oidc.auth.{HybridAuthService, AdminDatabaseClient}
import com.tesobe.oidc.config.OidcConfig
import com.tesobe.oidc.models.OidcClient
import org.slf4j.LoggerFactory

import java.security.SecureRandom
import java.util.{Base64, UUID}
import scala.concurrent.duration._

/** Client Bootstrap Service
  *
  * Automatically creates (but never modifies) standard OBP ecosystem clients on
  * startup:
  *   - OBP-API: Core banking API service
  *   - Portal: OBP Portal web application
  *   - Explorer II: API exploration tool
  *   - Opey II: OBP mobile/web client
  */
class ClientBootstrap(authService: HybridAuthService, config: OidcConfig) {

  private val logger = LoggerFactory.getLogger(getClass)
  private val secureRandom = new SecureRandom()

  // Constants for client configuration
  private val DEFAULT_GRANT_TYPES =
    List("authorization_code", "refresh_token", "client_credentials")
  private val DEFAULT_RESPONSE_TYPES = List("code")
  private val DEFAULT_SCOPES = List("openid", "profile", "email")
  private val DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_basic"

  // Simple client definition
  case class ClientDefinition(
      name: String,
      redirect_uris: String
  )

  // List of clients to create
  private val CLIENT_DEFINITIONS = List(
    ClientDefinition(
      name = "obp-api-client",
      redirect_uris = "http://localhost:8080/auth/openid-connect/callback"
    ),
    ClientDefinition(
      name = "obp-portal-client",
      redirect_uris = "http://localhost:5174/login/obp/callback"
    ),
    ClientDefinition(
      name = "obp-explorer-ii-client",
      redirect_uris = "http://localhost:5173/api/oauth2/callback"
      //  "http://localhost:3001/callback,http://localhost:3001/oauth/callback,http://localhost:3001/callback,http://localhost:3001/oauth/callback,http://localhost:5173/api/oauth2/callback"
    ),
    ClientDefinition(
      name = "obp-opey-ii-client",
      redirect_uris =
        "http://localhost:5000/callback,http://localhost:5000/oauth/callback"
    ),
    ClientDefinition(
      name = "obp-api-manager-ii",
      redirect_uris = "http://localhost:3003/login/obp/callback"
    ),
    ClientDefinition(
      name = "obp-stripe",
      redirect_uris = "http://localhost:4242/callback"
    ),
    ClientDefinition(
      name = "other-app-1",
      redirect_uris = "http://localhost:5175/login/obp/callback"
    ),
    ClientDefinition(
      name = "other-app-2",
      redirect_uris = "http://localhost:5176/login/obp/callback"
    ),
    ClientDefinition(
      name = "other-app-3",
      redirect_uris = "http://localhost:5177/login/obp/callback"
    ),
    ClientDefinition(
      name = "other-app-4",
      redirect_uris = "http://localhost:5178/login/obp/callback"
    ),
    ClientDefinition(name = "agent-1", redirect_uris = "http://localhost:5179/login/obp/callback"),
    ClientDefinition(name = "agent-2", redirect_uris = "http://localhost:5180/login/obp/callback"),
    ClientDefinition(name = "agent-3", redirect_uris = "http://localhost:5181/login/obp/callback"),
    ClientDefinition(name = "agent-4", redirect_uris = "http://localhost:5182/login/obp/callback"),
    ClientDefinition(name = "obp-hola", redirect_uris = "http://localhost:48123/main.html"),
    ClientDefinition(name = "obp-load-tester", redirect_uris = ""),
    ClientDefinition(name = "obp-sentinel", redirect_uris = "")
  )

  /** Generate secure database passwords and print ready-to-use configuration
    */
  def generateDeveloperConfig(): IO[Unit] = {
    IO {
      val dbUserPassword = generateSecurePassword()
      val dbAdminPassword = generateSecurePassword()

      println()
      println("=" * 80)
      println("DEVELOPER HELPER: Database Configuration")
      println("=" * 80)
      println()
      println("Database Setup Commands (copy & paste to terminal):")
      println("-" * 50)
      println("# Create database and users")
      println("sudo -u postgres psql << EOF")
      println("CREATE DATABASE sandbox;")
      println(s"CREATE USER oidc_user WITH PASSWORD '$dbUserPassword';")
      println(s"CREATE USER oidc_admin WITH PASSWORD '$dbAdminPassword';")
      println("GRANT CONNECT ON DATABASE sandbox TO oidc_user;")
      println("GRANT CONNECT ON DATABASE sandbox TO oidc_admin;")
      println("\\q")
      println("EOF")
      println()

      println(
        "Environment Variables for OBP-OIDC (copy to your .env or export):"
      )
      println("-" * 50)
      println("export DB_HOST=localhost")
      println("export DB_PORT=5432")
      println("export DB_NAME=sandbox")
      println("export OIDC_USER_USERNAME=oidc_user")
      println(s"export OIDC_USER_PASSWORD=$dbUserPassword")
      println("export DB_MAX_CONNECTIONS=10")
      println("export OIDC_ADMIN_USERNAME=oidc_admin")
      println(s"export OIDC_ADMIN_PASSWORD=$dbAdminPassword")
      println("export DB_ADMIN_MAX_CONNECTIONS=5")
      println()

      println("=" * 80)
      println(
        "Database configuration ready! Set up your database first, then run OBP-OIDC."
      )
      println("=" * 80)
      println()
    }
  }

  /** Initialize all standard OBP clients
    *
    * BEHAVIOR: Create-only mode - never modifies existing clients
    *   - First run: Creates all standard OBP ecosystem clients
    *   - Subsequent runs: Only creates newly added clients, preserves existing
    *     ones
    *   - Existing clients: Skipped with read-only message, configurations
    *     preserved
    *   - New apps: Automatically created when added to the codebase
    *
    * This ensures persistent state and prevents accidental modification of
    * manually configured client settings in production environments.
    */
  def initializeClients(): IO[Unit] = {
    println("DEBUG: ClientBootstrap.initializeClients() called")
    logger.info("ClientBootstrap.initializeClients() called")
    // Check if client bootstrap is disabled
    val skipBootstrap =
      sys.env.get("OIDC_SKIP_CLIENT_BOOTSTRAP").exists(_.toLowerCase == "true")
    println(
      s"DEBUG: OIDC_SKIP_CLIENT_BOOTSTRAP = ${sys.env.get("OIDC_SKIP_CLIENT_BOOTSTRAP").getOrElse("not set")}"
    )
    logger.info(
      s"OIDC_SKIP_CLIENT_BOOTSTRAP = ${sys.env.get("OIDC_SKIP_CLIENT_BOOTSTRAP").getOrElse("not set")}"
    )

    if (skipBootstrap) {
      println(
        "DEBUG: Client bootstrap disabled via OIDC_SKIP_CLIENT_BOOTSTRAP environment variable"
      )
      logger.info(
        "Client bootstrap disabled via OIDC_SKIP_CLIENT_BOOTSTRAP environment variable"
      )
      IO.unit
    } else {
      println(
        "DEBUG: Bootstrap not disabled - proceeding with client initialization"
      )
      println("DEBUG: Initializing OBP ecosystem OIDC clients...")
      logger.info(
        "Bootstrap not disabled - proceeding with client initialization"
      )
      logger.info("Initializing OBP ecosystem OIDC clients...")
      logger.info("Step 1: Checking admin database availability...")

      // Check if admin database is available first
      println("DEBUG: About to check admin database availability...")
      checkAdminDatabaseAvailability().flatMap { adminAvailable =>
        println(s"DEBUG: Admin database available = $adminAvailable")
        if (adminAvailable) {
          println(
            "DEBUG: Admin database available - proceeding with client management"
          )
          logger.info(
            "Step 2: Admin database available - proceeding with client management"
          )
          logger.info(
            "Step 3: Creating missing OBP ecosystem clients (read-only for existing)..."
          )
          for {
            _ <- IO(
              println("DEBUG: Starting configurable client creation...")
            )
            _ <- createConfiguredClients()
          } yield {
            println(
              "DEBUG: All OBP ecosystem clients initialized successfully"
            )
            logger.info("All OBP ecosystem clients initialized successfully")
          }
        } else {
          println(
            "DEBUG: Admin database not available - skipping automatic client creation"
          )
          logger.warn(
            "Step 2: Admin database not available - skipping automatic client creation"
          )
          logger.info("Step 3: Generating manual SQL commands instead...")
          logManualClientCreationSQL()
        }
      }
    }
  }

  /** Create clients based on environment variable configuration
    */
  private def createConfiguredClients(): IO[Unit] = {
    val enabledClients = getEnabledClients()
    println(
      s"DEBUG: Creating ${enabledClients.size} enabled clients: ${enabledClients.map(_.client_name).mkString(", ")}"
    )

    for {
      _ <- enabledClients.foldLeft(IO.unit) { (acc, client) =>
        acc.flatMap(_ =>
          ensureClient(client).flatMap(_ =>
            IO(println(s"DEBUG: ${client.client_name} processing completed"))
          )
        )
      }
    } yield ()
  }

  /** Get list of clients to create from CLIENT_DEFINITIONS
    */
  private def getEnabledClients(): List[OidcClient] = {
    CLIENT_DEFINITIONS.map { clientDef =>
      createClient(clientDef)
    }
  }

  /** Create a client configuration from ClientDefinition
    */
  private def createClient(clientDef: ClientDefinition): OidcClient = {
    val clientSecret = generateSecureSecret()
    val redirectUris = clientDef.redirect_uris.split(",").toList

    // Generate distinct UUIDs for different purposes
    val consumerId = UUID.randomUUID().toString // Internal consumer tracking ID
    val clientId = UUID.randomUUID().toString // OAuth2/OIDC client identifier

    OidcClient(
      client_id = clientId,
      client_secret = Some(clientSecret),
      client_name = clientDef.name,
      consumer_id = consumerId,
      redirect_uris = redirectUris,
      grant_types = DEFAULT_GRANT_TYPES,
      response_types = DEFAULT_RESPONSE_TYPES,
      scopes = DEFAULT_SCOPES,
      token_endpoint_auth_method = DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD,
      created_at = None
    )
  }

  /** Check if admin database is available for client operations
    */
  private def checkAdminDatabaseAvailability(): IO[Boolean] = {
    println(
      "   DEBUG: Testing admin database with listClients() operation..."
    )
    logger.info("   Testing admin database with listClients() operation...")
    // Try a simple admin database operation with timeout
    IO.race(
      IO.sleep(5.seconds),
      authService.listClients()
    ).map {
      case Left(_) =>
        println("   DEBUG: Admin database check TIMED OUT after 5 seconds")
        logger.warn("   Admin database check timed out after 5 seconds")
        false
      case Right(result) =>
        result match {
          case Right(clients) =>
            println(
              s"   DEBUG: Admin database responds - found ${clients.length} existing clients"
            )
            logger.info(
              s"   Admin database responds - found ${clients.length} existing clients"
            )
            true
          case Left(error) =>
            println(
              s"   DEBUG: Admin database error: ${error.error} - ${error.error_description
                  .getOrElse("No description")}"
            )
            logger.warn(
              s"   Admin database error: ${error.error} - ${error.error_description.getOrElse("No description")}"
            )
            false
        }
    }.handleErrorWith { error =>
      println(
        s"   DEBUG: Admin database exception: ${error.getClass.getSimpleName}: ${error.getMessage}"
      )
      logger.warn(s"   Admin database exception: ${error.getMessage}")
      IO.pure(false)
    }
  }

  /** Ensure client exists, create if not found (never modify existing clients)
    */
  private def ensureClient(clientConfig: OidcClient): IO[Unit] = {
    // Add timeout to prevent hanging
    IO.race(
      IO.sleep(10.seconds),
      performClientOperation(clientConfig)
    ).flatMap {
      case Left(_) =>
        logger.error(
          s"Client operation timed out for ${clientConfig.client_name}"
        )
        IO.unit
      case Right(_) =>
        IO.unit
    }
  }

  private def performClientOperation(clientConfig: OidcClient): IO[Unit] = {
    println(
      s"   DEBUG: Checking if client exists by name: ${clientConfig.client_name}"
    )
    logger.info(
      s"   Checking if client exists by name: ${clientConfig.client_name}"
    )
    authService.findClientByName(clientConfig.client_name).flatMap {
      case Some(existingClient) =>
        println(
          s"   DEBUG: Client exists: ${existingClient.client_name} (${existingClient.client_id}) - SKIPPING (read-only mode)"
        )
        logger.info(
          s"   Client exists: ${existingClient.client_name} - preserving existing configuration"
        )
        logger.info(
          s"   READ-ONLY: Not modifying existing client ${existingClient.client_name}"
        )
        IO.unit
      case None =>
        println(
          s"   DEBUG: Client not found - creating new client: ${clientConfig.client_name} (${clientConfig.client_id})"
        )
        logger.info(
          s"   Client not found - creating new client: ${clientConfig.client_name} (${clientConfig.client_id})"
        )
        authService.createClient(clientConfig).flatMap {
          case Right(createdClient) =>
            println(
              s"   DEBUG: Successfully created client: ${clientConfig.client_name}"
            )
            logger.info(
              s"   Successfully created client: ${clientConfig.client_name}"
            )
            printNewClientCredentials(createdClient)
          case Left(error) =>
            println(
              s"   DEBUG: Failed to create client ${clientConfig.client_name}: ${error.error} - ${error.error_description
                  .getOrElse("No description")}"
            )
            logger.error(
              s"   Failed to create client ${clientConfig.client_name}: ${error.error} - ${error.error_description
                  .getOrElse("No description")}"
            )
            logger.error(
              s"   Hint: Check if admin user has write permissions to v_oidc_admin_clients"
            )
            IO.unit
        }
    }
  }

  /** Print credentials of a newly created client. In API mode OBP-API
    * generates the key and secret, and they cannot be retrieved later, so this
    * is the one chance to see them.
    */
  private def printNewClientCredentials(client: OidcClient): IO[Unit] = {
    IO {
      println()
      println("=" * 80)
      println(s"NEW CLIENT CREATED: ${client.client_name}")
      println("Save these credentials now - the secret will not be shown again.")
      println("-" * 80)
      println(s"CONSUMER_ID: ${client.consumer_id}")
      println(s"CLIENT_ID (KEY): ${client.client_id}")
      println(s"CLIENT_SECRET: ${client.client_secret.getOrElse("Not returned")}")
      println(s"REDIRECT_URIS: ${client.redirect_uris.mkString(",")}")
      println("=" * 80)
      println()
    }
  }

  /** Log manual client creation SQL when admin database is not available
    */
  private def logManualClientCreationSQL(): IO[Unit] = {
    val clients = CLIENT_DEFINITIONS.map(createClient)

    IO {
      logger.info("Manual Client Creation SQL:")
      logger.info("=" * 60)

      clients.foreach { client =>
        logger.info(s"""
INSERT INTO v_oidc_admin_clients (
  name, apptype, description, developeremail, sub,
  secret, azp, aud, iss, redirecturl, company, consumerid, isactive,
  createdat, updatedat
) VALUES (
  '${client.client_name}',
  'WEB',
  'OIDC client for ${client.client_name}',
  'admin@tesobe.com',
  '${client.client_id}',
  '${client.client_secret.getOrElse("GENERATE_SECURE_SECRET")}',
  '${client.client_id}',
  'obp-api',
  'obp-oidc',
  '${client.redirect_uris.mkString(",")}',
  'TESOBE',
  '${client.client_id}',
  true,
  NOW(),
  NOW()
);""")
      }

      logger.info("=" * 60)
      logger.info("Run these SQL commands manually to create OIDC clients")
    }
  }

  /** Generate a secure client secret
    */
  private def generateSecureSecret(): String = {
    val bytes = new Array[Byte](32) // 256 bits
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  }

  /** Generate a secure database password (more user-friendly than base64)
    */
  private def generateSecurePassword(): String = {
    val chars =
      "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*"
    val length = 24
    (1 to length).map(_ => chars(secureRandom.nextInt(chars.length))).mkString
  }

  /** Generate fresh secret if environment variable contains placeholder
    */
  private def generateFreshSecretIfPlaceholder(
      envSecret: Option[String]
  ): String = {
    envSecret match {
      case Some(secret) if secret.contains("CHANGE_THIS") =>
        val fresh = generateSecureSecret()
        println(
          s"Generated fresh secret (was placeholder): ${fresh.take(20)}..."
        )
        fresh
      case Some(secret) if secret.nonEmpty =>
        println(s"Using existing secret: ${secret.take(20)}...")
        secret
      case _ =>
        val fresh = generateSecureSecret()
        println(
          s"Generated fresh secret (none provided): ${fresh.take(20)}..."
        )
        fresh
    }
  }

}

object ClientBootstrap {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Create and run client bootstrap
    */
  def initialize(
      authService: HybridAuthService,
      config: OidcConfig
  ): IO[Unit] = {
    println("DEBUG: ClientBootstrap.initialize() called from server")
    logger.info("ClientBootstrap.initialize() called from server")
    new ClientBootstrap(authService, config).initializeClients()
  }

  /** Generate database configuration for developers
    */
  def generateDatabaseConfig(config: OidcConfig): IO[Unit] = {
    new ClientBootstrap(null, config).generateDeveloperConfig()
  }
}
