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

import cats.effect.{IO, Resource}
import cats.implicits._
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig}
import com.tesobe.oidc.models.{User, UserInfo, OidcError, OidcClient}
import doobie._
import doobie.hikari.HikariTransactor
import doobie.implicits._
import doobie.postgres.implicits._
import com.zaxxer.hikari.HikariConfig
import at.favre.lib.crypto.bcrypt.BCrypt
import org.slf4j.LoggerFactory
import com.tesobe.oidc.auth.DatabaseUserInstances._

import java.time.Instant
import java.util.UUID

/** Database-based authentication service using PostgreSQL view v_oidc_users
  *
  * This service connects to the OBP database and authenticates users against
  * the authuser table via the read-only view created by the OIDC setup script.
  *
  * Password verification uses BCrypt to match the OBP-API implementation.
  */
class DatabaseAuthService(
    transactor: Transactor[IO],
    adminTransactor: Option[Transactor[IO]] = None,
    config: OidcConfig
) extends AuthService[IO] {

  private val logger = LoggerFactory.getLogger(getClass)

  // Test logging immediately when class is created
  logger.info("🚀 DatabaseAuthService created - logging is working!")
  println("🚀 DatabaseAuthService created - logging is working!")

  /** Get available providers for dropdown
    */
  def getAvailableProviders(): IO[List[String]] = {
    logger.debug("🔍 Fetching available providers from database")

    val excludedProviders =
      List("google", "yahoo", "azure", "auth0", "keycloak", "hydra", "mitreid")

    val query = sql"""
      SELECT DISTINCT provider
      FROM v_oidc_users
      WHERE validated = true
      ORDER BY provider
    """.query[String]

    query
      .to[List]
      .transact(transactor)
      .map { providers =>
        logger.info(
          s"🔍 Filtering out excluded providers: ${excludedProviders.mkString(", ")}"
        )
        providers.filterNot { provider =>
          excludedProviders.exists(excluded =>
            provider.toLowerCase.contains(excluded.toLowerCase)
          )
        }
      }
      .handleErrorWith { error =>
        logger.error("🚨 Database error while fetching providers", error)
        println(
          s"🚨 Database error while fetching providers: ${error.getMessage}"
        )
        IO.pure(List.empty[String])
      }
  }

  /** Authenticate a user by username, password, and provider Returns the user
    * information if authentication succeeds
    */
  def authenticate(
      username: String,
      password: String,
      provider: String
  ): IO[Either[OidcError, User]] = {
    logger.info(
      s"🔐 Starting authentication for username: '$username' with provider: '$provider'"
    )
    println(
      s"🔐 Starting authentication for username: '$username' with provider: '$provider'"
    )
    logger.debug(
      s"🔐 Authentication request details - username length: ${username.length}, password length: ${password.length}, provider: '$provider'"
    )
    println(
      s"🔐 Authentication request details - username length: ${username.length}, password length: ${password.length}, provider: '$provider'"
    )

    findUserByUsernameAndProvider(username, provider).flatMap {
      case None =>
        logger.warn(
          s"❌ User NOT FOUND in database: '$username' with provider: '$provider'"
        )
        println(
          s"❌ User NOT FOUND in database: '$username' with provider: '$provider'"
        )

        // Additional debugging: try to find user without provider constraint
        val debugResult = for {
          userCount <- getUsernameCount(username)
          _ <- IO {
            logger.warn(
              s"🔍 DEBUG: Found $userCount user(s) with username '$username'"
            )
            println(
              s"🔍 DEBUG: Found $userCount user(s) with username '$username'"
            )
          }
          userWithoutProvider <- findUserDetailsByUsernameOnly(username)
          _ <- userWithoutProvider match {
            case Some(foundUser) =>
              IO {
                logger.warn(
                  s"🔍 DEBUG: User '$username' found in database with details:"
                )
                logger.warn(s"  - username: '${foundUser.username}'")
                logger.warn(
                  s"  - provider: '${foundUser.provider}' (requested: '$provider')"
                )
                logger.warn(s"  - validated: ${foundUser.validated}")
                logger.warn(s"  - user_id: '${foundUser.userId}'")
                logger.warn(s"  - email: '${foundUser.email}'")
                println(
                  s"🔍 DEBUG: User '$username' found in database with details:"
                )
                println(s"  - username: '${foundUser.username}'")
                println(
                  s"  - provider: '${foundUser.provider}' (requested: '$provider')"
                )
                println(s"  - validated: ${foundUser.validated}")
                println(s"  - user_id: '${foundUser.userId}'")
                println(s"  - email: '${foundUser.email}'")
              }
            case None =>
              IO {
                logger.warn(
                  s"🔍 DEBUG: User '$username' does not exist in database at all"
                )
                println(
                  s"🔍 DEBUG: User '$username' does not exist in database at all"
                )
              }
          }
          _ <-
            if (userCount > 1) {
              getAllUserDetailsByUsername(username).flatMap { allUsers =>
                IO {
                  logger.warn(
                    s"🔍 DEBUG: All $userCount users with username '$username':"
                  )
                  println(
                    s"🔍 DEBUG: All $userCount users with username '$username':"
                  )
                  allUsers.zipWithIndex.foreach { case (user, index) =>
                    logger.warn(
                      s"  [${index + 1}] provider: '${user.provider}', validated: ${user.validated}, user_id: '${user.userId}', email: '${user.email}'"
                    )
                    println(
                      s"  [${index + 1}] provider: '${user.provider}', validated: ${user.validated}, user_id: '${user.userId}', email: '${user.email}'"
                    )
                  }
                }
              }
            } else {
              IO.unit
            }
        } yield Left(
          OidcError("invalid_grant", Some("Invalid username or password"))
        )

        debugResult
      case Some(dbUser) =>
        logger.info(
          s"✅ User FOUND in database: '$username' (userId: ${dbUser.userId})"
        )
        println(
          s"✅ User FOUND in database: '$username' (userId: ${dbUser.userId})"
        )
        logger.debug(
          s"🔍 Password hash length: ${dbUser.passwordHash.length}, Salt length: ${dbUser.passwordSalt.length}"
        )
        println(
          s"🔍 Password hash length: ${dbUser.passwordHash.length}, Salt length: ${dbUser.passwordSalt.length}"
        )

        verifyPassword(password, dbUser.passwordHash, dbUser.passwordSalt)
          .flatMap { isValid =>
            if (isValid) {
              logger.info(
                s"✅ Password verification SUCCESSFUL for user: '$username'"
              )
              println(
                s"✅ Password verification SUCCESSFUL for user: '$username'"
              )
              IO.pure(Right(dbUser.toUser))
            } else {
              logger.warn(
                s"❌ Password verification FAILED for user: '$username'"
              )
              println(s"❌ Password verification FAILED for user: '$username'")
              IO.pure(
                Left(
                  OidcError(
                    "invalid_grant",
                    Some("Invalid username or password")
                  )
                )
              )
            }
          }
    }
  }

  /** Get user by ID (for UserInfo endpoint) - required by AuthService interface
    */
  def getUserById(sub: String): IO[Option[User]] = {
    findUserByUserId(sub).map(_.map(_.toUser))
  }

  /** Get user information by username (for UserInfo endpoint)
    */
  def getUserInfo(username: String): IO[Option[UserInfo]] = {
    findUserByUsername(username).map(_.map(_.toUserInfo))
  }

  /** Find user by user_id from the database view
    */
  private def findUserByUserId(userId: String): IO[Option[DatabaseUser]] = {
    val query = sql"""
      SELECT user_id, username, firstname, lastname, email,
             validated, provider, password_pw, password_slt,
             createdat, updatedat
      FROM v_oidc_users
      WHERE username = $userId AND validated = true
    """.query[DatabaseUser]

    query.option.transact(transactor).handleErrorWith { error =>
      logger
        .error(s"Database error while finding user by username $userId", error)
      IO.pure(None)
    }
  }

  /** Find user by username from the database view
    */
  private def findUserByUsername(username: String): IO[Option[DatabaseUser]] = {
    logger.debug(
      s"🔍 Searching for user by username only: '$username', validated=true"
    )

    val query = sql"""
      SELECT user_id, username, firstname, lastname, email,
             validated, provider, password_pw, password_slt,
             createdat, updatedat
      FROM v_oidc_users
      WHERE username = $username AND validated = true
    """.query[DatabaseUser]

    query.option.transact(transactor).handleErrorWith { error =>
      logger.error(s"🚨 Database error while finding user $username", error)
      println(
        s"🚨 Database error while finding user $username: ${error.getMessage}"
      )
      IO.pure(None)
    }
  }

  /** Find user by username and provider from the database view
    */
  private def findUserByUsernameAndProvider(
      username: String,
      provider: String
  ): IO[Option[DatabaseUser]] = {
    logger.debug(
      s"🔍 Searching for user: username='$username', provider='$provider', validated=true"
    )
    println(
      s"🔍 Searching for user: username='$username', provider='$provider', validated=true"
    )

    val query = sql"""
      SELECT user_id, username, firstname, lastname, email,
             validated, provider, password_pw, password_slt,
             createdat, updatedat
      FROM v_oidc_users
      WHERE username = $username AND provider = $provider AND validated = true
    """.query[DatabaseUser]

    logger.debug(
      s"🔍 SQL Query: SELECT user_id, username, firstname, lastname, email, validated, provider, password_pw, password_slt, createdat, updatedat FROM v_oidc_users WHERE username = '$username' AND provider = '$provider' AND validated = true"
    )
    println(
      s"🔍 SQL Query: SELECT ... FROM v_oidc_users WHERE username = '$username' AND provider = '$provider' AND validated = true"
    )

    query.option
      .transact(transactor)
      .flatTap { result =>
        IO {
          result match {
            case Some(user) =>
              logger.debug(
                s"🎯 Query returned user: ${user.username} with provider: ${user.provider}"
              )
              println(
                s"🎯 Query returned user: ${user.username} with provider: ${user.provider}"
              )
            case None =>
              logger.debug(
                s"🎯 Query returned no results for username='$username', provider='$provider'"
              )
              println(
                s"🎯 Query returned no results for username='$username', provider='$provider'"
              )
          }
        }
      }
      .handleErrorWith { error =>
        logger.error(
          s"🚨 Database error while finding user by username $username and provider $provider",
          error
        )
        println(
          s"🚨 Database error while finding user by username $username and provider $provider: ${error.getMessage}"
        )
        IO.pure(None)
      }
  }

  /** Find user by username only for debugging purposes - returns detailed user
    * info
    */
  private def findUserDetailsByUsernameOnly(
      username: String
  ): IO[Option[DatabaseUser]] = {
    logger.debug(
      s"🔍 EXTRA DEBUG: Searching for user by username only: '$username' (ignoring provider and validation)"
    )
    println(
      s"🔍 EXTRA DEBUG: Searching for user by username only: '$username' (ignoring provider and validation)"
    )

    val query = sql"""
      SELECT user_id, username, firstname, lastname, email,
             validated, provider, password_pw, password_slt,
             createdat, updatedat
      FROM v_oidc_users
      WHERE username = $username
      LIMIT 1
    """.query[DatabaseUser]

    query.option.transact(transactor).handleErrorWith { error =>
      logger.error(
        s"🚨 Database error while finding user details for $username",
        error
      )
      println(
        s"🚨 Database error while finding user details for $username: ${error.getMessage}"
      )
      IO.pure(None)
    }
  }

  /** Get count of users with a specific username
    */
  private def getUsernameCount(username: String): IO[Int] = {
    logger.debug(s"🔍 Counting users with username: '$username'")

    val query = sql"""
      SELECT COUNT(*) FROM v_oidc_users WHERE username = $username
    """.query[Int]

    query.unique.transact(transactor).handleErrorWith { error =>
      logger
        .error(s"🚨 Database error while counting username $username", error)
      println(
        s"🚨 Database error while counting username $username: ${error.getMessage}"
      )
      IO.pure(0)
    }
  }

  /** Get all user details for a specific username (all providers)
    */
  private def getAllUserDetailsByUsername(
      username: String
  ): IO[List[DatabaseUser]] = {
    logger.debug(s"🔍 Getting all users with username: '$username'")

    val query = sql"""
      SELECT user_id, username, firstname, lastname, email,
             validated, provider, password_pw, password_slt,
             createdat, updatedat
      FROM v_oidc_users
      WHERE username = $username
      ORDER BY provider, validated DESC
    """.query[DatabaseUser]

    query.to[List].transact(transactor).handleErrorWith { error =>
      logger.error(
        s"🚨 Database error while getting all users for username $username",
        error
      )
      println(
        s"🚨 Database error while getting all users for username $username: ${error.getMessage}"
      )
      IO.pure(List.empty)
    }
  }

  /** Debug method to show sample users in database for troubleshooting
    */
  private def showSampleUsersForDebugging(): IO[Unit] = {
    logger.debug("🔍 DEBUG: Fetching sample users for troubleshooting...")
    println("🔍 DEBUG: Fetching sample users for troubleshooting...")

    val query = sql"""
      SELECT username, provider, validated, user_id
      FROM v_oidc_users
      ORDER BY username
      LIMIT 10
    """.query[(String, String, Boolean, String)]

    query
      .to[List]
      .transact(transactor)
      .flatMap { users =>
        if (users.nonEmpty) {
          logger.warn("🔍 DEBUG: Sample users in database:")
          println("🔍 DEBUG: Sample users in database:")
          users.foreach { case (username, provider, validated, userId) =>
            logger.warn(
              s"  - username: '$username', provider: '$provider', validated: $validated, userId: '$userId'"
            )
            println(
              s"  - username: '$username', provider: '$provider', validated: $validated, userId: '$userId'"
            )
          }

          // Also show total count
          val countQuery =
            sql"SELECT COUNT(*) FROM v_oidc_users WHERE validated = true"
              .query[Int]
          countQuery.unique.transact(transactor).map { count =>
            logger.warn(s"🔍 DEBUG: Total validated users in database: $count")
            println(s"🔍 DEBUG: Total validated users in database: $count")
          }
        } else {
          logger.warn("🔍 DEBUG: No users found in v_oidc_users table")
          println("🔍 DEBUG: No users found in v_oidc_users table")
          IO.unit
        }
      }
      .handleError { error =>
        logger.error("🚨 DEBUG: Could not fetch sample users", error)
        println(s"🚨 DEBUG: Could not fetch sample users: ${error.getMessage}")
      }
  }

  /** Find OIDC client by client_id (which maps to key_c in database)
    */
  def findClientByClientIdThatIsKey(
      clientId: String
  ): IO[Option[OidcClient]] = {
    println(
      s"🔍 DEBUG: findClientByClientIdThatIsKey() called for clientId: $clientId"
    )
    println(s"   Looking in v_oidc_clients view with column 'client_id'")
    val query = sql"""
      SELECT client_id, client_secret, client_name, consumer_id, redirect_uris,
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients
      WHERE client_id = $clientId
    """.query[DatabaseClient]

    query.option
      .transact(transactor)
      .map { result =>
        println(s"   📊 DEBUG: Query result: ${if (result.isDefined) "FOUND"
          else "NOT FOUND"}")
        result.map { client =>
          println(
            s"   ✅ DEBUG: Found client: ${client.client_name} with id: ${client.client_id}"
          )
          client.toOidcClient
        }
      }
      .handleErrorWith { error =>
        println(
          s"   ❌ DEBUG: Query error: ${error.getClass.getSimpleName}: ${error.getMessage}"
        )
        IO.pure(None)
      }
  }

  /** Find raw DatabaseClient by client_id (for configuration printing)
    */
  def findDatabaseClientById(clientId: String): IO[Option[DatabaseClient]] = {
    val query = sql"""
      SELECT client_id, client_secret, client_name, consumer_id, redirect_uris,
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients
      WHERE client_id = $clientId
    """.query[DatabaseClient]

    query.option.transact(transactor)
  }

  /** Validate client and redirect URI
    */
  def validateClient(clientId: String, redirectUri: String): IO[Boolean] = {
    findClientByClientIdThatIsKey(clientId).flatMap {
      case Some(client) =>
        val isValid = client.redirect_uris.contains(redirectUri)
        IO(
          logger.info(
            s"🔍 Validating redirect_uri for client: $clientId"
          )
        ) *>
          IO(
            logger.info(
              s"   📥 Requested redirect_uri: $redirectUri"
            )
          ) *>
          IO(
            logger.info(
              s"   📋 Allowed redirect_uris (${client.redirect_uris.size}): [${client.redirect_uris.mkString(", ")}]"
            )
          ) *>
          IO(
            println(
              s"🔍 Validating redirect_uri for client: $clientId"
            )
          ) *>
          IO(
            println(
              s"   📥 Requested redirect_uri: $redirectUri"
            )
          ) *>
          IO(
            println(
              s"   📋 Allowed redirect_uris (${client.redirect_uris.size}): [${client.redirect_uris.mkString(", ")}]"
            )
          ) *>
          IO(
            if (isValid) {
              logger.info(
                s"   ✅ Redirect URI validation PASSED: requested URI found in allowed list"
              )
              println(
                s"   ✅ Redirect URI validation PASSED: requested URI found in allowed list"
              )
            } else {
              logger.warn(
                s"   ❌ Redirect URI validation FAILED: requested URI NOT found in allowed list"
              )
              println(
                s"   ❌ Redirect URI validation FAILED: requested URI NOT found in allowed list"
              )
            }
          ) *>
          IO.pure(isValid)
      case None =>
        IO(
          logger.warn(
            s"❌ Client validation FAILED: client not found with clientId: $clientId"
          )
        ) *>
          IO(
            println(
              s"❌ Client validation FAILED: client not found with clientId: $clientId"
            )
          ) *>
          IO.pure(false)
    }
  }

  /** Authenticate a client by client_id and client_secret
    */
  def authenticateClient(
      clientId: String,
      clientSecret: String
  ): IO[Either[OidcError, OidcClient]] = {
    findClientByClientIdThatIsKey(clientId).map {
      case Some(client) =>
        client.client_secret match {
          case Some(secret) if secret == clientSecret =>
            Right(client)
          case Some(_) =>
            Left(
              OidcError("invalid_client", Some("Invalid client credentials"))
            )
          case None =>
            Left(
              OidcError(
                "invalid_client",
                Some("Client has no secret configured")
              )
            )
        }
      case None =>
        Left(OidcError("invalid_client", Some("Client not found")))
    }
  }

  /** Find OIDC client by client_name to prevent duplicates
    */
  def findClientByName(clientName: String): IO[Option[OidcClient]] = {
    println(s"🔍 DEBUG: findClientByName() called for clientName: $clientName")
    println(s"   Looking in v_oidc_clients view with column 'client_name'")
    val query = sql"""
      SELECT client_id, client_secret, client_name, consumer_id, redirect_uris,
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients
      WHERE client_name = $clientName
      LIMIT 1
    """.query[DatabaseClient]

    query.option
      .transact(transactor)
      .map { result =>
        println(s"   📊 DEBUG: Query result: ${if (result.isDefined) "FOUND"
          else "NOT FOUND"}")
        result.map { client =>
          println(
            s"   ✅ DEBUG: Found client: ${client.client_name} with id: ${client.client_id}"
          )
          client.toOidcClient
        }
      }
      .handleErrorWith { error =>
        println(
          s"   ❌ DEBUG: Query error: ${error.getClass.getSimpleName}: ${error.getMessage}"
        )
        IO.pure(None)
      }
  }

  /** Find all clients with duplicate names for cleanup purposes
    */
  def findDuplicateClientNames(): IO[List[String]] = {
    println("🔍 DEBUG: findDuplicateClientNames() called")
    val query = sql"""
      SELECT client_name, COUNT(*) as count
      FROM v_oidc_clients
      GROUP BY client_name
      HAVING COUNT(*) > 1
    """.query[(String, Int)]

    query
      .to[List]
      .transact(transactor)
      .map { duplicates =>
        println(
          s"   📊 DEBUG: Found ${duplicates.length} client names with duplicates"
        )
        duplicates.foreach { case (name, count) =>
          println(s"   ⚠️ WARNING: Client '$name' has $count duplicate entries")
          logger.warn(s"Client '$name' has $count duplicate entries")
        }
        duplicates.map(_._1)
      }
      .handleErrorWith { error =>
        println(
          s"   ❌ DEBUG: Query error: ${error.getClass.getSimpleName}: ${error.getMessage}"
        )
        IO.pure(List.empty[String])
      }
  }

  /** Get all clients with a specific name for cleanup purposes
    */
  def findAllClientsByName(clientName: String): IO[List[OidcClient]] = {
    println(
      s"🔍 DEBUG: findAllClientsByName() called for clientName: $clientName"
    )
    val query = sql"""
      SELECT client_id, client_secret, client_name, consumer_id, redirect_uris,
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients
      WHERE client_name = $clientName
      ORDER BY created_at ASC
    """.query[DatabaseClient]

    query
      .to[List]
      .transact(transactor)
      .map { clients =>
        println(
          s"   📊 DEBUG: Found ${clients.length} clients with name: $clientName"
        )
        clients.foreach { client =>
          println(
            s"     - ID: ${client.client_id}, Created: ${client.created_at.getOrElse("Unknown")}"
          )
        }
        clients.map(_.toOidcClient)
      }
      .handleErrorWith { error =>
        println(
          s"   ❌ DEBUG: Query error: ${error.getClass.getSimpleName}: ${error.getMessage}"
        )
        IO.pure(List.empty[OidcClient])
      }
  }

  // Admin client management methods using the admin transactor

  /** Create a new OIDC client using INSERT-only approach
    *
    * If a client with the same consumerid already exists, this will fail.
    * Clients are immutable after creation - no updates allowed.
    *
    * Requires write access to v_oidc_admin_clients view.
    */
  def createClient(client: OidcClient): IO[Either[OidcError, OidcClient]] = {
    logger.info(
      s"🔍 createClient() called for: ${client.client_name} (${client.client_id})"
    )
    adminTransactor match {
      case Some(adminTx) =>
        logger.info(
          s"✅ Admin transactor available, preparing INSERT for: ${client.client_id}"
        )
        val adminClient = AdminDatabaseClient.fromOidcClient(client, config)
        logger.info(s"🔧 Mapped OIDC client to database format:")
        logger.info(s"   name: ${adminClient.name}")
        logger.info(s"   consumerid: ${adminClient.consumerid}")
        logger.info(
          s"   secret: ${adminClient.secret.map(_.take(10)).getOrElse("None")}..."
        )
        logger.info(s"   redirecturl: ${adminClient.redirecturl}")

        val insertQuery = sql"""
          INSERT INTO v_oidc_admin_clients (
            name, apptype, description, developeremail, sub,
            secret, azp, aud, iss, redirecturl, company, key_c, consumerid, isactive,
            createdat, updatedat
          ) VALUES (
            ${adminClient.name}, ${adminClient.apptype}, ${adminClient.description},
            ${adminClient.developeremail}, ${adminClient.sub},
            ${adminClient.secret}, ${adminClient.azp}, ${adminClient.aud},
            ${adminClient.iss}, ${adminClient.redirecturl}, ${adminClient.company},
            ${adminClient.key_c}, ${adminClient.consumerid}, ${adminClient.isactive},
            ${adminClient.createdat}, ${adminClient.updatedat}
          )
        """.update

        logger.info(
          s"🔄 Executing INSERT query for client: ${client.client_id}"
        )
        insertQuery.run
          .transact(adminTx)
          .map { rowsAffected =>
            logger.info(
              s"📊 INSERT result: $rowsAffected rows affected for client: ${client.client_id}"
            )
            if (rowsAffected > 0) {
              logger.info(
                s"✅ Successfully created OIDC client: ${client.client_id}"
              )
              Right(client)
            } else {
              logger.error(
                s"❌ INSERT returned 0 rows affected for client: ${client.client_id}"
              )
              Left(
                OidcError(
                  "server_error",
                  Some("Failed to create client - no rows inserted")
                )
              )
            }
          }
          .handleErrorWith { error =>
            logger.error(
              s"❌ Database error creating client ${client.client_id}: ${error.getMessage}",
              error
            )
            logger.error(s"💡 Error type: ${error.getClass.getSimpleName}")
            IO.pure(
              Left(
                OidcError(
                  "server_error",
                  Some(
                    s"Database error: ${error.getMessage}. Client may already exist or database constraint violation."
                  )
                )
              )
            )
          }
      case None =>
        logger.error(
          s"❌ Admin database connection not available for client: ${client.client_id}"
        )
        IO.pure(
          Left(
            OidcError(
              "server_error",
              Some("Admin database connection not available")
            )
          )
        )
    }
  }

  /** Create client with INSERT-only approach (upsert pattern) If client exists,
    * this will fail - clients should be immutable after creation
    */

  /** Delete an OIDC client using the admin database connection
    */
  def deleteClient(clientId: String): IO[Either[OidcError, String]] = {
    adminTransactor match {
      case Some(adminTx) =>
        val deleteQuery =
          sql"DELETE FROM v_oidc_admin_clients WHERE consumerid = $clientId".update

        deleteQuery.run
          .transact(adminTx)
          .map { rowsAffected =>
            if (rowsAffected > 0) {
              logger.info(s"Successfully deleted OIDC client: $clientId")
              Right(s"Client $clientId deleted successfully")
            } else {
              Left(
                OidcError(
                  "invalid_client",
                  Some(s"Client not found: $clientId")
                )
              )
            }
          }
          .handleErrorWith { error =>
            logger.error(s"Failed to delete client $clientId", error)
            IO.pure(
              Left(
                OidcError(
                  "server_error",
                  Some(s"Database error: ${error.getMessage}")
                )
              )
            )
          }
      case None =>
        IO.pure(
          Left(
            OidcError(
              "server_error",
              Some("Admin database connection not available")
            )
          )
        )
    }
  }

  /** List all clients using the admin database connection
    */
  def listClients(): IO[Either[OidcError, List[OidcClient]]] = {
    println("🔍 DEBUG: listClients() called")
    logger.info("🔍 listClients() called")

    // Use the regular transactor and v_oidc_clients view to get proper client_id and consumer_id mapping
    val query = sql"""
      SELECT client_id, client_secret, client_name, consumer_id, redirect_uris,
             grant_types, response_types, scopes, token_endpoint_auth_method, created_at
      FROM v_oidc_clients
      ORDER BY client_name ASC
    """.query[DatabaseClient]

    println("🔄 DEBUG: Executing SELECT query on v_oidc_clients")
    logger.info("🔄 Executing SELECT query on v_oidc_clients")
    query
      .to[List]
      .transact(transactor)
      .map { clients =>
        println(
          s"📊 DEBUG: SELECT result: Found ${clients.length} clients in v_oidc_clients"
        )
        logger.info(
          s"📊 DEBUG: SELECT result: Found ${clients.length} clients in v_oidc_clients"
        )
        clients.foreach(client =>
          logger.info(
            s"   - ${client.client_name} (client_id: ${client.client_id}, consumer_id: ${client.consumer_id})"
          )
        )
        Right(clients.map(_.toOidcClient))
      }
      .handleErrorWith { error =>
        println(
          s"❌ DEBUG: Database error listing clients: ${error.getClass.getSimpleName}: ${error.getMessage}"
        )
        logger.error(
          s"❌ Database error listing clients: ${error.getMessage}",
          error
        )
        logger.error(s"💡 Error type: ${error.getClass.getSimpleName}")
        IO.pure(
          Left(
            OidcError(
              "server_error",
              Some(s"Database error: ${error.getMessage}")
            )
          )
        )
      }
  }

  /** Find client by ID from admin view for configuration printing (searches by
    * key_c)
    */
  def findAdminClientByClientIdThatIsKey(
      clientId: String
  ): IO[Option[OidcClient]] = {
    println(
      s"🔍 DEBUG: findAdminClientByClientIdThatIsKey() called for clientId: $clientId"
    )
    println(
      s"   Looking in v_oidc_admin_clients view with column 'key_c' (client_id)"
    )
    adminTransactor match {
      case Some(adminTx) =>
        val query = sql"""
          SELECT name, apptype, description, developeremail, sub,
                 createdat, updatedat, secret, azp, aud, iss, redirecturl,
                 logourl, userauthenticationurl, clientcertificate, company, key_c, consumerid, isactive
          FROM v_oidc_admin_clients
          WHERE key_c = $clientId
        """.query[AdminDatabaseClient]

        query.option
          .transact(adminTx)
          .map { result =>
            println(s"   📊 DEBUG: Query result: ${if (result.isDefined) "FOUND"
              else "NOT FOUND"}")
            result.map { client =>
              println(
                s"   ✅ DEBUG: Found client: ${client.name.getOrElse("No Name")} with key_c (client_id): ${client.key_c
                    .getOrElse("No Key")}"
              )
              println(
                s"   🔑 DEBUG: Database secret: ${client.secret.map(_.take(20)).getOrElse("None")}..."
              )
              val oidcClient = client.toOidcClient
              println(
                s"   🔑 DEBUG: Converted secret: ${oidcClient.client_secret.map(_.take(20)).getOrElse("None")}..."
              )
              oidcClient
            }
          }
          .handleErrorWith { error =>
            println(
              s"   ❌ DEBUG: Query error: ${error.getClass.getSimpleName}: ${error.getMessage}"
            )
            IO.pure(None)
          }
      case None =>
        println("   ❌ DEBUG: Admin transactor not available")
        IO.pure(None)
    }
  }

  /** Verify password using BCrypt - compatible with OBP-API Lift MegaProtoUser
    * implementation Based on OBP-API pattern: BCrypt.hashpw(password,
    * salt).substring(0, 44)
    */
  private def verifyPassword(
      plainPassword: String,
      storedHash: String,
      salt: String
  ): IO[Boolean] = {
    IO {
      try {
        logger.info(s"🔐 Starting password verification...")
        println(s"🔐 Starting password verification...")
        logger.debug(s"📝 Stored hash: '$storedHash'")
        println(s"📝 Stored hash: '$storedHash'")
        logger.debug(s"🧂 Salt: '$salt'")
        println(s"🧂 Salt: '$salt'")
        logger.debug(s"🔑 Plain password length: ${plainPassword.length}")
        println(s"🔑 Plain password length: ${plainPassword.length}")

        // Log hex representation for debugging
        logger.debug(
          s"📝 Stored hash (hex): ${storedHash.getBytes("UTF-8").map("%02x".format(_)).mkString}"
        )
        logger.debug(
          s"🧂 Salt (hex): ${salt.getBytes("UTF-8").map("%02x".format(_)).mkString}"
        )
        println(
          s"📝 Stored hash (hex): ${storedHash.getBytes("UTF-8").map("%02x".format(_)).mkString}"
        )
        println(
          s"🧂 Salt (hex): ${salt.getBytes("UTF-8").map("%02x".format(_)).mkString}"
        )

        val result = if (storedHash.startsWith("b;")) {
          // Lift MegaProtoUser BCrypt format: "b;" + BCrypt.hashpw(password, salt).substring(0, 44)
          val hashWithoutPrefix = storedHash.substring(2) // Remove "b;" prefix
          println(s"🔍 Detected Lift MegaProtoUser BCrypt format")
          println(s"🔍 Hash without prefix: '$hashWithoutPrefix'")

          try {
            // Use the BCrypt.hashpw approach that OBP-API uses
            // Import the jBCrypt library that OBP-API uses (org.mindrot.jbcrypt.BCrypt)
            import org.mindrot.jbcrypt.{BCrypt => JBCrypt}

            println(s"🔧 About to call JBCrypt.hashpw with:")
            println(
              s"   - password: [REDACTED] (length: ${plainPassword.length})"
            )
            println(s"   - salt: '$salt' (length: ${salt.length})")

            // Generate hash using the same method as OBP-API: BCrypt.hashpw(password, salt).substring(0, 44)
            val fullGeneratedHash = JBCrypt.hashpw(plainPassword, salt)
            println(
              s"🔨 Full generated hash: '$fullGeneratedHash' (length: ${fullGeneratedHash.length})"
            )

            val generatedHash = fullGeneratedHash.substring(0, 44)
            println(
              s"🔨 Truncated hash: '$generatedHash' (length: ${generatedHash.length})"
            )
            println(
              s"🔍 Expected hash:  '$hashWithoutPrefix' (length: ${hashWithoutPrefix.length})"
            )

            val isMatch = generatedHash == hashWithoutPrefix
            println(s"🧪 Hash comparison result: $isMatch")

            // Log character-by-character comparison for debugging
            if (!isMatch) {
              println(s"🔍 Character comparison:")
              val minLength =
                math.min(generatedHash.length, hashWithoutPrefix.length)
              var firstDifference = -1
              for (i <- 0 until minLength if firstDifference == -1) {
                val genChar = generatedHash.charAt(i)
                val expChar = hashWithoutPrefix.charAt(i)
                val match_char = if (genChar == expChar) "✓" else "✗"
                println(s"   [$i]: '$genChar' vs '$expChar' $match_char")
                if (genChar != expChar) {
                  println(s"   First difference at position $i")
                  firstDifference = i
                }
              }
              if (generatedHash.length != hashWithoutPrefix.length) {
                println(
                  s"   Length difference: ${generatedHash.length} vs ${hashWithoutPrefix.length}"
                )
              }
            }

            isMatch
          } catch {
            case e: Exception =>
              println(s"🧪 JBCrypt verification failed: ${e.getMessage}")

              // Fallback to the at.favre.lib BCrypt library
              try {
                // Try direct verification with reconstructed hash
                val reconstructedHash = hashWithoutPrefix + salt
                println(
                  s"🔨 Fallback: trying reconstructed hash '$reconstructedHash'"
                )

                val fallbackResult = BCrypt
                  .verifyer()
                  .verify(
                    plainPassword.toCharArray,
                    reconstructedHash.toCharArray
                  )
                  .verified
                println(s"🧪 Fallback verification result: $fallbackResult")
                fallbackResult
              } catch {
                case e2: Exception =>
                  println(s"🧪 Fallback also failed: ${e2.getMessage}")
                  false
              }
          }
        } else {
          // Standard BCrypt hash format
          println(s"🔍 Standard BCrypt format detected")
          try {
            BCrypt
              .verifyer()
              .verify(plainPassword.toCharArray, storedHash.toCharArray)
              .verified
          } catch {
            case e: Exception =>
              println(
                s"🧪 Standard BCrypt verification failed: ${e.getMessage}"
              )
              false
          }
        }

        if (result) {
          println(s"✅ Password verification SUCCESSFUL")
          logger.info(s"✅ Password verification SUCCESSFUL")
        } else {
          println(s"❌ Password verification FAILED")
          logger.warn(s"❌ Password verification FAILED")
        }

        result
      } catch {
        case e: Exception =>
          println(s"💥 Error during password verification: ${e.getMessage}")
          logger.error(
            s"💥 Error during password verification: ${e.getMessage}",
            e
          )
          e.printStackTrace()
          false
      }
    }
  }
}

/** Database user representation matching the v_oidc_users view structure
  */
case class DatabaseUser(
    userId: String, // user_id column
    username: String,
    firstname: String,
    lastname: String,
    email: String,
    validated: Boolean,
    provider: String,
    passwordHash: String, // password_pw column
    passwordSalt: String, // password_slt column
    createdAt: Option[Instant],
    updatedAt: Option[Instant]
) {

  def toUser: User = User(
    sub =
      username, // Use username as subject identifier for OBP-API compatibility
    username = username,
    password = "", // Never expose password, even if hashed
    name = Some(s"$firstname $lastname".trim),
    email = Some(email),
    email_verified = Some(validated),
    provider = Some(provider) // This will be used as the JWT issuer
  )

  def toUserInfo: UserInfo = UserInfo(
    sub =
      username, // Use username as subject identifier for OBP-API compatibility
    name = Some(s"$firstname $lastname".trim),
    given_name = Some(firstname),
    family_name = Some(lastname),
    email = Some(email),
    email_verified = Some(validated)
  )
}

/** Database client representation matching the v_oidc_clients view structure
  */
case class DatabaseClient(
    client_id: String,
    client_secret: Option[String],
    client_name: String,
    consumer_id: String,
    redirect_uris: Option[String], // Simple string from database
    grant_types: Option[String], // Simple string from database
    response_types: Option[String], // Simple string from database
    scopes: Option[String], // Simple string from database
    token_endpoint_auth_method: Option[String],
    created_at: Option[String]
) {
  def toOidcClient: OidcClient = OidcClient(
    client_id = client_id,
    client_secret = client_secret,
    consumer_id = consumer_id,
    client_name = client_name,
    redirect_uris = parseSimpleString(redirect_uris.orNull),
    grant_types = parseSimpleString(grant_types.orNull),
    response_types = parseSimpleString(response_types.orNull),
    scopes = parseSimpleString(scopes.orNull),
    token_endpoint_auth_method = token_endpoint_auth_method.getOrElse(""),
    created_at = created_at
  )

  private def parseSimpleString(str: String): List[String] = {
    if (str == null || str.trim.isEmpty) {
      List.empty
    } else {
      // Handle simple strings - split by comma or space, or treat as single value
      str.split("[,\\s]+").map(_.trim).filter(_.nonEmpty).toList
    }
  }
}

/** Admin database client representation matching the new v_oidc_admin_clients
  * schema
  */
case class AdminDatabaseClient(
    name: Option[String], // client_name
    apptype: Option[String], // application type
    description: Option[String], // description
    developeremail: Option[String], // developer email
    sub: Option[String], // subject (not used for client_id)
    consumerid: Option[String], // auto-generated ID
    createdat: Option[Instant], // created timestamp
    updatedat: Option[Instant], // updated timestamp
    secret: Option[String], // client_secret
    azp: Option[String], // authorized party
    aud: Option[String], // audience
    iss: Option[String], // issuer
    redirecturl: Option[String], // redirect_uris
    logourl: Option[String], // logo URL
    userauthenticationurl: Option[String], // user auth URL
    clientcertificate: Option[String], // client certificate
    company: Option[String], // company name
    key_c: Option[
      String
    ], // OAuth1/OAuth2 client identifier (maps to client_id in views)
    isactive: Option[Boolean] // is active
) {
  def toOidcClient: OidcClient = OidcClient(
    client_id = key_c.getOrElse(""), // Use key_c as the OAuth2 identifier
    client_secret = secret,
    client_name = name.getOrElse(""),
    consumer_id =
      consumerid.getOrElse(""), // Use consumerid as internal tracking
    redirect_uris = parseSimpleString(redirecturl.getOrElse("")),
    grant_types = List(
      "authorization_code",
      "refresh_token",
      "client_credentials"
    ), // Default values
    response_types = List("code"),
    scopes = List("openid", "profile", "email"),
    token_endpoint_auth_method = "client_secret_basic",
    created_at = createdat.map(_.toString)
  )

  private def parseSimpleString(str: String): List[String] = {
    if (str == null || str.trim.isEmpty) {
      List.empty
    } else {
      str.split("[,\\s]+").map(_.trim).filter(_.nonEmpty).toList
    }
  }
}

object AdminDatabaseClient {
  def fromOidcClient(
      client: OidcClient,
      config: OidcConfig
  ): AdminDatabaseClient = AdminDatabaseClient(
    name = Some(client.client_name),
    apptype = Some("WEB"), // Default app type
    description = Some(s"OIDC client for ${client.client_name}"),
    developeremail = Some("admin@tesobe.com"), // Default email
    sub = Some(client.client_name), // Use client name as sub
    consumerid = Some(client.consumer_id),
    createdat = None, // Let database set this
    updatedat = None, // Let database set this
    secret = client.client_secret,
    azp = Some(client.client_id),
    aud = Some("obp-api"),
    iss = Some(config.issuer),
    redirecturl = Some(client.redirect_uris.mkString(",")),
    logourl = None,
    userauthenticationurl = None,
    clientcertificate = None,
    company = Some("TESOBE"),
    key_c = Some(
      client.client_id
    ), // Use client_id as the OAuth2 identifier (maps to key_c in database)
    isactive = Some(true)
  )
}

object DatabaseAuthService {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Create a DatabaseAuthService with HikariCP connection pooling
    */
  def create(config: OidcConfig): Resource[IO, DatabaseAuthService] = {
    for {
      _ <- Resource.eval(
        IO(
          logger.info(
            "🔧 Creating DatabaseAuthService with read and admin transactors"
          )
        )
      )
      _ <- Resource.eval(
        IO(
          logger.info(
            s"   Read DB: ${config.database.username}@${config.database.host}:${config.database.port}/${config.database.database}"
          )
        )
      )
      _ <- Resource.eval(
        IO(
          logger.info(
            s"   Admin DB: ${config.adminDatabase.username}@${config.adminDatabase.host}:${config.adminDatabase.port}/${config.adminDatabase.database}"
          )
        )
      )
      readTransactor <- createTransactor(config.database)
      _ <- Resource.eval(
        IO(logger.info("✅ Read transactor created successfully"))
      )
      adminTransactor <- createTransactor(config.adminDatabase)
      _ <- Resource.eval(
        IO(logger.info("✅ Admin transactor created successfully"))
      )
      service = new DatabaseAuthService(
        readTransactor,
        Some(adminTransactor),
        config
      )
      _ <- Resource.eval(
        IO(logger.info("✅ DatabaseAuthService created with admin capabilities"))
      )
    } yield service
  }

  /** Create HikariCP transactor for database connections
    */
  private def createTransactor(
      dbConfig: DatabaseConfig
  ): Resource[IO, HikariTransactor[IO]] = {
    val hikariConfig = new HikariConfig()
    hikariConfig.setDriverClassName("org.postgresql.Driver")
    hikariConfig.setJdbcUrl(
      s"jdbc:postgresql://${dbConfig.host}:${dbConfig.port}/${dbConfig.database}"
    )
    hikariConfig.setUsername(dbConfig.username)
    hikariConfig.setPassword(dbConfig.password)
    hikariConfig.setMaximumPoolSize(dbConfig.maxConnections)
    hikariConfig.setMinimumIdle(2)
    hikariConfig.setConnectionTimeout(30000) // 30 seconds
    hikariConfig.setIdleTimeout(600000) // 10 minutes
    hikariConfig.setMaxLifetime(1800000) // 30 minutes
    hikariConfig.setLeakDetectionThreshold(60000) // 1 minute

    // Security settings
    hikariConfig.addDataSourceProperty("sslmode", "prefer")
    hikariConfig.addDataSourceProperty("tcpKeepAlive", "true")
    hikariConfig.addDataSourceProperty("ApplicationName", "OBP-OIDC-Provider")

    HikariTransactor.fromHikariConfig[IO](hikariConfig)
  }

  /** Test database connection and setup
    */
  def testConnection(config: OidcConfig): IO[Either[String, String]] = {
    createTransactor(config.database).use { transactor =>
      val testQuery = sql"SELECT COUNT(*) FROM v_oidc_users".query[Int]

      testQuery.unique
        .transact(transactor)
        .map { count =>
          val message =
            s"Database connection successful. Found $count validated users in v_oidc_users view."
          logger.info(message)
          Right(message)
        }
        .handleErrorWith { error =>
          val message = s"Database connection failed: ${error.getMessage}"
          logger.error(message, error)
          IO.pure(Left(message))
        }
    }
  }

  /** Test client view access
    */
  def testClientConnection(config: OidcConfig): IO[Either[String, String]] = {
    createTransactor(config.database).use { transactor =>
      val testQuery = sql"SELECT COUNT(*) FROM v_oidc_clients".query[Int]

      testQuery.unique
        .transact(transactor)
        .map { count =>
          val message =
            s"Client database connection successful. Found $count registered clients in v_oidc_clients view."
          logger.info(message)
          Right(message)
        }
        .handleErrorWith { error =>
          val message =
            s"Client database connection failed: ${error.getMessage}"
          logger.error(message, error)
          IO.pure(Left(message))
        }
    }
  }

  /** Test admin database connection and v_oidc_admin_clients view access
    */
  def testAdminConnection(config: OidcConfig): IO[Either[String, String]] = {
    createTransactor(config.adminDatabase).use { transactor =>
      val testQuery = sql"SELECT COUNT(*) FROM v_oidc_admin_clients".query[Int]

      testQuery.unique
        .transact(transactor)
        .map { count =>
          val message =
            s"Admin database connection successful. Found $count clients accessible via v_oidc_admin_clients view."
          logger.info(message)
          Right(message)
        }
        .handleErrorWith { error =>
          val message = s"Admin database connection failed: ${error.getMessage}"
          logger.error(message, error)
          IO.pure(Left(message))
        }
    }
  }
}

/** Doobie Read instance for DatabaseUser
  */
object DatabaseUserInstances {
  import doobie.util.Read

  implicit val databaseUserRead: Read[DatabaseUser] =
    Read[
      (
          String,
          String,
          String,
          String,
          String,
          Boolean,
          String,
          String,
          String,
          Option[Instant],
          Option[Instant]
      )
    ]
      .map {
        case (
              userId,
              username,
              firstname,
              lastname,
              email,
              validated,
              provider,
              passwordPw,
              passwordSalt,
              createdAt,
              updatedAt
            ) =>
          DatabaseUser(
            userId = userId,
            username = username,
            firstname = firstname,
            lastname = lastname,
            email = email,
            validated = validated,
            provider = provider,
            passwordHash = passwordPw,
            passwordSalt = passwordSalt,
            createdAt = createdAt,
            updatedAt = updatedAt
          )
      }

  implicit val adminDatabaseClientRead: Read[AdminDatabaseClient] =
    Read[
      (
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[Instant],
          Option[Instant],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[String],
          Option[Boolean]
      )
    ]
      .map {
        case (
              name,
              apptype,
              description,
              developeremail,
              sub,
              createdat,
              updatedat,
              secret,
              azp,
              aud,
              iss,
              redirecturl,
              logourl,
              userauthenticationurl,
              clientcertificate,
              company,
              key_c,
              consumerid,
              isactive
            ) =>
          AdminDatabaseClient(
            name = name,
            apptype = apptype,
            description = description,
            developeremail = developeremail,
            sub = sub,
            createdat = createdat,
            updatedat = updatedat,
            secret = secret,
            azp = azp,
            aud = aud,
            iss = iss,
            redirecturl = redirecturl,
            logourl = logourl,
            userauthenticationurl = userauthenticationurl,
            clientcertificate = clientcertificate,
            company = company,
            key_c = key_c,
            consumerid = consumerid,
            isactive = isactive
          )
      }

  // Explicit Read instance for DatabaseClient to handle nullable columns
  implicit val databaseClientRead: Read[DatabaseClient] =
    Read[
      (
          String, // client_id
          Option[String], // client_secret
          String, // client_name
          String, // consumer_id
          Option[String], // redirect_uris
          Option[String], // grant_types
          Option[String], // response_types
          Option[String], // scopes
          Option[String], // token_endpoint_auth_method
          Option[String] // created_at
      )
    ]
      .map {
        case (
              client_id,
              client_secret,
              client_name,
              consumer_id,
              redirect_uris,
              grant_types,
              response_types,
              scopes,
              token_endpoint_auth_method,
              created_at
            ) =>
          DatabaseClient(
            client_id = client_id,
            client_secret = client_secret,
            client_name = client_name,
            consumer_id = consumer_id,
            redirect_uris = redirect_uris,
            grant_types = grant_types,
            response_types = response_types,
            scopes = scopes,
            token_endpoint_auth_method = token_endpoint_auth_method,
            created_at = created_at
          )
      }
}
