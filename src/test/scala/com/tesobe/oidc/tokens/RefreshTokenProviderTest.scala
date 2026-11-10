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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc.tokens

import cats.effect.unsafe.implicits.global
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import com.tesobe.oidc.models.User
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

/** A refresh token carries the user's provider, so OBP-OIDC can look the user up in OBP-API when the token is
  * refreshed, even without a database and after a restart.
  */
class RefreshTokenProviderTest extends AnyFlatSpec with Matchers {

  private val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase = DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  "A refresh token" should "carry the user's provider" in {
    val claims = (for {
      jwtService <- JwtService(testConfig)
      token <- jwtService.generateRefreshToken(User("alice", "alice", "", provider = Some("obp-test")), "client-1", "openid")
      claims <- jwtService.validateRefreshToken(token)
    } yield claims).unsafeRunSync()
    claims.map(_.provider) should equal(Right(Some("obp-test")))
  }
}
