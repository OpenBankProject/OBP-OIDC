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
import cats.effect.unsafe.implicits.global
import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import org.http4s._
import org.http4s.circe._
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** The discovery document must be reachable at every standard well-known
  * location for an issuer with a path component (RFC 8414 path-inserted forms
  * and OIDC Discovery path-appended forms). MCP clients try the RFC 8414
  * forms first and fall back to guessed endpoint paths when discovery fails,
  * which breaks the OAuth flow — so a 404 on any of these is a bug.
  */
class DiscoveryEndpointTest extends AnyFunSuite with Matchers {

  private val testConfig = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase =
      DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  private val endpoint = DiscoveryEndpoint(testConfig)

  private val discoveryPaths = List(
    // OIDC Discovery: well-known appended to the issuer path
    "/obp-oidc/.well-known/openid-configuration",
    "/obp-oidc/.well-known/oauth-authorization-server",
    // RFC 8414: well-known inserted between host and issuer path
    "/.well-known/oauth-authorization-server/obp-oidc",
    "/.well-known/openid-configuration/obp-oidc"
  )

  private def run(method: Method, path: String): Option[Response[IO]] =
    endpoint.routes
      .run(Request[IO](method, Uri.unsafeFromString(path)))
      .value
      .unsafeRunSync()

  for (path <- discoveryPaths) {
    test(s"GET $path serves the discovery document with matching issuer") {
      val resp = run(Method.GET, path)
      resp shouldBe defined
      resp.get.status shouldBe Status.Ok

      val json = resp.get.as[io.circe.Json].unsafeRunSync()
      json.hcursor.downField("issuer").as[String] shouldBe Right(testConfig.issuer)
      json.hcursor.downField("registration_endpoint").succeeded shouldBe true
    }

    test(s"HEAD $path returns OK with empty body") {
      val resp = run(Method.HEAD, path)
      resp shouldBe defined
      resp.get.status shouldBe Status.Ok
      resp.get.as[String].unsafeRunSync() shouldBe ""
    }
  }
}
