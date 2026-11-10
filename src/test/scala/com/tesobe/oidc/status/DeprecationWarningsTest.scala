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

package com.tesobe.oidc.status

import com.tesobe.oidc.config.{DatabaseConfig, OidcConfig, ServerConfig}
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.time.Instant

/** OBP-OIDC warns that reading users and clients from SQL views is deprecated, and says so on the status page. */
class DeprecationWarningsTest extends AnyFlatSpec with Matchers {

  private val config = OidcConfig(
    issuer = "http://localhost:9000/obp-oidc",
    server = ServerConfig("localhost", 9000),
    database = DatabaseConfig("localhost", 5432, "test", "test", "test"),
    adminDatabase = DatabaseConfig("localhost", 5432, "test", "test_admin", "test_admin"),
    keyId = "test-key-1",
    tokenExpirationSeconds = 3600,
    codeExpirationSeconds = 600
  )

  "A configuration that reads SQL views" should "warn that this is deprecated" in {
    config.copy(useVerifyEndpoints = false).deprecationWarnings should equal(List(OidcConfig.SqlViewAccessDeprecated))
    OidcConfig.SqlViewAccessDeprecated should include("USE_VERIFY_ENDPOINTS=true")
  }

  "A configuration that uses OBP-API's endpoints" should "have no warnings" in {
    config.copy(useVerifyEndpoints = true).deprecationWarnings shouldBe empty
  }

  "The default configuration" should "use OBP-API's endpoints and name the OBP-API settings it still needs" in {
    config.useVerifyEndpoints shouldBe true
    config.needsDatabase shouldBe false
    config.missingObpApiSettings should equal(List("OBP_API_URL", "OBP_API_USERNAME", "OBP_API_PASSWORD", "OBP_API_CONSUMER_KEY"))
    config.copy(obpApiUrl = Some("http://localhost:8080"), obpApiUsername = Some("u"), obpApiPassword = Some("p"),
      obpApiConsumerKey = Some("k")).missingObpApiSettings shouldBe empty
  }

  "status.json" should "list the warnings" in {
    val report = StatusReport(overallOk = true, checks = Nil, generatedAt = Instant.EPOCH, credentialVerificationMethod = "x",
      clientVerificationMethod = "x", dynamicClientRegistrationEnabled = false, issuer = config.issuer,
      warnings = config.copy(useVerifyEndpoints = false).deprecationWarnings)
    val warnings = StatusReport.toJson(report).hcursor.downField("warnings").as[List[String]]
    warnings should equal(Right(List(OidcConfig.SqlViewAccessDeprecated)))
  }
}
