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

package com.tesobe.oidc.models

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import io.circe.syntax._

/** Tests for RFC 7591 Dynamic Client Registration response serialization
  *
  * RFC 7591 section 3.2.1: client metadata the client did not supply must be
  * omitted from the registration response entirely. Serializing them as JSON
  * null breaks strict clients (e.g. OpenAI Codex), which reject the response.
  */
class ClientRegistrationResponseTest extends AnyFunSuite with Matchers {

  private def response(
      logoUri: Option[String] = None,
      clientUri: Option[String] = None,
      contacts: Option[List[String]] = None
  ) = ClientRegistrationResponse(
    client_id = "test-client-id",
    client_secret = Some("test-secret"),
    client_id_issued_at = 1700000000L,
    client_secret_expires_at = 0,
    client_name = "Test Client",
    redirect_uris = List("http://localhost/callback"),
    grant_types = List("authorization_code"),
    response_types = List("code"),
    scope = "openid profile email",
    token_endpoint_auth_method = "client_secret_post",
    logo_uri = logoUri,
    client_uri = clientUri,
    contacts = contacts
  )

  test("unset optional fields are omitted, not serialized as null") {
    val json = response().asJson

    json.hcursor.downField("logo_uri").succeeded shouldBe false
    json.hcursor.downField("client_uri").succeeded shouldBe false
    json.hcursor.downField("contacts").succeeded shouldBe false
    json.noSpaces should not include "null"
  }

  test("supplied optional fields are still serialized") {
    val json = response(
      logoUri = Some("https://example.com/logo.png"),
      clientUri = Some("https://example.com"),
      contacts = Some(List("admin@example.com"))
    ).asJson

    json.hcursor.downField("logo_uri").as[String] shouldBe Right("https://example.com/logo.png")
    json.hcursor.downField("client_uri").as[String] shouldBe Right("https://example.com")
    json.hcursor.downField("contacts").as[List[String]] shouldBe Right(List("admin@example.com"))
  }

  test("required fields survive null-dropping") {
    val json = response().asJson

    json.hcursor.downField("client_id").as[String] shouldBe Right("test-client-id")
    json.hcursor.downField("client_secret").as[String] shouldBe Right("test-secret")
    json.hcursor.downField("token_endpoint_auth_method").as[String] shouldBe Right("client_secret_post")
  }
}
