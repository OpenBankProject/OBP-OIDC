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

package com.tesobe.oidc.auth

import com.tesobe.oidc.models.OidcClient

/** The grant types a client may be issued tokens for.
  *
  * They come from OBP: an administrator may set them on the Consumer (OBP-API's
  * PUT /obp/v7.0.0/management/consumers/CONSUMER_ID/grant-types). A Consumer that sets none allows every grant,
  * as before. When OBP does not say (an older OBP-API, or an older v_oidc_clients view whose grant_types are
  * hardcoded), every grant is allowed, so nothing that works today stops working.
  */
object ClientGrantTypes {
  val AuthorizationCode = "authorization_code"
  val RefreshToken = "refresh_token"
  val ClientCredentials = "client_credentials"

  /** Every grant: what a client may use when OBP does not say. */
  val All: List[String] = List(AuthorizationCode, RefreshToken, ClientCredentials)

  def allows(client: OidcClient, grantType: String): Boolean = client.grant_types.contains(grantType)

  /** The OAuth2 error for a grant the client may not use (RFC 6749 section 5.2). */
  def notAllowedDescription(client: OidcClient, grantType: String): String =
    s"This client may not use the $grantType grant. Its grant types are: ${client.grant_types.mkString(", ")}. " +
      "An administrator sets them on the client's OBP Consumer."
}
