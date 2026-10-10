/*
 * Copyright (c) 2026 TESOBE
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

import java.net.URI
import scala.util.Try

/** This object decides whether a redirect_uri may be used at all, whatever is registered for the client.
  *
  * OBP-API checks a Consumer's redirect URLs when they are written, with the same rules
  * (code.api.util.RedirectUrlValidation). Clients saved before that check existed can still hold entries
  * such as `javascript:...` or a plain-http public host, and in database mode OBP-OIDC reads them straight
  * from the v_oidc_clients view. Applying the rules again here, before a code is issued or an error is
  * redirected, means such an entry is never used as a redirect target. The rules are:
  *
  *   - `https:` with a host;
  *   - `http:` only for `localhost`, `127.0.0.1` or `[::1]`, for development;
  *   - a private-use app scheme in reverse-domain form (RFC 8252), such as `com.example.app:/callback`;
  *   - never a wildcard (`*`), user information (`user@host`) or a fragment (`#...`).
  */
object RedirectUriRules {

  private val loopbackHosts = Set("localhost", "127.0.0.1", "[::1]")

  // A reverse-domain scheme: at least two dot-separated labels, e.g. com.example.app or x-com.example.ios.
  private val reverseDomainScheme = """^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+$""".r

  /** Returns why a redirect_uri is not allowed, or None when it is allowed. */
  def problemWith(redirectUri: String): Option[String] =
    if (redirectUri == null || redirectUri.trim.isEmpty) Some("it is empty")
    else if (redirectUri.contains("*")) Some("a wildcard is not allowed")
    else
      Try(new URI(redirectUri)).toOption match {
        case None                                      => Some("it is not a valid URI")
        case Some(uri) if uri.getScheme == null        => Some("it has no scheme")
        case Some(uri) if uri.getRawFragment != null   => Some("a fragment is not allowed")
        case Some(uri) if uri.getRawUserInfo != null   => Some("user information is not allowed")
        case Some(uri) =>
          uri.getScheme.toLowerCase match {
            case "https" =>
              if (Option(uri.getHost).exists(_.nonEmpty)) None
              else Some("an https redirect_uri must name a host")
            case "http" =>
              if (Option(uri.getHost).map(_.toLowerCase).exists(loopbackHosts.contains)) None
              else Some("http is only allowed for localhost, 127.0.0.1 or [::1]; use https")
            case scheme if reverseDomainScheme.pattern.matcher(scheme).matches() => None
            case scheme =>
              Some(s"the scheme '$scheme' is not allowed; use https, or an app scheme in reverse-domain form such as com.example.app")
          }
      }

  def isAllowed(redirectUri: String): Boolean = problemWith(redirectUri).isEmpty
}
