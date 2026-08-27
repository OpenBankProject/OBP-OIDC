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

package com.tesobe.oidc

/** Exposes the build version of this server, read from the repo-root VERSION
  * file that Maven packages into the jar (see the <resources> section of
  * pom.xml). Bump VERSION to make a deployment visibly distinguishable on
  * /status and /status.json.
  */
object BuildVersion {

  lazy val version: String =
    Option(getClass.getResourceAsStream("/VERSION"))
      .map { stream =>
        try scala.io.Source.fromInputStream(stream, "UTF-8").mkString.trim
        finally stream.close()
      }
      .filter(_.nonEmpty)
      .getOrElse("unknown")
}
