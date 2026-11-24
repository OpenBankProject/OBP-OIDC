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

package com.tesobe.oidc.endpoints

import cats.effect.IO
import org.http4s.{CacheDirective, Charset, HttpRoutes, MediaType}
import org.http4s.dsl.io._
import org.http4s.headers.{`Cache-Control`, `Content-Type`}

/** GET /alive answers `true`, as OBP-API's /alive does. It checks nothing, so it shows only that the process is up and serves HTTP. It needs no login, and the answer must not be cached. Use /health for the same signal in OBP-API's {"status":"ok"} shape, and /status for the dependency checks. */
object AliveEndpoint {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] { case GET -> Root / "alive" =>
    Ok("true").map(
      _.withContentType(`Content-Type`(MediaType.application.json, Charset.`UTF-8`))
        .putHeaders(`Cache-Control`(CacheDirective.`no-store`))
    )
  }
}
