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
import cats.effect.unsafe.implicits.global
import org.http4s._
import org.http4s.headers.{`Cache-Control`, `Content-Type`}
import org.http4s.implicits._
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

class AliveEndpointTest extends AnyFunSuite with Matchers {

  private def call(method: Method, path: String): Response[IO] =
    AliveEndpoint.routes.orNotFound
      .run(Request[IO](method, Uri.unsafeFromString(path)))
      .unsafeRunSync()

  test("GET /alive answers true as JSON, without a login, and must not be cached") {
    val response = call(Method.GET, "/alive")
    response.status shouldBe Status.Ok
    response.bodyText.compile.string.unsafeRunSync() shouldBe "true"
    response.headers.get[`Content-Type`].map(_.mediaType) shouldBe Some(MediaType.application.json)
    response.headers.get[`Cache-Control`].map(_.values.toList) shouldBe Some(List(CacheDirective.`no-store`))
  }

  test("POST /alive is not a route") {
    call(Method.POST, "/alive").status shouldBe Status.NotFound
  }
}
