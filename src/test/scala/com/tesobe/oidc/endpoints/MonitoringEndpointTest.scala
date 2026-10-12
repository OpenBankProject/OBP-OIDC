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
import com.tesobe.oidc.monitoring.{LogCache, ObpRoleCheck, Telemetry}
import io.circe.Json
import org.http4s._
import org.http4s.circe._
import org.http4s.client.Client
import org.http4s.dsl.io._
import org.http4s.headers.Authorization
import org.http4s.implicits._
import org.scalatest.BeforeAndAfterEach
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** The log cache and Telemetry OBP-Sentinel reads, in OBP-API's shape, behind
  * the Roles OBP-API's own endpoints need, checked with OBP-API.
  */
class MonitoringEndpointTest extends AnyFunSuite with Matchers with BeforeAndAfterEach {

  override def beforeEach(): Unit = {
    LogCache.clear()
    Telemetry.clear()
  }

  /** OBP-API, where the token "good" holds the given Roles as a Scope, and any other token is refused. */
  private def obpApi(roles: Set[String]): Client[IO] =
    Client.fromHttpApp(HttpRoutes.of[IO] {
      case req @ GET -> Root / "obp" / "v7.0.0" / "banks" / "SYS" / "my" / "roles" / role =>
        req.headers.get[Authorization] match {
          case Some(Authorization(Credentials.Token(_, "good"))) =>
            if (roles.contains(role)) Ok(Json.obj("allowed_for_auth_modes" -> Json.arr(Json.fromString("UserOrApplication"))))
            else Ok(Json.obj("allowed_for_auth_modes" -> Json.arr()))
          case _ => IO.pure(Response[IO](Status.Unauthorized))
        }
    }.orNotFound)

  private def call(roles: Set[String], path: String, token: Option[String] = Some("good"), obpApiUrl: Boolean = true): Response[IO] = {
    val check = if (obpApiUrl) Some(ObpRoleCheck("http://obp-api", obpApi(roles)).unsafeRunSync()) else None
    val req = Request[IO](Method.GET, Uri.unsafeFromString(path))
      .putHeaders(token.map(t => Authorization(Credentials.Token(AuthScheme.Bearer, t))).toList)
    MonitoringEndpoint(check).routes.orNotFound.run(req).unsafeRunSync()
  }

  private def messages(response: Response[IO]): List[String] =
    response.as[Json].unsafeRunSync().hcursor.downField("entries").as[List[Json]].toOption.get
      .map(_.hcursor.downField("message").as[String].toOption.get)

  test("log lines are kept by level, newest first, with limit and offset") {
    LogCache.recordLine("12:00:00.000 [io-compute-1] WARN  c.t.o.Foo - first", fromStderr = false, now = 1)
    LogCache.recordLine("WARNING: second", fromStderr = false, now = 2)
    LogCache.recordLine("plain println", fromStderr = false, now = 3)
    val r = call(Set("CanGetSystemLogCacheWarning"), "/monitoring/log-cache/warning")
    r.status shouldBe Status.Ok
    messages(r) shouldBe List("WARNING: second", "c.t.o.Foo - first")
    messages(call(Set("CanGetSystemLogCacheWarning"), "/monitoring/log-cache/warning?limit=1&offset=1")) shouldBe
      List("c.t.o.Foo - first")
    messages(call(Set("CanGetSystemLogCacheInfo"), "/monitoring/log-cache/info")) shouldBe List("plain println")
  }

  test("stderr is error, and a stack trace joins the line before it") {
    LogCache.recordLine("java.lang.RuntimeException: boom", fromStderr = true)
    LogCache.recordLine("\tat com.tesobe.oidc.Foo.bar(Foo.scala:1)", fromStderr = true)
    messages(call(Set("CanGetSystemLogCacheAll"), "/monitoring/log-cache/error")) shouldBe
      List("java.lang.RuntimeException: boom\n\tat com.tesobe.oidc.Foo.bar(Foo.scala:1)")
  }

  test("println and logback lines are both kept once installed") {
    LogCache.install()
    println("DEBUG: from println")
    org.slf4j.LoggerFactory.getLogger("com.tesobe.oidc.Test").warn("from logback")
    messages(call(Set("CanGetSystemLogCacheAll"), "/monitoring/log-cache/debug")) should contain("DEBUG: from println")
    messages(call(Set("CanGetSystemLogCacheAll"), "/monitoring/log-cache/warning")) should contain("com.tesobe.oidc.Test - from logback")
  }

  test("the Roles OBP-API's own endpoints need are required") {
    call(Set("CanGetSystemLogCacheInfo"), "/monitoring/log-cache/error").status shouldBe Status.Forbidden
    call(Set("CanGetSystemLogCacheAll"), "/monitoring/log-cache/error").status shouldBe Status.Ok
    call(Set("CanGetSystemLogCacheError"), "/monitoring/log-cache/all").status shouldBe Status.Forbidden
    call(Set(), "/monitoring/telemetry").status shouldBe Status.Forbidden
    call(Set("CanGetTelemetry"), "/monitoring/telemetry").status shouldBe Status.Ok
  }

  test("no token, a refused token, or no OBP-API to ask") {
    call(Set("CanGetTelemetry"), "/monitoring/telemetry", token = None).status shouldBe Status.Unauthorized
    call(Set("CanGetTelemetry"), "/monitoring/telemetry", token = Some("bad")).status shouldBe Status.Unauthorized
    call(Set("CanGetTelemetry"), "/monitoring/telemetry", obpApiUrl = false).status shouldBe Status.ServiceUnavailable
  }

  test("an unknown level is not served") {
    call(Set("CanGetSystemLogCacheAll"), "/monitoring/log-cache/loud").status shouldBe Status.NotFound
  }

  test("Telemetry times requests by route, never by unmatched path") {
    val app = Telemetry.timed(HttpRoutes.of[IO] { case GET -> Root / "obp-oidc" / "jwks" => Ok("{}") }.orNotFound)
    app.run(Request[IO](Method.GET, uri"/obp-oidc/jwks")).unsafeRunSync()
    app.run(Request[IO](Method.GET, uri"/wp-admin/x1")).unsafeRunSync()
    val body = call(Set("CanGetTelemetry"), "/monitoring/telemetry?name_prefix=oidc.").as[Json].unsafeRunSync()
    body.hcursor.downField("api_instance_id").as[String].toOption.get should startWith("obp-oidc_")
    val routes = body.hcursor.downField("meters").as[List[Json]].toOption.get
      .map(_.hcursor.downField("tags").downField("route").as[String].toOption.get)
    routes should contain theSameElementsAs List("/obp-oidc/jwks", "unmatched")
  }
}
