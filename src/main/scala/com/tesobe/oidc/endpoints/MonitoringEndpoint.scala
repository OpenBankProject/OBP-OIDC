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
import com.tesobe.oidc.monitoring.{LogCache, ObpRoleCheck, RoleCheck, Telemetry}
import io.circe.Json
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import org.http4s.headers.Authorization
import org.slf4j.LoggerFactory

/** This server's log cache and Telemetry, for a monitor such as OBP-Sentinel,
  * guarded by the same Roles OBP-API's own log cache and Telemetry endpoints
  * need. The caller sends a Bearer token from OBP-API, which this server checks
  * with OBP-API (OBP_API_URL).
  */
class MonitoringEndpoint(roleCheck: Option[ObpRoleCheck]) {

  private val logger = LoggerFactory.getLogger(getClass)

  private def nonNegativeInt(value: Option[String]): Option[Int] =
    value.flatMap(_.toIntOption).filter(_ >= 0)

  private def bearer(req: Request[IO]): Option[String] =
    req.headers.get[Authorization].collect {
      case Authorization(Credentials.Token(scheme, token)) if scheme == AuthScheme.Bearer => token.trim
    }.filter(_.nonEmpty)

  private def error(status: Status, message: String): IO[Response[IO]] =
    IO.pure(Response[IO](status).withEntity(ObpRoleCheck.errorJson(message)))

  private def requireAnyRole(req: Request[IO], roles: List[String])(allowed: => IO[Response[IO]]): IO[Response[IO]] =
    (bearer(req), roleCheck) match {
      case (None, _)    => error(Status.Unauthorized, "Send a Bearer token from OBP-API")
      case (_, None)    => error(Status.ServiceUnavailable, "OBP_API_URL is not set")
      case (Some(token), Some(check)) =>
        check.mayUseAnyRole(token, roles).attempt.flatMap {
          case Right(RoleCheck.Allowed)      => allowed
          case Right(RoleCheck.Unauthorized) => error(Status.Unauthorized, "OBP-API did not accept the token")
          case Right(RoleCheck.Forbidden)    => error(Status.Forbidden, s"Requires one of the Roles: ${roles.mkString(", ")}")
          case Left(e) =>
            IO(logger.error(s"Role check: could not ask OBP-API: ${e.getMessage}")) *>
              error(Status.ServiceUnavailable, "Could not check the token with OBP-API")
        }
    }

  private def entryJson(entry: LogCache.Entry): Json =
    Json.obj("level" -> entry.level.asJson, "message" -> entry.message.asJson, "timestamp" -> entry.timestamp.asJson)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "monitoring" / "log-cache" / level if level == "all" || LogCache.Levels.contains(level) =>
      val roles =
        if (level == "all") List("CanGetSystemLogCacheAll")
        else List(s"CanGetSystemLogCache${level.capitalize}", "CanGetSystemLogCacheAll")
      requireAnyRole(req, roles) {
        val entries = LogCache.tail(level, nonNegativeInt(req.params.get("limit")), nonNegativeInt(req.params.get("offset")))
        Ok(Json.obj("entries" -> entries.map(entryJson).asJson))
      }

    case req @ GET -> Root / "monitoring" / "telemetry" =>
      requireAnyRole(req, List("CanGetTelemetry")) {
        Ok(Telemetry.report(req.params.get("name_prefix")))
      }
  }
}

object MonitoringEndpoint {
  def apply(roleCheck: Option[ObpRoleCheck]): MonitoringEndpoint = new MonitoringEndpoint(roleCheck)
}
