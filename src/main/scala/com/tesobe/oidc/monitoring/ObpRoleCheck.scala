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

package com.tesobe.oidc.monitoring

import cats.effect.{IO, Ref}
import io.circe.Json
import org.http4s._
import org.http4s.circe._
import org.http4s.client.Client
import org.http4s.headers.Authorization

import java.security.MessageDigest
import scala.concurrent.duration._

/** Whether an OBP-API token may see what this server guards with an OBP Role.
  * OBP-API answers, through GET /obp/v7.0.0/banks/SYS/my/roles/ROLE_NAME, with
  * the same rules its own endpoints use: the token's User holds the Role, or
  * its Consumer holds it as a Scope (auth mode UserOrApplication).
  */
sealed trait RoleCheck
object RoleCheck {
  case object Allowed extends RoleCheck
  case object Unauthorized extends RoleCheck
  case object Forbidden extends RoleCheck
}

final class ObpRoleCheck(
    obpApiUrl: String,
    client: Client[IO],
    cache: Ref[IO, Map[String, (RoleCheck, FiniteDuration)]]
) {
  import ObpRoleCheck._

  private def checkRole(token: String, role: String): IO[RoleCheck] = {
    val request = Request[IO](
      Method.GET,
      Uri.unsafeFromString(s"${obpApiUrl.stripSuffix("/")}/obp/v7.0.0/banks/SYS/my/roles/${Uri.pathEncode(role)}")
    ).putHeaders(Authorization(Credentials.Token(AuthScheme.Bearer, token)))
    client.run(request).use { response =>
      if (response.status == Status.Unauthorized) IO.pure(RoleCheck.Unauthorized)
      else if (!response.status.isSuccess) IO.pure(RoleCheck.Forbidden)
      else
        response.asJson.map { body =>
          val modes = body.hcursor.downField("allowed_for_auth_modes").as[List[String]].getOrElse(Nil)
          if (modes.contains("UserOrApplication")) RoleCheck.Allowed else RoleCheck.Forbidden
        }
    }
  }

  /** Allowed if the token may use any one of the Roles, as an endpoint needing any of them would decide. */
  def mayUseAnyRole(token: String, roles: List[String]): IO[RoleCheck] =
    for {
      now <- IO.monotonic
      key = sha256(token) + ":" + roles.mkString(",")
      cached <- cache.get.map(_.get(key).filter { case (_, at) => now - at < Ttl }.map(_._1))
      result <- cached match {
        case Some(result) => IO.pure(result)
        case None =>
          roles
            .foldLeft(IO.pure[RoleCheck](RoleCheck.Forbidden)) { (previous, role) =>
              previous.flatMap {
                case RoleCheck.Forbidden => checkRole(token, role)
                case decided             => IO.pure(decided)
              }
            }
            .flatTap { result =>
              cache.update { entries =>
                val kept = if (entries.size >= MaxCached) entries.filter { case (_, (_, at)) => now - at < Ttl } else entries
                (if (kept.size >= MaxCached) Map.empty[String, (RoleCheck, FiniteDuration)] else kept) + (key -> (result, now))
              }
            }
      }
    } yield result
}

object ObpRoleCheck {
  private val Ttl = 60.seconds
  private val MaxCached = 1000

  private def sha256(text: String): String =
    MessageDigest.getInstance("SHA-256").digest(text.getBytes("UTF-8")).map("%02x".format(_)).mkString

  def apply(obpApiUrl: String, client: Client[IO]): IO[ObpRoleCheck] =
    Ref.of[IO, Map[String, (RoleCheck, FiniteDuration)]](Map.empty).map(new ObpRoleCheck(obpApiUrl, client, _))

  def errorJson(message: String): Json = Json.obj("error" -> Json.fromString(message))
}
