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
import cats.syntax.all._
import com.tesobe.oidc.auth.AuthService
import com.tesobe.oidc.models.{OidcError, UserInfo}
import com.tesobe.oidc.tokens.JwtService
import io.circe.syntax._
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import org.http4s.headers.Authorization

class UserInfoEndpoint(authService: AuthService[IO], jwtService: JwtService[IO]) {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case req @ GET -> Root / "obp-oidc" / "userinfo" =>
      handleUserInfoRequest(req)
    case req @ POST -> Root / "obp-oidc" / "userinfo" =>
      handleUserInfoRequest(req)
  }

  private def handleUserInfoRequest(req: Request[IO]): IO[Response[IO]] = {
    extractAccessToken(req).flatMap {
      case Some(token) =>
        validateTokenAndGetUserInfo(token)
      case None =>
        BadRequest("Missing authorization header")
    }
  }

  private def extractAccessToken(req: Request[IO]): IO[Option[String]] = IO {
    req.headers.get[Authorization] match {
      case Some(Authorization(Credentials.Token(AuthScheme.Bearer, token))) => Some(token)
      case _ => None
    }
  }

  private def validateTokenAndGetUserInfo(token: String): IO[Response[IO]] = {
    jwtService.validateAccessToken(token).flatMap {
      case Right(claims) =>
        // Check if token has required scope for userinfo
        if (!claims.scope.contains("openid")) {
          Forbidden(
            OidcError("insufficient_scope", Some("Token must include 'openid' scope")).asJson
          )
        } else {
          // Look the user up by provider and username when the token says which provider. Without a database
          // this asks OBP-API, so /userinfo works after a restart.
          (claims.provider match {
            case Some(provider) => authService.getUserBySubAndProvider(claims.sub, provider)
            case None           => authService.getUserById(claims.sub)
          }).flatMap {
            case Some(user) =>
              val userInfo = UserInfo(
                sub = user.sub,
                name = user.name,
                email = if (claims.scope.contains("email")) user.email else None,
                email_verified = if (claims.scope.contains("email")) user.email_verified else None
              )
              Ok(userInfo.asJson)

            case None =>
              BadRequest("User not found")
          }
        }

      case Left(error) =>
        BadRequest("Invalid token")
    }
  }
}

object UserInfoEndpoint {
  def apply(authService: AuthService[IO], jwtService: JwtService[IO]): UserInfoEndpoint =
    new UserInfoEndpoint(authService, jwtService)
}
