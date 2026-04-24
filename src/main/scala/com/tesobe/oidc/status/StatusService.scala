/*
 * Copyright (c) 2025 TESOBE
 *
 * This file is part of OBP-OIDC.
 *
 * OBP-OIDC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.tesobe.oidc.status

import cats.effect.{IO, Ref, Resource}
import cats.syntax.all._
import com.tesobe.oidc.auth.{HybridAuthService, ObpApiCredentialsService}
import com.tesobe.oidc.config.{OidcConfig, VerifyCredentialsMethod, VerifyClientMethod}
import com.tesobe.oidc.tokens.JwtService
import io.circe.Json
import org.http4s._
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.`Content-Type`
import org.http4s.circe._
import org.typelevel.ci._
import org.slf4j.LoggerFactory

import java.time.Instant
import scala.concurrent.duration._

case class StatusCheck(name: String, ok: Boolean)

case class StatusReport(
    overallOk: Boolean,
    checks: List[StatusCheck],
    generatedAt: Instant
)

object StatusReport {
  def toJson(report: StatusReport): Json = Json.obj(
    "status" -> Json.fromString(if (report.overallOk) "ok" else "fail"),
    "generated_at" -> Json.fromString(report.generatedAt.toString),
    "checks" -> Json.arr(
      report.checks.map { c =>
        Json.obj(
          "name" -> Json.fromString(c.name),
          "ok" -> Json.fromBoolean(c.ok)
        )
      }: _*
    )
  )
}

class StatusService(
    client: Client[IO],
    config: OidcConfig,
    jwtService: JwtService[IO],
    cacheRef: Ref[IO, Option[(Instant, StatusReport)]],
    cacheTtlSeconds: Long
) {

  private val logger = LoggerFactory.getLogger(getClass)

  def getReport: IO[StatusReport] = {
    val now = IO.realTimeInstant
    now.flatMap { t =>
      cacheRef.get.flatMap {
        case Some((cachedAt, cached))
            if cachedAt.plusSeconds(cacheTtlSeconds).isAfter(t) =>
          IO.pure(cached)
        case _ =>
          runChecks().flatMap { r =>
            cacheRef.set(Some((t, r))).as(r)
          }
      }
    }
  }

  private def runChecks(): IO[StatusReport] = {
    // Checks that do not need the OBP API token, run in parallel
    val reachableIO = checkObpReachable()
    val jwksIO = checkJwks()
    val dbUserIO =
      if (config.needsDatabase &&
          config.verifyCredentialsMethod == VerifyCredentialsMethod.ViaOidcUsersView)
        checkDbUserView().map(Some(_))
      else IO.pure(None)
    val dbClientIO =
      if (config.needsDatabase) checkDbClientView().map(Some(_))
      else IO.pure(None)
    val dbAdminIO =
      if (config.needsDatabase) checkDbAdminView().map(Some(_))
      else IO.pure(None)

    // Authentication + probes require a DirectLogin token
    val tokenAndProbesIO: IO[List[StatusCheck]] = obtainToken().flatMap {
      case Left(_) =>
        // OBP API authentication failed. Mark all dependent checks as FAIL.
        IO.pure(dependentFailChecks())
      case Right(token) =>
        val authOk = StatusCheck("OBP API authentication", ok = true)
        val rolesIO = checkRoles()
        val probesIO = endpointProbes(token)
        (rolesIO, probesIO).parMapN { (roleChecks, probeChecks) =>
          authOk :: roleChecks ++ probeChecks
        }
    }

    for {
      tuple <- (
        reachableIO,
        tokenAndProbesIO,
        jwksIO,
        dbUserIO,
        dbClientIO,
        dbAdminIO
      ).parTupled
      (reach, tokenChecks, jwks, dbUser, dbClient, dbAdmin) = tuple
      service = StatusCheck("Service", ok = true)
      all =
        List(service, reach) ++ tokenChecks ++
          List(jwks) ++ dbUser.toList ++ dbClient.toList ++ dbAdmin.toList
      overall = all.forall(_.ok)
      now <- IO.realTimeInstant
    } yield StatusReport(overall, all, now)
  }

  private def dependentFailChecks(): List[StatusCheck] = {
    val base = List(
      StatusCheck("OBP API authentication", ok = false),
      StatusCheck("OBP API roles", ok = false),
      StatusCheck("Providers endpoint", ok = false)
    )
    val credential =
      if (config.verifyCredentialsMethod == VerifyCredentialsMethod.ViaApiEndpoint)
        List(
          StatusCheck("Credential verification endpoint", ok = false),
          StatusCheck("User lookup endpoint", ok = false)
        )
      else Nil
    val clientVerify =
      if (config.verifyClientMethod == VerifyClientMethod.ViaApiEndpoint)
        List(StatusCheck("Client verification endpoint", ok = false))
      else Nil
    val dcr =
      if (config.enableDynamicClientRegistration)
        List(StatusCheck("Consumer management endpoint", ok = false))
      else Nil
    base ++ credential ++ clientVerify ++ dcr
  }

  private def obtainToken(): IO[Either[String, String]] = {
    (
      config.obpApiUrl,
      config.obpApiUsername,
      config.obpApiPassword,
      config.obpApiConsumerKey
    ) match {
      case (Some(_), Some(_), Some(_), Some(_)) =>
        for {
          tokenRefLocal <- Ref.of[IO, Option[com.tesobe.oidc.auth.CachedToken]](None)
          service = new ObpApiCredentialsService(client, config, tokenRefLocal)
          result <- service.obtainDirectLoginToken().map {
            case Right(t)  => Right(t)
            case Left(err) => Left(err.error)
          }
        } yield result
      case _ =>
        IO.pure(Left("OBP API not configured"))
    }
  }

  private def checkObpReachable(): IO[StatusCheck] = {
    val name = "OBP API reachable"
    config.obpApiUrl match {
      case None => IO.pure(StatusCheck(name, ok = false))
      case Some(baseUrl) =>
        val endpoint = s"${baseUrl.stripSuffix("/")}/obp/v4.0.0/root"
        val req = Request[IO](Method.GET, Uri.unsafeFromString(endpoint))
        client
          .run(req)
          .use { resp => IO.pure(resp.status.isSuccess) }
          .handleError(_ => false)
          .map(ok => StatusCheck(name, ok))
    }
  }

  private def checkRoles(): IO[List[StatusCheck]] = {
    val requiredRoles =
      (config.verifyCredentialsMethod match {
        case VerifyCredentialsMethod.ViaApiEndpoint =>
          List("CanVerifyUserCredentials", "CanGetAnyUser")
        case _ => Nil
      }) ++ (config.verifyClientMethod match {
        case VerifyClientMethod.ViaApiEndpoint =>
          val base = List("CanGetOidcClient", "CanVerifyOidcClient", "CanGetConsumers")
          val createConsumer =
            if (config.enableDynamicClientRegistration || !config.skipClientBootstrap)
              List("CanCreateConsumer")
            else Nil
          base ++ createConsumer
        case _ => Nil
      })

    val name = "OBP API roles"
    if (requiredRoles.isEmpty) {
      IO.pure(List(StatusCheck(name, ok = true)))
    } else {
      ObpApiCredentialsService
        .checkRequiredRoles(config, requiredRoles)
        .map {
          case Right(rc) => List(StatusCheck(name, ok = rc.allPresent))
          case Left(_)   => List(StatusCheck(name, ok = false))
        }
        .handleError(_ => List(StatusCheck(name, ok = false)))
    }
  }

  /** Result of an endpoint probe. Decision rules:
    *   - 5xx: FAIL (server-side breakage).
    *   - 404 with body containing OBP-10404 ("could not find the requested URI"),
    *     or a bare 404 with no OBP- marker at all: FAIL (endpoint not deployed).
    *   - Anything else — including 2xx, 3xx, 4xx other than 404, and 404s carrying
    *     any other OBP-NNNNN code (e.g. OBP-20027 "User not found by provider and
    *     username"): OK. The endpoint is alive and processed the request; an
    *     application-level rejection of our deliberately-bogus payload is expected.
    */
  private def probeEndpoint(
      name: String,
      baseUrl: String,
      path: String,
      method: Method,
      token: String,
      body: Option[Json]
  ): IO[StatusCheck] = {
    val uri = Uri.unsafeFromString(s"${baseUrl.stripSuffix("/")}$path")
    val base = Request[IO](method, uri).putHeaders(
      Header.Raw(ci"DirectLogin", s"token=$token")
    )
    val req = body match {
      case Some(json) =>
        base.withEntity(json).putHeaders(`Content-Type`(MediaType.application.json))
      case None => base
    }
    client
      .run(req)
      .use { resp =>
        val code = resp.status.code
        if (code >= 500) IO.pure(StatusCheck(name, ok = false))
        else if (code == 404) {
          resp.as[String].map { responseBody =>
            val routeMissing =
              responseBody.contains("OBP-10404") ||
                !responseBody.contains("OBP-")
            StatusCheck(name, ok = !routeMissing)
          }
        } else IO.pure(StatusCheck(name, ok = true))
      }
      .handleError(_ => StatusCheck(name, ok = false))
  }

  private def endpointProbes(token: String): IO[List[StatusCheck]] = {
    config.obpApiUrl match {
      case None => IO.pure(Nil)
      case Some(baseUrl) =>
        val providers = probeEndpoint(
          "Providers endpoint",
          baseUrl,
          "/obp/v6.0.0/providers",
          Method.GET,
          token,
          None
        )
        val credentialProbes =
          if (config.verifyCredentialsMethod == VerifyCredentialsMethod.ViaApiEndpoint) {
            val verify = probeEndpoint(
              "Credential verification endpoint",
              baseUrl,
              "/obp/v6.0.0/users/verify-credentials",
              Method.POST,
              token,
              Some(
                Json.obj(
                  "username" -> Json.fromString(""),
                  "password" -> Json.fromString(""),
                  "provider" -> Json.fromString("")
                )
              )
            )
            val lookup = probeEndpoint(
              "User lookup endpoint",
              baseUrl,
              "/obp/v6.0.0/users/provider/__obp_oidc_status__/username/__obp_oidc_status__",
              Method.GET,
              token,
              None
            )
            List(verify, lookup)
          } else Nil

        val clientVerifyProbes =
          if (config.verifyClientMethod == VerifyClientMethod.ViaApiEndpoint) {
            List(
              probeEndpoint(
                "Client verification endpoint",
                baseUrl,
                "/obp/v6.0.0/oidc/clients/verify",
                Method.POST,
                token,
                Some(
                  Json.obj(
                    "client_id" -> Json.fromString("__obp_oidc_status__"),
                    "client_secret" -> Json.fromString("__obp_oidc_status__")
                  )
                )
              )
            )
          } else Nil

        val dcrProbes =
          if (config.enableDynamicClientRegistration) {
            List(
              probeEndpoint(
                "Consumer management endpoint",
                baseUrl,
                "/obp/v5.1.0/management/consumers",
                Method.POST,
                token,
                Some(Json.obj())
              )
            )
          } else Nil

        (providers :: credentialProbes ++ clientVerifyProbes ++ dcrProbes).parSequence
    }
  }

  private def withTimeout[A](fa: IO[A], fallback: A, label: String): IO[A] =
    fa.timeout(5.seconds).handleErrorWith { e =>
      IO(logger.warn(s"Status check '$label' failed: ${e.getMessage}")).as(fallback)
    }

  private def checkDbUserView(): IO[StatusCheck] = {
    val name = "User directory"
    withTimeout(
      HybridAuthService.testConnection(config).map {
        case Right(_) => StatusCheck(name, ok = true)
        case Left(_)  => StatusCheck(name, ok = false)
      },
      StatusCheck(name, ok = false),
      name
    )
  }

  private def checkDbClientView(): IO[StatusCheck] = {
    val name = "Client directory"
    withTimeout(
      HybridAuthService.testClientConnection(config).map {
        case Right(_) => StatusCheck(name, ok = true)
        case Left(_)  => StatusCheck(name, ok = false)
      },
      StatusCheck(name, ok = false),
      name
    )
  }

  private def checkDbAdminView(): IO[StatusCheck] = {
    val name = "Admin directory"
    withTimeout(
      HybridAuthService.testAdminConnection(config).map {
        case Right(_) => StatusCheck(name, ok = true)
        case Left(_)  => StatusCheck(name, ok = false)
      },
      StatusCheck(name, ok = false),
      name
    )
  }

  private def checkJwks(): IO[StatusCheck] = {
    val name = "Signing keys"
    jwtService.getJsonWebKey
      .map { jwk =>
        // n is the RSA modulus; non-empty means the key was generated
        StatusCheck(name, ok = jwk.n.nonEmpty)
      }
      .handleError(_ => StatusCheck(name, ok = false))
  }
}

object StatusService {

  def create(
      config: OidcConfig,
      jwtService: JwtService[IO],
      cacheTtlSeconds: Long = 30L
  ): Resource[IO, StatusService] = {
    for {
      client <- EmberClientBuilder.default[IO].build
      cacheRef <- Resource.eval(
        Ref.of[IO, Option[(Instant, StatusReport)]](None)
      )
    } yield new StatusService(client, config, jwtService, cacheRef, cacheTtlSeconds)
  }
}
