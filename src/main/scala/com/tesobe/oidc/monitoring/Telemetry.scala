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

import cats.data.Kleisli
import cats.effect.IO
import io.circe.Json
import io.circe.syntax._
import org.http4s.{HttpApp, Request, Status}

import java.lang.management.ManagementFactory
import java.util.UUID
import scala.collection.mutable

/** Aggregated numbers about how this server is running, in the shape of
  * OBP-API's GET /obp/v7.0.0/management/telemetry, so a monitor such as
  * OBP-Sentinel reads both the same way. Like OBP-API's Telemetry it never
  * records who made a call.
  */
object Telemetry {

  /** Names this process in the report, as OBP-API's api_instance_id does. */
  val instanceId: String = s"obp-oidc_${UUID.randomUUID()}"

  /** The commit this server was built from, from git.properties (see pom.xml). */
  lazy val gitCommit: String =
    Option(getClass.getResourceAsStream("/git.properties"))
      .flatMap { stream =>
        try {
          val props = new java.util.Properties()
          props.load(stream)
          Option(props.getProperty("git.commit.id"))
        } finally stream.close()
      }
      .filter(_.nonEmpty)
      .getOrElse("unknown")

  private final class Timing(var count: Long = 0, var totalSeconds: Double = 0, var maxSeconds: Double = 0)

  private val timers = mutable.LinkedHashMap.empty[(String, List[(String, String)]), Timing]

  def recordTiming(name: String, tags: Map[String, String], seconds: Double): Unit =
    synchronized {
      val timing = timers.getOrElseUpdate((name, tags.toList.sorted), new Timing())
      timing.count += 1
      timing.totalSeconds += seconds
      timing.maxSeconds = math.max(timing.maxSeconds, seconds)
    }

  def clear(): Unit = synchronized(timers.clear())

  private def statusClass(status: Status): String = s"${status.code / 100}xx"

  /** The route a request took. This server's paths hold no ids, except the
    * name of a stylesheet; anything it does not serve is "unmatched", so
    * probes for random paths do not each become a meter.
    */
  def route(req: Request[IO], status: Status): String =
    if (status == Status.NotFound) "unmatched"
    else if (req.pathInfo.renderString.startsWith("/static/css/")) "/static/css/FILE"
    else req.pathInfo.renderString

  /** Times every request by its route and status class. */
  def timed(app: HttpApp[IO]): HttpApp[IO] =
    Kleisli { req =>
      IO.monotonic.flatMap { started =>
        app.run(req).flatTap { resp =>
          IO.monotonic.map { ended =>
            recordTiming(
              "oidc.http.requests",
              Map("method" -> req.method.name, "route" -> route(req, resp.status), "status" -> statusClass(resp.status)),
              (ended - started).toNanos / 1e9
            )
          }
        }
      }
    }

  private def meter(name: String, kind: String, unit: String, tags: Map[String, String], measurements: (String, Double)*): Json =
    Json.obj(
      "name" -> name.asJson,
      "type" -> kind.asJson,
      "base_unit" -> unit.asJson,
      "tags" -> tags.asJson,
      "measurements" -> measurements.toMap.asJson
    )

  def report(namePrefix: Option[String]): Json = {
    val runtime = Runtime.getRuntime
    val timerMeters = synchronized {
      timers.toList.map { case ((name, tags), t) =>
        (name, tags.toMap, meter(name, "timer", "seconds", tags.toMap,
          "count" -> t.count.toDouble, "total_time" -> t.totalSeconds, "max" -> t.maxSeconds))
      }
    }
    val gauges = List(
      ("process.uptime", ManagementFactory.getRuntimeMXBean.getUptime / 1000.0, "seconds"),
      ("jvm.memory.used", (runtime.totalMemory - runtime.freeMemory).toDouble, "bytes"),
      ("jvm.memory.max", runtime.maxMemory.toDouble, "bytes"),
      ("jvm.threads.live", ManagementFactory.getThreadMXBean.getThreadCount.toDouble, "threads")
    ).map { case (name, value, unit) => (name, Map.empty[String, String], meter(name, "gauge", unit, Map.empty, "value" -> value)) }
    val meters = (timerMeters ++ gauges)
      .filter { case (name, _, _) => namePrefix.forall(name.startsWith) }
      .sortBy { case (name, tags, _) => name + tags.toList.sorted.mkString }
      .map(_._3)
    Json.obj(
      "api_instance_id" -> instanceId.asJson,
      "git_commit" -> gitCommit.asJson,
      "meters" -> meters.asJson
    )
  }
}
