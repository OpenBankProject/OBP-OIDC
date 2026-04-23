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

package com.tesobe.oidc.endpoints

import cats.effect.IO
import com.tesobe.oidc.endpoints.HtmlUtils.htmlEncode
import com.tesobe.oidc.status.{StatusCheck, StatusReport, StatusService}
import org.http4s._
import org.http4s.circe._
import org.http4s.dsl.io._
import org.http4s.headers.`Content-Type`

class StatusEndpoint(statusService: StatusService) {

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "status" =>
      statusService.getReport.flatMap { report =>
        Ok(renderHtml(report))
          .map(_.withContentType(`Content-Type`(MediaType.text.html)))
      }

    case GET -> Root / "status.json" =>
      statusService.getReport.flatMap { report =>
        Ok(StatusReport.toJson(report))
      }
  }

  private def renderRow(c: StatusCheck): String = {
    val label = if (c.ok) "OK" else "FAIL"
    val cls = if (c.ok) "ok" else "fail"
    s"""<tr class="$cls">
       |  <td class="name">${htmlEncode(c.name)}</td>
       |  <td class="badge"><span class="pill pill-$cls">$label</span></td>
       |</tr>""".stripMargin
  }

  private def renderHtml(report: StatusReport): String = {
    val overallLabel = if (report.overallOk) "All systems operational" else "Degraded service"
    val overallCls = if (report.overallOk) "ok" else "fail"
    val rows = report.checks.map(renderRow).mkString("\n")
    val generated = htmlEncode(report.generatedAt.toString)

    s"""<!DOCTYPE html>
       |<html>
       |<head>
       |  <title>Status - OBP OIDC Provider</title>
       |  <meta name="viewport" content="width=device-width, initial-scale=1.0">
       |  <link rel="stylesheet" href="/static/css/main.css">
       |  <style>
       |    .status-wrap { max-width: 720px; margin: 40px auto; padding: 30px; }
       |    .overall {
       |      display: inline-block;
       |      padding: 12px 20px;
       |      border-radius: 8px;
       |      font-weight: 600;
       |      margin: 20px 0 30px 0;
       |    }
       |    .overall.ok   { background: #d1fae5; color: #065f46; border: 2px solid #10b981; }
       |    .overall.fail { background: #fee2e2; color: #991b1b; border: 2px solid #ef4444; }
       |    table.status {
       |      width: 100%;
       |      border-collapse: collapse;
       |      margin-top: 10px;
       |    }
       |    table.status td {
       |      padding: 12px 16px;
       |      border-bottom: 1px solid #e9ecef;
       |    }
       |    table.status tr:last-child td { border-bottom: none; }
       |    .name { font-weight: 500; color: #2c3e50; }
       |    .badge { text-align: right; width: 80px; }
       |    .pill {
       |      display: inline-block;
       |      padding: 4px 10px;
       |      border-radius: 999px;
       |      font-size: 0.85rem;
       |      font-weight: 600;
       |    }
       |    .pill-ok   { background: #d1fae5; color: #065f46; }
       |    .pill-fail { background: #fee2e2; color: #991b1b; }
       |    .meta { color: #6b7280; font-size: 0.9rem; margin-top: 20px; }
       |  </style>
       |</head>
       |<body>
       |  <div class="container status-wrap">
       |    <h1>Service Status</h1>
       |    <p class="subtitle">OBP OIDC Provider</p>
       |    <div class="overall $overallCls" data-testid="status-overall">$overallLabel</div>
       |    <table class="status" data-testid="status-table">
       |      <tbody>
       |$rows
       |      </tbody>
       |    </table>
       |    <p class="meta">Generated at $generated. Results cached briefly. See also <a href="/status.json">/status.json</a>.</p>
       |    <p class="meta"><a href="/">Home</a></p>
       |  </div>
       |</body>
       |</html>""".stripMargin
  }
}

object StatusEndpoint {
  def apply(statusService: StatusService): StatusEndpoint =
    new StatusEndpoint(statusService)
}
