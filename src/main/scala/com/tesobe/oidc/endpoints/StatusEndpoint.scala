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

  private def renderDetailBlock(d: com.tesobe.oidc.status.CheckDetail): String = {
    def line(label: String, value: String): String =
      s"""<div class="detail-line"><span class="detail-label">${htmlEncode(label)}</span> <span class="detail-value">${htmlEncode(value)}</span></div>"""
    def block(label: String, value: String): String =
      s"""<div class="detail-line"><span class="detail-label">${htmlEncode(label)}</span></div><pre class="detail-pre">${htmlEncode(value)}</pre>"""

    val urlLine = (d.method, d.url) match {
      case (Some(m), Some(u)) => Some(line(m, u))
      case (None, Some(u))    => Some(line("URL", u))
      case _                  => None
    }

    val parts = List(
      urlLine,
      d.responseStatus.map(s => line("Response status", s.toString)),
      d.error.map(e => block("Error", e))
    ).flatten

    parts.mkString("\n")
  }

  private def renderRow(c: StatusCheck): String = {
    val label = if (c.ok) "OK" else "FAIL"
    val cls = if (c.ok) "ok" else "fail"
    val detailRow = c.detail match {
      case Some(d) if !c.ok =>
        val body = renderDetailBlock(d)
        if (body.isEmpty) ""
        else s"""
                |<tr class="$cls detail-row">
                |  <td colspan="2"><div class="detail-box">$body</div></td>
                |</tr>""".stripMargin
      case _ => ""
    }
    s"""<tr class="$cls">
       |  <td class="name">${htmlEncode(c.name)}</td>
       |  <td class="badge"><span class="pill pill-$cls">$label</span></td>
       |</tr>$detailRow""".stripMargin
  }

  private def renderHtml(report: StatusReport): String = {
    val overallLabel = if (report.overallOk) "All systems operational" else "Degraded service"
    val overallCls = if (report.overallOk) "ok" else "fail"
    val rows = report.checks.map(renderRow).mkString("\n")
    val generated = htmlEncode(report.generatedAt.toString)
    val credentialMethod = htmlEncode(report.credentialVerificationMethod)
    val clientMethod = htmlEncode(report.clientVerificationMethod)

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
       |    .config-box {
       |      background: #f3f4f6;
       |      border-left: 3px solid #6b7280;
       |      padding: 10px 14px;
       |      border-radius: 4px;
       |      margin: 0 0 20px 0;
       |      font-size: 0.9rem;
       |      color: #374151;
       |    }
       |    .config-line { margin: 4px 0; }
       |    .config-label { font-weight: 600; color: #1f2937; margin-right: 6px; }
       |    .config-value { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
       |    tr.detail-row td { padding: 0 16px 12px 16px; border-bottom: 1px solid #e9ecef; }
       |    .detail-box {
       |      background: #fff7f7;
       |      border-left: 3px solid #ef4444;
       |      padding: 10px 14px;
       |      border-radius: 4px;
       |      font-size: 0.85rem;
       |      color: #3f3f46;
       |    }
       |    .detail-line { margin: 4px 0; word-break: break-all; }
       |    .detail-label { font-weight: 600; color: #991b1b; margin-right: 6px; }
       |    .detail-value { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
       |    .detail-pre {
       |      margin: 4px 0 8px 0;
       |      padding: 8px 10px;
       |      background: #fff;
       |      border: 1px solid #fecaca;
       |      border-radius: 4px;
       |      overflow-x: auto;
       |      white-space: pre-wrap;
       |      word-break: break-word;
       |      font-size: 0.8rem;
       |      color: #1f2937;
       |    }
       |  </style>
       |</head>
       |<body>
       |  <div class="container status-wrap">
       |    <h1>Service Status</h1>
       |    <p class="subtitle">OBP OIDC Provider</p>
       |    <div class="overall $overallCls" data-testid="status-overall">$overallLabel</div>
       |    <div class="config-box" data-testid="status-config">
       |      <div class="config-line">
       |        <span class="config-label">Credential verification:</span>
       |        <span class="config-value" data-testid="status-credential-method">$credentialMethod</span>
       |      </div>
       |      <div class="config-line">
       |        <span class="config-label">Client verification:</span>
       |        <span class="config-value" data-testid="status-client-method">$clientMethod</span>
       |      </div>
       |    </div>
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
