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
import com.tesobe.oidc.stats.{StatsService, StatsEvent}
import com.tesobe.oidc.config.OidcConfig
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.headers.{`Content-Type`, Location}
import org.slf4j.LoggerFactory

class StatsEndpoint(statsService: StatsService[IO], config: OidcConfig) {

  private val logger = LoggerFactory.getLogger(getClass)

  val routes: HttpRoutes[IO] = HttpRoutes.of[IO] {
    case GET -> Root / "stats" =>
      logger.debug("Stats page requested")
      statsService.getStats.flatMap { stats =>
        val html = generateStatsHtml(stats)
        Ok(html).map(_.withContentType(`Content-Type`(MediaType.text.html)))
      }

    case POST -> Root / "stats" / "reset" =>
      logger.info("Stats reset requested")
      statsService.reset.flatMap { _ =>
        SeeOther(Location(Uri.unsafeFromString("/stats")))
      }
  }

  private def generateStatsHtml(
      stats: com.tesobe.oidc.stats.OidcStats
  ): String = {
    val uptime =
      com.tesobe.oidc.stats.StatsService.formatUptime(stats.serverStartTime)
    val startTime =
      com.tesobe.oidc.stats.StatsService.formatTimestamp(stats.serverStartTime)

    val recentEventsHtml = if (stats.recentEvents.nonEmpty) {
      stats.recentEvents
        .map { event =>
          val timestamp =
            com.tesobe.oidc.stats.StatsService.formatTimestamp(event.timestamp)
          val eventClass = event.eventType.toLowerCase.replace(" ", "-")
          s"""
           |<tr class="event-$eventClass">
           |  <td>$timestamp</td>
           |  <td><span class="event-type">${event.eventType}</span></td>
           |  <td>${event.details}</td>
           |</tr>""".stripMargin
        }
        .mkString("")
    } else {
      """<tr><td colspan="3"><em>No recent events</em></td></tr>"""
    }

    val totalTokenGrants =
      stats.authorizationCodeGrantsSuccessful + stats.refreshTokenGrantsSuccessful
    val totalFailedGrants =
      stats.authorizationCodeGrantsFailed + stats.refreshTokenGrantsFailed

    val successRate = if (totalTokenGrants + totalFailedGrants > 0) {
      val rate =
        (totalTokenGrants.toDouble / (totalTokenGrants + totalFailedGrants)) * 100
      f"$rate%.1f%%"
    } else "N/A"

    s"""<!DOCTYPE html>
       |<html>
       |<head>
       |    <title>OIDC Statistics - Real-time</title>
       |    <meta http-equiv="refresh" content="10">
       |    <style>
       |        body {
       |            font-family: 'Segoe UI', Arial, sans-serif;
       |            margin: 0;
       |            padding: 20px;
       |            background-color: #f5f7fa;
       |        }
       |        .container {
       |            max-width: 1200px;
       |            margin: 0 auto;
       |            background: white;
       |            border-radius: 10px;
       |            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
       |            overflow: hidden;
       |        }
       |        .header {
       |            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
       |            color: white;
       |            padding: 30px;
       |            text-align: center;
       |        }
       |        .header h1 {
       |            margin: 0;
       |            font-size: 2.5em;
       |            font-weight: 300;
       |        }
       |        .header p {
       |            margin: 10px 0 0 0;
       |            opacity: 0.9;
       |            font-size: 1.1em;
       |        }
       |        .auto-refresh {
       |            background: rgba(255,255,255,0.2);
       |            padding: 8px 16px;
       |            border-radius: 20px;
       |            display: inline-block;
       |            margin-top: 15px;
       |            font-size: 0.9em;
       |        }
       |        .stats-grid {
       |            display: grid;
       |            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
       |            gap: 20px;
       |            padding: 30px;
       |        }
       |        .stat-card {
       |            background: white;
       |            border-radius: 8px;
       |            padding: 25px;
       |            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
       |            border-left: 4px solid #667eea;
       |            transition: transform 0.2s ease;
       |        }
       |        .stat-card:hover {
       |            transform: translateY(-2px);
       |        }
       |        .stat-card.success {
       |            border-left-color: #10b981;
       |        }
       |        .stat-card.error {
       |            border-left-color: #ef4444;
       |        }
       |        .stat-card.info {
       |            border-left-color: #3b82f6;
       |        }
       |        .stat-number {
       |            font-size: 2.5em;
       |            font-weight: bold;
       |            color: #1f2937;
       |            margin: 0;
       |        }
       |        .stat-label {
       |            color: #6b7280;
       |            font-size: 1em;
       |            margin: 8px 0 0 0;
       |        }
       |        .stat-description {
       |            color: #9ca3af;
       |            font-size: 0.85em;
       |            margin: 5px 0 0 0;
       |        }
       |        .events-section {
       |            margin: 20px 30px;
       |        }
       |        .section-title {
       |            font-size: 1.5em;
       |            color: #1f2937;
       |            margin: 0 0 20px 0;
       |            font-weight: 500;
       |        }
       |        .events-table {
       |            width: 100%;
       |            border-collapse: collapse;
       |            background: white;
       |            border-radius: 8px;
       |            overflow: hidden;
       |            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
       |        }
       |        .events-table th {
       |            background: #f8fafc;
       |            padding: 15px;
       |            text-align: left;
       |            font-weight: 600;
       |            color: #374151;
       |            border-bottom: 1px solid #e5e7eb;
       |        }
       |        .events-table td {
       |            padding: 12px 15px;
       |            border-bottom: 1px solid #f3f4f6;
       |        }
       |        .events-table tr:hover {
       |            background-color: #f9fafb;
       |        }
       |        .event-type {
       |            font-weight: 600;
       |        }
       |        .event-authorization-code-success,
       |        .event-refresh-token-success,
       |        .event-login-success {
       |            border-left: 3px solid #10b981;
       |        }
       |        .event-authorization-code-failed,
       |        .event-refresh-token-failed,
       |        .event-login-failed {
       |            border-left: 3px solid #ef4444;
       |        }
       |        .nav {
       |            padding: 20px 30px;
       |            background: #f8fafc;
       |            border-top: 1px solid #e5e7eb;
       |        }
       |        .nav a {
       |            color: #667eea;
       |            text-decoration: none;
       |            margin-right: 20px;
       |            font-weight: 500;
       |        }
       |        .nav a:hover {
       |            text-decoration: underline;
       |        }
       |        .reset-btn {
       |            background: #ef4444;
       |            color: white;
       |            padding: 8px 16px;
       |            border: none;
       |            border-radius: 6px;
       |            cursor: pointer;
       |            font-weight: 500;
       |            transition: background 0.2s ease;
       |        }
       |        .reset-btn:hover {
       |            background: #dc2626;
       |        }
       |        @media (max-width: 768px) {
       |            .stats-grid {
       |                grid-template-columns: 1fr;
       |                gap: 15px;
       |                padding: 20px;
       |            }
       |            .header h1 {
       |                font-size: 2em;
       |            }
       |            .events-table {
       |                font-size: 0.9em;
       |            }
       |            .events-table th,
       |            .events-table td {
       |                padding: 10px;
       |            }
       |        }
       |    </style>
       |</head>
       |<body>
       |    <div class="container">
       |        <div class="header">
       |            <h1>OIDC Statistics</h1>
       |            <p>Real-time monitoring of OpenID Connect operations</p>
       |            <div class="auto-refresh">
       |                Auto-refreshing every 10 seconds
       |            </div>
       |        </div>
       |
       |        <div class="stats-grid">
       |            <div class="stat-card success">
       |                <h2 class="stat-number">${stats.refreshTokenGrantsSuccessful}</h2>
       |                <p class="stat-label">Refresh Tokens Used</p>
       |                <p class="stat-description">Successfully refreshed access tokens</p>
       |            </div>
       |
       |            <div class="stat-card success">
       |                <h2 class="stat-number">${stats.authorizationCodeGrantsSuccessful}</h2>
       |                <p class="stat-label">Authorization Codes</p>
       |                <p class="stat-description">Successfully exchanged for tokens</p>
       |            </div>
       |
       |            <div class="stat-card success">
       |                <h2 class="stat-number">${stats.loginAttemptsSuccessful}</h2>
       |                <p class="stat-label">Successful Logins</p>
       |                <p class="stat-description">Users authenticated successfully</p>
       |            </div>
       |
       |            <div class="stat-card error">
       |                <h2 class="stat-number">$totalFailedGrants</h2>
       |                <p class="stat-label">Failed Token Grants</p>
       |                <p class="stat-description">Authorization code + refresh token failures</p>
       |            </div>
       |
       |            <div class="stat-card error">
       |                <h2 class="stat-number">${stats.loginAttemptsFailed}</h2>
       |                <p class="stat-label">Failed Logins</p>
       |                <p class="stat-description">Authentication failures</p>
       |            </div>
       |
       |            <div class="stat-card info">
       |                <h2 class="stat-number">$successRate</h2>
       |                <p class="stat-label">Success Rate</p>
       |                <p class="stat-description">Token grant success percentage</p>
       |            </div>
       |
       |            <div class="stat-card info">
       |                <h2 class="stat-number">${stats.totalRequests}</h2>
       |                <p class="stat-label">Total Requests</p>
       |                <p class="stat-description">All HTTP requests processed</p>
       |            </div>
       |
       |            <div class="stat-card info">
       |                <h2 class="stat-number">$uptime</h2>
       |                <p class="stat-label">Server Uptime</p>
       |                <p class="stat-description">Started: $startTime UTC</p>
       |            </div>
       |        </div>
       |
       |        <div class="events-section">
       |            <h2 class="section-title">Recent Events</h2>
       |            <table class="events-table">
       |                <thead>
       |                    <tr>
       |                        <th>Timestamp (UTC)</th>
       |                        <th>Event Type</th>
       |                        <th>Details</th>
       |                    </tr>
       |                </thead>
       |                <tbody>
       |                    $recentEventsHtml
       |                </tbody>
       |            </table>
       |        </div>
       |
       |        <div class="nav">
       |            <a href="/">Back to Home</a>
       |            <a href="/clients">View Clients</a>
       |            <a href="/health">Health Check</a>
       |            <form style="display: inline;" method="post" action="/stats/reset">
       |                <button type="submit" class="reset-btn" onclick="return confirm('Are you sure you want to reset all statistics?')">
       |                    Reset Stats
       |                </button>
       |            </form>
       |        </div>
       |    </div>
       |</body>
       |</html>""".stripMargin
  }
}

object StatsEndpoint {
  def apply(statsService: StatsService[IO], config: OidcConfig): StatsEndpoint =
    new StatsEndpoint(statsService, config)
}
