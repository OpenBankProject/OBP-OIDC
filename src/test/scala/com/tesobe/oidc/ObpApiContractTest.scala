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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OBP-OIDC.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.tesobe.oidc

import io.circe.Json
import io.circe.parser.parse
import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.io.File

/** The contract between OBP-OIDC and OBP-API.
  *
  * `obp-api-contract/contract.json` lists every OBP-API call OBP-OIDC makes, with the response fields the
  * code reads. `obp-api-contract/snapshot.json` is what an OBP-API documents for those calls, written by
  * `obp-api-contract/snapshot.py` from its resource docs. These tests need no server: they check that the
  * list matches the code, and that every call reaches an endpoint OBP-API documents, with every field the
  * code reads. Retake the snapshot from a new OBP-API build to learn whether that build breaks OBP-OIDC.
  */
class ObpApiContractTest extends AnyFlatSpec with Matchers {
  import ObpApiContractTest._
  import ObpApiVersionTest.{read, repoRoot}

  "Every call in the contract" should "be in its source file" in {
    // Each needle of an entry must occur in the entry's source file.
    val gone = for {
      call <- calls
      text = read(new File(repoRoot, call.source))
      needle <- call.needles
      if !text.contains(needle)
    } yield s"${call.key} - $needle"
    gone shouldBe empty
  }

  "Every OBP-API call in the source" should "be in the contract" in {
    // A line that builds an OBP-API path must contain a needle of a call listed for that file, so a new
    // call cannot reach OBP-API without its fields being recorded. Lines that only name a path in a
    // message are listed in NotCalls.
    val unlisted = obpPathLines.filterNot { case (file, _, line) =>
      calls.exists(c => c.source == file && c.needles.exists(n => line.contains(n.trim))) ||
      NotCalls.keys.exists { case (f, fragment) => f == file && line.contains(fragment) }
    }
    unlisted.map { case (file, n, line) => s"$file:$n ${line.trim}" } shouldBe empty
  }

  it should "still have every line listed in NotCalls" in {
    val stale = NotCalls.keys.filterNot { case (file, fragment) =>
      val path = new File(repoRoot, file)
      path.isFile && read(path).contains(fragment)
    }
    stale shouldBe empty
  }

  "The snapshot" should "be taken for this contract" in {
    // snapshot.json must hold exactly the calls of contract.json; otherwise rerun snapshot.py.
    calls.map(_.key).toSet shouldBe endpoints.map(endpointKey).toSet
  }

  "Every call" should "reach an endpoint OBP-API documents" in {
    // Unless the entry records why not (undocumented_endpoint). A recorded gap that OBP-API has since
    // documented fails too, so the note goes.
    val problems = calls.flatMap { call =>
      val entry = documented(call)
      val missing = entry.forall(e => bool(e, "missing"))
      val gap = (missing, call.undocumentedEndpoint) match {
        case (true, None) => List(s"${call.key}: no documented endpoint")
        case (false, Some(_)) =>
          List(s"${call.key}: now documented as ${entry.map(str(_, "operation_id")).getOrElse("")}; drop undocumented_endpoint")
        case (true, Some(why)) =>
          info(s"known gap - ${call.key}: $why")
          Nil
        case (false, None) => Nil
      }
      val ambiguous = entry.toList.flatMap(e => strings(e, "ambiguous")) match {
        case Nil => Nil
        case ops => List(s"${call.key}: matches several endpoints ${ops.mkString(", ")}")
      }
      gap ++ ambiguous
    }
    problems shouldBe empty
  }

  "Every field the code reads" should "be documented" in {
    // Unless the entry lists it in undocumented_fields; a listed field that OBP-API now documents fails,
    // so the list shrinks.
    val problems = for {
      call <- calls
      entry <- documented(call).toList
      if !bool(entry, "missing")
      fields = strings(entry, "fields").toSet
      problem <-
        undocumentedReads(call.reads, fields).flatMap { read =>
          if (call.undocumentedFields.contains(read)) {
            info(s"known gap - ${call.key}: $read is not documented")
            Nil
          } else List(s"${call.key} (${str(entry, "operation_id")}): reads $read, not documented")
        } ++
          call.undocumentedFields.filter(fields.contains).map { field =>
            s"${call.key}: $field is now documented; drop it from undocumented_fields"
          }
    } yield problem
    problems shouldBe empty
  }

  "The field check" should "report a renamed or removed field" in {
    // With `consumer_secret` gone from the documented fields, the read is reported, and a read with an
    // alternative (`client_id|consumer_key`) passes on either field.
    undocumentedReads(List("consumer_id", "consumer_secret"), Set("consumer_id", "consumer_key")) shouldBe
      List("consumer_secret")
    undocumentedReads(List("client_id|consumer_key"), Set("consumer_key")) shouldBe empty
    undocumentedReads(List("client_id|consumer_key"), Set.empty) shouldBe List("client_id|consumer_key")
  }
}

object ObpApiContractTest {
  import ObpApiVersionTest.{read, relative, repoRoot}

  /** (file relative to the repository, fragment of the line) -> why the line names an OBP-API path
    * without calling it.
    */
  val NotCalls: Map[(String, String), String] = Map(
    ("src/main/scala/com/tesobe/oidc/auth/ObpApiCredentialsService.scala", "OBP API GET /obp/v6.0.0/providers") ->
      "Messages printed when the providers call fails.",
    ("src/main/scala/com/tesobe/oidc/auth/HybridAuthService.scala", "via OBP API endpoint (GET /obp/v6.0.0/") ->
      "Log messages before HybridAuthService hands a lookup to ObpApiCredentialsService or ObpApiClientService.",
    ("src/main/scala/com/tesobe/oidc/server/OidcServer.scala", "(GET /obp/v6.0.0/providers - no special role") ->
      "Startup message.",
    ("src/main/scala/com/tesobe/oidc/server/OidcServer.scala", "No special role required for GET /obp/v6.0.0/providers") ->
      "Startup message.",
    ("src/main/scala/com/tesobe/oidc/server/OidcServer.scala", "\", \"GET /obp/v") ->
      "The startup list of Roles and the endpoints that need them.",
    ("src/main/scala/com/tesobe/oidc/server/OidcServer.scala", "\", \"POST /obp/v") ->
      "The startup list of Roles and the endpoints that need them.",
    ("src/main/scala/com/tesobe/oidc/status/StatusService.scala", "val endpoint = s\"${baseUrl.stripSuffix(\"/\")}/obp/v6.0.0/root\"") ->
      "The URL the status page shows; ObpApiCredentialsService.checkObpApiRoot makes the call."
  )

  final case class Call(
      verb: String,
      path: String,
      source: String,
      needles: List[String],
      reads: List[String],
      undocumentedFields: List[String],
      undocumentedEndpoint: Option[String]
  ) {
    def key: String = s"$verb $path"
  }

  private def load(name: String): Json =
    parse(read(new File(repoRoot, s"obp-api-contract/$name"))).fold(e => throw e, identity)

  def str(json: Json, field: String): String = json.hcursor.get[String](field).getOrElse("")
  def bool(json: Json, field: String): Boolean = json.hcursor.get[Boolean](field).getOrElse(false)
  def strings(json: Json, field: String): List[String] = json.hcursor.get[List[String]](field).getOrElse(Nil)
  def endpointKey(json: Json): String = s"${str(json, "verb")} ${str(json, "path")}"

  lazy val calls: List[Call] =
    load("contract.json").hcursor.get[List[Json]]("calls").fold(e => throw e, identity).map { c =>
      Call(
        verb = str(c, "verb"),
        path = str(c, "path"),
        source = str(c, "source"),
        needles = strings(c, "needles"),
        reads = strings(c, "reads"),
        undocumentedFields = strings(c, "undocumented_fields"),
        undocumentedEndpoint = c.hcursor.get[String]("undocumented_endpoint").toOption
      )
    }

  lazy val endpoints: List[Json] =
    load("snapshot.json").hcursor.get[List[Json]]("endpoints").fold(e => throw e, identity)

  /** The snapshot entry for a call, or None. */
  def documented(call: Call): Option[Json] = endpoints.find(e => endpointKey(e) == call.key)

  /** The reads that `fields` does not document. A read written `a|b` is satisfied by either field. */
  def undocumentedReads(reads: List[String], fields: Set[String]): List[String] =
    reads.filterNot(_.split('|').exists(fields.contains))

  private def scalaFiles(dir: File): List[File] =
    Option(dir.listFiles()).toList.flatten.sortBy(_.getName).flatMap { f =>
      if (f.isDirectory) scalaFiles(f) else if (f.getName.endsWith(".scala")) List(f) else Nil
    }

  /** Lines of the main Scala sources that build an OBP-API path, skipping comments:
    * (file relative to the repository, line number, line).
    */
  def obpPathLines: List[(String, Int, String)] =
    for {
      file <- scalaFiles(new File(repoRoot, "src/main/scala"))
      rel = relative(file)
      (line, index) <- read(file).linesIterator.zipWithIndex.toList
      code = line.trim
      if !(code.startsWith("//") || code.startsWith("*") || code.startsWith("/*"))
      if code.contains("\"") && (code.contains("/obp/v") || code.contains("/obp/$"))
    } yield (rel, index + 1, line)
}
