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

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import scala.jdk.CollectionConverters._

/** Every path OBP-OIDC sends to OBP-API uses v5.1.0 or newer.
  *
  * OBP-API deployments can switch off the versions below v5.1.0. This test reads the sources and the
  * dev scripts and fails on any `obp/vX.Y.Z` below v5.1.0 that is not listed in [[ObpApiVersionTest.BelowV510]],
  * so a new call on an old version cannot slip in.
  */
class ObpApiVersionTest extends AnyFlatSpec with Matchers {
  import ObpApiVersionTest._

  "The source scan" should "read the real sources" in {
    // An empty result below must mean "no old version", not "no files".
    sourceFiles.size should be > 20
  }

  "OBP-OIDC" should "call OBP-API on v5.1.0 or newer" in {
    callsBelowV510 shouldBe empty
  }

  it should "still have every call site listed in BelowV510" in {
    // A call that moved to v5.1.0 must also leave the list.
    val stale = BelowV510.keys.filterNot { case (file, fragment) =>
      val path = new File(repoRoot, file)
      path.isFile && read(path).contains(fragment)
    }
    stale shouldBe empty
  }

  "The version matcher" should "find old versions with or without a leading slash, and not newer ones" in {
    versionsBelowV510("""s"$base/obp/v4.0.0/x"""") shouldBe List("obp/v4.0.0")
    versionsBelowV510("api POST obp/v5.0.0/banks") shouldBe List("obp/v5.0.0")
    versionsBelowV510(""""/obp/v2.2.0/a" and "/obp/v1.2.1/b"""") shouldBe List("obp/v2.2.0", "obp/v1.2.1")
    versionsBelowV510("/obp/v5.1.0/x") shouldBe empty
    versionsBelowV510("/obp/v6.0.0/root and /obp/v7.0.0/oidc/consents") shouldBe empty
    versionsBelowV510("/obp/dynamic-entity/x") shouldBe empty
  }
}

object ObpApiVersionTest {

  /** (file relative to the repository, fragment of the line) -> why that path is still below v5.1.0.
    * Empty: every call has a v5.1.0 or newer equivalent.
    */
  val BelowV510: Map[(String, String), String] = Map.empty

  /** Where OBP-API paths are written: the Scala sources and their resources, the dev scripts in the
    * repository root, and the example configuration.
    */
  private val SourceRoot = "src"
  private val Extensions = Set("scala", "java", "html", "js", "css", "xml", "conf", "properties", "sh")
  private val RootFiles = (name: String) => name.endsWith(".sh") || name == ".env.example"

  /** This file, whose examples name old versions on purpose. */
  private val ThisFile = "src/test/scala/com/tesobe/oidc/ObpApiVersionTest.scala"

  private val ObpVersion = """obp/v(\d+)\.(\d+)\.(\d+)""".r

  /** The repository root: the nearest directory, from where the tests run, that holds pom.xml and src. */
  lazy val repoRoot: File = {
    val start = new File(sys.props("user.dir")).getAbsoluteFile
    Iterator
      .iterate(start)(_.getParentFile)
      .takeWhile(_ != null)
      .find(dir => new File(dir, "pom.xml").isFile && new File(dir, "src/main/scala/com/tesobe/oidc").isDirectory)
      .getOrElse(sys.error(s"no OBP-OIDC repository at or above $start"))
  }

  def read(file: File): String = new String(Files.readAllBytes(file.toPath), StandardCharsets.UTF_8)

  def relative(file: File): String =
    repoRoot.toPath.relativize(file.toPath).asScala.map(_.toString).mkString("/")

  private def walk(dir: File): List[File] =
    Option(dir.listFiles()).toList.flatten.sortBy(_.getName).flatMap { f =>
      if (f.getName.startsWith(".")) Nil
      else if (f.isDirectory) walk(f)
      else if (Extensions.exists(ext => f.getName.endsWith("." + ext))) List(f)
      else Nil
    }

  lazy val sourceFiles: List[File] =
    walk(new File(repoRoot, SourceRoot)) ++
      Option(repoRoot.listFiles()).toList.flatten.filter(f => f.isFile && RootFiles(f.getName)).sortBy(_.getName)

  /** Every `obp/vX.Y.Z` in `line` whose version is below v5.1.0, as written. */
  def versionsBelowV510(line: String): List[String] =
    ObpVersion
      .findAllMatchIn(line)
      .filter { m =>
        val (major, minor) = (m.group(1).toInt, m.group(2).toInt)
        major < 5 || (major == 5 && minor < 1)
      }
      .map(_.matched)
      .toList

  def callsBelowV510: List[String] =
    for {
      file <- sourceFiles
      rel = relative(file)
      if rel != ThisFile
      (line, index) <- read(file).linesIterator.zipWithIndex.toList
      version <- versionsBelowV510(line)
      if !BelowV510.keys.exists { case (f, fragment) => f == rel && line.contains(fragment) }
    } yield s"$rel:${index + 1} $version"
}
