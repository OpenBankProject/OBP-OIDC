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

import java.io.{ByteArrayOutputStream, OutputStream, PrintStream}
import java.nio.charset.StandardCharsets
import scala.collection.mutable

/** The server's recent output, kept in memory per level as OBP-API keeps its
  * log cache, so a monitor such as OBP-Sentinel can read it through
  * GET /monitoring/log-cache/LEVEL in the same shape.
  *
  * Half of this server writes through println and half through logback (whose
  * console appender writes to stdout too), so the cache keeps every line of
  * stdout and stderr. A logback line has its level in it; any other line is
  * an error on stderr, else takes the level its text starts with (DEBUG ...,
  * WARNING ...), else info. Stack trace lines join the line before them.
  */
object LogCache {

  val Levels: List[String] = List("trace", "debug", "info", "warning", "error")

  final case class Entry(level: String, message: String, timestamp: Long)

  private val MaxPerLevel = 1000
  private val MaxMessageLength = 4000

  private val byLevel: Map[String, mutable.ArrayDeque[Entry]] =
    Levels.map(_ -> mutable.ArrayDeque.empty[Entry]).toMap
  private val everyLevel = mutable.ArrayDeque.empty[Entry]

  // As logback.xml writes it: "12:34:56.789 [thread] LEVEL logger - message"
  private val LogbackLine =
    """^\d{2}:\d{2}:\d{2}\.\d{3} \[[^\]]*\] (TRACE|DEBUG|INFO|WARN|ERROR) +(.*)$""".r
  private val Continuation = """^(?:\s+|Caused by:|\.\.\. \d+ more).*""".r

  private def levelOfText(line: String): String = {
    val upper = line.take(16).toUpperCase
    if (upper.startsWith("ERROR") || upper.startsWith("STARTUP ABORTED")) "error"
    else if (upper.startsWith("WARN")) "warning"
    else if (upper.startsWith("DEBUG")) "debug"
    else if (upper.startsWith("TRACE")) "trace"
    else "info"
  }

  private def keep(entries: mutable.ArrayDeque[Entry], entry: Entry, max: Int): Unit = {
    entries.prepend(entry) // newest first, as OBP-API returns them
    if (entries.length > max) entries.removeLast()
  }

  private def replaceNewest(entries: mutable.ArrayDeque[Entry], old: Entry, updated: Entry): Unit =
    if (entries.nonEmpty && (entries.head eq old)) entries.update(0, updated)

  def record(level: String, message: String, now: Long = System.currentTimeMillis()): Unit =
    synchronized {
      val entry = Entry(level.toUpperCase, message.take(MaxMessageLength), now)
      keep(byLevel(level), entry, MaxPerLevel)
      keep(everyLevel, entry, MaxPerLevel * Levels.length)
    }

  /** One line written to stdout or stderr. */
  def recordLine(line: String, fromStderr: Boolean, now: Long = System.currentTimeMillis()): Unit =
    synchronized {
      if (line.trim.nonEmpty) line match {
        case Continuation() if everyLevel.nonEmpty =>
          val last = everyLevel.head
          if (last.message.length < MaxMessageLength) {
            val updated = last.copy(message = (last.message + "\n" + line).take(MaxMessageLength))
            replaceNewest(byLevel(last.level.toLowerCase), last, updated)
            replaceNewest(everyLevel, last, updated)
          }
        case LogbackLine(level, rest) =>
          record(if (level == "WARN") "warning" else level.toLowerCase, rest, now)
        case _ =>
          record(if (fromStderr) "error" else levelOfText(line), line, now)
      }
    }

  /** The kept lines of one level, or of every level ("all"), newest first. */
  def tail(level: String, limit: Option[Int], offset: Option[Int]): List[Entry] =
    synchronized {
      val entries = if (level == "all") everyLevel else byLevel(level)
      val start = offset.getOrElse(0)
      entries.slice(start, limit.fold(entries.length)(start + _)).toList
    }

  def clear(): Unit =
    synchronized {
      byLevel.values.foreach(_.clear())
      everyLevel.clear()
    }

  /** Writes through to `out` and keeps each complete line. */
  private final class LineTee(out: OutputStream, fromStderr: Boolean) extends OutputStream {
    private val line = new ByteArrayOutputStream()

    private def endLine(): Unit = {
      val text = line.toString(StandardCharsets.UTF_8.name).stripSuffix("\r")
      line.reset()
      try recordLine(text, fromStderr)
      catch { case _: Throwable => () } // never let keeping a line break the output itself
    }

    override def write(b: Int): Unit = synchronized {
      out.write(b)
      if (b == '\n') endLine() else if (line.size < MaxMessageLength) line.write(b)
    }

    override def write(b: Array[Byte], off: Int, len: Int): Unit = synchronized {
      out.write(b, off, len)
      var i = off
      while (i < off + len) {
        if (b(i) == '\n') endLine() else if (line.size < MaxMessageLength) line.write(b(i).toInt)
        i += 1
      }
    }

    override def flush(): Unit = out.flush()
  }

  @volatile private var installed = false

  /** Keep everything written to stdout and stderr, as well as writing it as before. Call once, first thing. */
  def install(): Unit = synchronized {
    if (!installed) {
      installed = true
      val out = new PrintStream(new LineTee(System.out, fromStderr = false), true, StandardCharsets.UTF_8.name)
      val err = new PrintStream(new LineTee(System.err, fromStderr = true), true, StandardCharsets.UTF_8.name)
      System.setOut(out)
      System.setErr(err)
      // println goes through scala.Console, which took System.out when it loaded. Its setters are
      // private[scala]: without them only logback's lines are kept.
      try {
        Console.getClass.getMethod("setOutDirect", classOf[PrintStream]).invoke(Console, out)
        Console.getClass.getMethod("setErrDirect", classOf[PrintStream]).invoke(Console, err)
      } catch { case _: Exception => () }
    }
  }
}
