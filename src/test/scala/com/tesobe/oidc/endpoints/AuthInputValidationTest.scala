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

import com.tesobe.oidc.endpoints.AuthEndpoint.{MaxPasswordLength, MaxProviderLength, MaxUsernameLength, validateAuthInput}
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers

/** Tests the login form checks in AuthEndpoint. Only empty and oversized fields are refused:
  * length and strength rules apply where credentials are set, not when an existing user signs in.
  */
class AuthInputValidationTest extends AnyFunSuite with Matchers {

  private val user = "testuser"
  private val pass = "password123456"
  private val prov = "obp-test"

  test("The username bound is 100 characters, the size of OBP-API's username column") {
    MaxUsernameLength shouldBe 100
  }

  test("The password and provider bounds are 512 characters") {
    MaxPasswordLength shouldBe 512
    MaxProviderLength shouldBe 512
  }

  // Short credentials that existing users may have

  test("A 7-character username is accepted") {
    validateAuthInput("hongwei", pass, prov) shouldBe Right(("hongwei", pass, prov))
  }

  test("A 1-character username is accepted") {
    validateAuthInput("a", pass, prov).isRight shouldBe true
  }

  test("A short email as username is accepted") {
    validateAuthInput("a@b.de", pass, prov).isRight shouldBe true
  }

  test("A short password is accepted") {
    validateAuthInput(user, "abc", prov) shouldBe Right((user, "abc", prov))
  }

  test("A 1-character password is accepted") {
    validateAuthInput(user, "x", prov).isRight shouldBe true
  }

  test("A short provider is accepted") {
    validateAuthInput(user, pass, "obp").isRight shouldBe true
  }

  test("Short username, password and provider together are accepted") {
    validateAuthInput("bob", "pw", "x") shouldBe Right(("bob", "pw", "x"))
  }

  // Empty fields

  test("An empty username is refused") {
    validateAuthInput("", pass, prov) shouldBe Left("Username is empty")
  }

  test("A whitespace-only username is refused") {
    validateAuthInput("   ", pass, prov) shouldBe Left("Username is empty")
  }

  test("An empty password is refused") {
    validateAuthInput(user, "", prov) shouldBe Left("Password is empty")
  }

  test("An empty provider is refused") {
    validateAuthInput(user, pass, "") shouldBe Left("Provider is empty")
  }

  test("A whitespace-only provider is refused") {
    validateAuthInput(user, pass, "   ") shouldBe Left("Provider is empty")
  }

  // Upper bounds

  test("A username of exactly 100 characters is accepted") {
    validateAuthInput("a" * 100, pass, prov).isRight shouldBe true
  }

  test("A username of 101 characters is refused") {
    validateAuthInput("a" * 101, pass, prov) shouldBe Left("Username is longer than 100 characters")
  }

  test("A password of exactly 512 characters is accepted") {
    validateAuthInput(user, "b" * 512, prov).isRight shouldBe true
  }

  test("A password of 513 characters is refused") {
    validateAuthInput(user, "b" * 513, prov) shouldBe Left("Password is longer than 512 characters")
  }

  test("A provider of exactly 512 characters is accepted") {
    validateAuthInput(user, pass, "c" * 512).isRight shouldBe true
  }

  test("A provider of 513 characters is refused") {
    validateAuthInput(user, pass, "c" * 513) shouldBe Left("Provider is longer than 512 characters")
  }

  test("Very long input is refused (DoS protection)") {
    validateAuthInput("a" * 10000, pass, prov).isLeft shouldBe true
  }

  // Trimming

  test("Username and provider are trimmed") {
    validateAuthInput("  testuser  ", pass, "  obp-test  ") shouldBe Right(("testuser", pass, "obp-test"))
  }

  test("Password is not trimmed") {
    validateAuthInput(user, "  secret  ", prov) shouldBe Right((user, "  secret  ", prov))
  }

  // What the check must not do

  test("The reason for a refusal never contains the input") {
    val password = "p" * 600
    val reason = validateAuthInput(user, password, prov).left.getOrElse(fail("expected a refusal"))
    reason should not include password
  }

  test("Input that looks like SQL is checked by length only; parameterized queries keep it safe") {
    validateAuthInput("admin' OR '1'='1", pass, prov).isRight shouldBe true
  }

  test("Special characters and non-ASCII letters are accepted") {
    validateAuthInput("O'Brien", "p@ssw0rd!#$%", prov).isRight shouldBe true
    validateAuthInput("jürgen", "pässwörd", prov).isRight shouldBe true
  }
}
