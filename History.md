# 4.1.0 / 2020-06-13

  * Add pre-defined generators and compatibility tests for SHA384 and SHA512

# 4.0.0 / 2020-06-13

  * Breaking: Implement PBKFD2 key derivation (#18)

# 3.1.0 / 2019-04-29

  * Add encrypt/decrypt without base64 encoding (thanks [@mcgillowen](https://github.com/mcgillowen))
  * Test: Drop support for pre-1.10, add 1.12
  * Test: Simplify / cleanup test file

# 3.0.1 / 2019-01-29

  * Fix: v3 versions require another go-modules name

# 3.0.0 / 2018-11-02

  * Breaking: Fix race condition with guessing messagedigest

# 2.0.2 / 2018-09-18

  * Fix: v2 versions require another go-modules name

# 2.0.1 / 2018-09-18

  * Add modules file
  * Fix some linter warnings
  * Add benchmarks

# 2.0.0 / 2018-09-11

  * Make digest function configurable on encrypt, add tests
  * message digest support sha1 and sha256 (thanks @yoozoo)

# 1.2.0 / 2018-04-26

  * Add byte-operations, remove import path comment

# 1.1.0 / 2017-09-18

  * Add salt validation and improve comments
  * Added ability to pass custom salt to everyencrypt call (thanks @VojtechBartos)
