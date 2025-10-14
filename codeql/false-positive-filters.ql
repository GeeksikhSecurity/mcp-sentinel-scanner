/**
 * @name False Positive Filters for MCP Security Analysis
 * @description Filters out test credentials, demo keys, and placeholder values
 * @kind problem
 * @problem.severity recommendation
 * @id mcp/false-positive-filter
 * @tags security credentials false-positives
 */

import javascript
import python

/**
 * Predicate to identify test/demo indicators
 */
predicate isTestIndicator(string s) {
  s.regexpMatch("(?i).*(test|demo|example|sample|placeholder|dummy|fake|mock).*")
}

/**
 * Predicate to identify placeholder patterns
 */
predicate isPlaceholderPattern(string s) {
  s.regexpMatch("(?i).*(YOUR_|REPLACE_|INSERT_|ADD_).*") or
  s.regexpMatch(".*<[^>]+>.*")
}

/**
 * Predicate to identify fake patterns
 */
predicate isFakePattern(string s) {
  s.regexpMatch("(?i).*(12345+|67890+|abcdef+|qwerty+).*") or
  s.regexpMatch(".*1{4,}.*") or
  s.regexpMatch(".*0{4,}.*")
}

/**
 * Predicate to identify test key prefixes
 */
predicate hasTestKeyPrefix(string s) {
  s.regexpMatch("(?i)(sk_test_|pk_test_|test_|demo_).*")
}

/**
 * Main false positive filter
 */
predicate isFalsePositiveCredential(string credential, string filepath) {
  credential.length() < 8 or
  isTestIndicator(credential) or
  isPlaceholderPattern(credential) or
  isFakePattern(credential) or
  hasTestKeyPrefix(credential) or
  filepath.regexpMatch("(?i).*(test|demo|example)/.*")
}

/**
 * JavaScript credentials with filtering
 */
from StringLiteral str, string value, string filepath
where 
  str.getValue() = value and
  str.getFile().getAbsolutePath() = filepath and
  value.regexpMatch(".*[a-zA-Z0-9]{16,}.*") and
  not isFalsePositiveCredential(value, filepath) and
  value.length() >= 16 and
  value.regexpMatch(".*[a-zA-Z].*") and
  value.regexpMatch(".*[0-9].*")
select str, "Potential credential: " + value.prefix(20) + "..."