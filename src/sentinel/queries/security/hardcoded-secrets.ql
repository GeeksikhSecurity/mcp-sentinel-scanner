/**
 * @name Hardcoded secrets and API keys
 * @description Detects hardcoded secrets, API keys, and credentials in source code
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id js/hardcoded-secrets
 * @tags security
 *       external/cwe/cwe-798
 *       pci-dss
 */

import javascript

/**
 * A string literal that may contain a hardcoded secret
 */
class PotentialSecret extends StringLiteral {
  PotentialSecret() {
    // API keys patterns
    this.getValue().regexpMatch("(?i)(api[_-]?key|apikey)\\s*[=:]\\s*['\"][a-zA-Z0-9]{20,}['\"]") or
    
    // Secret keys
    this.getValue().regexpMatch("(?i)(secret[_-]?key|secretkey)\\s*[=:]\\s*['\"][a-zA-Z0-9]{20,}['\"]") or
    
    // Access tokens
    this.getValue().regexpMatch("(?i)(access[_-]?token|accesstoken)\\s*[=:]\\s*['\"][a-zA-Z0-9]{20,}['\"]") or
    
    // Database passwords
    this.getValue().regexpMatch("(?i)(password|pwd|pass)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]") or
    
    // JWT tokens
    this.getValue().regexpMatch("(?i)eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+") or
    
    // AWS keys
    this.getValue().regexpMatch("(?i)AKIA[0-9A-Z]{16}") or
    
    // Private keys
    this.getValue().regexpMatch("-----BEGIN (RSA )?PRIVATE KEY-----") or
    
    // Generic high-entropy strings
    (this.getValue().length() > 20 and
     this.getValue().regexpMatch("[a-zA-Z0-9+/]{20,}") and
     this.getEntropy() > 4.5)
  }
  
  /**
   * Calculate Shannon entropy of the string
   */
  float getEntropy() {
    result = this.getValue().entropy()
  }
  
  /**
   * Check if this appears to be a test or example value
   */
  predicate isTestValue() {
    this.getValue().regexpMatch("(?i).*(test|example|demo|fake|mock|placeholder).*") or
    this.getValue().regexpMatch("(?i)your[_-]?key[_-]?here") or
    this.getValue().regexpMatch("(?i)insert[_-]?token") or
    this.getValue() = "xxxxxxxxxxxxxxxx" or
    this.getValue() = "1234567890abcdef"
  }
  
  /**
   * Check if this is in a test file
   */
  predicate isInTestFile() {
    this.getFile().getBaseName().regexpMatch(".*\\.(test|spec)\\.(js|ts)$") or
    this.getFile().getAbsolutePath().regexpMatch(".*/test/.*") or
    this.getFile().getAbsolutePath().regexpMatch(".*/__tests__/.*")
  }
  
  /**
   * Check if this is in a configuration example file
   */
  predicate isInExampleFile() {
    this.getFile().getBaseName().regexpMatch(".*\\.example\\.(js|ts|json)$") or
    this.getFile().getAbsolutePath().regexpMatch(".*/examples?/.*") or
    this.getFile().getBaseName() = "README.md"
  }
}

/**
 * A variable assignment that may contain a hardcoded secret
 */
class SecretAssignment extends AssignmentExpr {
  SecretAssignment() {
    this.getRhs() instanceof PotentialSecret and
    this.getLhs().(VarAccess).getName().regexpMatch("(?i).*(key|secret|token|password|pwd|pass|auth).*")
  }
}

/**
 * A property assignment that may contain a hardcoded secret
 */
class SecretProperty extends Property {
  SecretProperty() {
    this.getName().regexpMatch("(?i).*(key|secret|token|password|pwd|pass|auth).*") and
    this.getValue() instanceof PotentialSecret
  }
}

from ASTNode secret, string message, string secretType
where
  (
    secret instanceof PotentialSecret and
    not secret.(PotentialSecret).isTestValue() and
    not secret.(PotentialSecret).isInTestFile() and
    not secret.(PotentialSecret).isInExampleFile() and
    message = "Hardcoded secret detected in string literal" and
    secretType = "string_literal"
  ) or
  (
    secret instanceof SecretAssignment and
    not secret.(SecretAssignment).getRhs().(PotentialSecret).isTestValue() and
    not secret.(SecretAssignment).getRhs().(PotentialSecret).isInTestFile() and
    message = "Hardcoded secret in variable assignment" and
    secretType = "assignment"
  ) or
  (
    secret instanceof SecretProperty and
    not secret.(SecretProperty).getValue().(PotentialSecret).isTestValue() and
    not secret.(SecretProperty).getValue().(PotentialSecret).isInTestFile() and
    message = "Hardcoded secret in object property" and
    secretType = "property"
  )
select secret, message + " (type: " + secretType + ")"