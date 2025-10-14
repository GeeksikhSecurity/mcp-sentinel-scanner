/**
 * @name Cardholder data exposure risks
 * @description Detects potential exposure of cardholder data in logs, console outputs, and error messages
 * @kind problem
 * @problem.severity error
 * @security-severity 9.5
 * @precision high
 * @id js/pci-cardholder-data-exposure
 * @tags security
 *       pci-dss
 *       external/cwe/cwe-532
 */

import javascript

/**
 * A pattern that matches potential credit card numbers
 */
class CreditCardPattern extends StringLiteral {
  CreditCardPattern() {
    // Visa: 4xxx-xxxx-xxxx-xxxx
    this.getValue().regexpMatch("4[0-9]{3}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}") or
    
    // MasterCard: 5xxx-xxxx-xxxx-xxxx
    this.getValue().regexpMatch("5[1-5][0-9]{2}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}") or
    
    // American Express: 3xxx-xxxxxx-xxxxx
    this.getValue().regexpMatch("3[47][0-9]{2}[\\s-]?[0-9]{6}[\\s-]?[0-9]{5}") or
    
    // Discover: 6xxx-xxxx-xxxx-xxxx
    this.getValue().regexpMatch("6(?:011|5[0-9]{2})[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}") or
    
    // Generic 13-19 digit pattern
    this.getValue().regexpMatch("[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{1,7}")
  }
  
  predicate isTestData() {
    // Common test credit card numbers
    this.getValue().regexpMatch("4111111111111111") or  // Visa test
    this.getValue().regexpMatch("5555555555554444") or  // MasterCard test
    this.getValue().regexpMatch("378282246310005") or   // Amex test
    this.getValue().regexpMatch("4000000000000002") or  // Visa test declined
    // Pattern suggests test data
    this.getValue().regexpMatch(".*test.*") or
    this.getValue().regexpMatch(".*example.*") or
    this.getValue().regexpMatch(".*demo.*")
  }
}

/**
 * A variable or property that may contain cardholder data
 */
class CardholderDataIdentifier extends VarAccess {
  CardholderDataIdentifier() {
    this.getName().regexpMatch("(?i).*(card|credit|payment|pan|ccn|cc_?number|card_?number).*") or
    this.getName().regexpMatch("(?i).*(cvv|cvc|security_?code|exp|expiry|expiration).*")
  }
}

/**
 * Logging or output operations that may expose cardholder data
 */
class LoggingOperation extends DataFlow::CallNode {
  LoggingOperation() {
    // Console logging
    this.getCalleeName() = "log" and this.getReceiver().getAPropertyRead("console").flowsTo(this.getReceiver()) or
    this.getCalleeName() = "error" and this.getReceiver().getAPropertyRead("console").flowsTo(this.getReceiver()) or
    this.getCalleeName() = "warn" and this.getReceiver().getAPropertyRead("console").flowsTo(this.getReceiver()) or
    this.getCalleeName() = "info" and this.getReceiver().getAPropertyRead("console").flowsTo(this.getReceiver()) or
    this.getCalleeName() = "debug" and this.getReceiver().getAPropertyRead("console").flowsTo(this.getReceiver()) or
    
    // Winston logging
    this.getCalleeName() = "log" or
    this.getCalleeName() = "error" or
    this.getCalleeName() = "warn" or
    this.getCalleeName() = "info" or
    this.getCalleeName() = "debug" or
    
    // Other logging libraries
    this.getCalleeName() = "trace" or
    
    // Alert/notification functions
    this.getCalleeName() = "alert" or
    
    // HTTP response that might expose data
    this.getCalleeName() = "send" or
    this.getCalleeName() = "json" or
    this.getCalleeName() = "write"
  }
}

/**
 * Error handling that may expose cardholder data
 */
class ErrorExposure extends DataFlow::CallNode {
  ErrorExposure() {
    // Error constructors with sensitive data
    this.getCalleeName() = "Error" or
    this.getCalleeName() = "TypeError" or
    this.getCalleeName() = "ValidationError" or
    
    // Throwing errors
    exists(ThrowStmt throw |
      throw.getExpr() = this.asExpr()
    )
  }
}

/**
 * Database operations that may store unencrypted cardholder data
 */
class DatabaseStorage extends DataFlow::CallNode {
  DatabaseStorage() {
    // SQL operations
    this.getCalleeName() = "query" or
    this.getCalleeName() = "execute" or
    
    // ORM operations
    this.getCalleeName() = "save" or
    this.getCalleeName() = "create" or
    this.getCalleeName() = "insert" or
    this.getCalleeName() = "update" or
    
    // NoSQL operations
    this.getCalleeName() = "insertOne" or
    this.getCalleeName() = "insertMany" or
    this.getCalleeName() = "updateOne" or
    this.getCalleeName() = "updateMany" or
    this.getCalleeName() = "replaceOne"
  }
}

/**
 * Check if encryption is applied to cardholder data
 */
predicate isEncrypted(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getCalleeName().regexpMatch("(?i).*(encrypt|hash|cipher|crypto).*") and
    call.getAnArgument().flowsTo(node)
  ) or
  exists(DataFlow::CallNode call |
    call.getCalleeName() = "createHash" or
    call.getCalleeName() = "createCipher" or
    call.getCalleeName() = "createCipheriv" and
    call.getAnArgument().flowsTo(node)
  )
}

/**
 * Check if data is tokenized
 */
predicate isTokenized(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getCalleeName().regexpMatch("(?i).*(token|mask|redact).*") and
    call.getAnArgument().flowsTo(node)
  )
}

from ASTNode exposure, string message, string riskLevel
where
  (
    // Credit card patterns in logging
    exists(LoggingOperation log, CreditCardPattern cc |
      cc.flow().flowsTo(log.getAnArgument()) and
      not cc.isTestData() and
      exposure = log and
      message = "Potential credit card number logged to console/file" and
      riskLevel = "CRITICAL"
    )
  ) or
  (
    // Cardholder data identifiers in logging
    exists(LoggingOperation log, CardholderDataIdentifier card |
      card.flow().flowsTo(log.getAnArgument()) and
      exposure = log and
      message = "Cardholder data variable logged without encryption" and
      riskLevel = "HIGH"
    )
  ) or
  (
    // Credit card data in error messages
    exists(ErrorExposure error, CreditCardPattern cc |
      cc.flow().flowsTo(error.getAnArgument()) and
      not cc.isTestData() and
      exposure = error and
      message = "Credit card data exposed in error message" and
      riskLevel = "CRITICAL"
    )
  ) or
  (
    // Unencrypted cardholder data storage
    exists(DatabaseStorage db, CardholderDataIdentifier card |
      card.flow().flowsTo(db.getAnArgument()) and
      not isEncrypted(card.flow()) and
      not isTokenized(card.flow()) and
      exposure = db and
      message = "Cardholder data stored without encryption or tokenization" and
      riskLevel = "CRITICAL"
    )
  ) or
  (
    // Credit card patterns in database storage
    exists(DatabaseStorage db, CreditCardPattern cc |
      cc.flow().flowsTo(db.getAnArgument()) and
      not cc.isTestData() and
      not isEncrypted(cc.flow()) and
      not isTokenized(cc.flow()) and
      exposure = db and
      message = "Credit card number stored in database without encryption" and
      riskLevel = "CRITICAL"
    )
  )
select exposure, message + " (Risk Level: " + riskLevel + ")"