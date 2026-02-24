/**
 * @name SQL injection vulnerabilities
 * @description Detects potential SQL injection vulnerabilities in database queries
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id js/sql-injection
 * @tags security
 *       external/cwe/cwe-89
 *       pci-dss
 */

import javascript
import semmle.javascript.security.dataflow.SqlInjectionQuery
import DataFlow::PathGraph

/**
 * A taint-tracking configuration for SQL injection vulnerabilities
 */
class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource or
    source instanceof ClientSideRemoteFlowSource or
    // User input from request parameters
    source = any(HTTP::RequestInputAccess input) or
    // Form data
    source = any(HTTP::RequestBodyAccess input) or
    // URL parameters
    source = any(HTTP::RequestParameterAccess input) or
    // Headers (potentially dangerous)
    source = any(HTTP::RequestHeaderAccess input)
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlInjection::Sink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Parameterized queries are safe
    node = any(SqlInjection::Sanitizer sanitizer) or
    // Explicit sanitization functions
    node = any(DataFlow::CallNode call |
      call.getCalleeName() = "escape" or
      call.getCalleeName() = "escapeId" or
      call.getCalleeName() = "sanitize" or
      call.getCalleeName() = "validate"
    ).getAnArgument() or
    // Type conversion to number (basic sanitization)
    node = any(DataFlow::CallNode call |
      call.getCalleeName() = "parseInt" or
      call.getCalleeName() = "parseFloat" or
      call.getCalleeName() = "Number"
    )
  }
}

/**
 * Enhanced SQL injection sink that includes more database libraries
 */
class EnhancedSqlSink extends DataFlow::Node {
  EnhancedSqlSink() {
    // Standard SQL injection sinks
    this instanceof SqlInjection::Sink or
    
    // MySQL library calls
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "query" and
      call.getReceiver().getAPropertyRead("createConnection").getACall().flowsTo(call.getReceiver()) and
      this = call.getArgument(0)
    ) or
    
    // PostgreSQL library calls
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "query" and
      (call.getReceiver().getAPropertyRead("Client").getACall().flowsTo(call.getReceiver()) or
       call.getReceiver().getAPropertyRead("Pool").getACall().flowsTo(call.getReceiver())) and
      this = call.getArgument(0)
    ) or
    
    // MongoDB query injection (NoSQL injection)
    exists(DataFlow::CallNode call |
      (call.getCalleeName() = "find" or
       call.getCalleeName() = "findOne" or
       call.getCalleeName() = "aggregate" or
       call.getCalleeName() = "update" or
       call.getCalleeName() = "remove") and
      this = call.getArgument(0)
    ) or
    
    // ORM query builders (Sequelize, TypeORM, etc.)
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "raw" and
      this = call.getArgument(0)
    ) or
    
    // Knex.js raw queries
    exists(DataFlow::CallNode call |
      call.getReceiver().getAPropertyRead("raw").flowsTo(call) and
      this = call.getArgument(0)
    )
  }
}

/**
 * Check for string concatenation in SQL queries
 */
class StringConcatenationSqlSink extends DataFlow::Node {
  StringConcatenationSqlSink() {
    exists(AddExpr add |
      add.getAnOperand().getStringValue().regexpMatch("(?i).*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*") and
      this.asExpr() = add
    ) or
    exists(TemplateLiteral template |
      template.getAnElement().getStringValue().regexpMatch("(?i).*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*") and
      template.getATemplateElement() instanceof TemplateElement and
      this.asExpr() = template
    )
  }
}

/**
 * Enhanced configuration that includes string concatenation
 */
class EnhancedSqlInjectionConfig extends TaintTracking::Configuration {
  EnhancedSqlInjectionConfig() { this = "EnhancedSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource or
    source instanceof ClientSideRemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof EnhancedSqlSink or
    sink instanceof StringConcatenationSqlSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Parameterized queries
    node = any(SqlInjection::Sanitizer sanitizer) or
    // Explicit validation
    node = any(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(validate|sanitize|escape|clean).*")
    ).getAnArgument()
  }
}

from EnhancedSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability: user input from $@ flows to SQL query.",
  source.getNode(), "here"