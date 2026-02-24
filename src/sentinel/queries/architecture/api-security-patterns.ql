/**
 * @name API security pattern analysis
 * @description Analyzes API security patterns and identifies potential vulnerabilities
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id js/api-security-patterns
 * @tags security
 *       api
 *       architecture
 *       rest
 *       graphql
 */

import javascript

/**
 * Express.js route handlers
 */
class ExpressRouteHandler extends DataFlow::CallNode {
  ExpressRouteHandler() {
    this.getCalleeName() = "get" or
    this.getCalleeName() = "post" or
    this.getCalleeName() = "put" or
    this.getCalleeName() = "delete" or
    this.getCalleeName() = "patch" or
    this.getCalleeName() = "use"
  }
  
  /**
   * Get the route path
   */
  string getRoutePath() {
    result = this.getArgument(0).getStringValue()
  }
  
  /**
   * Check if route has authentication middleware
   */
  predicate hasAuthentication() {
    exists(DataFlow::CallNode middleware |
      middleware.getCalleeName().regexpMatch("(?i).*(auth|authenticate|verify|check).*") and
      middleware.flowsTo(this.getAnArgument())
    )
  }
  
  /**
   * Check if route has rate limiting
   */
  predicate hasRateLimit() {
    exists(DataFlow::CallNode middleware |
      middleware.getCalleeName().regexpMatch("(?i).*(rate|limit|throttle).*") and
      middleware.flowsTo(this.getAnArgument())
    )
  }
  
  /**
   * Check if route validates input
   */
  predicate hasInputValidation() {
    exists(DataFlow::CallNode validation |
      validation.getCalleeName().regexpMatch("(?i).*(validate|sanitize|check|joi|yup).*") and
      validation.flowsTo(this.getAnArgument())
    )
  }
  
  /**
   * Check if route is sensitive (handles sensitive data)
   */
  predicate isSensitiveRoute() {
    this.getRoutePath().regexpMatch("(?i).*(password|credit|card|payment|auth|login|admin|user|profile).*")
  }
}

/**
 * GraphQL resolvers
 */
class GraphQLResolver extends Function {
  GraphQLResolver() {
    exists(ObjectExpr resolvers |
      resolvers.getAProperty().getValue() = this and
      resolvers.getAProperty().getName().regexpMatch("(?i).*(query|mutation|subscription).*")
    )
  }
  
  /**
   * Check if resolver has authentication
   */
  predicate hasAuthentication() {
    exists(DataFlow::CallNode auth |
      auth.getCalleeName().regexpMatch("(?i).*(auth|authenticate|verify|check).*") and
      auth.asExpr().getParent*() = this.getBody()
    )
  }
  
  /**
   * Check if resolver has depth limiting
   */
  predicate hasDepthLimit() {
    exists(DataFlow::CallNode limit |
      limit.getCalleeName().regexpMatch("(?i).*(depth|limit|complexity).*") and
      limit.asExpr().getParent*() = this.getBody()
    )
  }
}

/**
 * CORS configuration analysis
 */
class CORSConfiguration extends DataFlow::CallNode {
  CORSConfiguration() {
    this.getCalleeName() = "cors" or
    this.getCalleeName() = "use" and
    this.getAnArgument().(DataFlow::CallNode).getCalleeName() = "cors"
  }
  
  /**
   * Check if CORS allows all origins
   */
  predicate allowsAllOrigins() {
    exists(ObjectExpr config |
      config = this.getArgument(0).asExpr() and
      config.getAProperty().getName() = "origin" and
      (config.getAProperty().getValue().(StringLiteral).getValue() = "*" or
       config.getAProperty().getValue().(BooleanLiteral).getValue() = true)
    )
  }
  
  /**
   * Check if CORS allows credentials
   */
  predicate allowsCredentials() {
    exists(ObjectExpr config |
      config = this.getArgument(0).asExpr() and
      config.getAProperty().getName() = "credentials" and
      config.getAProperty().getValue().(BooleanLiteral).getValue() = true
    )
  }
}

/**
 * JWT token handling
 */
class JWTOperation extends DataFlow::CallNode {
  JWTOperation() {
    this.getCalleeName() = "sign" or
    this.getCalleeName() = "verify" or
    this.getCalleeName() = "decode"
  }
  
  /**
   * Check if JWT uses weak secret
   */
  predicate usesWeakSecret() {
    exists(StringLiteral secret |
      secret = this.getArgument(1).asExpr() and
      (secret.getValue().length() < 32 or
       secret.getValue().regexpMatch("(?i).*(secret|password|key|test|demo).*"))
    )
  }
  
  /**
   * Check if JWT has expiration
   */
  predicate hasExpiration() {
    exists(ObjectExpr options |
      options = this.getArgument(2).asExpr() and
      options.getAProperty().getName().regexpMatch("(?i).*(exp|expires|expiresIn).*")
    )
  }
}

/**
 * API versioning patterns
 */
class APIVersioning extends ExpressRouteHandler {
  APIVersioning() {
    this.getRoutePath().regexpMatch(".*/v[0-9]+/.*") or
    this.getRoutePath().regexpMatch(".*/api/[0-9]+/.*")
  }
  
  /**
   * Check if multiple versions are supported
   */
  predicate hasMultipleVersions() {
    exists(ExpressRouteHandler other |
      other != this and
      other.getRoutePath().regexpMatch(".*/v[0-9]+/.*") and
      this.getRoutePath().regexpMatch(".*/v[0-9]+/.*")
    )
  }
}

/**
 * Rate limiting configuration
 */
class RateLimitConfig extends DataFlow::CallNode {
  RateLimitConfig() {
    this.getCalleeName().regexpMatch("(?i).*(rateLimit|rateLimiter|throttle).*")
  }
  
  /**
   * Check if rate limit is too permissive
   */
  predicate isTooPermissive() {
    exists(ObjectExpr config |
      config = this.getArgument(0).asExpr() and
      config.getAProperty().getName() = "max" and
      config.getAProperty().getValue().(NumberLiteral).getValue() > 1000
    )
  }
}

from ASTNode issue, string message, string category, string severity
where
  (
    // Missing authentication on sensitive routes
    exists(ExpressRouteHandler route |
      route = issue and
      route.isSensitiveRoute() and
      not route.hasAuthentication() and
      message = "Sensitive API route '" + route.getRoutePath() + "' lacks authentication" and
      category = "authentication" and
      severity = "HIGH"
    )
  ) or
  (
    // Missing input validation
    exists(ExpressRouteHandler route |
      route = issue and
      (route.getCalleeName() = "post" or route.getCalleeName() = "put" or route.getCalleeName() = "patch") and
      not route.hasInputValidation() and
      message = "API route '" + route.getRoutePath() + "' lacks input validation" and
      category = "validation" and
      severity = "MEDIUM"
    )
  ) or
  (
    // Missing rate limiting on public endpoints
    exists(ExpressRouteHandler route |
      route = issue and
      not route.hasRateLimit() and
      not route.hasAuthentication() and
      message = "Public API route '" + route.getRoutePath() + "' lacks rate limiting" and
      category = "rate_limiting" and
      severity = "MEDIUM"
    )
  ) or
  (
    // Insecure CORS configuration
    exists(CORSConfiguration cors |
      cors = issue and
      cors.allowsAllOrigins() and
      cors.allowsCredentials() and
      message = "CORS allows all origins with credentials (security risk)" and
      category = "cors" and
      severity = "HIGH"
    )
  ) or
  (
    // Weak JWT secret
    exists(JWTOperation jwt |
      jwt = issue and
      jwt.usesWeakSecret() and
      message = "JWT uses weak or predictable secret" and
      category = "jwt" and
      severity = "HIGH"
    )
  ) or
  (
    // JWT without expiration
    exists(JWTOperation jwt |
      jwt = issue and
      jwt.getCalleeName() = "sign" and
      not jwt.hasExpiration() and
      message = "JWT token created without expiration time" and
      category = "jwt" and
      severity = "MEDIUM"
    )
  ) or
  (
    // GraphQL resolver without authentication
    exists(GraphQLResolver resolver |
      resolver = issue and
      not resolver.hasAuthentication() and
      message = "GraphQL resolver lacks authentication" and
      category = "graphql" and
      severity = "MEDIUM"
    )
  ) or
  (
    // GraphQL without depth limiting
    exists(GraphQLResolver resolver |
      resolver = issue and
      not resolver.hasDepthLimit() and
      message = "GraphQL resolver lacks depth/complexity limiting" and
      category = "graphql" and
      severity = "LOW"
    )
  ) or
  (
    // Permissive rate limiting
    exists(RateLimitConfig rateLimit |
      rateLimit = issue and
      rateLimit.isTooPermissive() and
      message = "Rate limit configuration is too permissive (>1000 requests)" and
      category = "rate_limiting" and
      severity = "LOW"
    )
  )
select issue, message + " (Category: " + category + ", Severity: " + severity + ")"