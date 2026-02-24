/**
 * @name Angular performance optimization opportunities
 * @description Identifies Angular-specific performance issues and optimization opportunities
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id js/angular-performance
 * @tags performance
 *       angular
 *       optimization
 *       frontend
 */

import javascript

/**
 * Angular component class
 */
class AngularComponent extends ClassDeclaration {
  AngularComponent() {
    this.getADecorator().getExpression().(DataFlow::CallNode).getCalleeName() = "Component"
  }
  
  /**
   * Get the component decorator
   */
  Decorator getComponentDecorator() {
    result = this.getADecorator() and
    result.getExpression().(DataFlow::CallNode).getCalleeName() = "Component"
  }
  
  /**
   * Check if component implements OnPush change detection
   */
  predicate usesOnPushChangeDetection() {
    exists(ObjectExpr config |
      config = this.getComponentDecorator().getExpression().(DataFlow::CallNode).getArgument(0).asExpr() and
      config.getAProperty().getName() = "changeDetection" and
      config.getAProperty().getValue().(DataFlow::PropRead).getPropertyName() = "OnPush"
    )
  }
  
  /**
   * Check if component implements OnDestroy
   */
  predicate implementsOnDestroy() {
    exists(MethodDefinition method |
      method = this.getAMethod() and
      method.getName() = "ngOnDestroy"
    )
  }
  
  /**
   * Check if component has trackBy function for ngFor
   */
  predicate hasTrackByFunction() {
    exists(MethodDefinition method |
      method = this.getAMethod() and
      method.getName().regexpMatch(".*trackBy.*")
    )
  }
}

/**
 * Angular service class
 */
class AngularService extends ClassDeclaration {
  AngularService() {
    this.getADecorator().getExpression().(DataFlow::CallNode).getCalleeName() = "Injectable"
  }
  
  /**
   * Check if service is provided in root
   */
  predicate isProvidedInRoot() {
    exists(ObjectExpr config |
      config = this.getADecorator().getExpression().(DataFlow::CallNode).getArgument(0).asExpr() and
      config.getAProperty().getName() = "providedIn" and
      config.getAProperty().getValue().(StringLiteral).getValue() = "root"
    )
  }
}

/**
 * RxJS Observable operations
 */
class RxJSOperation extends DataFlow::CallNode {
  RxJSOperation() {
    this.getCalleeName() = "subscribe" or
    this.getCalleeName() = "pipe" or
    this.getCalleeName() = "map" or
    this.getCalleeName() = "filter" or
    this.getCalleeName() = "switchMap" or
    this.getCalleeName() = "mergeMap" or
    this.getCalleeName() = "concatMap" or
    this.getCalleeName() = "exhaustMap"
  }
  
  /**
   * Check if subscription is unsubscribed
   */
  predicate isUnsubscribed() {
    exists(DataFlow::CallNode unsubscribe |
      unsubscribe.getCalleeName() = "unsubscribe" and
      this.flowsTo(unsubscribe.getReceiver())
    )
  }
  
  /**
   * Check if using takeUntil pattern
   */
  predicate usesTakeUntil() {
    exists(DataFlow::CallNode takeUntil |
      takeUntil.getCalleeName() = "takeUntil" and
      takeUntil.getReceiver() = this
    )
  }
}

/**
 * HTTP client operations
 */
class HttpClientOperation extends DataFlow::CallNode {
  HttpClientOperation() {
    this.getCalleeName() = "get" or
    this.getCalleeName() = "post" or
    this.getCalleeName() = "put" or
    this.getCalleeName() = "delete" and
    this.getReceiver().getAPropertyRead("http").exists()
  }
  
  /**
   * Check if HTTP request has error handling
   */
  predicate hasErrorHandling() {
    exists(DataFlow::CallNode catchError |
      catchError.getCalleeName() = "catchError" and
      this.flowsTo(catchError.getReceiver())
    )
  }
  
  /**
   * Check if HTTP request has loading state management
   */
  predicate hasLoadingState() {
    exists(DataFlow::CallNode finalize |
      finalize.getCalleeName() = "finalize" and
      this.flowsTo(finalize.getReceiver())
    )
  }
}

/**
 * Angular template expressions
 */
class TemplateExpression extends StringLiteral {
  TemplateExpression() {
    exists(ObjectExpr component |
      component.getAProperty().getName() = "template" and
      component.getAProperty().getValue() = this
    )
  }
  
  /**
   * Check for function calls in template
   */
  predicate hasFunctionCalls() {
    this.getValue().regexpMatch(".*\\{\\{.*\\(\\).*\\}\\}.*")
  }
  
  /**
   * Check for ngFor without trackBy
   */
  predicate hasNgForWithoutTrackBy() {
    this.getValue().regexpMatch(".*\\*ngFor.*") and
    not this.getValue().regexpMatch(".*trackBy.*")
  }
  
  /**
   * Check for async pipe usage
   */
  predicate usesAsyncPipe() {
    this.getValue().regexpMatch(".*\\|\\s*async.*")
  }
}

/**
 * Bundle size analysis
 */
class ImportStatement extends ImportDeclaration {
  ImportStatement() {
    any()
  }
  
  /**
   * Check for barrel imports
   */
  predicate isBarrelImport() {
    this.getImportedPath().getValue().regexpMatch(".*@angular/.*") and
    not this.getImportedPath().getValue().regexpMatch(".*/.*")
  }
  
  /**
   * Check for large library imports
   */
  predicate isLargeLibraryImport() {
    this.getImportedPath().getValue().regexpMatch(".*(lodash|moment|rxjs).*") and
    not this.getImportedPath().getValue().regexpMatch(".*/.*")
  }
}

/**
 * Lazy loading configuration
 */
class LazyLoadingRoute extends ObjectExpr {
  LazyLoadingRoute() {
    this.getAProperty().getName() = "loadChildren"
  }
  
  /**
   * Check if using dynamic import
   */
  predicate usesDynamicImport() {
    exists(ArrowFunctionExpr arrow |
      arrow = this.getAProperty().getValue() and
      arrow.getBody().(DataFlow::CallNode).getCalleeName() = "import"
    )
  }
}

from ASTNode issue, string message, string category, string impact
where
  (
    // Component without OnPush change detection
    exists(AngularComponent component |
      component = issue and
      not component.usesOnPushChangeDetection() and
      message = "Component should use OnPush change detection for better performance" and
      category = "change_detection" and
      impact = "MEDIUM"
    )
  ) or
  (
    // Component without OnDestroy implementation
    exists(AngularComponent component |
      component = issue and
      not component.implementsOnDestroy() and
      message = "Component should implement OnDestroy for proper cleanup" and
      category = "memory_leaks" and
      impact = "HIGH"
    )
  ) or
  (
    // Observable subscription without unsubscribe
    exists(RxJSOperation subscription |
      subscription = issue and
      subscription.getCalleeName() = "subscribe" and
      not subscription.isUnsubscribed() and
      not subscription.usesTakeUntil() and
      message = "Observable subscription without unsubscribe (memory leak risk)" and
      category = "memory_leaks" and
      impact = "HIGH"
    )
  ) or
  (
    // HTTP request without error handling
    exists(HttpClientOperation http |
      http = issue and
      not http.hasErrorHandling() and
      message = "HTTP request without error handling" and
      category = "error_handling" and
      impact = "MEDIUM"
    )
  ) or
  (
    // Function calls in template
    exists(TemplateExpression template |
      template = issue and
      template.hasFunctionCalls() and
      message = "Function calls in template cause unnecessary re-evaluations" and
      category = "template_performance" and
      impact = "MEDIUM"
    )
  ) or
  (
    // ngFor without trackBy
    exists(TemplateExpression template |
      template = issue and
      template.hasNgForWithoutTrackBy() and
      message = "*ngFor without trackBy function causes unnecessary DOM updates" and
      category = "template_performance" and
      impact = "MEDIUM"
    )
  ) or
  (
    // Barrel imports (bundle size impact)
    exists(ImportStatement import |
      import = issue and
      import.isBarrelImport() and
      message = "Barrel import may increase bundle size - use specific imports" and
      category = "bundle_size" and
      impact = "LOW"
    )
  ) or
  (
    // Large library imports
    exists(ImportStatement import |
      import = issue and
      import.isLargeLibraryImport() and
      message = "Importing entire library - consider tree-shaking or specific imports" and
      category = "bundle_size" and
      impact = "MEDIUM"
    )
  ) or
  (
    // Service not provided in root
    exists(AngularService service |
      service = issue and
      not service.isProvidedInRoot() and
      message = "Service should be provided in root for tree-shaking benefits" and
      category = "tree_shaking" and
      impact = "LOW"
    )
  ) or
  (
    // Route without lazy loading
    exists(LazyLoadingRoute route |
      route = issue and
      not route.usesDynamicImport() and
      message = "Route should use dynamic import for lazy loading" and
      category = "lazy_loading" and
      impact = "MEDIUM"
    )
  )
select issue, message + " (Category: " + category + ", Impact: " + impact + ")"