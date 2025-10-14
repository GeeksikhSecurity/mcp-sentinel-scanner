/**
 * @name Memory leak detection in Node.js
 * @description Detects potential memory leaks in long-running Node.js processes
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id js/memory-leaks
 * @tags performance
 *       reliability
 *       nodejs
 */

import javascript

/**
 * Event listener registration without corresponding removal
 */
class UnremovedEventListener extends DataFlow::CallNode {
  UnremovedEventListener() {
    (this.getCalleeName() = "addEventListener" or
     this.getCalleeName() = "on" or
     this.getCalleeName() = "addListener") and
    not exists(DataFlow::CallNode removal |
      (removal.getCalleeName() = "removeEventListener" or
       removal.getCalleeName() = "off" or
       removal.getCalleeName() = "removeListener") and
      removal.getReceiver() = this.getReceiver() and
      removal.getArgument(0).getStringValue() = this.getArgument(0).getStringValue()
    )
  }
  
  string getEventType() {
    result = this.getArgument(0).getStringValue()
  }
}

/**
 * Timer functions without corresponding cleanup
 */
class UncleanedTimer extends DataFlow::CallNode {
  UncleanedTimer() {
    (this.getCalleeName() = "setTimeout" or
     this.getCalleeName() = "setInterval") and
    not exists(DataFlow::CallNode cleanup |
      (cleanup.getCalleeName() = "clearTimeout" or
       cleanup.getCalleeName() = "clearInterval") and
      cleanup.getArgument(0).getALocalSource() = this
    )
  }
}

/**
 * Stream objects without proper cleanup
 */
class UncleanedStream extends DataFlow::CallNode {
  UncleanedStream() {
    // File streams
    (this.getCalleeName() = "createReadStream" or
     this.getCalleeName() = "createWriteStream") and
    not exists(DataFlow::CallNode cleanup |
      cleanup.getCalleeName() = "close" and
      cleanup.getReceiver().getALocalSource() = this
    ) and
    not exists(DataFlow::CallNode cleanup |
      cleanup.getCalleeName() = "destroy" and
      cleanup.getReceiver().getALocalSource() = this
    )
  }
}

/**
 * Database connections without proper cleanup
 */
class UncleanedDatabaseConnection extends DataFlow::CallNode {
  UncleanedDatabaseConnection() {
    // MySQL connections
    (this.getCalleeName() = "createConnection" or
     this.getCalleeName() = "createPool") and
    not exists(DataFlow::CallNode cleanup |
      (cleanup.getCalleeName() = "end" or
       cleanup.getCalleeName() = "destroy" or
       cleanup.getCalleeName() = "close") and
      cleanup.getReceiver().getALocalSource() = this
    ) or
    
    // MongoDB connections
    this.getCalleeName() = "connect" and
    not exists(DataFlow::CallNode cleanup |
      cleanup.getCalleeName() = "close" and
      cleanup.getReceiver().getALocalSource() = this
    )
  }
}

/**
 * Large object creation in loops
 */
class LargeObjectInLoop extends ObjectExpr {
  LargeObjectInLoop() {
    this.getNumProperty() > 10 and
    exists(LoopStmt loop |
      loop.getBody().getAChildStmt*() = this.getParent*()
    )
  }
}

/**
 * Array operations that may cause memory growth
 */
class MemoryGrowthArray extends DataFlow::CallNode {
  MemoryGrowthArray() {
    this.getCalleeName() = "push" and
    exists(LoopStmt loop |
      loop.getBody().getAChildStmt*() = this.asExpr().getParent*()
    ) and
    not exists(DataFlow::CallNode clear |
      (clear.getCalleeName() = "splice" or
       clear.getCalleeName() = "pop" or
       clear.getCalleeName() = "shift") and
      clear.getReceiver() = this.getReceiver()
    )
  }
}

/**
 * Closure variables that may cause memory leaks
 */
class LeakyClosureVariable extends Variable {
  LeakyClosureVariable() {
    exists(Function outer, Function inner |
      this.getScope() = outer and
      inner.getEnclosingFunction() = outer and
      inner.getAParameter().getAReference() = this.getAnAccess() and
      // Large object or array assigned to closure variable
      exists(AssignmentExpr assign |
        assign.getLhs() = this.getAnAccess() and
        (assign.getRhs() instanceof ObjectExpr or
         assign.getRhs() instanceof ArrayExpr or
         assign.getRhs().(DataFlow::CallNode).getCalleeName() = "require")
      )
    )
  }
}

/**
 * Global variables that accumulate data
 */
class AccumulatingGlobalVariable extends GlobalVariable {
  AccumulatingGlobalVariable() {
    exists(AssignmentExpr assign |
      assign.getLhs() = this.getAnAccess() and
      assign.getRhs().(DataFlow::CallNode).getCalleeName() = "push"
    ) or
    exists(CompoundAssignmentExpr compound |
      compound.getLhs() = this.getAnAccess() and
      compound.getOperator() = "+="
    )
  }
}

/**
 * Buffer allocations without size limits
 */
class UnlimitedBufferAllocation extends DataFlow::CallNode {
  UnlimitedBufferAllocation() {
    this.getCalleeName() = "alloc" and
    this.getReceiver().getAPropertyRead("Buffer").flowsTo(this.getReceiver()) and
    // Check if size is from user input or unbounded
    exists(DataFlow::Node size |
      size = this.getArgument(0) and
      (size instanceof RemoteFlowSource or
       not exists(Literal lit | lit.flow().flowsTo(size)))
    )
  }
}

from ASTNode leak, string message, string severity
where
  (
    leak instanceof UnremovedEventListener and
    message = "Event listener '" + leak.(UnremovedEventListener).getEventType() + "' registered without removal" and
    severity = "MEDIUM"
  ) or
  (
    leak instanceof UncleanedTimer and
    message = "Timer created without cleanup (potential memory leak)" and
    severity = "MEDIUM"
  ) or
  (
    leak instanceof UncleanedStream and
    message = "Stream created without proper cleanup" and
    severity = "HIGH"
  ) or
  (
    leak instanceof UncleanedDatabaseConnection and
    message = "Database connection created without cleanup" and
    severity = "HIGH"
  ) or
  (
    leak instanceof LargeObjectInLoop and
    message = "Large object created inside loop (potential memory growth)" and
    severity = "MEDIUM"
  ) or
  (
    leak instanceof MemoryGrowthArray and
    message = "Array growing in loop without cleanup" and
    severity = "MEDIUM"
  ) or
  (
    leak instanceof LeakyClosureVariable and
    message = "Closure variable may cause memory leak" and
    severity = "LOW"
  ) or
  (
    leak instanceof AccumulatingGlobalVariable and
    message = "Global variable accumulating data without bounds" and
    severity = "HIGH"
  ) or
  (
    leak instanceof UnlimitedBufferAllocation and
    message = "Buffer allocation without size validation" and
    severity = "HIGH"
  )
select leak, message + " (Severity: " + severity + ")"