/**
 * @name AI prompt injection vulnerabilities
 * @description Detects potential prompt injection vulnerabilities in AI/ML integrations
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id js/ai-prompt-injection
 * @tags security
 *       ai
 *       ml
 *       prompt-injection
 */

import javascript
import DataFlow::PathGraph

/**
 * A taint-tracking configuration for prompt injection vulnerabilities
 */
class PromptInjectionConfig extends TaintTracking::Configuration {
  PromptInjectionConfig() { this = "PromptInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // User input sources
    source instanceof RemoteFlowSource or
    source instanceof ClientSideRemoteFlowSource or
    // HTTP request data
    source = any(HTTP::RequestInputAccess input) or
    // Form data and parameters
    source = any(HTTP::RequestBodyAccess input) or
    source = any(HTTP::RequestParameterAccess input) or
    // File uploads
    source = any(FileSystemReadAccess input) or
    // Database queries (user-generated content)
    source = any(DatabaseAccess input)
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof AIPromptSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Input validation and sanitization
    node = any(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(sanitize|validate|escape|clean|filter).*")
    ).getAnArgument() or
    
    // Prompt template systems with built-in escaping
    node = any(DataFlow::CallNode call |
      call.getCalleeName() = "template" and
      call.getArgument(1).getAPropertyRead("escape").exists()
    ).getAnArgument() or
    
    // Explicit prompt injection prevention
    node = any(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(prevent|block|filter).*injection.*")
    ).getAnArgument()
  }
}

/**
 * AI/ML API calls that accept prompts
 */
class AIPromptSink extends DataFlow::Node {
  AIPromptSink() {
    // OpenAI API calls
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "create" and
      (call.getReceiver().getAPropertyRead("completions").exists() or
       call.getReceiver().getAPropertyRead("chat").exists() or
       call.getReceiver().getAPropertyRead("edits").exists()) and
      this = call.getArgument(0).getAPropertyWrite("prompt").getRhs()
    ) or
    
    // Anthropic Claude API
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "complete" and
      this = call.getArgument(0).getAPropertyWrite("prompt").getRhs()
    ) or
    
    // Hugging Face transformers
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "generate" and
      this = call.getArgument(0)
    ) or
    
    // LangChain prompt templates
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "format" and
      call.getReceiver().getAPropertyRead("PromptTemplate").exists() and
      this = call.getAnArgument()
    ) or
    
    // Custom AI service calls
    exists(DataFlow::CallNode call |
      call.getCalleeName().regexpMatch("(?i).*(prompt|generate|complete|ask|query).*") and
      call.getReceiver().getAPropertyRead().getName().regexpMatch("(?i).*(ai|ml|gpt|claude|llm).*") and
      this = call.getAnArgument()
    ) or
    
    // Direct prompt construction
    exists(TemplateLiteral template |
      template.getAnElement().getStringValue().regexpMatch("(?i).*(prompt|instruction|system|user|assistant).*") and
      this.asExpr() = template
    )
  }
}

/**
 * Dangerous prompt patterns that indicate injection attempts
 */
class DangerousPromptPattern extends StringLiteral {
  DangerousPromptPattern() {
    // System prompt override attempts
    this.getValue().regexpMatch("(?i).*ignore (previous|all) instructions.*") or
    this.getValue().regexpMatch("(?i).*forget (everything|all|previous).*") or
    this.getValue().regexpMatch("(?i).*new instructions?:.*") or
    this.getValue().regexpMatch("(?i).*system:.*") or
    this.getValue().regexpMatch("(?i).*override.*") or
    
    // Role manipulation
    this.getValue().regexpMatch("(?i).*you are now.*") or
    this.getValue().regexpMatch("(?i).*act as.*") or
    this.getValue().regexpMatch("(?i).*pretend to be.*") or
    this.getValue().regexpMatch("(?i).*roleplay.*") or
    
    // Jailbreak attempts
    this.getValue().regexpMatch("(?i).*jailbreak.*") or
    this.getValue().regexpMatch("(?i).*DAN.*") or
    this.getValue().regexpMatch("(?i).*do anything now.*") or
    
    // Information extraction attempts
    this.getValue().regexpMatch("(?i).*show me your.*") or
    this.getValue().regexpMatch("(?i).*what are your instructions.*") or
    this.getValue().regexpMatch("(?i).*reveal your.*") or
    
    // Code execution attempts
    this.getValue().regexpMatch("(?i).*execute.*code.*") or
    this.getValue().regexpMatch("(?i).*run.*script.*") or
    this.getValue().regexpMatch("(?i).*eval\\(.*") or
    
    // Prompt injection markers
    this.getValue().regexpMatch(".*\\[\\[.*\\]\\].*") or
    this.getValue().regexpMatch(".*\\{\\{.*\\}\\}.*") or
    this.getValue().regexpMatch(".*<\\|.*\\|>.*")
  }
}

/**
 * Model configuration that may be vulnerable to injection
 */
class VulnerableModelConfig extends DataFlow::Node {
  VulnerableModelConfig() {
    exists(ObjectExpr config |
      // High temperature settings (more creative/unpredictable)
      config.getAProperty().getName() = "temperature" and
      config.getAProperty().getValue().(NumberLiteral).getValue() > 0.8 and
      this.asExpr() = config
    ) or
    exists(ObjectExpr config |
      // No content filtering
      config.getAProperty().getName() = "content_filter" and
      config.getAProperty().getValue().(BooleanLiteral).getValue() = false and
      this.asExpr() = config
    ) or
    exists(ObjectExpr config |
      // High max tokens (allows long responses)
      config.getAProperty().getName() = "max_tokens" and
      config.getAProperty().getValue().(NumberLiteral).getValue() > 2000 and
      this.asExpr() = config
    )
  }
}

/**
 * Unsafe prompt concatenation
 */
class UnsafePromptConcatenation extends AddExpr {
  UnsafePromptConcatenation() {
    // Direct string concatenation with user input
    exists(DataFlow::Node userInput |
      userInput instanceof RemoteFlowSource and
      userInput.asExpr() = this.getAnOperand()
    ) and
    // Contains prompt-like keywords
    exists(StringLiteral prompt |
      prompt = this.getAnOperand() and
      prompt.getValue().regexpMatch("(?i).*(prompt|instruction|system|user|assistant).*")
    )
  }
}

from PromptInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink, string alertType
where 
  config.hasFlowPath(source, sink) and
  (
    (sink.getNode() instanceof AIPromptSink and alertType = "User input flows to AI prompt") or
    (exists(DangerousPromptPattern pattern |
      pattern.flow().flowsTo(sink.getNode()) and
      alertType = "Dangerous prompt pattern detected"
    )) or
    (exists(UnsafePromptConcatenation concat |
      concat.flow().flowsTo(sink.getNode()) and
      alertType = "Unsafe prompt concatenation with user input"
    ))
  )
select sink.getNode(), source, sink,
  alertType + ": potential prompt injection vulnerability from $@",
  source.getNode(), "user input"