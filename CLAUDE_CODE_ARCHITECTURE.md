# Architectural Guidelines for AI Product Development with Claude Code

Based on Flatfile's engineering philosophy, adapted for Claude Code and defensive security tooling.

## Core Principles

### 1. **Design for Non-Determinism**
AI systems require different architectural patterns than traditional software:

**State Management**
- Implement optimistic updates with rollback strategies
- Track confidence scores alongside data transformations
- Build audit trails for AI decisions that users can inspect
- Design for "eventual correctness" rather than immediate perfection

**Error Boundaries**
```typescript
// Example pattern for graceful degradation
interface AIResponse<T> {
  data: T | null;
  confidence: number;
  fallback?: T;
  reasoning?: string;
  canRetry: boolean;
  modelUsed: 'sonnet-4.5' | 'opus' | 'rule-based';
}
```

**Security Boundaries (Defensive-Only Development)**
```typescript
// Validate security tasks before execution
async function validateSecurityTask(task: SecurityTask): Promise<boolean> {
  const offensivePatterns = [
    /bulk.*credential.*harvest/i,
    /mass.*ssh.*key.*collection/i,
    /automated.*cookie.*theft/i,
    /exploit.*development/i
  ];

  if (offensivePatterns.some(p => p.test(task.description))) {
    throw new Error('Offensive security tasks not supported. Only defensive security tools allowed.');
  }

  // Allow: vulnerability detection, security analysis, detection rules
  return true;
}
```

### 2. **Streaming-First Architecture**

**Real-Time Response Handling**
- Stream tokens from Claude rather than waiting for complete responses
- Update UI progressively as content arrives
- Show intermediate states (thinking, processing, validating)
- Allow users to interrupt or redirect mid-stream

**Implementation Pattern**
```typescript
// Progressive disclosure with streaming
async function* processWithClaude(input: Input) {
  yield { status: 'analyzing', preview: null };

  for await (const chunk of claudeStream(input)) {
    // Sanitize output in real-time
    const sanitized = sanitizeOutput(chunk);

    // Security check during streaming
    if (detectsSensitiveData(sanitized)) {
      yield { status: 'blocked', reason: 'sensitive_data_detected' };
      break;
    }

    yield { status: 'processing', preview: sanitized };
  }

  yield { status: 'complete', result: finalResult };
}
```

**Security in Streaming Context**
```typescript
async function* secureSecurityScan(targets: Target[]) {
  // Validate input before streaming
  await validateSecurityTask({ targets });

  for (const target of targets) {
    yield { status: 'scanning', target: target.path };

    const findings = await scanTarget(target);

    // Filter false positives in real-time
    const validated = findings.filter(f => f.confidence > 0.7);

    yield {
      status: 'findings',
      target: target.path,
      results: validated,
      confidence: averageConfidence(validated)
    };
  }
}
```

### 3. **Agent-Aware UI Patterns**

**Transparency & Control**
- **Intent Visualization**: Show what the AI is planning before execution
- **Corrective Control**: Allow users to guide/correct mid-process
- **Confidence Indicators**: Surface uncertainty clearly
- **Undo/Redo for AI Actions**: Make AI operations reversible

**Task Planning & Tracking (TodoWrite Pattern)**
```typescript
// Use structured task management for complex operations
interface TaskManager {
  tasks: Task[];

  // Break down complex requests into trackable units
  plan(request: UserRequest): Task[] {
    const tasks = decompose(request);
    return tasks.map(t => ({
      content: t.description,           // Imperative: "Scan repository"
      activeForm: t.presentContinuous,  // Continuous: "Scanning repository"
      status: 'pending' as const
    }));
  }

  // Update task state as work progresses
  async execute(tasks: Task[]) {
    // Rule: Exactly ONE task in 'in_progress' at a time
    for (const task of tasks) {
      task.status = 'in_progress';
      await TodoWrite({ todos: tasks });

      await performTask(task);

      // Mark completed IMMEDIATELY after finishing
      task.status = 'completed';
      await TodoWrite({ todos: tasks });
    }
  }
}
```

**Security Scanner Task Example**
```typescript
// Example: Multi-repository security scan with task tracking
async function scanRepositoriesWithProgress(repos: Repository[]) {
  const tasks = [
    { content: 'Validate repository access', activeForm: 'Validating repository access', status: 'pending' },
    ...repos.map(r => ({
      content: `Scan ${r.name} for vulnerabilities`,
      activeForm: `Scanning ${r.name}`,
      status: 'pending'
    })),
    { content: 'Generate security report', activeForm: 'Generating security report', status: 'pending' },
    { content: 'Apply false positive filters', activeForm: 'Applying false positive filters', status: 'pending' }
  ];

  await TodoWrite({ todos: tasks });

  // Validate access
  tasks[0].status = 'in_progress';
  await TodoWrite({ todos: tasks });
  await validateAccess(repos);
  tasks[0].status = 'completed';
  await TodoWrite({ todos: tasks });

  // Scan each repository
  for (let i = 0; i < repos.length; i++) {
    const taskIndex = i + 1;
    tasks[taskIndex].status = 'in_progress';
    await TodoWrite({ todos: tasks });

    await scanRepository(repos[i]);

    tasks[taskIndex].status = 'completed';
    await TodoWrite({ todos: tasks });
  }

  // Generate and filter results
  // ... continue pattern
}
```

**Multi-Agent Collaboration**
```
User Space          Agent Space           System Space
┌──────────┐       ┌──────────┐         ┌──────────┐
│  Human   │◄─────►│  Claude  │◄───────►│ Validation│
│  Input   │       │ Sonnet4.5│         │  Layer   │
└──────────┘       └──────────┘         └──────────┘
     │                   │                     │
     └───────────────────┴─────────────────────┘
          Shared Canvas with TodoWrite
```

**VSCode Integration - Clickable File References**
```typescript
// When referencing code locations in VSCode, use markdown links
interface FileReference {
  // For files: [filename.ts](src/filename.ts)
  file: (path: string) => `[${path}](${path})`;

  // For specific lines: [scanner.py:142](src/scanner.py#L142)
  line: (path: string, line: number) => `[${path}:${line}](${path}#L${line})`;

  // For line ranges: [utils.py:50-75](src/utils.py#L50-L75)
  range: (path: string, start: number, end: number) =>
    `[${path}:${start}-${end}](${path}#L${start}-L${end})`;

  // For folders: [src/filters/](src/filters/)
  folder: (path: string) => `[${path}](${path})`;
}

// DO NOT use backticks or code blocks for file references
// ❌ Bad: `src/scanner.py`
// ✅ Good: [src/scanner.py](src/scanner.py)
```

## Technical Implementation

### 4. **Prompt Architecture**

**System Prompts as Infrastructure**
Treat prompts like database schemas - version controlled, tested, and evolved carefully:

```typescript
// Prompt versioning system
interface PromptVersion {
  version: string;
  systemPrompt: string;
  examples: Example[];
  constraints: Constraint[];
  evaluationCriteria: Metric[];
  cacheConfig: CacheConfig;  // NEW: Prompt caching configuration
}

// A/B test prompts in production
class PromptRouter {
  async route(context: Context): Promise<PromptVersion> {
    // Route based on user segment, complexity, or experiments
    if (context.taskComplexity === 'high') {
      return this.getPrompt('opus-reasoning-v2');
    }
    return this.getPrompt('sonnet45-default-v3');
  }
}
```

**Structured Output Patterns**
```typescript
// Always request structured outputs from Claude
const prompt = `
Analyze this code for security vulnerabilities and return JSON:
{
  "findings": [{
    "type": "credential_exposure" | "injection_vulnerability" | "crypto_weakness",
    "severity": "critical" | "high" | "medium" | "low",
    "location": {"file": "...", "line": 123},
    "confidence": 0.0-1.0,
    "description": "...",
    "remediation": "..."
  }],
  "falsePositives": [{
    "finding": "...",
    "reason": "test_file" | "example_code" | "configuration"
  }],
  "summary": {
    "totalFindings": 0,
    "criticalCount": 0,
    "averageConfidence": 0.0
  },
  "reasoning": "step-by-step analysis explanation"
}`;
```

**Prompt Caching for Cost Optimization**
```typescript
// Leverage Claude's prompt caching (90% cost reduction on cached tokens)
interface CachedPromptConfig {
  systemPrompt: string;           // Cached portion (>1024 tokens)
  cachedExamples: Example[];      // Few-shot examples (cached)
  cachedSecurityRules: Rule[];    // Static security patterns (cached)
  dynamicInput: string;           // User-specific input (not cached)
}

async function optimizedSecurityScan(config: CachedPromptConfig) {
  // First 1024+ tokens eligible for 5-minute cache
  const messages = [
    {
      role: "system",
      content: [
        {
          type: "text",
          text: config.systemPrompt,
          cache_control: { type: "ephemeral" }  // Cache system prompt
        },
        {
          type: "text",
          text: formatExamples(config.cachedExamples),
          cache_control: { type: "ephemeral" }  // Cache examples
        },
        {
          type: "text",
          text: formatSecurityRules(config.cachedSecurityRules),
          cache_control: { type: "ephemeral" }  // Cache rules
        }
      ]
    },
    {
      role: "user",
      content: config.dynamicInput  // Only this changes per request
    }
  ];

  return await claude.messages.create({
    model: "claude-sonnet-4-5-20250929",
    messages
  });
}

// Cost comparison:
// Without caching: 10,000 tokens × $3/MTok = $0.03 per scan
// With caching:    9,000 cached × $0.30/MTok + 1,000 new × $3/MTok = $0.0057 per scan
// Savings: 81% cost reduction
```

### 5. **Performance at Scale**

**Concurrent AI Operations**
```typescript
// Batch similar operations
async function batchTransform(records: Record[]) {
  // Group records by complexity
  const batches = groupByComplexity(records);

  // Process in parallel with different strategies
  return Promise.all(
    batches.map(batch => {
      if (batch.complexity === 'simple') {
        return fastPathProcess(batch);  // Rule-based
      }
      if (batch.complexity === 'medium') {
        return claudeSonnet45Process(batch);  // Sonnet 4.5
      }
      return claudeOpusProcess(batch);  // Opus for complex reasoning
    })
  );
}
```

**Caching Strategy**
```typescript
interface CacheStrategy {
  // Semantic similarity caching for repeated queries
  semanticCache: Map<string, {
    embedding: number[];
    response: AIResponse;
    timestamp: number;
  }>;

  // Check if similar query exists (cosine similarity > 0.95)
  async checkCache(query: string): Promise<AIResponse | null> {
    const queryEmbedding = await embed(query);

    for (const [key, cached] of this.semanticCache) {
      const similarity = cosineSimilarity(queryEmbedding, cached.embedding);

      if (similarity > 0.95 && !this.isStale(cached.timestamp)) {
        return cached.response;
      }
    }

    return null;
  }

  // Prompt result memoization
  memoizedPrompts: LRUCache<string, AIResponse>;

  // Edge caching for common transformations
  edgeCache: CDNCache;

  // Store and reuse few-shot examples
  exampleLibrary: Map<string, Example[]>;
}
```

### 6. **Development Workflow with Claude Code**

**Agent-Assisted Development**
```bash
# Recommended workflow for security scanner development
1. Describe the security check in natural language
2. Let Claude generate the detection logic scaffold
3. Iterate on false positive reduction with Claude
4. Human reviews for security implications and edge cases
5. Use TodoWrite to track multi-step implementation
```

**Tool Building Philosophy**
- **Build when**: Off-the-shelf tools don't handle AI-specific patterns
- **Examples for Security Tools**:
  - Vulnerability confidence calibration tools
  - False positive filtering frameworks
  - Security finding aggregation pipelines
  - Agent interaction debuggers for scan workflows
  - Prompt testing frameworks for detection rules

## System Design Patterns

### 7. **Compositional Architecture**

**Component Design**
```typescript
// Components that compose with AI
interface AICapableComponent<TInput, TOutput> {
  // Works with or without AI
  transform(input: TInput): TOutput;

  // AI-enhanced path (Sonnet 4.5 by default)
  transformWithAI(input: TInput, context: AIContext): Promise<TOutput>;

  // Hybrid approach with confidence-based routing
  async transformHybrid(input: TInput): Promise<TOutput> {
    const ruleBasedResult = this.transform(input);

    if (ruleBasedResult.confidence > 0.9) {
      return ruleBasedResult;
    }

    // Fall back to AI for uncertain cases
    return this.transformWithAI(input, {
      priorResult: ruleBasedResult
    });
  }

  // Validate output regardless of method
  validate(output: TOutput): ValidationResult;
}
```

**Security Scanner Composition Example**
```typescript
// Composable security scanner pipeline
class SecurityScanner {
  private detectors: SecurityDetector[] = [
    new CredentialDetector(),
    new InjectionDetector(),
    new CryptoWeaknessDetector()
  ];

  async scan(target: Target): Promise<Finding[]> {
    const allFindings: Finding[] = [];

    // Run detectors in parallel
    const results = await Promise.all(
      this.detectors.map(d => d.detect(target))
    );

    // Flatten and deduplicate
    const findings = results.flat();

    // AI-based false positive filtering
    const filtered = await this.filterWithAI(findings);

    return filtered;
  }

  private async filterWithAI(findings: Finding[]): Promise<Finding[]> {
    // Use cached prompt for efficiency
    return claudeFilterFalsePositives(findings, {
      useCache: true,
      confidenceThreshold: 0.7
    });
  }
}
```

**Data Flow**
```
Input → Validation → AI Processing → Validation → Output
  ↓                        ↓                ↓
  └────────────────────────┴────────────────┘
         Feedback Loop (TodoWrite tracking)
```

### 8. **Resilience Patterns**

**Fallback Chains**
```typescript
async function resilientSecurityScan(data: CodeData) {
  try {
    // Primary: Sonnet 4.5 (best balance of speed/accuracy)
    return await claudeSonnet45(data, {
      temperature: 0.2,  // Lower temperature for security analysis
      useCache: true
    });
  } catch (error) {
    if (error.type === 'rate_limit') {
      // Wait and retry with exponential backoff
      await sleep(exponentialBackoff(error.retryAfter));
      return await claudeSonnet45(data);
    }

    try {
      // Fallback: Rule-based detection
      return await ruleBasedSecurityScan(data);
    } catch (fallbackError) {
      // Last resort: Return empty results with error flag
      return {
        findings: [],
        error: 'All detection methods failed',
        canRetry: true
      };
    }
  }
}
```

**Circuit Breakers for AI Services**
```typescript
class CircuitBreaker {
  private failures = 0;
  private lastFailure: number | null = null;
  private state: 'closed' | 'open' | 'half-open' = 'closed';

  async call<T>(fn: () => Promise<T>, fallback: () => T): Promise<T> {
    if (this.state === 'open') {
      // Check if enough time has passed to try again
      if (Date.now() - this.lastFailure! > 60000) {
        this.state = 'half-open';
      } else {
        return fallback();
      }
    }

    try {
      const result = await fn();

      if (this.state === 'half-open') {
        this.state = 'closed';
        this.failures = 0;
      }

      return result;
    } catch (error) {
      this.failures++;
      this.lastFailure = Date.now();

      if (this.failures >= 3) {
        this.state = 'open';
      }

      return fallback();
    }
  }
}

// Usage in security scanner
const aiCircuitBreaker = new CircuitBreaker();

async function scanWithCircuitBreaker(target: Target) {
  return aiCircuitBreaker.call(
    () => claudeSonnet45Scan(target),
    () => ruleBasedScan(target)  // Deterministic fallback
  );
}
```

### 9. **Evaluation & Iteration**

**Continuous Evaluation**
```typescript
interface SecurityScanEvaluation {
  // Compare AI output against known vulnerabilities
  accuracy: (findings: Finding[], groundTruth: Vulnerability[]) => {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    f1Score: number;
  };

  // Measure user corrections
  userSatisfaction: (findings: Finding[], userEdits: Edit[]) => {
    acceptanceRate: number;
    correctionRate: number;
    averageConfidence: number;
  };

  // Track business metrics
  impact: (findings: Finding[]) => {
    criticalVulnerabilitiesFound: number;
    timeToDetection: number;
    falsePositiveRate: number;
    scanCoverage: number;
  };
}
```

**Feedback Loops**
```typescript
// Capture user corrections as training data
class FeedbackCollector {
  async recordCorrection(finding: Finding, correction: Correction) {
    await this.store.save({
      originalFinding: finding,
      userCorrection: correction,
      timestamp: Date.now(),
      confidence: finding.confidence
    });

    // Analyze patterns in corrections
    await this.analyzePattern(correction);
  }

  async analyzePattern(correction: Correction) {
    // If many corrections for a specific pattern, update rules
    const similarCorrections = await this.store.findSimilar(correction);

    if (similarCorrections.length > 10) {
      await this.suggestRuleUpdate(similarCorrections);
    }
  }
}
```

- Log confidence vs. actual accuracy correlation
- A/B test prompt variations in production
- Build evaluation datasets from real usage

## Operational Excellence

### 10. **Observability for AI Systems**

**Logging Strategy**
```typescript
interface AIOperationLog {
  promptVersion: string;
  modelUsed: 'claude-sonnet-4-5-20250929' | 'claude-opus-3' | 'rule-based';
  inputHash: string;
  outputHash: string;
  tokensUsed: {
    input: number;
    output: number;
    cached: number;  // Tokens served from cache
  };
  costs: {
    input: number;
    output: number;
    cached: number;
    total: number;
  };
  latency: number;
  confidence: number;
  userAccepted: boolean;
  corrections?: Correction[];
  cacheHit: boolean;

  // Security-specific fields
  findingsCount: number;
  severityDistribution: Record<Severity, number>;
  falsePositiveRate?: number;
}
```

**Metrics to Track**
```typescript
interface AIMetrics {
  // Performance metrics
  promptEffectivenessOverTime: TimeSeries;
  aiVsRuleBasedPerformance: Comparison;
  userInterventionRate: number;
  costPerOperation: number;
  latencyPercentiles: { p50: number; p95: number; p99: number };

  // Model usage distribution
  modelUsage: {
    sonnet45: { count: number; cost: number };
    opus: { count: number; cost: number };
    ruleBased: { count: number; cost: number };
  };

  // Cache effectiveness
  cacheHitRate: number;
  cacheLatencyReduction: number;
  cacheCostSavings: number;

  // Security scanner specific
  vulnerabilityDetectionRate: number;
  falsePositiveRate: number;
  averageScanTime: number;
  coveragePercentage: number;
}
```

### 11. **Cost Management**

**Smart Model Routing**
```typescript
function selectModel(task: SecurityTask): ModelConfig {
  // Use rule-based for simple pattern matching
  if (task.complexity < 0.3) {
    return {
      type: 'rule-based',
      cost: 0,
      latency: 10  // ms
    };
  }

  // Sonnet 4.5 as primary model (best balance)
  if (task.requiresReasoning || task.requiresContextUnderstanding) {
    return {
      type: 'claude-sonnet-4-5-20250929',
      cost: 3.00,  // $3 per million input tokens
      latency: 500,
      useCache: true  // Enable caching for 90% cost reduction
    };
  }

  // Opus only for extremely complex multi-step reasoning
  if (task.requiresDeepAnalysis && task.complexity > 0.9) {
    return {
      type: 'claude-opus-3',
      cost: 15.00,  // $15 per million input tokens
      latency: 1000
    };
  }

  // Default to Sonnet 4.5
  return {
    type: 'claude-sonnet-4-5-20250929',
    cost: 3.00,
    useCache: true
  };
}
```

**Optimization Strategies**
```typescript
class CostOptimizer {
  // Use Claude's prompt caching for repeated context
  async scanWithCaching(targets: Target[]) {
    // System prompt and security rules are cached
    const cachedContext = await this.buildCachedContext();

    // Each scan only pays for the target-specific input
    return Promise.all(
      targets.map(target =>
        claudeScan(target, {
          cachedContext,
          // 90% cost reduction on cached tokens
          cacheControl: { type: 'ephemeral' }
        })
      )
    );
  }

  // Semantic caching for similar queries
  async scanWithSemanticCache(target: Target) {
    const cached = await this.semanticCache.find(target);

    if (cached && cached.similarity > 0.95) {
      return cached.result;  // Zero cost
    }

    const result = await claudeScan(target);
    await this.semanticCache.store(target, result);

    return result;
  }

  // Batch operations when latency allows
  async batchScan(targets: Target[], maxLatency: number) {
    if (targets.length === 1 || maxLatency < 1000) {
      // Scan individually for low latency
      return Promise.all(targets.map(t => this.scanWithCaching([t])));
    }

    // Batch multiple targets in single request
    return this.scanWithCaching(targets);
  }

  // Progressive enhancement: start simple, upgrade if needed
  async adaptiveScan(target: Target) {
    // Try rule-based first (free)
    const ruleResult = await ruleBasedScan(target);

    if (ruleResult.confidence > 0.8) {
      return ruleResult;  // High confidence, no AI needed
    }

    // Upgrade to Sonnet 4.5 for uncertain cases
    return claudeSonnet45Scan(target, {
      priorResult: ruleResult,
      useCache: true
    });
  }
}
```

**Cost Monitoring**
```typescript
interface CostTracker {
  daily: {
    sonnet45: { requests: number; tokens: number; cost: number };
    opus: { requests: number; tokens: number; cost: number };
    cached: { requests: number; tokens: number; savings: number };
  };

  alerts: {
    dailyBudget: number;
    warningThreshold: number;
    currentSpend: number;
  };

  // Alert when approaching budget
  async checkBudget() {
    if (this.alerts.currentSpend > this.alerts.warningThreshold) {
      await this.notify('Approaching daily AI budget');

      // Automatically fall back to rule-based
      this.enableCostSavingMode();
    }
  }
}
```

### 12. **Context Window Optimization**

**Managing Large Codebases**
```typescript
// Sonnet 4.5 has a 200K token context window
// Average token count: 1 token ≈ 4 characters

interface ContextStrategy {
  maxTokens: 200000;
  reservedForResponse: 4096;
  availableForContext: 195904;

  // Prioritize most relevant context
  prioritize(files: File[], budget: number): File[] {
    return files
      .map(f => ({
        file: f,
        relevance: this.calculateRelevance(f),
        tokens: this.estimateTokens(f)
      }))
      .sort((a, b) => b.relevance - a.relevance)
      .reduce((acc, item) => {
        if (acc.tokens + item.tokens <= budget) {
          acc.files.push(item.file);
          acc.tokens += item.tokens;
        }
        return acc;
      }, { files: [] as File[], tokens: 0 }).files;
  }

  // Intelligent chunking for large files
  chunkLargeFile(file: File, maxChunkTokens: number): Chunk[] {
    // Split at function/class boundaries, not arbitrary lines
    const ast = parseAST(file.content);

    return ast.topLevelNodes.reduce((chunks, node) => {
      const nodeTokens = this.estimateTokens(node);

      if (nodeTokens > maxChunkTokens) {
        // Node too large, split further
        return [...chunks, ...this.splitNode(node, maxChunkTokens)];
      }

      // Try to add to current chunk
      const currentChunk = chunks[chunks.length - 1];

      if (currentChunk.tokens + nodeTokens <= maxChunkTokens) {
        currentChunk.nodes.push(node);
        currentChunk.tokens += nodeTokens;
      } else {
        // Start new chunk
        chunks.push({ nodes: [node], tokens: nodeTokens });
      }

      return chunks;
    }, [] as Chunk[]);
  }

  // Calculate relevance for security scanning
  calculateRelevance(file: File): number {
    let score = 0;

    // Prioritize files likely to contain vulnerabilities
    if (file.path.includes('auth')) score += 10;
    if (file.path.includes('api')) score += 8;
    if (file.path.includes('config')) score += 7;
    if (file.path.includes('secret')) score += 10;
    if (file.path.includes('password')) score += 10;

    // Prioritize by file type
    if (file.ext === '.py') score += 5;
    if (file.ext === '.js' || file.ext === '.ts') score += 5;
    if (file.ext === '.yaml' || file.ext === '.json') score += 6;

    // Deprioritize test files (but don't exclude)
    if (file.path.includes('test')) score -= 3;
    if (file.path.includes('__pycache__')) score -= 10;

    return score;
  }
}
```

**Example: Security Scanner with Context Optimization**
```typescript
async function scanRepositoryOptimized(repo: Repository) {
  // Get all files
  const allFiles = await repo.listFiles();

  // Filter and prioritize
  const relevantFiles = contextStrategy.prioritize(
    allFiles.filter(f => !f.path.includes('node_modules')),
    150000  // Leave room for prompt and response
  );

  // Track with TodoWrite
  const tasks = relevantFiles.map(f => ({
    content: `Scan ${f.path}`,
    activeForm: `Scanning ${f.path}`,
    status: 'pending' as const
  }));

  await TodoWrite({ todos: tasks });

  // Scan in batches to stay within context window
  const batches = chunk(relevantFiles, 50);

  for (const batch of batches) {
    await scanBatch(batch, tasks);
  }
}
```

### 13. **Tool Integration Patterns**

**MCP (Model Context Protocol) Integration**
```typescript
// Define security scanning tools for MCP
interface MCPSecurityTools {
  tools: [
    {
      name: "scan_file_for_credentials",
      description: "Scans a file for exposed credentials (API keys, passwords, tokens)",
      inputSchema: {
        type: "object",
        properties: {
          filePath: { type: "string" },
          confidenceThreshold: { type: "number", default: 0.7 }
        },
        required: ["filePath"]
      }
    },
    {
      name: "check_injection_vulnerability",
      description: "Analyzes code for SQL/command injection vulnerabilities",
      inputSchema: {
        type: "object",
        properties: {
          code: { type: "string" },
          language: { type: "string", enum: ["python", "javascript", "typescript", "go"] }
        },
        required: ["code", "language"]
      }
    },
    {
      name: "validate_crypto_implementation",
      description: "Checks cryptographic implementations for common weaknesses",
      inputSchema: {
        type: "object",
        properties: {
          code: { type: "string" },
          algorithm: { type: "string" }
        },
        required: ["code"]
      }
    }
  ];
}

// Tool approval workflow
interface ToolConfig {
  name: string;
  requiresApproval: boolean;
  autoApprovePatterns?: RegExp[];
  securityLevel: 'safe' | 'read-only' | 'destructive';
}

const toolRegistry: ToolConfig[] = [
  {
    name: "scan_file_for_credentials",
    requiresApproval: false,
    securityLevel: 'read-only'
  },
  {
    name: "write_file",
    requiresApproval: true,
    securityLevel: 'destructive'
  },
  {
    name: "bash_command",
    requiresApproval: true,
    autoApprovePatterns: [/^git status/, /^git diff/, /^npm test/],
    securityLevel: 'destructive'
  }
];

// Rate limiting for tool usage
class ToolRateLimiter {
  private limits = new Map<string, { count: number; resetAt: number }>();

  async checkLimit(toolName: string, maxPerMinute: number): Promise<boolean> {
    const now = Date.now();
    const limit = this.limits.get(toolName);

    if (!limit || now > limit.resetAt) {
      this.limits.set(toolName, { count: 1, resetAt: now + 60000 });
      return true;
    }

    if (limit.count >= maxPerMinute) {
      return false;  // Rate limit exceeded
    }

    limit.count++;
    return true;
  }
}
```

## Team Practices

### 14. **Ownership & Velocity**

**Full-Stack AI Features**
- Single engineer owns: prompt → API → UI → evaluation
- Ship MVPs fast, iterate based on real usage
- Make complexity invisible to users
- Default to simple solutions that scale

**Security Scanner Development Example**
```typescript
// One engineer owns entire feature
class CredentialScanner {
  // 1. Prompt engineering
  private prompt = `...`;

  // 2. API integration
  async scanAPI(file: string): Promise<Finding[]> { ... }

  // 3. CLI interface
  async scanCLI(args: CLIArgs): Promise<void> { ... }

  // 4. Evaluation
  async evaluate(results: Finding[]): Promise<Metrics> { ... }
}
```

**Code Review Focus**
- Prompt clarity and testability
- Error handling and fallbacks
- Performance implications (cost & latency)
- User experience during AI operations
- Security implications of tool usage
- TodoWrite usage for complex operations

### 15. **Quality Standards**

**What Great Looks Like**
- **Taste**: Loading states during AI processing are thoughtfully designed
- **Velocity**: Ship a rough AI feature, refine based on usage data
- **Judgment**: Know when to use AI vs. rules vs. human-in-loop
- **Systems Thinking**: AI components compose elegantly
- **Ownership**: Own the user outcome, not just the code
- **Security**: Defensive-only tools with clear ethical boundaries

**Example: High-Quality Security Scanner**
```typescript
class HighQualityScanner {
  async scan(target: Target): Promise<Report> {
    // 1. Taste: Show progress with TodoWrite
    await this.initializeProgress();

    // 2. Velocity: Start with simple rules, upgrade to AI
    const quickResults = await this.fastRuleScan(target);

    if (quickResults.confidence > 0.8) {
      return quickResults;  // Ship fast result
    }

    // 3. Judgment: Use AI for uncertain cases
    const aiResults = await this.aiEnhancedScan(target, {
      priorResults: quickResults
    });

    // 4. Systems thinking: Compose filters
    const filtered = await this.falsePositiveFilter
      .then(this.severityClassifier)
      .then(this.deduplicator)
      .apply(aiResults);

    // 5. Ownership: Include actionable remediation
    return {
      findings: filtered,
      remediation: await this.generateRemediation(filtered),
      confidence: this.calculateConfidence(filtered)
    };
  }
}
```

## Quick Start Checklist

When building a new AI-powered security feature:

- [ ] Define success metrics before writing code
- [ ] Validate defensive-only purpose (no offensive capabilities)
- [ ] Design the non-AI fallback first (rule-based detection)
- [ ] Implement streaming/progressive UI with TodoWrite tracking
- [ ] Add confidence indicators to all findings
- [ ] Build evaluation framework (precision, recall, F1)
- [ ] Create undo/correction mechanisms for findings
- [ ] Implement cost controls (caching, model selection)
- [ ] Add observability (logs, metrics, traces)
- [ ] Test with real messy codebases
- [ ] Configure prompt caching for repeated context
- [ ] Use clickable file references for VSCode integration
- [ ] Ship and iterate based on user feedback

## Security Scanner Specific Patterns

### **Defensive Security Best Practices**

```typescript
// Always validate intent before scanning
class DefensiveScannerGuard {
  async validateScanRequest(request: ScanRequest): Promise<void> {
    // Block offensive patterns
    const offensiveIntents = [
      'harvest credentials',
      'collect ssh keys in bulk',
      'steal browser cookies',
      'exploit vulnerability'
    ];

    if (offensiveIntents.some(intent =>
      request.description.toLowerCase().includes(intent)
    )) {
      throw new Error(
        'Offensive security tasks are not supported. ' +
        'This tool is for defensive security analysis only.'
      );
    }

    // Allow defensive patterns
    const defensiveIntents = [
      'detect vulnerabilities',
      'find exposed credentials',
      'security audit',
      'compliance check'
    ];

    if (!defensiveIntents.some(intent =>
      request.description.toLowerCase().includes(intent)
    )) {
      // Ask for clarification
      await this.clarifyIntent(request);
    }
  }
}
```

### **Multi-Repository Scanning Pattern**

```typescript
async function scanMultipleRepos(repos: Repository[]) {
  // Use TodoWrite to track progress
  const tasks = [
    { content: 'Initialize scan environment', activeForm: 'Initializing scan', status: 'pending' },
    ...repos.map(r => ({
      content: `Scan ${r.name} for vulnerabilities`,
      activeForm: `Scanning ${r.name}`,
      status: 'pending'
    })),
    { content: 'Aggregate results', activeForm: 'Aggregating results', status: 'pending' },
    { content: 'Apply false positive filters', activeForm: 'Filtering false positives', status: 'pending' },
    { content: 'Generate consolidated report', activeForm: 'Generating report', status: 'pending' }
  ];

  await TodoWrite({ todos: tasks });

  // Execute with progress tracking
  tasks[0].status = 'in_progress';
  await TodoWrite({ todos: tasks });
  await initializeEnvironment();
  tasks[0].status = 'completed';
  await TodoWrite({ todos: tasks });

  // Scan each repo
  const results = [];
  for (let i = 0; i < repos.length; i++) {
    const taskIndex = i + 1;
    tasks[taskIndex].status = 'in_progress';
    await TodoWrite({ todos: tasks });

    const result = await scanRepository(repos[i]);
    results.push(result);

    tasks[taskIndex].status = 'completed';
    await TodoWrite({ todos: tasks });
  }

  // Aggregate
  tasks[repos.length + 1].status = 'in_progress';
  await TodoWrite({ todos: tasks });
  const aggregated = aggregateResults(results);
  tasks[repos.length + 1].status = 'completed';

  // Filter
  tasks[repos.length + 2].status = 'in_progress';
  await TodoWrite({ todos: tasks });
  const filtered = await filterFalsePositives(aggregated);
  tasks[repos.length + 2].status = 'completed';

  // Report
  tasks[repos.length + 3].status = 'in_progress';
  await TodoWrite({ todos: tasks });
  const report = await generateReport(filtered);
  tasks[repos.length + 3].status = 'completed';
  await TodoWrite({ todos: tasks });

  return report;
}
```

## Key Takeaways

Build AI-powered security tools like operating systems, not applications. Provide a **platform** where humans and AI collaborate on defensive security, with:

1. **Clear ethical boundaries** - Defensive only, no offensive capabilities
2. **Graceful degradation** - Rule-based fallbacks when AI is unavailable
3. **Transparent operations** - TodoWrite tracking for complex scans
4. **Cost optimization** - Prompt caching, smart model selection
5. **Iterative improvement** - Learn from false positives and user corrections
6. **Context awareness** - VSCode integration with clickable references
7. **Production readiness** - Observability, error handling, rate limiting

Make the complex feel simple, the non-deterministic feel reliable, and the powerful feel accessible—while maintaining strong ethical guardrails for security tooling.

---

## Model Reference

**Primary Model: Claude Sonnet 4.5**
- Model ID: `claude-sonnet-4-5-20250929`
- Context window: 200,000 tokens
- Best for: Most AI tasks, code analysis, security scanning
- Cost: $3/MTok input, $15/MTok output
- With caching: $0.30/MTok cached tokens (90% savings)

**Secondary Model: Claude Opus 3**
- Use for: Extremely complex multi-step reasoning only
- Cost: $15/MTok input, $75/MTok output
- Recommendation: Reserve for <5% of tasks

**Cost Optimization Priority:**
1. Rule-based detection (free)
2. Sonnet 4.5 with caching (90% cheaper)
3. Sonnet 4.5 without caching
4. Opus (only when absolutely necessary)
