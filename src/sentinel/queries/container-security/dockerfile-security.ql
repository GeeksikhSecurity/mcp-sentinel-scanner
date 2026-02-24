/**
 * @name Dockerfile security vulnerabilities
 * @description Detects security issues in Dockerfile configurations
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id js/dockerfile-security
 * @tags security
 *       container
 *       docker
 *       devops
 */

import javascript

/**
 * Dockerfile content analysis
 */
class DockerfileContent extends File {
  DockerfileContent() {
    this.getBaseName() = "Dockerfile" or
    this.getExtension() = "dockerfile"
  }
  
  /**
   * Get all lines in the Dockerfile
   */
  string getLine(int lineNumber) {
    result = this.getALine().getText() and
    lineNumber = this.getALine().getLineNumber()
  }
  
  /**
   * Check if running as root user
   */
  predicate runsAsRoot() {
    not exists(string line |
      line = this.getLine(_) and
      line.regexpMatch("(?i)USER\\s+(?!root|0).*")
    )
  }
  
  /**
   * Check for hardcoded secrets
   */
  predicate containsSecrets() {
    exists(string line |
      line = this.getLine(_) and
      (line.regexpMatch("(?i).*password\\s*=\\s*['\"][^'\"]+['\"].*") or
       line.regexpMatch("(?i).*api[_-]?key\\s*=\\s*['\"][^'\"]+['\"].*") or
       line.regexpMatch("(?i).*secret\\s*=\\s*['\"][^'\"]+['\"].*") or
       line.regexpMatch("(?i).*token\\s*=\\s*['\"][^'\"]+['\"].*"))
    )
  }
  
  /**
   * Check for latest tag usage
   */
  predicate usesLatestTag() {
    exists(string line |
      line = this.getLine(_) and
      line.regexpMatch("(?i)FROM\\s+[^:]+:latest.*")
    )
  }
  
  /**
   * Check for package manager cache cleanup
   */
  predicate cleansPackageCache() {
    exists(string line |
      line = this.getLine(_) and
      (line.regexpMatch("(?i).*apt-get\\s+clean.*") or
       line.regexpMatch("(?i).*rm\\s+-rf\\s+/var/lib/apt/lists/\\*.*") or
       line.regexpMatch("(?i).*yum\\s+clean\\s+all.*") or
       line.regexpMatch("(?i).*apk\\s+--no-cache.*"))
    )
  }
  
  /**
   * Check for unnecessary packages
   */
  predicate installsUnnecessaryPackages() {
    exists(string line |
      line = this.getLine(_) and
      (line.regexpMatch("(?i).*apt-get\\s+install.*curl.*wget.*") or
       line.regexpMatch("(?i).*yum\\s+install.*curl.*wget.*") or
       line.regexpMatch("(?i).*apk\\s+add.*curl.*wget.*"))
    )
  }
  
  /**
   * Check for COPY with broad permissions
   */
  predicate usesBroadCopy() {
    exists(string line |
      line = this.getLine(_) and
      line.regexpMatch("(?i)COPY\\s+\\.\\s+.*")
    )
  }
  
  /**
   * Check for exposed sensitive ports
   */
  predicate exposesSensitivePorts() {
    exists(string line |
      line = this.getLine(_) and
      (line.regexpMatch("(?i)EXPOSE\\s+22\\b.*") or      // SSH
       line.regexpMatch("(?i)EXPOSE\\s+3306\\b.*") or    // MySQL
       line.regexpMatch("(?i)EXPOSE\\s+5432\\b.*") or    // PostgreSQL
       line.regexpMatch("(?i)EXPOSE\\s+6379\\b.*") or    // Redis
       line.regexpMatch("(?i)EXPOSE\\s+27017\\b.*"))     // MongoDB
    )
  }
  
  /**
   * Check for health check configuration
   */
  predicate hasHealthCheck() {
    exists(string line |
      line = this.getLine(_) and
      line.regexpMatch("(?i)HEALTHCHECK.*")
    )
  }
  
  /**
   * Check for multi-stage build usage
   */
  predicate usesMultiStage() {
    exists(string line1, string line2 |
      line1 = this.getLine(_) and
      line2 = this.getLine(_) and
      line1.regexpMatch("(?i)FROM\\s+.*\\s+AS\\s+.*") and
      line2.regexpMatch("(?i)FROM\\s+.*")
    )
  }
}

/**
 * Docker Compose security issues
 */
class DockerComposeContent extends File {
  DockerComposeContent() {
    this.getBaseName().regexpMatch("docker-compose.*\\.ya?ml")
  }
  
  predicate hasPrivilegedContainers() {
    exists(string content |
      content = this.getContents() and
      content.regexpMatch("(?s).*privileged:\\s*true.*")
    )
  }
  
  predicate exposesHostNetwork() {
    exists(string content |
      content = this.getContents() and
      content.regexpMatch("(?s).*network_mode:\\s*host.*")
    )
  }
  
  predicate mountsHostRoot() {
    exists(string content |
      content = this.getContents() and
      content.regexpMatch("(?s).*-\\s*/:/.*")
    )
  }
  
  predicate hasNoResourceLimits() {
    exists(string content |
      content = this.getContents() and
      not content.regexpMatch("(?s).*deploy:.*resources:.*limits:.*")
    )
  }
}

/**
 * Kubernetes security issues in YAML files
 */
class KubernetesManifest extends File {
  KubernetesManifest() {
    this.getExtension() = "yaml" or this.getExtension() = "yml" and
    this.getContents().regexpMatch("(?s).*apiVersion:.*kind:.*")
  }
  
  predicate runsAsRoot() {
    exists(string content |
      content = this.getContents() and
      not content.regexpMatch("(?s).*securityContext:.*runAsNonRoot:\\s*true.*")
    )
  }
  
  predicate allowsPrivilegeEscalation() {
    exists(string content |
      content = this.getContents() and
      not content.regexpMatch("(?s).*securityContext:.*allowPrivilegeEscalation:\\s*false.*")
    )
  }
  
  predicate hasNoResourceLimits() {
    exists(string content |
      content = this.getContents() and
      not content.regexpMatch("(?s).*resources:.*limits:.*")
    )
  }
  
  predicate exposesHostPorts() {
    exists(string content |
      content = this.getContents() and
      content.regexpMatch("(?s).*hostPort:.*")
    )
  }
}

from File containerFile, string issue, string severity, int lineNumber
where
  (
    containerFile instanceof DockerfileContent and
    containerFile.(DockerfileContent).runsAsRoot() and
    issue = "Container runs as root user (security risk)" and
    severity = "HIGH" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerfileContent and
    containerFile.(DockerfileContent).containsSecrets() and
    issue = "Hardcoded secrets found in Dockerfile" and
    severity = "CRITICAL" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerfileContent and
    containerFile.(DockerfileContent).usesLatestTag() and
    issue = "Using 'latest' tag is not recommended for production" and
    severity = "MEDIUM" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerfileContent and
    not containerFile.(DockerfileContent).cleansPackageCache() and
    issue = "Package manager cache not cleaned (increases image size)" and
    severity = "LOW" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerfileContent and
    containerFile.(DockerfileContent).usesBroadCopy() and
    issue = "COPY . command copies entire context (potential security risk)" and
    severity = "MEDIUM" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerfileContent and
    containerFile.(DockerfileContent).exposesSensitivePorts() and
    issue = "Exposing sensitive database/service ports" and
    severity = "HIGH" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerfileContent and
    not containerFile.(DockerfileContent).hasHealthCheck() and
    issue = "No health check configured" and
    severity = "LOW" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerComposeContent and
    containerFile.(DockerComposeContent).hasPrivilegedContainers() and
    issue = "Privileged containers detected (security risk)" and
    severity = "CRITICAL" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerComposeContent and
    containerFile.(DockerComposeContent).exposesHostNetwork() and
    issue = "Host network mode exposes container to host network" and
    severity = "HIGH" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof DockerComposeContent and
    containerFile.(DockerComposeContent).mountsHostRoot() and
    issue = "Mounting host root directory (/) is dangerous" and
    severity = "CRITICAL" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof KubernetesManifest and
    containerFile.(KubernetesManifest).runsAsRoot() and
    issue = "Kubernetes pod runs as root user" and
    severity = "HIGH" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof KubernetesManifest and
    containerFile.(KubernetesManifest).allowsPrivilegeEscalation() and
    issue = "Privilege escalation not disabled" and
    severity = "HIGH" and
    lineNumber = 1
  ) or
  (
    containerFile instanceof KubernetesManifest and
    containerFile.(KubernetesManifest).hasNoResourceLimits() and
    issue = "No resource limits configured" and
    severity = "MEDIUM" and
    lineNumber = 1
  )
select containerFile, issue + " (Severity: " + severity + ")"