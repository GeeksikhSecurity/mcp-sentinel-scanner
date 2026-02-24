"""Robust repository cloning utility with error handling."""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any

class RepositoryCloner:
    """Robust repository cloner with comprehensive error handling."""
    
    def __init__(self, base_path: str = ".cache/repo_corpus"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def clone_repositories(self, repo_urls: List[str]) -> Dict[str, Any]:
        """Clone multiple repositories with error handling."""
        results = {'successful': [], 'failed': []}
        
        for repo_url in repo_urls:
            result = self.clone_single_repository(repo_url)
            if result['status'] == 'success':
                results['successful'].append(result)
            else:
                results['failed'].append(result)
        
        return results
    
    def clone_single_repository(self, repo_url: str) -> Dict[str, Any]:
        """Clone a single repository with error handling."""
        repo_name = self._extract_repo_name(repo_url)
        target_path = self.base_path / repo_name
        
        if target_path.exists():
            return {'repo_url': repo_url, 'repo_name': repo_name, 'status': 'skipped'}
        
        try:
            cmd = ['git', 'clone', repo_url, str(target_path)]
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if process.returncode == 0:
                return {'repo_url': repo_url, 'repo_name': repo_name, 'status': 'success'}
            else:
                error = self._parse_git_error(process.stderr)
                return {'repo_url': repo_url, 'repo_name': repo_name, 'status': 'failed', 'error': error}
        
        except Exception as e:
            return {'repo_url': repo_url, 'repo_name': repo_name, 'status': 'failed', 'error': str(e)}
    
    def _extract_repo_name(self, repo_url: str) -> str:
        """Extract repository name from URL."""
        if repo_url.endswith('.git'):
            repo_url = repo_url[:-4]
        parts = repo_url.rstrip('/').split('/')
        return f"{parts[-2]}-{parts[-1]}" if len(parts) >= 2 else parts[-1]
    
    def _parse_git_error(self, stderr: str) -> str:
        """Parse Git error messages."""
        if 'not found' in stderr.lower():
            return 'Repository not found'
        elif 'permission denied' in stderr.lower():
            return 'Access denied'
        elif 'timeout' in stderr.lower():
            return 'Network timeout'
        return stderr.split('\n')[0] if stderr else 'Unknown error'