const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const API_KEY = 'sk-1234567890abcdef'; // Hardcoded secret

const app = express();

app.get('/api/:file', (req, res) => {
  const filename = req.params.file;
  
  // Path traversal vulnerability
  const filePath = path.join(__dirname, '../../../', filename);
  
  // Command injection
  exec(`cat ${filename}`, (error, stdout) => {
    res.send(stdout);
  });
  
  // Log injection
  console.log(`Accessing file: ${filename}`);
});

// Test function
function testFunction() {
  const MOCK_SECRET = 'test-secret-123456789';
  console.log('Testing with:', MOCK_SECRET);
}

module.exports = app;