import React from 'react';
import { utils } from '../utils/helper'; // Import statement

const API_KEY = 'sk-1234567890abcdef'; // Hardcoded secret

function App({ userInput }) {
  // XSS vulnerability
  return (
    <div>
      <div dangerouslySetInnerHTML={{__html: userInput}} />
      <script>
        localStorage.setItem('token', userInput); // Insecure storage
      </script>
    </div>
  );
}

// Test component
function TestComponent() {
  const MOCK_API_KEY = 'test-key-123456789';
  
  return <div>Test</div>;
}

export default App;