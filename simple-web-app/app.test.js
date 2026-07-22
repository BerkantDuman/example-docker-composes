const http = require('http');

// ============================================
// Configuration (Single Responsibility)
// ============================================
const config = {
  baseUrl: 'http://localhost:4000',
  defaultTimeout: 5000
};

// ============================================
// HTTP Client (Single Responsibility)
// ============================================
class HttpClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
  }

  get(path, timeout = config.defaultTimeout) {
    return this.request(path, 'GET', timeout);
  }

  request(path, method, timeout) {
    return new Promise((resolve, reject) => {
      const url = new URL(path, this.baseUrl);
      const req = http.request(url, { method }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data
          });
        });
      });

      req.on('error', reject);
      req.setTimeout(timeout, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      req.end();
    });
  }
}

// ============================================
// Assertions (Single Responsibility)
// ============================================
const assert = {
  equals(actual, expected, message) {
    if (actual !== expected) {
      throw new Error(message || `Expected ${expected}, got ${actual}`);
    }
  },

  exists(value, message) {
    if (value === undefined || value === null) {
      throw new Error(message || 'Value should exist');
    }
  },

  isTrue(condition, message) {
    if (!condition) {
      throw new Error(message || 'Condition should be true');
    }
  }
};

// ============================================
// Test Runner (Single Responsibility)
// ============================================
class TestRunner {
  constructor() {
    this.results = { passed: 0, failed: 0 };
  }

  async run(name, testFn) {
    try {
      await testFn();
      console.log(`✓ ${name}`);
      this.results.passed++;
      return true;
    } catch (error) {
      console.log(`✗ ${name}`);
      console.log(`  Error: ${error.message}`);
      this.results.failed++;
      return false;
    }
  }

  printSummary() {
    console.log(`\n-----------------------`);
    console.log(`Results: ${this.results.passed} passed, ${this.results.failed} failed`);
    console.log(`-----------------------`);
  }

  getExitCode() {
    return this.results.failed > 0 ? 1 : 0;
  }
}

// ============================================
// Test Cases (Open/Closed - Easy to extend)
// ============================================
const createTestCases = (client) => [
  {
    name: 'Server should be running on port 4000',
    test: async () => {
      const res = await client.get('/');
      assert.exists(res.status, 'Server not responding');
    }
  },
  {
    name: '/home endpoint should exist (timeout expected due to delay)',
    test: async () => {
      try {
        await client.get('/home', 1000);
        throw new Error('Should have timed out');
      } catch (error) {
        assert.equals(error.message, 'Request timeout', 'Endpoint should exist but timeout');
      }
    }
  },
  {
    name: 'Static middleware should handle requests',
    test: async () => {
      const res = await client.get('/nonexistent-file.html');
      assert.isTrue(
        res.status === 404 || res.status === 200,
        'Static middleware not working'
      );
    }
  },
  {
    name: 'Unknown route should return 404',
    test: async () => {
      const res = await client.get('/unknown-route-12345');
      assert.equals(res.status, 404, `Expected 404, got ${res.status}`);
    }
  },
  {
    name: 'Response should include headers',
    test: async () => {
      const res = await client.get('/');
      assert.exists(res.headers, 'Headers should exist');
    }
  }
];

// ============================================
// Main (Dependency Injection)
// ============================================
async function main() {
  console.log('Running tests for app.js...\n');
  console.log('Note: Server must be running on port 4000\n');

  const client = new HttpClient(config.baseUrl);
  const runner = new TestRunner();
  const testCases = createTestCases(client);

  for (const { name, test } of testCases) {
    await runner.run(name, test);
  }

  runner.printSummary();
  process.exit(runner.getExitCode());
}

main().catch(err => {
  console.error('Test runner error:', err);
  process.exit(1);
});
