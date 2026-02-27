/**
 * Phishing Guard Extension - Simple Test Script
 * Basic validation tests for the extension
 */

const fs = require('fs');
const path = require('path');

console.log('[TEST] Running extension validation tests...\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (error) {
    console.log(`✗ ${name}: ${error.message}`);
    failed++;
  }
}

// Test manifest exists
test('manifest.json exists', () => {
  if (!fs.existsSync('manifest.json')) {
    throw new Error('manifest.json not found');
  }
});

// Test manifest is valid JSON
test('manifest.json is valid JSON', () => {
  const content = fs.readFileSync('manifest.json', 'utf8');
  JSON.parse(content);
});

// Test required manifest fields
test('manifest has required fields', () => {
  const manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));
  const required = ['manifest_version', 'name', 'version', 'description'];
  for (const field of required) {
    if (!manifest[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }
});

// Test manifest version is 3
test('manifest_version is 3', () => {
  const manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));
  if (manifest.manifest_version !== 3) {
    throw new Error(`manifest_version should be 3, got ${manifest.manifest_version}`);
  }
});

// Test required files exist
test('background.js exists', () => {
  if (!fs.existsSync('background.js')) {
    throw new Error('background.js not found');
  }
});

test('content.js exists', () => {
  if (!fs.existsSync('content.js')) {
    throw new Error('content.js not found');
  }
});

test('popup.html exists', () => {
  if (!fs.existsSync('popup.html')) {
    throw new Error('popup.html not found');
  }
});

// Test icons exist
test('icon16.png exists', () => {
  if (!fs.existsSync('images/icon16.png')) {
    throw new Error('images/icon16.png not found');
  }
});

test('icon48.png exists', () => {
  if (!fs.existsSync('images/icon48.png')) {
    throw new Error('images/icon48.png not found');
  }
});

test('icon128.png exists', () => {
  if (!fs.existsSync('images/icon128.png')) {
    throw new Error('images/icon128.png not found');
  }
});

// Test documentation exists
test('PRIVACY_POLICY.md exists', () => {
  if (!fs.existsSync('PRIVACY_POLICY.md')) {
    throw new Error('PRIVACY_POLICY.md not found');
  }
});

test('INSTALL.md exists', () => {
  if (!fs.existsSync('INSTALL.md')) {
    throw new Error('INSTALL.md not found');
  }
});

// Test build scripts exist
test('Build scripts exist', () => {
  if (!fs.existsSync('scripts/build.js')) {
    throw new Error('scripts/build.js not found');
  }
});

console.log(`\n[TEST] Results: ${passed} passed, ${failed} failed`);

if (failed > 0) {
  process.exit(1);
}
