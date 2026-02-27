/**
 * Phishing Guard Extension - Lint Script
 * Basic linting for extension files
 */

const fs = require('fs');

console.log('[LINT] Running code linting...\n');

let issues = 0;

function lintFile(filePath, checks) {
  if (!fs.existsSync(filePath)) {
    console.log(`⚠ File not found: ${filePath}`);
    issues++;
    return;
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const lines = content.split('\n');

  console.log(`\n📄 ${filePath}`);

  checks.forEach(check => {
    const matches = check.regex.test(content);
    if (check.shouldExist && !matches) {
      console.log(`  ⚠ ${check.message}`);
      issues++;
    } else if (!check.shouldExist && matches) {
      console.log(`  ⚠ ${check.message}`);
      issues++;
    }
  });

  // Check for console.log in production files
  if (!filePath.includes('scripts/')) {
    const consoleLogs = content.match(/console\.(log|debug)\(/g);
    if (consoleLogs) {
      console.log(`  ℹ Found ${consoleLogs.length} console.log statements`);
    }
  }
}

// Lint JavaScript files
lintFile('manifest.json', [
  { regex: /"manifest_version":\s*3/, shouldExist: true, message: 'Should use manifest_version 3' },
  { regex: /"name":/, shouldExist: true, message: 'Should have a name' },
  { regex: /"version":/, shouldExist: true, message: 'Should have a version' }
]);

lintFile('background.js', [
  { regex: /chrome\.runtime\.onInstalled/, shouldExist: true, message: 'Should handle onInstalled event' },
  { regex: /chrome\.runtime\.onMessage/, shouldExist: true, message: 'Should handle onMessage event' }
]);

lintFile('content.js', [
  { regex: /chrome\.runtime\.onMessage/, shouldExist: true, message: 'Should handle messages from background' }
]);

lintFile('popup.js', [
  { regex: /DOMContentLoaded/, shouldExist: true, message: 'Should wait for DOM to load' }
]);

// Lint documentation
lintFile('PRIVACY_POLICY.md', [
  { regex: /Data Collection/i, shouldExist: true, message: 'Should mention data collection' },
  { regex: /privacy/i, shouldExist: true, message: 'Should mention privacy' }
]);

console.log(`\n[LINT] Found ${issues} issues`);

if (issues > 0) {
  console.log('\nNote: Some issues may be warnings, not errors.');
}
