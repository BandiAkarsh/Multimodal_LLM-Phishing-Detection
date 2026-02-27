/**
 * Phishing Guard Extension - Clean Script
 * Removes build artifacts
 */

const fs = require('fs');
const path = require('path');

const dirsToClean = ['dist', 'node_modules', '.tmp'];

console.log('[CLEAN] Cleaning build artifacts...\n');

let cleaned = 0;

for (const dir of dirsToClean) {
  if (fs.existsSync(dir)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
      console.log(`✓ Removed: ${dir}/`);
      cleaned++;
    } catch (error) {
      console.log(`✗ Failed to remove: ${dir}/ - ${error.message}`);
    }
  } else {
    console.log(`○ Not found: ${dir}/`);
  }
}

console.log(`\n[CLEAN] Cleaned ${cleaned} directories`);
