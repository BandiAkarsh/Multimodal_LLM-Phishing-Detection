#!/usr/bin/env node

/**
 * Phishing Guard Extension Release Script
 * Creates GitHub releases with distribution packages
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const CONFIG = {
  extensionName: 'Phishing Guard',
  repoOwner: 'yourusername',
  repoName: 'phishing-detection-project',
  distDir: 'dist'
};

function log(message, type = 'info') {
  const colors = {
    info: '\x1b[36m',
    success: '\x1b[32m',
    warning: '\x1b[33m',
    error: '\x1b[31m',
    reset: '\x1b[0m'
  };
  console.log(`${colors[type]}[RELEASE]${colors.reset} ${message}`);
}

function getCurrentVersion() {
  const manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));
  return manifest.version;
}

function validateRelease(version) {
  log('Validating release...', 'info');
  
  // Check if version is tagged
  try {
    execSync(`git rev-parse v${version}`, { stdio: 'pipe' });
    log(`Tag v${version} exists`, 'success');
  } catch {
    log(`Tag v${version} does not exist. Create it first:`, 'warning');
    log(`  git tag v${version}`, 'info');
    log(`  git push origin v${version}`, 'info');
    return false;
  }
  
  // Check if dist exists
  if (!fs.existsSync(CONFIG.distDir)) {
    log(`Dist directory not found. Run: npm run build:dist`, 'error');
    return false;
  }
  
  // Check for ZIP file
  const zipFile = `phishing-guard-v${version}.zip`;
  const zipPath = path.join(CONFIG.distDir, zipFile);
  if (!fs.existsSync(zipPath)) {
    log(`ZIP file not found: ${zipPath}`, 'error');
    log(`Run: npm run build:dist`, 'info');
    return false;
  }
  
  log('All validations passed', 'success');
  return true;
}

function generateReleaseNotes(version) {
  log('Generating release notes...', 'info');
  
  // Read CHANGELOG
  const changelog = fs.readFileSync('CHANGELOG.md', 'utf8');
  
  // Extract version section
  const versionPattern = new RegExp(`## \\[${version}\\].*?(?=## \\[|$)`, 's');
  const match = changelog.match(versionPattern);
  
  if (match) {
    let notes = match[0];
    // Remove version header
    notes = notes.replace(/## \[.*?\].*/, '').trim();
    
    // Add installation section
    notes += `\n\n## Installation\n\n`;
    notes += `### Chrome Web Store\n`;
    notes += `Coming soon...\n\n`;
    notes += `### Manual Installation\n`;
    notes += `1. Download \`phishing-guard-v${version}.zip\` from this release\n`;
    notes += `2. Extract the ZIP file\n`;
    notes += `3. Open Chrome and go to \`chrome://extensions/\`\n`;
    notes += `4. Enable "Developer mode" (toggle in top right)\n`;
    notes += `5. Click "Load unpacked"\n`;
    notes += `6. Select the extracted folder\n`;
    notes += `7. Done!\n`;
    
    return notes;
  }
  
  return `Release v${version}\n\nSee CHANGELOG.md for details.`;
}

function createGitHubRelease(version, notes) {
  log('Creating GitHub release...', 'info');
  
  const zipFile = `phishing-guard-v${version}.zip`;
  const zipPath = path.join(CONFIG.distDir, zipFile);
  
  // Check if gh CLI is installed
  try {
    execSync('gh --version', { stdio: 'pipe' });
  } catch {
    log('GitHub CLI (gh) not installed. Install it:', 'error');
    log('  https://cli.github.com/', 'info');
    return false;
  }
  
  // Write notes to temp file
  const notesFile = path.join('.tmp', 'release-notes.md');
  fs.mkdirSync('.tmp', { recursive: true });
  fs.writeFileSync(notesFile, notes);
  
  try {
    // Create release
    const cmd = `gh release create v${version} "${zipPath}" \
      --title "Phishing Guard v${version}" \
      --notes-file "${notesFile}" \
      --repo ${CONFIG.repoOwner}/${CONFIG.repoName}`;
    
    execSync(cmd, { stdio: 'inherit' });
    
    log(`Release v${version} created successfully!`, 'success');
    return true;
  } catch (error) {
    log(`Failed to create release: ${error.message}`, 'error');
    return false;
  } finally {
    // Cleanup
    if (fs.existsSync(notesFile)) {
      fs.unlinkSync(notesFile);
    }
  }
}

function updateLatestRelease(version) {
  log('Updating latest release info...', 'info');
  
  const releaseInfo = {
    version: version,
    date: new Date().toISOString(),
    downloadUrl: `https://github.com/${CONFIG.repoOwner}/${CONFIG.repoName}/releases/download/v${version}/phishing-guard-v${version}.zip`
  };
  
  fs.writeFileSync(
    path.join(CONFIG.distDir, 'latest-release.json'),
    JSON.stringify(releaseInfo, null, 2)
  );
  
  log('Updated latest-release.json', 'success');
}

function main() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║        Phishing Guard - Release Management                ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('\n');
  
  const args = process.argv.slice(2);
  const skipValidation = args.includes('--skip-validation');
  
  const version = getCurrentVersion();
  log(`Preparing release for v${version}`, 'info');
  
  // Validate
  if (!skipValidation) {
    if (!validateRelease(version)) {
      process.exit(1);
    }
  }
  
  // Generate release notes
  const notes = generateReleaseNotes(version);
  
  // Show preview
  console.log('\n--- Release Notes Preview ---\n');
  console.log(notes);
  console.log('\n-----------------------------\n');
  
  // Ask for confirmation (in real usage)
  // For now, auto-continue
  
  // Create GitHub release
  if (createGitHubRelease(version, notes)) {
    updateLatestRelease(version);
    
    console.log('\n');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║              RELEASE COMPLETED SUCCESSFULLY               ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log(`\nVersion: v${version}`);
    console.log(`GitHub Release: https://github.com/${CONFIG.repoOwner}/${CONFIG.repoName}/releases/tag/v${version}`);
    console.log('\nNext steps:');
    console.log('1. Visit the GitHub release page');
    console.log('2. Upload to Chrome Web Store');
    console.log('3. Update website/download links');
    console.log('\n');
  }
}

main();
