/**
 * Phishing Guard Extension - Version Management Script
 * Bumps version numbers across all files
 */

const fs = require('fs');
const path = require('path');

const VERSION_TYPES = ['patch', 'minor', 'major'];

function parseVersion(version) {
  const parts = version.split('.').map(Number);
  return { major: parts[0], minor: parts[1], patch: parts[2] };
}

function bumpVersion(currentVersion, type) {
  const v = parseVersion(currentVersion);
  
  switch (type) {
    case 'major':
      v.major++;
      v.minor = 0;
      v.patch = 0;
      break;
    case 'minor':
      v.minor++;
      v.patch = 0;
      break;
    case 'patch':
    default:
      v.patch++;
      break;
  }
  
  return `${v.major}.${v.minor}.${v.patch}`;
}

function updateManifest(version) {
  const manifestPath = 'manifest.json';
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.version = version;
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  console.log(`✓ Updated manifest.json to v${version}`);
}

function updatePackageJson(version) {
  const packagePath = 'package.json';
  if (fs.existsSync(packagePath)) {
    const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
    pkg.version = version;
    fs.writeFileSync(packagePath, JSON.stringify(pkg, null, 2));
    console.log(`✓ Updated package.json to v${version}`);
  }
}

function updateBuildScript(version) {
  const buildScriptPath = 'scripts/build.js';
  if (fs.existsSync(buildScriptPath)) {
    let content = fs.readFileSync(buildScriptPath, 'utf8');
    content = content.replace(/version: '[^']*'/, `version: '${version}'`);
    fs.writeFileSync(buildScriptPath, content);
    console.log(`✓ Updated build.js to v${version}`);
  }
  
  const buildShPath = 'scripts/build.sh';
  if (fs.existsSync(buildShPath)) {
    let content = fs.readFileSync(buildShPath, 'utf8');
    content = content.replace(/VERSION="[^"]*"/, `VERSION="${version}"`);
    fs.writeFileSync(buildShPath, content);
    console.log(`✓ Updated build.sh to v${version}`);
  }
}

function main() {
  const args = process.argv.slice(2);
  const bumpType = args[0] || 'patch';
  
  if (!VERSION_TYPES.includes(bumpType)) {
    console.error(`Invalid version type: ${bumpType}`);
    console.log(`Usage: node scripts/version.js [${VERSION_TYPES.join('|')}]`);
    process.exit(1);
  }
  
  // Read current version from manifest
  const manifest = JSON.parse(fs.readFileSync('manifest.json', 'utf8'));
  const currentVersion = manifest.version;
  const newVersion = bumpVersion(currentVersion, bumpType);
  
  console.log(`\n[VERSION] Bumping ${bumpType} version...`);
  console.log(`Current: v${currentVersion}`);
  console.log(`New:     v${newVersion}\n`);
  
  updateManifest(newVersion);
  updatePackageJson(newVersion);
  updateBuildScript(newVersion);
  
  console.log(`\n✓ Version bumped to v${newVersion}`);
  console.log('\nDon\'t forget to:');
  console.log('  1. Update CHANGELOG.md');
  console.log('  2. Create a git tag: git tag v' + newVersion);
  console.log('  3. Push tag: git push origin v' + newVersion);
}

main();
