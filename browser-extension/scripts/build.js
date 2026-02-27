#!/usr/bin/env node

/**
 * Phishing Guard Extension Build Script
 * Creates distribution package for Chrome Web Store
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Configuration
const CONFIG = {
  sourceDir: '.',
  distDir: 'dist',
  assetsDir: 'store-assets',
  manifestFile: 'manifest.json',
  extensionName: 'phishing-guard',
  version: '2.0.0'
};

// Files to include in the distribution
const INCLUDE_FILES = [
  'manifest.json',
  'background.js',
  'content.js',
  'popup.html',
  'popup.js',
  'popup.css',
  'styles.css',
  'images/icon16.png',
  'images/icon48.png',
  'images/icon128.png'
];

// Files to exclude
const EXCLUDE_PATTERNS = [
  'node_modules',
  'dist',
  'scripts',
  'store-assets',
  'docs',
  'test',
  '.git',
  '.tmp',
  'test-page.html',
  'content-script.js',
  'detector.js',
  'STANDALONE_SUMMARY.md',
  '*.md',
  'package.json',
  'package-lock.json'
];

function log(message, type = 'info') {
  const colors = {
    info: '\x1b[36m',
    success: '\x1b[32m',
    warning: '\x1b[33m',
    error: '\x1b[31m',
    reset: '\x1b[0m'
  };
  console.log(`${colors[type]}[BUILD]${colors.reset} ${message}`);
}

function ensureDirectory(dir) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    log(`Created directory: ${dir}`, 'info');
  }
}

function cleanDirectory(dir) {
  if (fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true });
    log(`Cleaned directory: ${dir}`, 'warning');
  }
}

function copyFile(src, dest) {
  const destDir = path.dirname(dest);
  ensureDirectory(destDir);
  
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    log(`Copied: ${src} → ${dest}`, 'success');
    return true;
  } else {
    log(`Missing: ${src}`, 'warning');
    return false;
  }
}

function shouldInclude(file) {
  const relativePath = path.relative(CONFIG.sourceDir, file);
  
  // Check exclude patterns
  for (const pattern of EXCLUDE_PATTERNS) {
    if (relativePath.includes(pattern)) return false;
  }
  
  // Check include patterns
  if (INCLUDE_FILES.includes(relativePath)) return true;
  
  return false;
}

function copyExtensionFiles() {
  log('Copying extension files...', 'info');
  
  let copied = 0;
  let missing = 0;
  
  for (const file of INCLUDE_FILES) {
    const src = path.join(CONFIG.sourceDir, file);
    const dest = path.join(CONFIG.distDir, file);
    
    if (copyFile(src, dest)) {
      copied++;
    } else {
      missing++;
    }
  }
  
  log(`Files copied: ${copied}`, 'success');
  if (missing > 0) {
    log(`Files missing: ${missing}`, 'warning');
  }
  
  return { copied, missing };
}

function createZipPackage() {
  log('Creating ZIP package...', 'info');
  
  const zipName = `${CONFIG.extensionName}-v${CONFIG.version}.zip`;
  const zipPath = path.join(CONFIG.distDir, zipName);
  
  try {
    // Change to dist directory and zip contents
    process.chdir(CONFIG.distDir);
    
    // Get all files except the zip itself
    const files = fs.readdirSync('.').filter(f => f !== zipName);
    
    // Create zip using system command
    const cmd = `zip -r "${zipName}" ${files.join(' ')}`;
    execSync(cmd, { stdio: 'inherit' });
    
    process.chdir('..');
    
    log(`Created: ${zipPath}`, 'success');
    return zipPath;
  } catch (error) {
    log(`Failed to create ZIP: ${error.message}`, 'error');
    process.chdir('..');
    return null;
  }
}

function validateManifest() {
  log('Validating manifest.json...', 'info');
  
  const manifestPath = path.join(CONFIG.distDir, 'manifest.json');
  
  if (!fs.existsSync(manifestPath)) {
    log('manifest.json not found in dist', 'error');
    return false;
  }
  
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    
    // Required fields for Chrome Web Store
    const required = ['manifest_version', 'name', 'version', 'description'];
    for (const field of required) {
      if (!manifest[field]) {
        log(`Missing required field: ${field}`, 'error');
        return false;
      }
    }
    
    // Check manifest version
    if (manifest.manifest_version !== 3) {
      log('Warning: manifest_version should be 3 for Chrome Web Store', 'warning');
    }
    
    // Check icons exist
    if (manifest.icons) {
      for (const [size, iconPath] of Object.entries(manifest.icons)) {
        const fullPath = path.join(CONFIG.distDir, iconPath);
        if (!fs.existsSync(fullPath)) {
          log(`Missing icon: ${iconPath}`, 'warning');
        }
      }
    }
    
    log('Manifest validation passed', 'success');
    return true;
  } catch (error) {
    log(`Manifest validation failed: ${error.message}`, 'error');
    return false;
  }
}

function calculateSize() {
  log('Calculating package size...', 'info');
  
  let totalSize = 0;
  
  function getSize(dir) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stats = fs.statSync(filePath);
      if (stats.isDirectory()) {
        getSize(filePath);
      } else {
        totalSize += stats.size;
      }
    }
  }
  
  getSize(CONFIG.distDir);
  
  const sizeInKB = (totalSize / 1024).toFixed(2);
  const sizeInMB = (totalSize / (1024 * 1024)).toFixed(2);
  
  log(`Total size: ${sizeInKB} KB (${sizeInMB} MB)`, 'info');
  
  // Chrome Web Store limit is 2GB, but we should warn if over 100MB
  if (totalSize > 100 * 1024 * 1024) {
    log('Warning: Package size exceeds 100MB', 'warning');
  }
  
  return totalSize;
}

function generateBuildInfo() {
  const buildInfo = {
    version: CONFIG.version,
    buildDate: new Date().toISOString(),
    files: INCLUDE_FILES,
    size: calculateSize()
  };
  
  const infoPath = path.join(CONFIG.distDir, 'build-info.json');
  fs.writeFileSync(infoPath, JSON.stringify(buildInfo, null, 2));
  log('Created build-info.json', 'success');
}

function main() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║       Phishing Guard Extension Build System               ║');
  console.log('║              Chrome Web Store Ready                       ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('\n');
  
  const args = process.argv.slice(2);
  const shouldZip = args.includes('--zip') || args.includes('--dist');
  const cleanFirst = args.includes('--clean');
  
  // Clean if requested
  if (cleanFirst) {
    cleanDirectory(CONFIG.distDir);
  }
  
  // Ensure dist directory exists
  ensureDirectory(CONFIG.distDir);
  
  // Copy files
  const { copied, missing } = copyExtensionFiles();
  
  if (copied === 0) {
    log('No files were copied. Build failed.', 'error');
    process.exit(1);
  }
  
  // Validate manifest
  if (!validateManifest()) {
    log('Manifest validation failed. Build may be incomplete.', 'warning');
  }
  
  // Generate build info
  generateBuildInfo();
  
  // Calculate size
  calculateSize();
  
  // Create ZIP if requested
  if (shouldZip) {
    const zipPath = createZipPackage();
    if (zipPath) {
      console.log('\n');
      console.log('╔════════════════════════════════════════════════════════════╗');
      console.log('║                  BUILD SUCCESSFUL!                        ║');
      console.log('╚════════════════════════════════════════════════════════════╝');
      console.log(`\nDistribution ZIP: ${zipPath}`);
      console.log('\nNext steps:');
      console.log('1. Upload to Chrome Web Store Developer Dashboard');
      console.log('2. Or distribute the ZIP file directly');
      console.log('3. Update store-assets/ with screenshots');
      console.log('\n');
    }
  } else {
    console.log('\n');
    console.log('╔════════════════════════════════════════════════════════════╗');
    console.log('║              BUILD COMPLETED SUCCESSFULLY                 ║');
    console.log('╚════════════════════════════════════════════════════════════╝');
    console.log(`\nOutput directory: ${CONFIG.distDir}/`);
    console.log('\nTo create a ZIP package, run:');
    console.log('  npm run build:zip');
    console.log('\n');
  }
}

// Run main function
main();
