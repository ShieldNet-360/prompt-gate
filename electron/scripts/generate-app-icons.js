#!/usr/bin/env node
// Generate application icons for all platforms from the green-shield SVG.
// Run: node scripts/generate-app-icons.js
// Requires: sharp (npm install --save-dev sharp)

const fs = require('fs');
const path = require('path');

let sharp;
try {
  sharp = require('sharp');
} catch {
  console.error('sharp not found. Install it: npm install --save-dev sharp');
  process.exit(1);
}

const resDir = path.join(__dirname, '..', 'resources');
const svgBuf = fs.readFileSync(path.join(resDir, 'app-icon-blue.svg'));

async function generate() {
  // 512x512 PNG — used by electron-builder for Linux and as base for .icns/.ico
  await sharp(svgBuf)
    .resize(512, 512, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toFile(path.join(resDir, 'icon.png'));
  console.log('  ✓ icon.png (512x512)');

  // Generate multiple sizes for Windows .ico (electron-builder can
  // auto-convert icon.png → icon.ico when png2icons or the built-in
  // converter is available, but having an explicit 256px helps).
  await sharp(svgBuf)
    .resize(256, 256, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .png()
    .toFile(path.join(resDir, 'icon@256.png'));
  console.log('  ✓ icon@256.png (256x256 — for .ico conversion)');

  console.log('\nDone. electron-builder will auto-convert icon.png to .icns/.ico at package time.');
}

generate().catch((err) => {
  console.error(err);
  process.exit(1);
});
