#!/usr/bin/env node
// Generate tray icon PNGs from SVG sources in resources/.
// Run: node scripts/generate-tray-icons.js
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

// Map: output base name → source SVG
const icons = {
  // State 1: agent OK, proxy OFF → white badge (checkmark)
  'tray-icon':       'tray-white.svg',
  // State 2: agent OK, proxy ON → green badge (checkmark)
  'tray-icon-on':    'tray-green.svg',
  // State 3: agent error → red badge (exclamation)
  'tray-icon-error': 'tray-red.svg',
};

async function generate() {
  for (const [outName, svgFile] of Object.entries(icons)) {
    const svgBuf = fs.readFileSync(path.join(resDir, svgFile));

    // 1x (22px height, preserve aspect)
    await sharp(svgBuf)
      .resize({ height: 22 })
      .png()
      .toFile(path.join(resDir, `${outName}.png`));

    // 2x (44px height for Retina / HiDPI)
    await sharp(svgBuf)
      .resize({ height: 44 })
      .png()
      .toFile(path.join(resDir, `${outName}@2x.png`));

    console.log(`  ✓ ${outName}.png + ${outName}@2x.png`);
  }
  console.log('Done.');
}

generate().catch((err) => {
  console.error(err);
  process.exit(1);
});
