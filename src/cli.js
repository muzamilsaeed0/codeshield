
const fs = require('node:fs');
const path = require('node:path');
const { scanFile } = require('./scanner');

const target = process.argv[2];

function scanTarget(targetPath) {
  const stats = fs.statSync(targetPath);

  if (stats.isFile()) {
    if (path.extname(targetPath) !== '.js') {
      return [];
    }

    return scanFile(targetPath).map((finding) => ({
      ...finding,
      file: targetPath,
    }));
  }

  if (stats.isDirectory()) {
    const findings = [];
    const entries = fs.readdirSync(targetPath, {
      withFileTypes: true,
    });

    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) {
        continue;
      }

      const entryPath = path.join(targetPath, entry.name);

      if (entry.isDirectory()) {
        findings.push(...scanTarget(entryPath));
      } else if (entry.isFile() && path.extname(entry.name) === '.js') {
        findings.push(
          ...scanFile(entryPath).map((finding) => ({
            ...finding,
            file: entryPath,
          }))
        );
      }
    }

    return findings;
  }

  return [];
}

function main() {
  if (!target) {
    console.error('Usage: npm run scan -- <javascript-file-or-directory>');
    process.exitCode = 1;
    return;
  }

  const filePath = path.resolve(target);

  try {
    const findings = scanTarget(filePath);

    if (findings.length === 0) {
      console.log('No findings detected.');
    } else {
      console.log(`Found ${findings.length} potential issue(s):`);

      for (const finding of findings) {
        console.log(
          `[${finding.severity.toUpperCase()}] ${finding.rule} ` +
          `${finding.file}:${finding.line}: ${finding.message}`
        );
      }
    }
  } catch (error) {
    console.error(`Scan failed: ${error.message}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = { scanTarget };