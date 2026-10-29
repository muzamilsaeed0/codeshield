
const fs = require('node:fs');

function scanFile(filePath) {
  const source = fs.readFileSync(filePath, 'utf8');
  const findings = [];

  let state = 'code';
  let line = 1;
  let index = 0;

  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1];

    if (char === '\n') {
      line++;
      if (state === 'line-comment') {
        state = 'code';
      }
      index++;
      continue;
    }

    if (state === 'line-comment') {
      index++;
      continue;
    }

    if (state === 'block-comment') {
      if (char === '*' && next === '/') {
        state = 'code';
        index += 2;
      } else {
        index++;
      }
      continue;
    }

    if (state === 'single-string' || state === 'double-string') {
      const closingQuote = state === 'single-string' ? "'" : '"';

      if (char === '\\') {
        index += 2;
      } else {
        if (char === closingQuote) {
          state = 'code';
        }
        index++;
      }
      continue;
    }

    if (state === 'template-string') {
      if (char === '\\') {
        index += 2;
      } else {
        if (char === '`') {
          state = 'code';
        }
        index++;
      }
      continue;
    }

    if (char === '/' && next === '/') {
      state = 'line-comment';
      index += 2;
      continue;
    }

    if (char === '/' && next === '*') {
      state = 'block-comment';
      index += 2;
      continue;
    }

    if (char === "'") {
      state = 'single-string';
      index++;
      continue;
    }

    if (char === '"') {
      state = 'double-string';
      index++;
      continue;
    }

    if (char === '`') {
      state = 'template-string';
      index++;
      continue;
    }

   const match = source.slice(index).match(/^eval\s*\(/);
const previousChar = source[index - 1];
const isIdentifierPart = previousChar && /[A-Za-z0-9_$]/.test(previousChar);

   if (match && !isIdentifierPart) {
      findings.push({
        rule: 'JS001',
        severity: 'warning',
        line,
        message: 'Potentially unsafe eval() usage detected.',
      });

      index += match[0].length;
      continue;
    }

    index++;
  }

  return findings;
}

module.exports = { scanFile };
