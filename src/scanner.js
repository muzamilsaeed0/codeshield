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

    const remaining = source.slice(index);
    const previousChar = source[index - 1];
    const isIdentifierPart =
      previousChar && /[A-Za-z0-9_$]/.test(previousChar);

    if (!isIdentifierPart) {
      const evalMatch = remaining.match(/^eval\s*\(/);
      const functionMatch = remaining.match(/^new\s+Function\s*\(/);
      const timerMatch = remaining.match(/^(?:window\s*\.\s*)?setTimeout\s*\(\s*(['"])/);
      const intervalMatch = remaining.match(/^(?:window\s*\.\s*)?setInterval\s*\(\s*(['"])/);
      const atobMatch = remaining.match(/^(?:window\s*\.\s*)?atob\s*\(/);
      const suspiciousCharCodeMatch = remaining.match(
        /^eval\s*\(\s*String\s*\.\s*fromCharCode\s*\(/
      );

      if (suspiciousCharCodeMatch) {
        findings.push({
          rule: 'JS006',
          severity: 'warning',
          line,
          message: 'Character-code conversion combined with eval() may hide executable code.',
        });

        index += suspiciousCharCodeMatch[0].length;
        continue;
      }

      if (evalMatch) {
        findings.push({
          rule: 'JS001',
          severity: 'warning',
          line,
          message: 'Potentially unsafe eval() usage detected.',
        });

        index += evalMatch[0].length;
        continue;
      }

      if (functionMatch) {
        findings.push({
          rule: 'JS002',
          severity: 'warning',
          line,
          message: 'Dynamic code construction with new Function() detected.',
        });

        index += functionMatch[0].length;
        continue;
      }

      if (timerMatch) {
        findings.push({
          rule: 'JS003',
          severity: 'warning',
          line,
          message: 'String-based setTimeout() may execute dynamic code.',
        });

        index += timerMatch[0].length;
        continue;
      }

      if (intervalMatch) {
        findings.push({
          rule: 'JS004',
          severity: 'warning',
          line,
          message: 'String-based setInterval() may execute dynamic code.',
        });

        index += intervalMatch[0].length;
        continue;
      }

      if (atobMatch) {
        findings.push({
          rule: 'JS005',
          severity: 'warning',
          line,
          message: 'Base64 decoding with atob() may be used to hide code.',
        });

        index += atobMatch[0].length;
        continue;
      }
    }

    index++;
  }

  return findings;
}

module.exports = { scanFile };
