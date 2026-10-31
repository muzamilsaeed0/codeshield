const fs = require('node:fs');

function scanFile(filePath) {
  const source = fs.readFileSync(filePath, 'utf8');
  const findings = [];

  let state = 'code';
  let templateExpressionDepth = 0;
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
      } else if (char === '$' && next === '{') {
        state = 'code';
        templateExpressionDepth = 1;
        index += 2;
      } else {
        if (char === '`') {
          state = 'code';
        }
        index++;
      }
      continue;
    }

    if (templateExpressionDepth > 0) {
      if (char === '{') {
        templateExpressionDepth++;
        index++;
        continue;
      }

      if (char === '}') {
        templateExpressionDepth--;

        if (templateExpressionDepth === 0) {
          state = 'template-string';
        }

        index++;
        continue;
      }
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
      const functionMatch = remaining.match(/^(?:new\s+)?Function\s*\(/);
      const timerMatch = remaining.match(/^(?:window\s*\.\s*)?setTimeout\s*\(\s*(['"])/);
      const intervalMatch = remaining.match(/^(?:window\s*\.\s*)?setInterval\s*\(\s*(['"])/);
      const atobMatch = remaining.match(/^(?:window\s*\.\s*)?atob\s*\(/);
        const documentWriteMatch = remaining.match(/^document\s*\.\s*(?:write|writeln)\s*\(/);
        const innerHtmlMatch = remaining.match(
  /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\.\s*innerHTML\s*=(?!=|>)/
);
const outerHtmlMatch = remaining.match(
  /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\.\s*outerHTML\s*=(?!=|>)/
);
        const insertAdjacentHtmlMatch = remaining.match(
  /^[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*\s*\.\s*insertAdjacentHTML\s*\(/
);

const domParserMatch = remaining.match(
  /^(?:new\s+)?DOMParser\s*\(\s*\)\s*\.\s*parseFromString\s*\(/
);
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
        message: 'Dynamic code construction with Function() detected.',
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

        if (documentWriteMatch) {
  findings.push({
    rule: 'JS007',
    severity: 'warning',
    line,
    message: 'Dynamic HTML injection using document.write() may create DOM XSS risk.',
  });

  index += documentWriteMatch[0].length;
  continue;
}
        if (innerHtmlMatch) {
  findings.push({
    rule: 'JS008',
    severity: 'warning',
    line,
    message: 'Assignment to innerHTML may create DOM XSS risk.',
  });

  index += innerHtmlMatch[0].length;
  continue;
}

if (outerHtmlMatch) {
  findings.push({
    rule: 'JS009',
    severity: 'warning',
    line,
    message: 'Assignment to outerHTML may create DOM XSS risk.',
  });

  index += outerHtmlMatch[0].length;
  continue;
}
  
    if (insertAdjacentHtmlMatch) {
  findings.push({
    rule: 'JS010',
    severity: 'warning',
    line,
    message: 'insertAdjacentHTML() may introduce unsafe HTML into the DOM.',
  });

  index += insertAdjacentHtmlMatch[0].length;
  continue;
}

if (domParserMatch) {
  findings.push({
    rule: 'JS011',
    severity: 'warning',
    line,
    message: 'DOMParser.parseFromString() may parse untrusted HTML.',
  });

  index += domParserMatch[0].length;
  continue;
}
    }

    index++;
  }

  return findings;
    
}

module.exports = { scanFile };
