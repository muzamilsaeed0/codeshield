const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { scanFile } = require('../src/scanner');

test('detects eval() and reports the correct line', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'sample.js');

  try {
    fs.writeFileSync(
      filePath,
      "const message = 'hello';\neval('2 + 2');\n",
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'JS001');
    assert.equal(findings[0].line, 2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('returns no findings for a file without eval()', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'safe.js');

  try {
    fs.writeFileSync(filePath, "const total = 2 + 2;\n", 'utf8');

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
test('ignores eval() mentioned in a single-line comment', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'comment.js');

  try {
    fs.writeFileSync(filePath, '// eval("test")\nconst total = 2 + 2;\n', 'utf8');

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores eval() mentioned inside a string', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'string.js');

  try {
    fs.writeFileSync(filePath, 'const text = \'eval("test")\';\n', 'utf8');

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores eval() inside a multiline comment', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'comment.js');

  try {
    fs.writeFileSync(
      filePath,
      '/*\neval("test");\n*/\nconst total = 2 + 2;\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores eval() inside a template string', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'template.js');

  try {
    fs.writeFileSync(
      filePath,
      'const message = `eval("test")`;\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('does not flag my_eval() as eval()', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'variable.js');

  try {
    fs.writeFileSync(filePath, 'my_eval("test");\n', 'utf8');

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
test('does not flag identifiers ending with eval-like names', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'identifiers.js');

  try {
    fs.writeFileSync(
      filePath,
      '$eval("test");\n_eval("test");\nsomeeval("test");\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects multiple eval() calls on different lines', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'multiple.js');

  try {
    fs.writeFileSync(
      filePath,
      'eval("first");\nconst total = 2 + 2;\neval("second");\n',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 2);
    assert.deepEqual(
      findings.map((finding) => finding.line),
      [1, 3]
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('throws an error when the target file does not exist', () => {
  const missingFile = path.join(
    os.tmpdir(),
    `codeshield-missing-${Date.now()}.js`
  );

  assert.throws(
    () => scanFile(missingFile),
    { code: 'ENOENT' }
  );
});

const { scanTarget } = require('../src/cli');

test('scans a directory and reports JavaScript findings with file paths', () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'codeshield-directory-')
  );

  const safeFile = path.join(tempDir, 'safe.js');
  const unsafeFile = path.join(tempDir, 'unsafe.js');

  try {
    fs.writeFileSync(safeFile, 'const total = 2 + 2;\n', 'utf8');
    fs.writeFileSync(unsafeFile, 'eval("test");\n', 'utf8');

    const findings = scanTarget(tempDir);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'JS001');
    assert.equal(findings[0].line, 1);
    assert.equal(findings[0].file, unsafeFile);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('skips node_modules and hidden directories', () => {
  const tempDir = fs.mkdtempSync(
    path.join(os.tmpdir(), 'codeshield-ignore-')
  );

  try {
    fs.mkdirSync(path.join(tempDir, 'node_modules'));
    fs.mkdirSync(path.join(tempDir, '.hidden'));

    fs.writeFileSync(
      path.join(tempDir, 'node_modules', 'dependency.js'),
      'eval("dependency");\n',
      'utf8'
    );

    fs.writeFileSync(
      path.join(tempDir, '.hidden', 'secret.js'),
      'eval("hidden");\n',
      'utf8'
    );

    fs.writeFileSync(
      path.join(tempDir, 'app.js'),
      'const total = 2 + 2;\n',
      'utf8'
    );

    assert.deepEqual(scanTarget(tempDir), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
test('detects new Function() and reports the correct line', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'dynamic-code.js');

  try {
    fs.writeFileSync(
      filePath,
      'const total = 2 + 2;\nconst run = new Function("return 2 + 2");\n',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'JS002');
    assert.equal(findings[0].line, 2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects Function() without new and reports the correct line', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'dynamic-function.js');

  try {
    fs.writeFileSync(
      filePath,
      'const total = 2 + 2;\nconst run = Function("return 2 + 2");\n',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'JS002');
    assert.equal(findings[0].line, 2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores new Function() mentioned in comments and strings', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'text-only.js');

  try {
    fs.writeFileSync(
      filePath,
      '// new Function("test")\nconst text = "new Function()";\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores Function() without new when mentioned in comments and strings', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'function-text.js');

  try {
    fs.writeFileSync(
      filePath,
      '// Function("test")\nconst text = "Function()";\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores eval() inside template string text', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'template-edge.js');

  try {
    fs.writeFileSync(
      filePath,
      'const text = `eval("example")`;\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores eval() text inside a regular expression', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'regex-edge.js');

  try {
    fs.writeFileSync(
      filePath,
      'const pattern = /eval\\("example"\\)/;\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects string-based setTimeout code execution', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'timer.js');

  try {
    fs.writeFileSync(
      filePath,
      'setTimeout("runTask()", 1000);\n',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 1);
    assert.equal(findings[0].rule, 'JS003');
    assert.equal(findings[0].line, 1);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('does not flag callback-based setTimeout', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'timer-safe.js');

  try {
    fs.writeFileSync(
      filePath,
      'setTimeout(() => runTask(), 1000);\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects string-based setInterval', () => {
  const filePath = path.join(os.tmpdir(), 'codeshield-interval.js');
  fs.writeFileSync(filePath, 'setInterval("runTask()", 1000);');

  try {
    const findings = scanFile(filePath);
    assert.ok(findings.some((finding) => finding.rule === 'JS004'));
  } finally {
    fs.unlinkSync(filePath);
  }
});

test('does not flag callback-based setInterval', () => {
  const filePath = path.join(os.tmpdir(), 'codeshield-interval-safe.js');
  fs.writeFileSync(filePath, 'setInterval(() => runTask(), 1000);');

  try {
    const findings = scanFile(filePath);
    assert.ok(!findings.some((finding) => finding.rule === 'JS004'));
  } finally {
    fs.unlinkSync(filePath);
  }
});

test('detects atob() usage', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'obfuscated.js');

  try {
    fs.writeFileSync(filePath, 'const payload = atob("YWxlcnQoMSk=");');

    const findings = scanFile(filePath);

    assert.ok(findings.some((finding) => finding.rule === 'JS005'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('does not flag atob() inside comments and strings', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'safe-atob.js');

  try {
    fs.writeFileSync(
      filePath,
      '// atob("hidden")\nconst example = "atob(test)";'
    );

    const findings = scanFile(filePath);

    assert.ok(!findings.some((finding) => finding.rule === 'JS005'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('does not flag normal String.fromCharCode() usage', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'safe-charcode.js');

  try {
    fs.writeFileSync(
      filePath,
      'const letters = String.fromCharCode(65, 66, 67);'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 0);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects String.fromCharCode() combined with eval()', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'suspicious-charcode.js');

  try {
    fs.writeFileSync(
      filePath,
      'eval(String.fromCharCode(97, 108, 101, 114, 116));'
    );

    const findings = scanFile(filePath);

    assert.ok(
      findings.some((finding) => finding.rule === 'JS006'),
      'Expected JS006 suspicious character-code warning'
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects eval() inside template literal expressions', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'template-expression.js');

  try {
    fs.writeFileSync(
      filePath,
      'const message = `Hello ${eval("alert(1)")}`;'
    );

    const findings = scanFile(filePath);

    assert.ok(
      findings.some((finding) => finding.rule === 'JS001'),
      'Expected JS001 warning inside template expression'
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects eval() inside nested template expressions', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'nested-template.js');

  try {
    fs.writeFileSync(
      filePath,
      'const message = `Result: ${(() => { const value = { nested: true }; return eval("alert(1)"); })()}`;'
    );

    const findings = scanFile(filePath);

    assert.ok(findings.some((finding) => finding.rule === 'JS001'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores braces inside strings in template expressions', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'sample.js');

  try {
    fs.writeFileSync(
      filePath,
      'const message = `Result: ${(() => { const text = "}"; return eval("alert(1)"); })()}`;',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.ok(findings.some((finding) => finding.rule === 'JS001'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects eval() inside nested template literals', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'sample.js');

  try {
    fs.writeFileSync(
      filePath,
      'const message = `Outer ${`Inner ${eval("alert(1)")}`}`;',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.ok(findings.some((finding) => finding.rule === 'JS001'));
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects document.write() and document.writeln()', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'document-write.js');

  try {
    fs.writeFileSync(
      filePath,
      'document.write("<h1>Hello</h1>");\ndocument.writeln("<p>Test</p>");\n',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 2);
    assert.equal(findings[0].rule, 'JS007');
    assert.equal(findings[0].line, 1);
    assert.equal(findings[1].rule, 'JS007');
    assert.equal(findings[1].line, 2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores document.write() inside comments and strings', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'document-write-safe.js');

  try {
    fs.writeFileSync(
      filePath,
      '// document.write("test")\nconst text = "document.write()";\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('detects innerHTML and outerHTML assignments', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'dom-injection.js');

  try {
    fs.writeFileSync(
      filePath,
      'element.innerHTML = userInput;\ncontainer.outerHTML = userInput;\n',
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 2);
    assert.equal(findings[0].rule, 'JS008');
    assert.equal(findings[0].line, 1);
    assert.equal(findings[1].rule, 'JS009');
    assert.equal(findings[1].line, 2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('ignores innerHTML and outerHTML in comments and strings', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'dom-safe.js');

  try {
    fs.writeFileSync(
      filePath,
      '// element.innerHTML = input;\nconst text = "element.outerHTML = input";\n',
      'utf8'
    );

    assert.deepEqual(scanFile(filePath), []);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
test('detects nested DOM assignments but ignores equality comparisons', () => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'codeshield-'));
  const filePath = path.join(tempDir, 'dom-edge.js');

  try {
    fs.writeFileSync(
      filePath,
      [
        'this.element.innerHTML = userInput;',
        'app.container.outerHTML = userInput;',
        'if (element.innerHTML === userInput) {}',
        'if (container.outerHTML == userInput) {}',
        '',
      ].join('\n'),
      'utf8'
    );

    const findings = scanFile(filePath);

    assert.equal(findings.length, 2);
    assert.equal(findings[0].rule, 'JS008');
    assert.equal(findings[0].line, 1);
    assert.equal(findings[1].rule, 'JS009');
    assert.equal(findings[1].line, 2);
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});