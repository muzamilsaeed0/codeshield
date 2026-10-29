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
