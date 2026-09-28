import { parse } from '/tmp/node_modules/acorn/dist/acorn.mjs';
import { readFileSync } from 'fs';

// 已知 secret 属性键名
const SECRET_KEYS = new Set([
  'apiKey','api_key','apikey','accessKey','access_key','accessToken','access_token',
  'secretKey','secret_key','clientSecret','client_secret','clientId','client_id',
  'authToken','auth_token','privateKey','private_key','publishableKey',
  'token','secret','password','passwd','credential','credentials',
  'appKey','app_key','appSecret','app_secret','consumerKey','consumer_key',
  'consumerSecret','consumer_secret','signingKey','signing_key',
]);

// identifier length <= 3 作为 minified 变量的判定阈值
// 依据：terser/webpack 使用 base54 命名序列（a-z,A-Z,$,_），
//   length=1: 54 个名称，length=2: 3510 个，length=3: 228150 个
// 实际 bundle 作用域内局部变量数极少超过 3510，故 <=3 覆盖几乎所有 minified 变量
// 参考：JSNaughty (ESEC/FSE 2017), JSZap (USENIX WebApps 2010), Terser nth_identifier 文档
const MAX_MINIFIED_ID_LEN = 3;

function entropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, v) => sum + (v/s.length)*Math.log2(v/s.length), 0);
}

function isSecretLike(val) {
  if (val.length < 20 || val.length > 150) return false;
  if (entropy(val) < 4.5) return false;
  // 排除纯字母字符表
  if (/^[A-Za-z]{20,}$/.test(val)) return false;
  // 排除 CSS module 名（含双下划线 + 末尾 hash）
  if (/__[A-Za-z0-9]{4,}$/.test(val)) return false;
  // 排除 Redux action / 路径类字符串
  if (/^[A-Z_]+\/[A-Z_]+/.test(val)) return false;
  return true;
}

function scanFile(filePath) {
  let code;
  try {
    code = readFileSync(filePath, 'utf8');
  } catch { return []; }

  let ast;
  try {
    ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module' });
  } catch {
    try {
      ast = parse(code, { ecmaVersion: 'latest', sourceType: 'script' });
    } catch { return []; }
  }

  // Step 1：收集所有短变量声明（length <= 3）且值为高熵字符串
  const varMap = {};
  function collectVars(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'VariableDeclarator' &&
        node.id?.type === 'Identifier' &&
        node.id.name.length <= MAX_MINIFIED_ID_LEN &&
        node.init?.type === 'Literal' &&
        typeof node.init.value === 'string') {
      const val = node.init.value;
      if (isSecretLike(val)) {
        varMap[node.id.name] = val;
      }
    }
    for (const key of Object.keys(node)) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(collectVars);
      else if (child && typeof child === 'object' && child.type) collectVars(child);
    }
  }
  collectVars(ast);

  if (Object.keys(varMap).length === 0) return [];

  // Step 2：找 ObjectExpression 里 key 是 secret 键名、value 是上面短变量的 Property
  const results = [];
  function findCallSites(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'Property') {
      const keyName = node.key?.name || node.key?.value;
      if (SECRET_KEYS.has(keyName) &&
          node.value?.type === 'Identifier' &&
          node.value.name.length <= MAX_MINIFIED_ID_LEN &&
          varMap[node.value.name]) {
        results.push({
          propKey: keyName,
          varName: node.value.name,
          val: varMap[node.value.name],
          entropy: Math.round(entropy(varMap[node.value.name]) * 100) / 100,
          file: filePath,
        });
      }
    }
    for (const key of Object.keys(node)) {
      const child = node[key];
      if (Array.isArray(child)) child.forEach(findCallSites);
      else if (child && typeof child === 'object' && child.type) findCallSites(child);
    }
  }
  findCallSites(ast);

  return results;
}

// Files to scan: replace with your own JS bundle paths, or wire to argv.
const testFiles = process.argv.slice(2).length
  ? process.argv.slice(2)
  : [
      './example_bundle_1.js',
      './example_bundle_2.js',
    ];

for (const f of testFiles) {
  const hits = scanFile(f);
  console.log(`\n=== ${f.split('/').slice(-2).join('/')} ===`);
  if (hits.length === 0) {
    console.log('  无命中');
  } else {
    for (const h of hits) {
      console.log(`  {${h.propKey}: ${h.varName}} → "${h.val.slice(0,60)}"  entropy=${h.entropy}`);
    }
  }
}
