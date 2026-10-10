#!/usr/bin/env node
/**
 * Comprehensive deobfuscator / cleaner for hsj.js and hsw.js.
 *
 * Passes (in order):
 *   1. String-decoder resolution
 *        Detect every string-array decoder in the source (`er`, `sn`, `ZA`, ...),
 *        run the source in a Node VM sandbox, probe each decoder over its full
 *        argument range, build per-decoder lookup tables. Replace every
 *        `decoder(N)` call with the literal decoded string. Aliases (local
 *        `var f = er; f(N)`) are resolved with proper lexical scoping. Numeric
 *        `var X = 391; f(X)` is propagated by constant-folding.
 *
 *   2. Inline trivial decoder-alias `var X = decoder;` declarations
 *        After pass 1 most aliases are dead, but the `var f = er;` declarations
 *        themselves remain. We drop those whose RHS is a known decoder and
 *        whose name has no other use after substitution.
 *
 *   3. Extract embedded binary blobs
 *        asm.js / WASM modules ship their bytecode as base64 strings passed
 *        through `atob` (or aliases). We extract each such blob to a sidecar
 *        `<name>.blobs.bin` and replace the JS string with a short marker
 *        comment + the FIRST 24 bytes (hex) so the source stays inspectable
 *        but readable.
 *
 *   4. Member-access cleanup
 *        `obj["foo"]` becomes `obj.foo` when `"foo"` is a valid identifier.
 *        Also numeric constant computed members: `obj[42]` stays as-is.
 *
 *   5. Sequence-expression flattening
 *        Top-level `(a, b, c);` statements become `a; b; c;`. Sequence
 *        expressions in for-init/update positions are left alone (syntax-bound).
 *
 *   6. Dead-variable elimination
 *        After all rewrites, `var X = N;` declarations whose name has no
 *        remaining read are removed. Conservative — only drops declarations
 *        whose value has no side effects.
 *
 *   7. Function-parameter renaming
 *        Function parameters get sequential single-letter names (a, b, c, ...)
 *        but ONLY when ALL of the function's locals are minified single/two-
 *        letter names — this preserves intentional names in upstream libraries.
 *
 * Final output is emitted via `astring` (then beautified by jsbeautifier on
 * the Python wrapper side).
 *
 * Usage:
 *     node deobf.js <input.js> <output.js>
 */
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const acorn = require('acorn');
const astring = require('astring');

const INPUT = process.argv[2] || 'hsw_b.js';
const OUTPUT = process.argv[3] || (INPUT.replace(/\.js$/, '') + '_deobf.js');
const BLOBS_BIN = OUTPUT.replace(/\.js$/, '') + '.blobs.bin';
const BLOBS_JSON = OUTPUT.replace(/\.js$/, '') + '.blobs.json';

const src = fs.readFileSync(INPUT, 'utf-8');

// =============================================================================
// STEP A — Detect string decoders
// =============================================================================
// Legacy builds mark decoders with `void 0 === NAME.prop`.
const decoderMarkerRe = /void 0 === (\w+)\.(\w{6})\b/g;
const decoderNames = new Set();
let mm;
while ((mm = decoderMarkerRe.exec(src))) decoderNames.add(mm[1]);

// Newer builds (2026+) declare decoders as `NAME = function(arg){ ...
// if (void 0 !== CACHE[arg]) return CACHE[arg]; ... }`. Detect every such
// memoised decoder and recover its assigned name by scanning backwards to
// the enclosing `NAME = function(arg){` declarator.
const decoderMemoRe = /if\s*\(\s*void 0\s*!==\s*([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*\)\s*return\s*\1\s*\[\s*\2\s*\]/g;
while ((mm = decoderMemoRe.exec(src))) {
    const arg = mm[2];
    const back = src.slice(Math.max(0, mm.index - 900), mm.index);
    const fRe = new RegExp('([A-Za-z_$][\\w$]*)\\s*=\\s*function\\s*\\(\\s*' + arg + '[^)]*\\)\\s*\\{', 'g');
    let fm = null, f;
    while ((f = fRe.exec(back))) fm = f;
    if (fm) decoderNames.add(fm[1]);
}
if (decoderNames.size === 0) { console.error('no decoder marker pattern found'); process.exit(1); }
console.error(`[deobf] decoders: ${[...decoderNames].join(',')}`);

// =============================================================================
// STEP B — Run in sandbox to capture each decoder
// =============================================================================
const decoderInitCalls = [...decoderNames].map(n => `try { ${n}(0); } catch(_){}`).join(' ');
const decoderExports = [...decoderNames].map(n => `${n}: ${n}`).join(', ');
const exposurePatch = `
;try {
    globalThis.__deobf_patch_reached = 1;
    ${decoderInitCalls}
    globalThis.__deobf_decoders = { ${decoderExports} };
} catch (e) { globalThis.__deobf_err = String(e); }
`;

let patched = src;
let probeAst;
try { probeAst = acorn.parse(src, { ecmaVersion: 2022, sourceType: 'script', allowReturnOutsideFunction: true }); }
catch (e) { console.error('[deobf] parse failed:', e.message); process.exit(1); }

// Place exposure patch at IIFE body, before first top-level return (or before close)
let insertionByte = -1;
for (const node of probeAst.body) {
    let iifeFunction = null;
    if (node.type === 'ExpressionStatement') {
        let expr = node.expression;
        if (expr.type === 'UnaryExpression') expr = expr.argument;
        if (expr.type === 'CallExpression' && expr.callee.type === 'FunctionExpression') {
            iifeFunction = expr.callee;
        }
    } else if (node.type === 'VariableDeclaration') {
        for (const d of node.declarations) {
            if (d.init && d.init.type === 'CallExpression' && d.init.callee.type === 'FunctionExpression') {
                iifeFunction = d.init.callee; break;
            }
        }
    }
    if (iifeFunction && iifeFunction.body && iifeFunction.body.type === 'BlockStatement') {
        const stmts = iifeFunction.body.body;
        const firstReturn = stmts.findIndex(s => s.type === 'ReturnStatement');
        insertionByte = firstReturn >= 0 ? stmts[firstReturn].start : iifeFunction.body.end - 1;
        break;
    }
}
if (insertionByte > 0) {
    patched = src.slice(0, insertionByte) + '\n' + exposurePatch + '\n' + src.slice(insertionByte);
}

function loose() {
    const inner = function() { return loose(); };
    return new Proxy(inner, {
        get(_t, k) {
            if (k === Symbol.toPrimitive) return () => 'stub';
            if (k === Symbol.iterator) return undefined;
            if (k === 'then') return undefined;
            if (k === 'length') return 0;
            return loose();
        },
        set() { return true; },
        apply() { return loose(); },
        construct() { return loose(); },
    });
}
const ctx = {
    globalThis: null, console: { log: () => {}, error: () => {}, warn: () => {} },
    window: loose(), document: loose(), navigator: loose(), location: loose(),
    setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    requestAnimationFrame: () => 0,
    Math, Date, JSON, String, Number, Boolean, Array, Object, Symbol, Error, RegExp,
    Uint8Array, Uint16Array, Uint32Array, Int8Array, Int16Array, Int32Array,
    Float32Array, Float64Array, ArrayBuffer, DataView,
    Map, Set, WeakMap, WeakSet, Promise, Reflect, Proxy,
    parseInt, parseFloat, isFinite, isNaN, decodeURI, decodeURIComponent,
    encodeURI, encodeURIComponent, Function,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    crypto: { getRandomValues: (a) => { for (let i=0;i<a.length;i++) a[i] = Math.floor(Math.random()*256); return a; } },
    performance: { now: () => Date.now() },
    process: undefined,
    self: null, global: null,
    WebAssembly: { instantiate: () => Promise.resolve({}), Memory: function(){ this.buffer = new ArrayBuffer(65536); }, compile: () => Promise.resolve({}) },
    Buffer: typeof Buffer !== 'undefined' ? Buffer : undefined,
    URL: typeof URL !== 'undefined' ? URL : function(){},
    URLSearchParams: typeof URLSearchParams !== 'undefined' ? URLSearchParams : function(){},
};
ctx.globalThis = ctx; ctx.window = ctx; ctx.self = ctx; ctx.global = ctx;
vm.createContext(ctx);
try {
    new vm.Script(patched, { filename: INPUT }).runInContext(ctx, { timeout: 30000 });
} catch (e) {
    console.error(`[deobf] script err (continuing): ${e.message}`);
}
const decoders = ctx.__deobf_decoders || {};
const decoderFns = Object.entries(decoders).filter(([, fn]) => typeof fn === 'function');
if (decoderFns.length === 0) {
    console.error('[deobf] no decoders captured. err:', ctx.__deobf_err); process.exit(1);
}
const lookups = new Map();
for (const [name, fn] of decoderFns) {
    const map = new Map();
    for (let n = -1000; n < 4000; n++) {
        try { const v = fn(n); if (typeof v === 'string' && v.length > 0 && v.length < 5000) map.set(n, v); } catch(_) {}
    }
    lookups.set(name, map);
    console.error(`[deobf] ${name}: decoded ${map.size} strings`);
}

// =============================================================================
// STEP C — Parse, walk, transform
// =============================================================================
const ast = acorn.parse(src, { ecmaVersion: 2022, sourceType: 'script', allowReturnOutsideFunction: true, locations: true });

// ---- Scope tracking ----
// Each scope tracks:
//   aliases:   Map<name, decoderName>   (var X = decoder)
//   numConsts: Map<name, number>        (var X = 391)
//   used:     Set<name>                 (names read anywhere in this+nested scopes)
function makeScope(parent) {
    return {
        aliases: new Map(parent ? parent.aliases : null),
        numConsts: new Map(parent ? parent.numConsts : null),
        atobAliases: new Set(parent ? parent.atobAliases : null),
        parent,
    };
}
const rootScope = makeScope(null);
for (const d of decoderNames) rootScope.aliases.set(d, d);
rootScope.atobAliases.add('atob');

// ---- Pass 1+2: Collect aliases + replace decoder calls + inline numeric/alias vars ----
let replacedDecoderCalls = 0;
let blobsExtracted = 0;
let bracketToDot = 0;
const blobs = [];

function isValidIdentifier(s) {
    return typeof s === 'string' && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(s) && !RESERVED.has(s);
}
const RESERVED = new Set([
    'break','case','catch','class','const','continue','debugger','default','delete',
    'do','else','export','extends','finally','for','function','if','import','in',
    'instanceof','new','return','super','switch','this','throw','try','typeof',
    'var','void','while','with','yield','let','static','enum','await','implements',
    'interface','package','private','protected','public','true','false','null','undefined',
]);

function collectAliases(body, scope) {
    function consider(idNode, initNode) {
        if (!idNode || idNode.type !== 'Identifier' || !initNode) return;
        if (initNode.type === 'Literal' && typeof initNode.value === 'number') {
            scope.numConsts.set(idNode.name, initNode.value);
            return;
        }
        if (initNode.type === 'UnaryExpression' && initNode.operator === '-' &&
            initNode.argument.type === 'Literal' && typeof initNode.argument.value === 'number') {
            scope.numConsts.set(idNode.name, -initNode.argument.value);
            return;
        }
        if (initNode.type === 'Identifier') {
            if (scope.aliases.has(initNode.name)) {
                scope.aliases.set(idNode.name, scope.aliases.get(initNode.name));
            } else if (scope.atobAliases.has(initNode.name)) {
                scope.atobAliases.add(idNode.name);
            }
        }
    }
    function scanStmts(stmts) {
        if (!stmts) return;
        if (!Array.isArray(stmts)) stmts = [stmts];
        for (const s of stmts) {
            if (!s) continue;
            if (s.type === 'VariableDeclaration') {
                for (const d of s.declarations) consider(d.id, d.init);
            } else if (s.type === 'ExpressionStatement' &&
                       s.expression && s.expression.type === 'AssignmentExpression' &&
                       s.expression.operator === '=' &&
                       s.expression.left.type === 'Identifier') {
                consider(s.expression.left, s.expression.right);
            }
        }
    }
    if (Array.isArray(body)) scanStmts(body);
    else if (body && body.type === 'Program') scanStmts(body.body);
    else if (body && body.type === 'BlockStatement') scanStmts(body.body);
}

let currentScope = rootScope;
collectAliases(ast, currentScope);

function transform(node) {
    if (!node || typeof node !== 'object') return;

    const opensScope = node.type === 'FunctionDeclaration'
                    || node.type === 'FunctionExpression'
                    || node.type === 'ArrowFunctionExpression';
    if (opensScope) {
        currentScope = makeScope(currentScope);
        collectAliases(node.body, currentScope);
    }

    // ---- Pass 1: decoder call replacement ----
    if (node.type === 'CallExpression' &&
        node.callee && node.callee.type === 'Identifier' &&
        currentScope.aliases.has(node.callee.name) &&
        node.arguments.length >= 1) {
        let n;
        const a0 = node.arguments[0];
        if (a0.type === 'Literal' && typeof a0.value === 'number') n = a0.value;
        else if (a0.type === 'Identifier' && currentScope.numConsts.has(a0.name)) {
            n = currentScope.numConsts.get(a0.name);
        }
        if (typeof n === 'number') {
            const dName = currentScope.aliases.get(node.callee.name);
            const map = lookups.get(dName);
            if (map && map.has(n)) {
                const str = map.get(n);
                node.type = 'Literal';
                node.value = str;
                node.raw = JSON.stringify(str);
                delete node.callee;
                delete node.arguments;
                replacedDecoderCalls++;
                return;   // don't recurse
            }
        }
    }

    // ---- Pass 3: blob extraction ----
    // Detect any CallExpression where ANY argument is a long string literal
    // (>= 200 chars). These are base64 / charcode blobs being loaded into
    // asm.js / WASM memory. We extract each to a sidecar binary file and
    // replace the JS string with a `__BLOB_N__` placeholder.
    if (node.type === 'CallExpression' && node.arguments.length >= 1) {
        for (let ai = 0; ai < node.arguments.length; ai++) {
            const arg = node.arguments[ai];
            if (arg && arg.type === 'Literal' && typeof arg.value === 'string' && arg.value.length >= 200) {
                const b64 = arg.value;
                try {
                    const bytes = Buffer.from(b64, 'base64');
                    if (bytes.length >= 32) {
                        const idx = blobs.length;
                        blobs.push({
                            idx,
                            line: node.loc ? node.loc.start.line : -1,
                            callee: node.callee && node.callee.type === 'Identifier' ? node.callee.name : '?',
                            argIndex: ai,
                            b64Length: b64.length,
                            byteLength: bytes.length,
                            bytesHexHead: bytes.slice(0, 24).toString('hex'),
                            bytes,
                        });
                        node.arguments[ai] = {
                            type: 'Literal',
                            value: `__BLOB_${idx}__/* ${bytes.length}B head=${bytes.slice(0, 8).toString('hex')} */`,
                            raw: JSON.stringify(`__BLOB_${idx}__`),
                        };
                        blobsExtracted++;
                    }
                } catch (_) {}
            }
        }
    }

    // Recurse
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) transform(c);
        else if (v && typeof v === 'object' && v.type) transform(v);
    }

    if (opensScope) currentScope = currentScope.parent;
}
transform(ast);

// ---- Pass: bracket→dot (post-order so decoder-replaced Literals are visible) ----
function bracketDotPass(node) {
    if (!node || typeof node !== 'object') return;
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) bracketDotPass(c);
        else if (v && typeof v === 'object' && v.type) bracketDotPass(v);
    }
    if (node.type === 'MemberExpression' && node.computed && node.property &&
        node.property.type === 'Literal' && typeof node.property.value === 'string' &&
        isValidIdentifier(node.property.value)) {
        node.computed = false;
        node.property = { type: 'Identifier', name: node.property.value };
        bracketToDot++;
    }
}
bracketDotPass(ast);

console.error(`[deobf] decoder-calls replaced: ${replacedDecoderCalls}`);
console.error(`[deobf] bracket->dot: ${bracketToDot}`);
console.error(`[deobf] blobs extracted: ${blobsExtracted} (${blobs.reduce((s,b)=>s+b.byteLength,0)} bytes total)`);

// =============================================================================
// STEP D — Scope-aware: dead-var removal + parameter/local renaming
// =============================================================================
// Build a proper scope tree. For each function scope, count Identifier
// LOCAL references (declarations + reads inside that scope) — separate from
// nested function scopes' references.

function makeScope2(parent, fnNode) {
    return {
        parent,
        fnNode,
        declared: new Map(),   // localName -> { kind: 'param'|'var'|'fn', node, declarator?, init? }
        refCount: new Map(),   // localName -> number of read-references in THIS scope (not nested)
        children: [],
    };
}

const programScope = makeScope2(null, null);

function declareName(scope, name, info) {
    if (!scope.declared.has(name)) scope.declared.set(name, info);
}
function incRef(scope, name) {
    scope.refCount.set(name, (scope.refCount.get(name) || 0) + 1);
}

// Walk: for each function scope, register its params and `var`-declared
// names, then count Identifier uses inside that scope (not inside child fns).
function buildScopes(node, scope) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
        // Register the function's name (declaration) in the PARENT scope
        if (node.type === 'FunctionDeclaration' && node.id) declareName(scope, node.id.name, { kind: 'fn', node });
        const childScope = makeScope2(scope, node);
        scope.children.push(childScope);
        // Register params
        for (const p of node.params) {
            if (p.type === 'Identifier') declareName(childScope, p.name, { kind: 'param', node: p });
            // TODO: destructuring patterns — not handled (obfuscated code rarely uses them)
        }
        // Register hoisted vars + function decls inside the body
        function hoistDecls(n) {
            if (!n || typeof n !== 'object') return;
            if (n.type === 'VariableDeclaration') {
                for (const d of n.declarations) {
                    if (d.id && d.id.type === 'Identifier') {
                        declareName(childScope, d.id.name, { kind: 'var', node: d.id, declarator: d, init: d.init });
                    }
                }
            } else if (n.type === 'FunctionDeclaration') {
                if (n.id) declareName(childScope, n.id.name, { kind: 'fn', node: n });
                return;   // don't recurse into nested function bodies
            } else if (n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression') {
                return;   // nested function — its decls belong to its own scope
            }
            for (const k of Object.keys(n)) {
                if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
                const v = n[k];
                if (Array.isArray(v)) for (const c of v) hoistDecls(c);
                else if (v && typeof v === 'object' && v.type) hoistDecls(v);
            }
        }
        if (node.body && node.body.type === 'BlockStatement') {
            for (const s of node.body.body) hoistDecls(s);
        }
        // Recurse into the function body to find child scopes (but not to count refs — that's a separate pass)
        if (node.body) {
            if (node.body.type === 'BlockStatement') {
                for (const s of node.body.body) buildScopes(s, childScope);
            } else {
                buildScopes(node.body, childScope);
            }
        }
        return;
    }
    // Non-function node — recurse into children at the SAME scope
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) buildScopes(c, scope);
        else if (v && typeof v === 'object' && v.type) buildScopes(v, scope);
    }
}
buildScopes(ast, programScope);

// Hoist any top-level var declarations into programScope
(function hoistTop(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'VariableDeclaration') {
        for (const d of node.declarations) {
            if (d.id && d.id.type === 'Identifier') {
                declareName(programScope, d.id.name, { kind: 'var', node: d.id, declarator: d, init: d.init });
            }
        }
    } else if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
        return;
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) hoistTop(c);
        else if (v && typeof v === 'object' && v.type) hoistTop(v);
    }
})(ast);

// For each function scope, count Identifier reads inside that scope's
// extent (excluding nested function bodies). An "Identifier read" is a node
// where the Identifier is being USED (not just declared).
function countRefsInScope(scope) {
    // Walk the function body — for FunctionExpression node, walk node.body
    const root = scope.fnNode ? scope.fnNode.body : ast;
    function walk(n, parent, key) {
        if (!n || typeof n !== 'object') return;
        // Stop at nested function expressions/declarations — they have their own scope
        if (n !== root && (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression')) {
            return;
        }
        if (n.type === 'Identifier' && scope.declared.has(n.name)) {
            // Skip: this Identifier is a declaration site, not a reference
            const skip =
                (parent && parent.type === 'VariableDeclarator' && key === 'id') ||
                (parent && (parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression' || parent.type === 'ArrowFunctionExpression') && key === 'id') ||
                (parent && parent.params && parent.params.includes(n)) ||
                (parent && parent.type === 'Property' && parent.key === n && !parent.computed) ||
                (parent && parent.type === 'MemberExpression' && parent.property === n && !parent.computed);
            if (!skip) incRef(scope, n.name);
        }
        for (const k of Object.keys(n)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = n[k];
            if (Array.isArray(v)) for (let i = 0; i < v.length; i++) walk(v[i], n, k);
            else if (v && typeof v === 'object' && v.type) walk(v, n, k);
        }
    }
    walk(root, null, null);
}
function walkScopes(scope, fn) {
    fn(scope);
    for (const c of scope.children) walkScopes(c, fn);
}
walkScopes(programScope, countRefsInScope);

// ---- Drop dead numeric/alias vars in each scope ----
let declsRemoved = 0;
function dropDead(scope) {
    for (const [name, info] of [...scope.declared]) {
        if (info.kind !== 'var' || !info.declarator) continue;
        const init = info.init;
        const isSimpleNum = init && init.type === 'Literal' && typeof init.value === 'number';
        const isSimpleUnaryNum = init && init.type === 'UnaryExpression' && init.operator === '-' &&
                                  init.argument.type === 'Literal' && typeof init.argument.value === 'number';
        const isDecoderAliasInit = init && init.type === 'Identifier' && decoderNames.has(init.name);
        const isAtobAliasInit = init && init.type === 'Identifier' && init.name === 'atob';
        const refs = scope.refCount.get(name) || 0;
        if ((isSimpleNum || isSimpleUnaryNum || isDecoderAliasInit || isAtobAliasInit) && refs === 0) {
            // Mark declarator for removal by clearing its init and id
            info.declarator.__drop = true;
            declsRemoved++;
        }
    }
}
walkScopes(programScope, dropDead);

// Actually remove dropped declarators from VariableDeclarations
function applyDropDecls(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'VariableDeclaration') {
        node.declarations = node.declarations.filter(d => !d.__drop);
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) applyDropDecls(c);
        else if (v && typeof v === 'object' && v.type) applyDropDecls(v);
    }
}
applyDropDecls(ast);

// Remove empty VariableDeclaration nodes (those whose all declarators were dropped)
function dropEmptyVarDecls(node) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node.body)) {
        node.body = node.body.filter(s => !(s && s.type === 'VariableDeclaration' && s.declarations.length === 0));
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) dropEmptyVarDecls(c);
        else if (v && typeof v === 'object' && v.type) dropEmptyVarDecls(v);
    }
}
dropEmptyVarDecls(ast);
console.error(`[deobf] dead decls removed: ${declsRemoved}`);

// ---- Rename function parameters + scope locals to short readable names ----
// Sequential per function: a, b, c, ..., z, a1, b1, ...
function nthName(i) {
    const letters = 'abcdefghijklmnopqrstuvwxyz';
    if (i < 26) return letters[i];
    const round = Math.floor(i / 26);
    return letters[i % 26] + round;
}

let renamedLocals = 0;
function renameScope(scope) {
    if (!scope.fnNode) return;   // skip the program scope to preserve top-level names

    // Decide whether this function looks minified-enough to rename.
    // Heuristic: at least 1 declared name AND >=60% of them are <=3 chars.
    const names = [...scope.declared.keys()];
    if (names.length < 1) return;
    const shortNames = names.filter(n => n.length <= 3);
    if (shortNames.length / names.length < 0.6) return;

    // Build mapping: preserve obviously-keep names (e.g. longer than 4 chars)
    // and rename the rest in declaration order.
    const renameMap = new Map();
    let counter = 0;
    // Params first (in declaration order)
    const fn = scope.fnNode;
    for (const p of fn.params) {
        if (p.type === 'Identifier' && p.name.length <= 3) {
            renameMap.set(p.name, nthName(counter++));
        }
    }
    // Other declared names — order = insertion order
    for (const name of names) {
        if (renameMap.has(name)) continue;
        const info = scope.declared.get(name);
        if ((info.kind === 'var' || info.kind === 'fn') && name.length <= 3) {
            renameMap.set(name, nthName(counter++));
        }
    }
    if (renameMap.size === 0) return;

    // Apply renames. For nested functions, recurse but TEMPORARILY remove
    // any names from renameMap that the nested function shadows (so we
    // don't rewrite the shadow's identifier into the outer name).
    const root = scope.fnNode.body;
    function walk(n, parent, key, activeMap) {
        if (!n || typeof n !== 'object') return;
        if (n !== root && (n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression' || n.type === 'ArrowFunctionExpression')) {
            // Compute the set of names this nested function declares.
            const shadowed = new Set();
            for (const p of n.params) {
                if (p.type === 'Identifier') shadowed.add(p.name);
            }
            // Hoisted vars in nested function body
            function collectVars(nn) {
                if (!nn || typeof nn !== 'object') return;
                if (nn.type === 'VariableDeclaration') {
                    for (const d of nn.declarations) {
                        if (d.id && d.id.type === 'Identifier') shadowed.add(d.id.name);
                    }
                } else if (nn.type === 'FunctionDeclaration') {
                    if (nn.id) shadowed.add(nn.id.name);
                    return;
                } else if (nn.type === 'FunctionExpression' || nn.type === 'ArrowFunctionExpression') {
                    return;
                }
                for (const k of Object.keys(nn)) {
                    if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
                    const v = nn[k];
                    if (Array.isArray(v)) for (const c of v) collectVars(c);
                    else if (v && typeof v === 'object' && v.type) collectVars(v);
                }
            }
            if (n.body && n.body.type === 'BlockStatement') for (const s of n.body.body) collectVars(s);
            const inherited = new Map(activeMap);
            for (const s of shadowed) inherited.delete(s);
            if (inherited.size === 0) return;
            // Recurse into nested function with the inherited map (only names
            // the nested function does NOT shadow)
            for (const k of Object.keys(n)) {
                if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
                const v = n[k];
                if (Array.isArray(v)) for (let i = 0; i < v.length; i++) walk(v[i], n, k, inherited);
                else if (v && typeof v === 'object' && v.type) walk(v, n, k, inherited);
            }
            return;
        }
        if (n.type === 'Identifier' && activeMap.has(n.name)) {
            const skipRename =
                (parent && parent.type === 'Property' && parent.key === n && !parent.computed) ||
                (parent && parent.type === 'MemberExpression' && parent.property === n && !parent.computed);
            if (!skipRename) {
                n.name = activeMap.get(n.name);
                renamedLocals++;
            }
        }
        for (const k of Object.keys(n)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = n[k];
            if (Array.isArray(v)) for (let i = 0; i < v.length; i++) walk(v[i], n, k, activeMap);
            else if (v && typeof v === 'object' && v.type) walk(v, n, k, activeMap);
        }
    }
    // Also rename params themselves
    for (const p of fn.params) {
        if (p.type === 'Identifier' && renameMap.has(p.name)) {
            p.name = renameMap.get(p.name);
        }
    }
    walk(root, null, null, renameMap);
}
walkScopes(programScope, renameScope);
console.error(`[deobf] renamed locals: ${renamedLocals}`);

// =============================================================================
// STEP F — Sequence-expression flattening
// =============================================================================
// asm.js / compiled output is dominated by sequence expressions:
//   `(a = 1, b = 2, c = f(b), d)` — multiple side-effecting expressions
//   chained with the comma operator. In STATEMENT positions, these can be
//   split into separate statements. In other positions (e.g., `return`,
//   ternary branch), they must stay as-is.
//
// We flatten when a SequenceExpression appears as the expression of an
// ExpressionStatement, or as an init/update inside `for` (where comma is
// already meaningful — we DON'T flatten there).
let sequencesFlattened = 0;
function flattenSequences(node) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node.body)) {
        const newBody = [];
        for (const s of node.body) {
            if (s && s.type === 'ExpressionStatement' && s.expression && s.expression.type === 'SequenceExpression') {
                for (const expr of s.expression.expressions) {
                    newBody.push({ type: 'ExpressionStatement', expression: expr });
                }
                sequencesFlattened++;
            } else if (s && s.type === 'ReturnStatement' && s.argument && s.argument.type === 'SequenceExpression') {
                // `return (a, b, c)` → `a; b; return c;`
                const exprs = s.argument.expressions;
                for (let i = 0; i < exprs.length - 1; i++) {
                    newBody.push({ type: 'ExpressionStatement', expression: exprs[i] });
                }
                newBody.push({ type: 'ReturnStatement', argument: exprs[exprs.length - 1] });
                sequencesFlattened++;
            } else if (s && s.type === 'ThrowStatement' && s.argument && s.argument.type === 'SequenceExpression') {
                const exprs = s.argument.expressions;
                for (let i = 0; i < exprs.length - 1; i++) {
                    newBody.push({ type: 'ExpressionStatement', expression: exprs[i] });
                }
                newBody.push({ type: 'ThrowStatement', argument: exprs[exprs.length - 1] });
                sequencesFlattened++;
            } else {
                newBody.push(s);
            }
        }
        node.body = newBody;
    }
    // Also flatten in IfStatement consequent/alternate: `if (X) (a, b, c);`
    // becomes `if (X) { a; b; c; }`
    if (node.type === 'IfStatement') {
        for (const branch of ['consequent', 'alternate']) {
            const b = node[branch];
            if (b && b.type === 'ExpressionStatement' &&
                b.expression && b.expression.type === 'SequenceExpression') {
                node[branch] = {
                    type: 'BlockStatement',
                    body: b.expression.expressions.map(e => ({ type: 'ExpressionStatement', expression: e })),
                };
                sequencesFlattened++;
            }
        }
    }
    // Same for loops
    if (node.type === 'WhileStatement' || node.type === 'DoWhileStatement' || node.type === 'ForStatement') {
        const b = node.body;
        if (b && b.type === 'ExpressionStatement' && b.expression && b.expression.type === 'SequenceExpression') {
            node.body = {
                type: 'BlockStatement',
                body: b.expression.expressions.map(e => ({ type: 'ExpressionStatement', expression: e })),
            };
            sequencesFlattened++;
        }
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) flattenSequences(c);
        else if (v && typeof v === 'object' && v.type) flattenSequences(v);
    }
}
// Run repeatedly until stable (nested sequences may need multiple passes)
for (let i = 0; i < 5; i++) {
    const before = sequencesFlattened;
    flattenSequences(ast);
    if (sequencesFlattened === before) break;
}
console.error(`[deobf] sequences flattened: ${sequencesFlattened}`);

// =============================================================================
// STEP G — For-init sequence flattening
// =============================================================================
// `for ((a = 1, b = 2, c = f()); cond; update) body` becomes
//   `a = 1; b = 2; c = f(); for (; cond; update) body`
// Only safe when the for-init is a SequenceExpression (not a
// VariableDeclaration — those would change scope) and the surrounding
// node accepts a leading statement block.
let forInitsFlattened = 0;
function flattenForInits(node, parent, key, index) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'ForStatement' && node.init &&
        node.init.type === 'SequenceExpression') {
        const pre = node.init.expressions.map(e =>
            ({ type: 'ExpressionStatement', expression: e }));
        node.init = null;
        forInitsFlattened++;
        // wrap the for + its preamble in a BlockStatement so we don't
        // collide with neighbour statements (preserves scope semantics).
        const block = { type: 'BlockStatement', body: [...pre, node] };
        if (Array.isArray(parent[key])) {
            parent[key][index] = block;
        } else {
            parent[key] = block;
        }
        return;
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) {
            for (let i = 0; i < v.length; i++) flattenForInits(v[i], node, k, i);
        } else if (v && typeof v === 'object' && v.type) {
            flattenForInits(v, node, k, null);
        }
    }
}
flattenForInits(ast, { ast }, 'ast', null);
console.error(`[deobf] for-inits flattened: ${forInitsFlattened}`);

// =============================================================================
// STEP H — Drop the obfuscation rotation IIFE
// =============================================================================
// Both bundles ship an `!(function(a, b) { for (...) { try { ... break; } catch
// { j.push(j.shift()); } } })(stringTableFn)` loop whose entire purpose is to
// permute the string table at module load — after our string-decoder
// resolution pass it's pure dead code that pretends to do parseInt math on
// table indices. Recognize by structure: `!(IIFE)(...)` whose body contains
// the `j.push(j.shift())` rotation. Replace with an empty statement.
let rotationIIFEsRemoved = 0;
function looksLikePushShift(stmt) {
    if (!stmt || stmt.type !== 'ExpressionStatement') return false;
    const e = stmt.expression;
    return e && e.type === 'CallExpression' &&
        e.callee && e.callee.type === 'MemberExpression' &&
        e.callee.property && e.callee.property.name === 'push' &&
        e.arguments && e.arguments.length === 1 &&
        e.arguments[0].type === 'CallExpression' &&
        e.arguments[0].callee &&
        e.arguments[0].callee.type === 'MemberExpression' &&
        e.arguments[0].callee.property &&
        e.arguments[0].callee.property.name === 'shift';
}
function findPushShiftInTryCatch(node) {
    let found = false;
    function scan(n) {
        if (!n || typeof n !== 'object' || found) return;
        if (n.type === 'TryStatement' && n.handler &&
            n.handler.body && Array.isArray(n.handler.body.body)) {
            for (const stmt of n.handler.body.body) {
                if (looksLikePushShift(stmt)) { found = true; return; }
            }
        }
        for (const k of Object.keys(n)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = n[k];
            if (Array.isArray(v)) for (const c of v) scan(c);
            else if (v && typeof v === 'object' && v.type) scan(v);
            if (found) return;
        }
    }
    scan(node);
    return found;
}
function isRotationIIFE(s) {
    // !(function(a, b) { ... })(arg) where the function body is JUST
    // the rotation loop (at most a couple top-level statements, and
    // the for-loop with try/catch push/shift is one of them).
    if (!s || s.type !== 'ExpressionStatement') return false;
    if (!s.expression || s.expression.type !== 'UnaryExpression') return false;
    if (s.expression.operator !== '!') return false;
    const call = s.expression.argument;
    if (!call || call.type !== 'CallExpression') return false;
    if (!call.callee || call.callee.type !== 'FunctionExpression') return false;
    const body = call.callee.body;
    if (!body || !Array.isArray(body.body)) return false;
    // Real rotation IIFEs are tiny — typically ≤ 3 top-level statements.
    // The HSW outer module IIFE has hundreds. Use this as a cheap guard.
    if (body.body.length > 5) return false;
    return findPushShiftInTryCatch(body);
}
function dropRotationIIFE(node) {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node.body)) {
        for (let i = 0; i < node.body.length; i++) {
            if (isRotationIIFE(node.body[i])) {
                node.body.splice(i, 1, { type: 'EmptyStatement' });
                rotationIIFEsRemoved++;
            }
        }
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) dropRotationIIFE(c);
        else if (v && typeof v === 'object' && v.type) dropRotationIIFE(v);
    }
}
dropRotationIIFE(ast);
console.error(`[deobf] rotation-IIFEs dropped: ${rotationIIFEsRemoved}`);

// =============================================================================
// STEP I — Single-use alias inlining
// =============================================================================
// Pattern: `var f4 = h[1]; ... f4(x)` where `f4` has exactly ONE remaining
// reference after all prior passes. Inline the access. Conservative — only
// inlines when RHS is a simple MemberExpression or Identifier (no side
// effects) and the name fits the obfuscation-generated 2-3 char shape.
let aliasesInlined = 0;
function inlineSingleUseAliases(scope) {
    // build use-count map across this scope's bodyOwner
    const useCounts = new Map();
    function count(node) {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'Identifier') {
            useCounts.set(node.name, (useCounts.get(node.name) || 0) + 1);
        }
        if (node.type === 'MemberExpression' && !node.computed) {
            count(node.object);
            return;
        }
        for (const k of Object.keys(node)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = node[k];
            if (Array.isArray(v)) for (const c of v) count(c);
            else if (v && typeof v === 'object' && v.type) count(v);
        }
    }
    count(scope.bodyOwner);

    // collect aliases: `var X = simple;` where X has exactly 2 uses (the
    // decl itself + ONE usage downstream).
    const aliasMap = new Map();
    function collectAliases(node) {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'VariableDeclarator' &&
            node.id && node.id.type === 'Identifier' &&
            node.init && (node.init.type === 'MemberExpression' || node.init.type === 'Identifier')) {
            const name = node.id.name;
            if (name.length <= 3 && useCounts.get(name) === 2) {
                // verify init is side-effect-free: identifier or
                // non-computed member chain of identifiers
                let n = node.init;
                let ok = true;
                while (n.type === 'MemberExpression') {
                    if (n.computed) { ok = false; break; }
                    n = n.object;
                }
                if (ok && n.type === 'Identifier') {
                    aliasMap.set(name, node.init);
                }
            }
        }
        // don't descend into nested functions — they have their own scopes
        if (node.type === 'FunctionExpression' || node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') {
            return;
        }
        for (const k of Object.keys(node)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = node[k];
            if (Array.isArray(v)) for (const c of v) collectAliases(c);
            else if (v && typeof v === 'object' && v.type) collectAliases(v);
        }
    }
    collectAliases(scope.bodyOwner);

    if (aliasMap.size === 0) return;

    // Replace identifier references with the alias RHS
    function rewrite(node, parent, key, idx) {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'Identifier' && aliasMap.has(node.name)) {
            // skip declarations themselves
            if (!(parent && parent.type === 'VariableDeclarator' && key === 'id')) {
                const rhs = JSON.parse(JSON.stringify(aliasMap.get(node.name)));
                if (Array.isArray(parent[key])) parent[key][idx] = rhs;
                else parent[key] = rhs;
                aliasesInlined++;
                return;
            }
        }
        if (node.type === 'FunctionExpression' || node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') {
            return;
        }
        for (const k of Object.keys(node)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = node[k];
            if (Array.isArray(v)) for (let i = 0; i < v.length; i++) rewrite(v[i], node, k, i);
            else if (v && typeof v === 'object' && v.type) rewrite(v, node, k, null);
        }
    }
    rewrite(scope.bodyOwner, null, null, null);

    // Drop the declarators we inlined
    function dropDecls(node) {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'VariableDeclaration' && Array.isArray(node.declarations)) {
            node.declarations = node.declarations.filter(d =>
                !(d.id && d.id.type === 'Identifier' && aliasMap.has(d.id.name))
            );
        }
        if (node.type === 'FunctionExpression' || node.type === 'FunctionDeclaration' || node.type === 'ArrowFunctionExpression') {
            return;
        }
        for (const k of Object.keys(node)) {
            if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
            const v = node[k];
            if (Array.isArray(v)) for (const c of v) dropDecls(c);
            else if (v && typeof v === 'object' && v.type) dropDecls(v);
        }
    }
    dropDecls(scope.bodyOwner);
}
// run on every scope we tracked during the rename pass
walkScopes(programScope, scope => { if (scope.bodyOwner) inlineSingleUseAliases(scope); });
console.error(`[deobf] aliases inlined: ${aliasesInlined}`);

// =============================================================================
// STEP J — Constant string concatenation folding
// =============================================================================
// `"foo" + "bar"` → `"foobar"`. Recursively folds chains.
let stringsFolded = 0;
function foldStringConcat(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'BinaryExpression' && node.operator === '+') {
        foldStringConcat(node.left);
        foldStringConcat(node.right);
        if (node.left.type === 'Literal' && typeof node.left.value === 'string' &&
            node.right.type === 'Literal' && typeof node.right.value === 'string') {
            node.type = 'Literal';
            node.value = node.left.value + node.right.value;
            node.raw = JSON.stringify(node.value);
            delete node.left; delete node.right; delete node.operator;
            stringsFolded++;
        }
        return;
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) foldStringConcat(c);
        else if (v && typeof v === 'object' && v.type) foldStringConcat(v);
    }
}
for (let i = 0; i < 5; i++) {
    const before = stringsFolded;
    foldStringConcat(ast);
    if (stringsFolded === before) break;
}
console.error(`[deobf] string concats folded: ${stringsFolded}`);

// =============================================================================
// STEP K — Useless `!` prefix on IIFE statements
// =============================================================================
// `!(function(){...})(args);` is just `(function(){...})(args);` — the `!`
// is a leftover from minifier tooling to avoid `function statement` parsing.
// We're emitting through astring so the parens are already explicit — drop
// the `!`.
let bangsRemoved = 0;
function removeUselessBangs(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'ExpressionStatement' && node.expression &&
        node.expression.type === 'UnaryExpression' &&
        node.expression.operator === '!' &&
        node.expression.argument &&
        node.expression.argument.type === 'CallExpression') {
        node.expression = node.expression.argument;
        bangsRemoved++;
    }
    for (const k of Object.keys(node)) {
        if (k === 'type' || k === 'loc' || k === 'range' || k === 'start' || k === 'end') continue;
        const v = node[k];
        if (Array.isArray(v)) for (const c of v) removeUselessBangs(c);
        else if (v && typeof v === 'object' && v.type) removeUselessBangs(v);
    }
}
removeUselessBangs(ast);
console.error(`[deobf] useless !-prefix removed: ${bangsRemoved}`);

// =============================================================================
// STEP E — Emit
// =============================================================================
fs.writeFileSync(OUTPUT, astring.generate(ast));
console.error(`[deobf] wrote ${OUTPUT}`);

if (blobs.length) {
    const concat = Buffer.concat(blobs.map(b => b.bytes));
    fs.writeFileSync(BLOBS_BIN, concat);
    const index = blobs.map(b => ({
        idx: b.idx, line: b.line, decoderName: b.decoderName,
        byteOffset: blobs.slice(0, b.idx).reduce((s, x) => s + x.byteLength, 0),
        byteLength: b.byteLength,
        bytesHexHead: b.bytesHexHead,
    }));
    fs.writeFileSync(BLOBS_JSON, JSON.stringify(index, null, 2));
    console.error(`[deobf] wrote ${BLOBS_BIN} (${concat.length} bytes) + ${BLOBS_JSON}`);
}

// Diagnostic
console.error(`[deobf] patch_reached=${ctx.__deobf_patch_reached || 0} err=${ctx.__deobf_err || ''}`);
