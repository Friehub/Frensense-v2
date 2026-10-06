// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Static sink/source tables shared by the JS and TS specs.

// ── Static sink/source tables ─────────────────────────────────────────────────

pub(super) static JS_SINK_NAMES: &[(&str, frensense_lang::spec::SinkLabel)] = &[
    // Modern attack patterns
    (
        "insertAdjacentHTML",
        frensense_lang::spec::SinkLabel::XssDom,
    ),
    (
        "insertAdjacentElement",
        frensense_lang::spec::SinkLabel::XssDom,
    ),
    (
        "createContextualFragment",
        frensense_lang::spec::SinkLabel::XssDom,
    ),
    ("write", frensense_lang::spec::SinkLabel::XssDom),
    ("writeln", frensense_lang::spec::SinkLabel::XssDom),
    ("srcdoc", frensense_lang::spec::SinkLabel::XssDom),
    ("setAttribute", frensense_lang::spec::SinkLabel::XssDom),
    ("setAttributeNS", frensense_lang::spec::SinkLabel::XssDom),
    (
        "setHeader",
        frensense_lang::spec::SinkLabel::HeaderInjection,
    ),
    ("header", frensense_lang::spec::SinkLabel::HeaderInjection),
    ("append", frensense_lang::spec::SinkLabel::HeaderInjection),
    ("cookie", frensense_lang::spec::SinkLabel::CookiePoisoning),
    (
        "type",
        frensense_lang::spec::SinkLabel::ContentTypeInjection,
    ),
    ("appendFile", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "appendFileSync",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("copyFile", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "copyFileSync",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("mkdir", frensense_lang::spec::SinkLabel::PathTraversal),
    ("mkdirSync", frensense_lang::spec::SinkLabel::PathTraversal),
    ("rename", frensense_lang::spec::SinkLabel::PathTraversal),
    ("renameSync", frensense_lang::spec::SinkLabel::PathTraversal),
    ("rmdir", frensense_lang::spec::SinkLabel::PathTraversal),
    ("rmdirSync", frensense_lang::spec::SinkLabel::PathTraversal),
    ("lstat", frensense_lang::spec::SinkLabel::PathTraversal),
    ("lstatSync", frensense_lang::spec::SinkLabel::PathTraversal),
    ("chmod", frensense_lang::spec::SinkLabel::PathTraversal),
    ("chown", frensense_lang::spec::SinkLabel::PathTraversal),
    ("symlink", frensense_lang::spec::SinkLabel::PathTraversal),
    ("realpath", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "realpathSync",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    (
        "createWriteStream",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("openSync", frensense_lang::spec::SinkLabel::PathTraversal),
    ("fopen", frensense_lang::spec::SinkLabel::PathTraversal),
    ("readdir", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "readdirSync",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("axios.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.post", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.put", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.delete", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.patch", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.request", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.head", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.options", frensense_lang::spec::SinkLabel::Ssrf),
    ("got.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("got.post", frensense_lang::spec::SinkLabel::Ssrf),
    ("got.put", frensense_lang::spec::SinkLabel::Ssrf),
    ("got.stream", frensense_lang::spec::SinkLabel::Ssrf),
    ("superagent.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("superagent.post", frensense_lang::spec::SinkLabel::Ssrf),
    ("ky.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("ky.post", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.request", frensense_lang::spec::SinkLabel::Ssrf),
    ("https.request", frensense_lang::spec::SinkLabel::Ssrf),
    ("undici.fetch", frensense_lang::spec::SinkLabel::Ssrf),
    ("undici.request", frensense_lang::spec::SinkLabel::Ssrf),
    ("needle.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("needle.post", frensense_lang::spec::SinkLabel::Ssrf),
    (
        "execaCommand",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "execaCommandSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("$", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "shell.exec",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "shell.run",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("cp.exec", frensense_lang::spec::SinkLabel::CommandInjection),
    ("aggregate", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("distinct", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("count", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "countDocuments",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    (
        "estimatedDocumentCount",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    (
        "findOneAndUpdate",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    (
        "findOneAndDelete",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    (
        "findOneAndReplace",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    (
        "replaceOne",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("bulkWrite", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("update", frensense_lang::spec::SinkLabel::NoSqlInjection), // mongoose Model.update
    ("remove", frensense_lang::spec::SinkLabel::NoSqlInjection), // mongoose Model.remove
    ("hget", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("hset", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("del", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("keys", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "deepMerge",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("merge", frensense_lang::spec::SinkLabel::PrototypePollution),
    (
        "defaults",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "extend",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "assign",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "deepExtend",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("mixin", frensense_lang::spec::SinkLabel::PrototypePollution),
    (
        "cloneDeep",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("sign", frensense_lang::spec::SinkLabel::JwtWeakAlgorithm),
    ("decode", frensense_lang::spec::SinkLabel::JwtUnsafeDecode),
    ("existsSync", frensense_lang::spec::SinkLabel::Toctou),
    ("exists", frensense_lang::spec::SinkLabel::Toctou),
    ("gql", frensense_lang::spec::SinkLabel::GraphqlInjection),
    (
        "buildSchema",
        frensense_lang::spec::SinkLabel::GraphqlInjection,
    ),
    ("graphql", frensense_lang::spec::SinkLabel::GraphqlInjection),
    (
        "makeExecutableSchema",
        frensense_lang::spec::SinkLabel::GraphqlInjection,
    ),
    (
        "cp.spawn",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "cp.execFile",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "proc.exec",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "childProcess.exec",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    // Code Execution
    ("eval", frensense_lang::spec::SinkLabel::CodeExecution),
    ("Function", frensense_lang::spec::SinkLabel::CodeExecution),
    ("setTimeout", frensense_lang::spec::SinkLabel::CodeExecution),
    (
        "setInterval",
        frensense_lang::spec::SinkLabel::CodeExecution,
    ),
    (
        "runInNewContext",
        frensense_lang::spec::SinkLabel::CodeExecution,
    ),
    (
        "runInThisContext",
        frensense_lang::spec::SinkLabel::CodeExecution,
    ),
    ("require", frensense_lang::spec::SinkLabel::CodeExecution),
    ("import", frensense_lang::spec::SinkLabel::CodeExecution),
    // Command Injection
    ("exec", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "execSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("spawn", frensense_lang::spec::SinkLabel::CommandInjection),
    (
        "spawnSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "execFile",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "execFileSync",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    (
        "shelljs.exec",
        frensense_lang::spec::SinkLabel::CommandInjection,
    ),
    ("execa", frensense_lang::spec::SinkLabel::CommandInjection),
    // SQL Injection
    ("query", frensense_lang::spec::SinkLabel::SqlInjection),
    ("execute", frensense_lang::spec::SinkLabel::SqlInjection),
    ("executeRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("queryRaw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("raw", frensense_lang::spec::SinkLabel::SqlInjection),
    ("prepare", frensense_lang::spec::SinkLabel::SqlInjection),
    ("run", frensense_lang::spec::SinkLabel::SqlInjection), // sqlite3/knex .run()
    ("one", frensense_lang::spec::SinkLabel::SqlInjection), // pg-promise
    ("none", frensense_lang::spec::SinkLabel::SqlInjection),
    // Path Traversal
    ("readFile", frensense_lang::spec::SinkLabel::PathTraversal),
    (
        "readFileSync",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    (
        "createReadStream",
        frensense_lang::spec::SinkLabel::PathTraversal,
    ),
    ("writeFile", frensense_lang::spec::SinkLabel::PathTraversal),
    ("unlink", frensense_lang::spec::SinkLabel::PathTraversal),
    ("stat", frensense_lang::spec::SinkLabel::PathTraversal),
    ("access", frensense_lang::spec::SinkLabel::PathTraversal),
    // SSRF
    ("fetch", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("axios.post", frensense_lang::spec::SinkLabel::Ssrf),
    ("http.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("https.get", frensense_lang::spec::SinkLabel::Ssrf),
    ("got", frensense_lang::spec::SinkLabel::Ssrf),
    ("node-fetch", frensense_lang::spec::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    (
        "location.href",
        frensense_lang::spec::SinkLabel::OpenRedirect,
    ),
    (
        "window.location",
        frensense_lang::spec::SinkLabel::OpenRedirect,
    ),
    // XSS
    ("innerHTML", frensense_lang::spec::SinkLabel::XssDom),
    ("outerHTML", frensense_lang::spec::SinkLabel::XssDom),
    ("document.write", frensense_lang::spec::SinkLabel::XssDom),
    ("document.writeln", frensense_lang::spec::SinkLabel::XssDom),
    (
        "dangerouslySetInnerHTML",
        frensense_lang::spec::SinkLabel::XssDom,
    ),
    // MongoDB / ORM
    ("updateOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "updateMany",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("insertOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "insertMany",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("deleteOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "deleteMany",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("findOne", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("find", frensense_lang::spec::SinkLabel::NoSqlInjection), // collection.find / mongoose find
    ("findById", frensense_lang::spec::SinkLabel::NoSqlInjection),
    (
        "findByIdAndUpdate",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    (
        "findByIdAndDelete",
        frensense_lang::spec::SinkLabel::NoSqlInjection,
    ),
    ("findAll", frensense_lang::spec::SinkLabel::NoSqlInjection),
    ("destroy", frensense_lang::spec::SinkLabel::NoSqlInjection), // sequelize Model.destroy
    // Storage Write
    ("setItem", frensense_lang::spec::SinkLabel::StorageWrite),
    // Log Leak
    // SSTI - Template engine renders
    ("ejs.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "ejs.renderFile",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    ("pug.compile", frensense_lang::spec::SinkLabel::TemplateSsti),
    ("pug.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "handlebars.compile",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "handlebars.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "nunjucks.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "nunjucks.renderString",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "nunjucks.renderFile",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "marko.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    ("eta.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    ("swig.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "liquid.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "mustache.render",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    ("jade.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "react-dom/server.renderToString",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    (
        "vue-server-renderer.renderToString",
        frensense_lang::spec::SinkLabel::TemplateSsti,
    ),
    // Insecure Deserialization
    (
        "serialize",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "deserialize",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "yaml.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "js-yaml.load",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "msgpack.decode",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    (
        "msgpack.unpack",
        frensense_lang::spec::SinkLabel::UnsafeDeserialize,
    ),
    // Prototype Pollution
    (
        "Object.assign",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "_.merge",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "lodash.merge",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "_.defaultsDeep",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("_.set", frensense_lang::spec::SinkLabel::PrototypePollution),
    (
        "_.unset",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "lodash.unset",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("unset", frensense_lang::spec::SinkLabel::PrototypePollution),
    (
        "_.omit",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "lodash.omit",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    ("omit", frensense_lang::spec::SinkLabel::PrototypePollution),
    (
        "$.extend",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "jQuery.extend",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "angular.merge",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    (
        "setPrototypeOf",
        frensense_lang::spec::SinkLabel::PrototypePollution,
    ),
    // XXE
    ("DOMParser", frensense_lang::spec::SinkLabel::Xxe),
    // JWT: jwt.sign kept (tainted payload signed into a token is worth
    // flagging); verify/decode removed, they are validators, not sinks.
    ("jwt.sign", frensense_lang::spec::SinkLabel::Jwt),
    // Cloudflare Workers / Prisma
    ("c.redirect", frensense_lang::spec::SinkLabel::OpenRedirect),
    ("env.KV.put", frensense_lang::spec::SinkLabel::StorageWrite),
    (
        "KVNamespace.put",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "KVNamespace.delete",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "env.DB.prepare",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    ("res.send", frensense_lang::spec::SinkLabel::XssReflected),
    ("res.json", frensense_lang::spec::SinkLabel::ResponseLeak),
    (
        "res.redirect",
        frensense_lang::spec::SinkLabel::OpenRedirect,
    ),
    ("res.render", frensense_lang::spec::SinkLabel::TemplateSsti),
    (
        "revalidatePath",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "prisma.queryRawUnsafe",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    (
        "prisma.executeRawUnsafe",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    (
        "R2Bucket.put",
        frensense_lang::spec::SinkLabel::StorageWrite,
    ),
    (
        "D1Database.prepare",
        frensense_lang::spec::SinkLabel::SqlInjection,
    ),
    (
        "DurableObjectStub.fetch",
        frensense_lang::spec::SinkLabel::Ssrf,
    ),
    ("Queue.send", frensense_lang::spec::SinkLabel::Ssrf),
];

/// Per-slot danger facts for sinks whose argument positions carry different
/// semantics. `(call, dangerous_slots, binding_args_safe)`.
///
/// Without these, `jwt.verify(token, secret)` alerts on slot 1 (the
/// developer-controlled secret) and `query(sql, params)` alerts on the
/// *parameterized* values, the two largest structural FP classes.
/// Empty `dangerous_slots` = every slot dangerous (the default when a call
/// has no entry here).
pub(super) static JS_SINK_SIGNATURES: &[(&str, &[usize], bool)] = &[
    // ── Crypto / auth: slot 1 is a developer-controlled key/secret ──
    // NOTE: jwt.verify/jwt.decode are deliberately NOT here and NOT in the
    // sink table: verification APIs consume tainted tokens *by design*,
    // they validate, they don't execute. Treating them as sinks made every
    // auth middleware a false positive.
    ("decrypt", &[0], false), // crypto.decrypt(ciphertext, key)
    ("privateDecrypt", &[0], false),
    ("createDecipheriv", &[0, 1], false),
    // ── Parameterized SQL: slot 1+ is the binding channel (safe) ──
    ("prepare", &[0], true), // db.prepare(sql) - slot 0 is SQL string, receiver is DB handle
    ("query", &[0], true),   // pool.query(sql, params)
    ("execute", &[0], true), // mysql2 / prepare(sql, params)
    ("raw", &[0], true),     // sequelize
    // NOTE: pg-promise `any` and sqlite `all` deliberately absent: as bare
    // names they match `Promise.any(...)`/`Promise.all(...)` - ubiquitous,
    // benign JS - with no receiver guard for non-HTTP verbs (juice-shop
    // restoreOverwrittenFilesWithOriginals.ts:26). Restore them with the
    // spec's ambiguous-verb + receiver-root vocabulary (sqlite/pg-promise
    // roots), not as blanket sinks.
    ("one", &[0], true),
    ("none", &[0], true),
    ("get", &[0], true), // sqlite .get(sql, params)
    ("run", &[0], true), // sqlite .run(sql, params)
    // ── Open Redirect: slot 0 is the target URL (receiver is context/response) ──
    ("redirect", &[0], false),
    // ── Template rendering: slot 0 is the view name (template-executed),
    // slot 1 the locals data object (data only, not SSTI) ──
    ("res.render", &[0], false),
    ("ejs.render", &[0], false),
    ("pug.render", &[0], false),
    ("handlebars.render", &[0], false),
    ("nunjucks.render", &[0], false),
    // ── Path traversal: slot 0 is the destination path, slot 1 the file
    // content buffer (tainted upload bytes written to a fixed path are not
    // traversal) ──
    ("writeFile", &[0], false),
    // ── Storage / KV / Cache: receiver is the storage handle ──
    ("put", &[0, 1], false),
    ("delete", &[0], false),
    ("del", &[0], false),
    ("set", &[0, 1], false),
    ("append", &[0, 1], false),
    // ── HTTP fetch: slot 1 is the request-options/init object ──
    // (fetch(url, init): taint in init.method/body IS dangerous, but the
    //  options object is also where SSRF host overrides live; leave all-args
    //  dangerous, SSRF via options is real. Only restrict clear cases.)
    ("createHmac", &[1], false),     // createHmac(algo, key)
    ("createCipheriv", &[2], false), // createCipheriv(algo, key, iv)
    ("scrypt", &[0], false),         // scrypt(password, salt), slot 0 is the credential
    ("pbkdf2", &[0], false),
    // ── IDOR-class finders: identity-payload only (see JS_IDOR_SINKS) ──
    // (`findOne({ _id: taint })` answers "which record" - an access-control
    // concern, not an injection; the driver parameterizes values). Kept
    // dangerous at slot 0: identity payloads are reported (Idor class),
    // everything else on these sinks is suppressed by the engine's
    // identity-payload emission gate.
    ("findOne", &[0], false),
    ("findOneAndUpdate", &[0], false),
    ("findOneAndDelete", &[0], false),
    ("findOneAndReplace", &[0], false),
    ("findByIdAndUpdate", &[0], false),
    ("findByIdAndDelete", &[0], false),
    ("find", &[0], false),
    ("findAll", &[0], false),
    ("update", &[0], false),
    ("updateOne", &[0], false),
    ("updateMany", &[0], false),
    ("deleteOne", &[0], false),
    ("deleteMany", &[0], false),
    ("destroy", &[0], false),
    ("count", &[0], false),
];

/// Top-level object keys that mark a query payload as an *identity*
/// payload (which record, an access-control question). Deliberately does
/// NOT include clause wrappers (`where`, `$where`, `filter`, ...): the
/// driver parameterizes clause leaf values, so a where-wrapped taint is
/// structurally unprovable as a violation and must not report (zero-FP).
pub(super) const JS_IDOR_IDENTITY_KEYS: &[&str] = &["_id", "id", "owner", "userId", "user"];

/// IDOR-class finder/updater sinks: these only report when the tainted
/// argument IS an identity payload (see `LanguageSpec::known_idor_sinks`).
pub(super) static JS_IDOR_SINKS: &[(&str, &[&str])] = &[
    ("findOne", JS_IDOR_IDENTITY_KEYS),
    ("findOneAndUpdate", JS_IDOR_IDENTITY_KEYS),
    ("findOneAndDelete", JS_IDOR_IDENTITY_KEYS),
    ("findOneAndReplace", JS_IDOR_IDENTITY_KEYS),
    ("findByIdAndUpdate", JS_IDOR_IDENTITY_KEYS),
    ("findByIdAndDelete", JS_IDOR_IDENTITY_KEYS),
    ("find", JS_IDOR_IDENTITY_KEYS),
    ("findAll", JS_IDOR_IDENTITY_KEYS),
    ("update", JS_IDOR_IDENTITY_KEYS),
    ("updateOne", JS_IDOR_IDENTITY_KEYS),
    ("updateMany", JS_IDOR_IDENTITY_KEYS),
    ("deleteOne", JS_IDOR_IDENTITY_KEYS),
    ("deleteMany", JS_IDOR_IDENTITY_KEYS),
    ("destroy", JS_IDOR_IDENTITY_KEYS),
    ("count", JS_IDOR_IDENTITY_KEYS),
];

pub(super) static JS_SOURCE_PATTERNS: &[&str] = &[
    "req.session",
    "req.session.userId",
    "req.session.user",
    "session.",
    "req.url",
    "req.path",
    "req.hostname",
    "req.ip",
    "req.protocol",
    "req.originalUrl",
    "req.subdomains",
    "ws.data",
    "socket.data",
    "msg.data",
    "message.data",
    "ctx.request.query",
    "ctx.request.headers",
    "ctx.request.url",
    "ctx.state",
    "c.req.header",
    "c.req.path",
    "c.req.url",
    "c.req.json",
    "c.req.text",
    "c.req.formData",
    "event.headers",
    "event.requestContext",
    "event.multiValueQueryStringParameters",
    "event.isBase64Encoded",
    "req.body",
    "req.query",
    "req.params",
    "req.headers",
    "req.cookies",
    "req.file",
    "req.files",
    "request.body",
    "request.query",
    "request.params",
    "ctx.request.body",
    "ctx.query",
    "ctx.params",
    "c.req.raw",
    "c.req.query",
    "c.req.param",
    "c.req",
    "event.body",
    "event.queryStringParameters",
    "event.pathParameters",
    // NOTE: `process.env` deliberately NOT a source: env vars are
    // developer-controlled config, not attacker input. Treating them as
    // sources was the largest FP class in the Juice Shop baseline.
    // `process.argv` stays: CLI arguments are genuinely user-controlled.
    "process.argv",
    // Hardened for object destructuring: const { body, query, params } = req.
    // `file`/`files` deliberately absent: as bare entries they made ANY
    // parameter, phi, or member root named `file` a taint source (plain
    // helpers like `validateFile(file)` alerted on every readFile/exec use).
    // Uploads stay covered by the dotted `req.file`/`req.files` patterns.
    "body",
    "query",
    "params",
    "headers",
    "cookies",
];

/// Trusted session-store roots for JS/TS web apps: values derived from a
/// session accessor's return (`security.authenticatedUsers.get(token)`) are
/// server-issued, not attacker-controlled. Declared here as language/framework
/// vocabulary so no seed sidecar is needed.
pub(super) static JS_SESSION_ROOTS: &[&str] = &["authenticatedUsers"];
