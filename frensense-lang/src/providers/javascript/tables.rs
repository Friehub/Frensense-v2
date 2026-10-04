// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Static sink/source tables shared by the JS and TS specs.

// ── Static sink/source tables ─────────────────────────────────────────────────

pub(super) static JS_SINK_NAMES: &[(&'static str, crate::spec::SinkLabel)] = &[
    // Modern attack patterns
    ("insertAdjacentHTML", crate::spec::SinkLabel::XssDom),
    ("insertAdjacentElement", crate::spec::SinkLabel::XssDom),
    ("createContextualFragment", crate::spec::SinkLabel::XssDom),
    ("write", crate::spec::SinkLabel::XssDom),
    ("writeln", crate::spec::SinkLabel::XssDom),
    ("srcdoc", crate::spec::SinkLabel::XssDom),
    ("setAttribute", crate::spec::SinkLabel::XssDom),
    ("setAttributeNS", crate::spec::SinkLabel::XssDom),
    ("setHeader", crate::spec::SinkLabel::HeaderInjection),
    ("header", crate::spec::SinkLabel::HeaderInjection),
    ("append", crate::spec::SinkLabel::HeaderInjection),
    ("cookie", crate::spec::SinkLabel::CookiePoisoning),
    ("type", crate::spec::SinkLabel::ContentTypeInjection),
    ("appendFile", crate::spec::SinkLabel::PathTraversal),
    ("appendFileSync", crate::spec::SinkLabel::PathTraversal),
    ("copyFile", crate::spec::SinkLabel::PathTraversal),
    ("copyFileSync", crate::spec::SinkLabel::PathTraversal),
    ("mkdir", crate::spec::SinkLabel::PathTraversal),
    ("mkdirSync", crate::spec::SinkLabel::PathTraversal),
    ("rename", crate::spec::SinkLabel::PathTraversal),
    ("renameSync", crate::spec::SinkLabel::PathTraversal),
    ("rmdir", crate::spec::SinkLabel::PathTraversal),
    ("rmdirSync", crate::spec::SinkLabel::PathTraversal),
    ("lstat", crate::spec::SinkLabel::PathTraversal),
    ("lstatSync", crate::spec::SinkLabel::PathTraversal),
    ("chmod", crate::spec::SinkLabel::PathTraversal),
    ("chown", crate::spec::SinkLabel::PathTraversal),
    ("symlink", crate::spec::SinkLabel::PathTraversal),
    ("realpath", crate::spec::SinkLabel::PathTraversal),
    ("realpathSync", crate::spec::SinkLabel::PathTraversal),
    ("createWriteStream", crate::spec::SinkLabel::PathTraversal),
    ("openSync", crate::spec::SinkLabel::PathTraversal),
    ("fopen", crate::spec::SinkLabel::PathTraversal),
    ("readdir", crate::spec::SinkLabel::PathTraversal),
    ("readdirSync", crate::spec::SinkLabel::PathTraversal),
    ("axios.get", crate::spec::SinkLabel::Ssrf),
    ("axios.post", crate::spec::SinkLabel::Ssrf),
    ("axios.put", crate::spec::SinkLabel::Ssrf),
    ("axios.delete", crate::spec::SinkLabel::Ssrf),
    ("axios.patch", crate::spec::SinkLabel::Ssrf),
    ("axios.request", crate::spec::SinkLabel::Ssrf),
    ("axios.head", crate::spec::SinkLabel::Ssrf),
    ("axios.options", crate::spec::SinkLabel::Ssrf),
    ("got.get", crate::spec::SinkLabel::Ssrf),
    ("got.post", crate::spec::SinkLabel::Ssrf),
    ("got.put", crate::spec::SinkLabel::Ssrf),
    ("got.stream", crate::spec::SinkLabel::Ssrf),
    ("superagent.get", crate::spec::SinkLabel::Ssrf),
    ("superagent.post", crate::spec::SinkLabel::Ssrf),
    ("ky.get", crate::spec::SinkLabel::Ssrf),
    ("ky.post", crate::spec::SinkLabel::Ssrf),
    ("http.request", crate::spec::SinkLabel::Ssrf),
    ("https.request", crate::spec::SinkLabel::Ssrf),
    ("undici.fetch", crate::spec::SinkLabel::Ssrf),
    ("undici.request", crate::spec::SinkLabel::Ssrf),
    ("needle.get", crate::spec::SinkLabel::Ssrf),
    ("needle.post", crate::spec::SinkLabel::Ssrf),
    ("execaCommand", crate::spec::SinkLabel::CommandInjection),
    ("execaCommandSync", crate::spec::SinkLabel::CommandInjection),
    ("$", crate::spec::SinkLabel::CommandInjection),
    ("shell.exec", crate::spec::SinkLabel::CommandInjection),
    ("shell.run", crate::spec::SinkLabel::CommandInjection),
    ("cp.exec", crate::spec::SinkLabel::CommandInjection),
    ("aggregate", crate::spec::SinkLabel::NoSqlInjection),
    ("distinct", crate::spec::SinkLabel::NoSqlInjection),
    ("count", crate::spec::SinkLabel::NoSqlInjection),
    ("countDocuments", crate::spec::SinkLabel::NoSqlInjection),
    (
        "estimatedDocumentCount",
        crate::spec::SinkLabel::NoSqlInjection,
    ),
    ("findOneAndUpdate", crate::spec::SinkLabel::NoSqlInjection),
    ("findOneAndDelete", crate::spec::SinkLabel::NoSqlInjection),
    ("findOneAndReplace", crate::spec::SinkLabel::NoSqlInjection),
    ("replaceOne", crate::spec::SinkLabel::NoSqlInjection),
    ("bulkWrite", crate::spec::SinkLabel::NoSqlInjection),
    ("update", crate::spec::SinkLabel::NoSqlInjection), // mongoose Model.update
    ("remove", crate::spec::SinkLabel::NoSqlInjection), // mongoose Model.remove
    ("hget", crate::spec::SinkLabel::NoSqlInjection),
    ("hset", crate::spec::SinkLabel::NoSqlInjection),
    ("del", crate::spec::SinkLabel::NoSqlInjection),
    ("keys", crate::spec::SinkLabel::NoSqlInjection),
    ("deepMerge", crate::spec::SinkLabel::PrototypePollution),
    ("merge", crate::spec::SinkLabel::PrototypePollution),
    ("defaults", crate::spec::SinkLabel::PrototypePollution),
    ("extend", crate::spec::SinkLabel::PrototypePollution),
    ("assign", crate::spec::SinkLabel::PrototypePollution),
    ("deepExtend", crate::spec::SinkLabel::PrototypePollution),
    ("mixin", crate::spec::SinkLabel::PrototypePollution),
    ("cloneDeep", crate::spec::SinkLabel::PrototypePollution),
    ("sign", crate::spec::SinkLabel::JwtWeakAlgorithm),
    ("decode", crate::spec::SinkLabel::JwtUnsafeDecode),
    ("existsSync", crate::spec::SinkLabel::Toctou),
    ("exists", crate::spec::SinkLabel::Toctou),
    ("gql", crate::spec::SinkLabel::GraphqlInjection),
    ("buildSchema", crate::spec::SinkLabel::GraphqlInjection),
    ("graphql", crate::spec::SinkLabel::GraphqlInjection),
    (
        "makeExecutableSchema",
        crate::spec::SinkLabel::GraphqlInjection,
    ),
    ("cp.spawn", crate::spec::SinkLabel::CommandInjection),
    ("cp.execFile", crate::spec::SinkLabel::CommandInjection),
    ("proc.exec", crate::spec::SinkLabel::CommandInjection),
    (
        "childProcess.exec",
        crate::spec::SinkLabel::CommandInjection,
    ),
    // Code Execution
    ("eval", crate::spec::SinkLabel::CodeExecution),
    ("Function", crate::spec::SinkLabel::CodeExecution),
    ("setTimeout", crate::spec::SinkLabel::CodeExecution),
    ("setInterval", crate::spec::SinkLabel::CodeExecution),
    ("runInNewContext", crate::spec::SinkLabel::CodeExecution),
    ("runInThisContext", crate::spec::SinkLabel::CodeExecution),
    ("require", crate::spec::SinkLabel::CodeExecution),
    ("import", crate::spec::SinkLabel::CodeExecution),
    // Command Injection
    ("exec", crate::spec::SinkLabel::CommandInjection),
    ("execSync", crate::spec::SinkLabel::CommandInjection),
    ("spawn", crate::spec::SinkLabel::CommandInjection),
    ("spawnSync", crate::spec::SinkLabel::CommandInjection),
    ("execFile", crate::spec::SinkLabel::CommandInjection),
    ("execFileSync", crate::spec::SinkLabel::CommandInjection),
    ("shelljs.exec", crate::spec::SinkLabel::CommandInjection),
    ("execa", crate::spec::SinkLabel::CommandInjection),
    // SQL Injection
    ("query", crate::spec::SinkLabel::SqlInjection),
    ("execute", crate::spec::SinkLabel::SqlInjection),
    ("executeRaw", crate::spec::SinkLabel::SqlInjection),
    ("queryRaw", crate::spec::SinkLabel::SqlInjection),
    ("raw", crate::spec::SinkLabel::SqlInjection),
    ("prepare", crate::spec::SinkLabel::SqlInjection),
    ("run", crate::spec::SinkLabel::SqlInjection), // sqlite3/knex .run()
    ("one", crate::spec::SinkLabel::SqlInjection), // pg-promise
    ("none", crate::spec::SinkLabel::SqlInjection),
    // Path Traversal
    ("readFile", crate::spec::SinkLabel::PathTraversal),
    ("readFileSync", crate::spec::SinkLabel::PathTraversal),
    ("createReadStream", crate::spec::SinkLabel::PathTraversal),
    ("writeFile", crate::spec::SinkLabel::PathTraversal),
    ("unlink", crate::spec::SinkLabel::PathTraversal),
    ("stat", crate::spec::SinkLabel::PathTraversal),
    ("access", crate::spec::SinkLabel::PathTraversal),
    // SSRF
    ("fetch", crate::spec::SinkLabel::Ssrf),
    ("axios.get", crate::spec::SinkLabel::Ssrf),
    ("axios.post", crate::spec::SinkLabel::Ssrf),
    ("http.get", crate::spec::SinkLabel::Ssrf),
    ("https.get", crate::spec::SinkLabel::Ssrf),
    ("got", crate::spec::SinkLabel::Ssrf),
    ("node-fetch", crate::spec::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", crate::spec::SinkLabel::OpenRedirect),
    ("location.href", crate::spec::SinkLabel::OpenRedirect),
    ("window.location", crate::spec::SinkLabel::OpenRedirect),
    // XSS
    ("innerHTML", crate::spec::SinkLabel::XssDom),
    ("outerHTML", crate::spec::SinkLabel::XssDom),
    ("document.write", crate::spec::SinkLabel::XssDom),
    ("document.writeln", crate::spec::SinkLabel::XssDom),
    ("dangerouslySetInnerHTML", crate::spec::SinkLabel::XssDom),
    // MongoDB / ORM
    ("updateOne", crate::spec::SinkLabel::NoSqlInjection),
    ("updateMany", crate::spec::SinkLabel::NoSqlInjection),
    ("insertOne", crate::spec::SinkLabel::NoSqlInjection),
    ("insertMany", crate::spec::SinkLabel::NoSqlInjection),
    ("deleteOne", crate::spec::SinkLabel::NoSqlInjection),
    ("deleteMany", crate::spec::SinkLabel::NoSqlInjection),
    ("findOne", crate::spec::SinkLabel::NoSqlInjection),
    ("find", crate::spec::SinkLabel::NoSqlInjection), // collection.find / mongoose find
    ("findById", crate::spec::SinkLabel::NoSqlInjection),
    ("findByIdAndUpdate", crate::spec::SinkLabel::NoSqlInjection),
    ("findByIdAndDelete", crate::spec::SinkLabel::NoSqlInjection),
    ("findAll", crate::spec::SinkLabel::NoSqlInjection),
    ("destroy", crate::spec::SinkLabel::NoSqlInjection), // sequelize Model.destroy
    // Storage Write
    ("setItem", crate::spec::SinkLabel::StorageWrite),
    // Log Leak
    // SSTI - Template engine renders
    ("ejs.render", crate::spec::SinkLabel::TemplateSsti),
    ("ejs.renderFile", crate::spec::SinkLabel::TemplateSsti),
    ("pug.compile", crate::spec::SinkLabel::TemplateSsti),
    ("pug.render", crate::spec::SinkLabel::TemplateSsti),
    ("handlebars.compile", crate::spec::SinkLabel::TemplateSsti),
    ("handlebars.render", crate::spec::SinkLabel::TemplateSsti),
    ("nunjucks.render", crate::spec::SinkLabel::TemplateSsti),
    (
        "nunjucks.renderString",
        crate::spec::SinkLabel::TemplateSsti,
    ),
    ("nunjucks.renderFile", crate::spec::SinkLabel::TemplateSsti),
    ("marko.render", crate::spec::SinkLabel::TemplateSsti),
    ("eta.render", crate::spec::SinkLabel::TemplateSsti),
    ("swig.render", crate::spec::SinkLabel::TemplateSsti),
    ("liquid.render", crate::spec::SinkLabel::TemplateSsti),
    ("mustache.render", crate::spec::SinkLabel::TemplateSsti),
    ("jade.render", crate::spec::SinkLabel::TemplateSsti),
    (
        "react-dom/server.renderToString",
        crate::spec::SinkLabel::TemplateSsti,
    ),
    (
        "vue-server-renderer.renderToString",
        crate::spec::SinkLabel::TemplateSsti,
    ),
    // Insecure Deserialization
    ("serialize", crate::spec::SinkLabel::UnsafeDeserialize),
    ("deserialize", crate::spec::SinkLabel::UnsafeDeserialize),
    ("yaml.load", crate::spec::SinkLabel::UnsafeDeserialize),
    ("js-yaml.load", crate::spec::SinkLabel::UnsafeDeserialize),
    ("msgpack.decode", crate::spec::SinkLabel::UnsafeDeserialize),
    ("msgpack.unpack", crate::spec::SinkLabel::UnsafeDeserialize),
    // Prototype Pollution
    ("Object.assign", crate::spec::SinkLabel::PrototypePollution),
    ("_.merge", crate::spec::SinkLabel::PrototypePollution),
    ("lodash.merge", crate::spec::SinkLabel::PrototypePollution),
    ("_.defaultsDeep", crate::spec::SinkLabel::PrototypePollution),
    ("_.set", crate::spec::SinkLabel::PrototypePollution),
    ("_.unset", crate::spec::SinkLabel::PrototypePollution),
    ("lodash.unset", crate::spec::SinkLabel::PrototypePollution),
    ("unset", crate::spec::SinkLabel::PrototypePollution),
    ("_.omit", crate::spec::SinkLabel::PrototypePollution),
    ("lodash.omit", crate::spec::SinkLabel::PrototypePollution),
    ("omit", crate::spec::SinkLabel::PrototypePollution),
    ("$.extend", crate::spec::SinkLabel::PrototypePollution),
    ("jQuery.extend", crate::spec::SinkLabel::PrototypePollution),
    ("angular.merge", crate::spec::SinkLabel::PrototypePollution),
    ("setPrototypeOf", crate::spec::SinkLabel::PrototypePollution),
    // XXE
    ("DOMParser", crate::spec::SinkLabel::Xxe),
    // JWT: jwt.sign kept (tainted payload signed into a token is worth
    // flagging); verify/decode removed, they are validators, not sinks.
    ("jwt.sign", crate::spec::SinkLabel::Jwt),
    // Cloudflare Workers / Prisma
    ("c.redirect", crate::spec::SinkLabel::OpenRedirect),
    ("env.KV.put", crate::spec::SinkLabel::StorageWrite),
    ("KVNamespace.put", crate::spec::SinkLabel::StorageWrite),
    ("KVNamespace.delete", crate::spec::SinkLabel::StorageWrite),
    ("env.DB.prepare", crate::spec::SinkLabel::SqlInjection),
    ("res.send", crate::spec::SinkLabel::XssReflected),
    ("res.json", crate::spec::SinkLabel::ResponseLeak),
    ("res.redirect", crate::spec::SinkLabel::OpenRedirect),
    ("res.render", crate::spec::SinkLabel::TemplateSsti),
    ("revalidatePath", crate::spec::SinkLabel::StorageWrite),
    (
        "prisma.queryRawUnsafe",
        crate::spec::SinkLabel::SqlInjection,
    ),
    (
        "prisma.executeRawUnsafe",
        crate::spec::SinkLabel::SqlInjection,
    ),
    ("R2Bucket.put", crate::spec::SinkLabel::StorageWrite),
    ("D1Database.prepare", crate::spec::SinkLabel::SqlInjection),
    ("DurableObjectStub.fetch", crate::spec::SinkLabel::Ssrf),
    ("Queue.send", crate::spec::SinkLabel::Ssrf),
];

/// Per-slot danger facts for sinks whose argument positions carry different
/// semantics. `(call, dangerous_slots, binding_args_safe)`.
///
/// Without these, `jwt.verify(token, secret)` alerts on slot 1 (the
/// developer-controlled secret) and `query(sql, params)` alerts on the
/// *parameterized* values, the two largest structural FP classes.
/// Empty `dangerous_slots` = every slot dangerous (the default when a call
/// has no entry here).
pub(super) static JS_SINK_SIGNATURES: &[(&'static str, &'static [usize], bool)] = &[
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
pub(super) static JS_IDOR_SINKS: &[(&'static str, &'static [&'static str])] = &[
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
