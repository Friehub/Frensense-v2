// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Static sink/source tables shared by the JS and TS specs.

// ── Static sink/source tables ─────────────────────────────────────────────────

pub(super) static JS_SINK_NAMES: &[(&str, crate::role_map::SinkLabel)] = &[
    // Modern attack patterns
    ("insertAdjacentHTML", crate::role_map::SinkLabel::XssDom),
    ("insertAdjacentElement", crate::role_map::SinkLabel::XssDom),
    (
        "createContextualFragment",
        crate::role_map::SinkLabel::XssDom,
    ),
    ("write", crate::role_map::SinkLabel::XssDom),
    ("writeln", crate::role_map::SinkLabel::XssDom),
    ("srcdoc", crate::role_map::SinkLabel::XssDom),
    ("setAttribute", crate::role_map::SinkLabel::XssDom),
    ("setAttributeNS", crate::role_map::SinkLabel::XssDom),
    ("setHeader", crate::role_map::SinkLabel::HeaderInjection),
    ("header", crate::role_map::SinkLabel::HeaderInjection),
    ("append", crate::role_map::SinkLabel::HeaderInjection),
    ("cookie", crate::role_map::SinkLabel::CookiePoisoning),
    ("type", crate::role_map::SinkLabel::ContentTypeInjection),
    ("appendFile", crate::role_map::SinkLabel::PathTraversal),
    ("appendFileSync", crate::role_map::SinkLabel::PathTraversal),
    ("copyFile", crate::role_map::SinkLabel::PathTraversal),
    ("copyFileSync", crate::role_map::SinkLabel::PathTraversal),
    ("mkdir", crate::role_map::SinkLabel::PathTraversal),
    ("mkdirSync", crate::role_map::SinkLabel::PathTraversal),
    ("rename", crate::role_map::SinkLabel::PathTraversal),
    ("renameSync", crate::role_map::SinkLabel::PathTraversal),
    ("rmdir", crate::role_map::SinkLabel::PathTraversal),
    ("rmdirSync", crate::role_map::SinkLabel::PathTraversal),
    ("lstat", crate::role_map::SinkLabel::PathTraversal),
    ("lstatSync", crate::role_map::SinkLabel::PathTraversal),
    ("chmod", crate::role_map::SinkLabel::PathTraversal),
    ("chown", crate::role_map::SinkLabel::PathTraversal),
    ("symlink", crate::role_map::SinkLabel::PathTraversal),
    ("realpath", crate::role_map::SinkLabel::PathTraversal),
    ("realpathSync", crate::role_map::SinkLabel::PathTraversal),
    (
        "createWriteStream",
        crate::role_map::SinkLabel::PathTraversal,
    ),
    ("openSync", crate::role_map::SinkLabel::PathTraversal),
    ("fopen", crate::role_map::SinkLabel::PathTraversal),
    ("readdir", crate::role_map::SinkLabel::PathTraversal),
    ("readdirSync", crate::role_map::SinkLabel::PathTraversal),
    ("axios.get", crate::role_map::SinkLabel::Ssrf),
    ("axios.post", crate::role_map::SinkLabel::Ssrf),
    ("axios.put", crate::role_map::SinkLabel::Ssrf),
    ("axios.delete", crate::role_map::SinkLabel::Ssrf),
    ("axios.patch", crate::role_map::SinkLabel::Ssrf),
    ("axios.request", crate::role_map::SinkLabel::Ssrf),
    ("axios.head", crate::role_map::SinkLabel::Ssrf),
    ("axios.options", crate::role_map::SinkLabel::Ssrf),
    ("got.get", crate::role_map::SinkLabel::Ssrf),
    ("got.post", crate::role_map::SinkLabel::Ssrf),
    ("got.put", crate::role_map::SinkLabel::Ssrf),
    ("got.stream", crate::role_map::SinkLabel::Ssrf),
    ("superagent.get", crate::role_map::SinkLabel::Ssrf),
    ("superagent.post", crate::role_map::SinkLabel::Ssrf),
    ("ky.get", crate::role_map::SinkLabel::Ssrf),
    ("ky.post", crate::role_map::SinkLabel::Ssrf),
    ("http.request", crate::role_map::SinkLabel::Ssrf),
    ("https.request", crate::role_map::SinkLabel::Ssrf),
    ("undici.fetch", crate::role_map::SinkLabel::Ssrf),
    ("undici.request", crate::role_map::SinkLabel::Ssrf),
    ("needle.get", crate::role_map::SinkLabel::Ssrf),
    ("needle.post", crate::role_map::SinkLabel::Ssrf),
    ("execaCommand", crate::role_map::SinkLabel::CommandInjection),
    (
        "execaCommandSync",
        crate::role_map::SinkLabel::CommandInjection,
    ),
    ("$", crate::role_map::SinkLabel::CommandInjection),
    ("shell.exec", crate::role_map::SinkLabel::CommandInjection),
    ("shell.run", crate::role_map::SinkLabel::CommandInjection),
    ("cp.exec", crate::role_map::SinkLabel::CommandInjection),
    ("aggregate", crate::role_map::SinkLabel::NoSqlInjection),
    ("distinct", crate::role_map::SinkLabel::NoSqlInjection),
    ("count", crate::role_map::SinkLabel::NoSqlInjection),
    ("countDocuments", crate::role_map::SinkLabel::NoSqlInjection),
    (
        "estimatedDocumentCount",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    (
        "findOneAndUpdate",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    (
        "findOneAndDelete",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    (
        "findOneAndReplace",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    ("replaceOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("bulkWrite", crate::role_map::SinkLabel::NoSqlInjection),
    ("update", crate::role_map::SinkLabel::NoSqlInjection), // mongoose Model.update
    ("remove", crate::role_map::SinkLabel::NoSqlInjection), // mongoose Model.remove
    ("hget", crate::role_map::SinkLabel::NoSqlInjection),
    ("hset", crate::role_map::SinkLabel::NoSqlInjection),
    ("del", crate::role_map::SinkLabel::NoSqlInjection),
    ("keys", crate::role_map::SinkLabel::NoSqlInjection),
    ("deepMerge", crate::role_map::SinkLabel::PrototypePollution),
    ("merge", crate::role_map::SinkLabel::PrototypePollution),
    ("defaults", crate::role_map::SinkLabel::PrototypePollution),
    ("extend", crate::role_map::SinkLabel::PrototypePollution),
    ("assign", crate::role_map::SinkLabel::PrototypePollution),
    ("deepExtend", crate::role_map::SinkLabel::PrototypePollution),
    ("mixin", crate::role_map::SinkLabel::PrototypePollution),
    ("cloneDeep", crate::role_map::SinkLabel::PrototypePollution),
    ("sign", crate::role_map::SinkLabel::JwtWeakAlgorithm),
    ("decode", crate::role_map::SinkLabel::JwtUnsafeDecode),
    ("existsSync", crate::role_map::SinkLabel::Toctou),
    ("exists", crate::role_map::SinkLabel::Toctou),
    ("gql", crate::role_map::SinkLabel::GraphqlInjection),
    ("buildSchema", crate::role_map::SinkLabel::GraphqlInjection),
    ("graphql", crate::role_map::SinkLabel::GraphqlInjection),
    (
        "makeExecutableSchema",
        crate::role_map::SinkLabel::GraphqlInjection,
    ),
    ("cp.spawn", crate::role_map::SinkLabel::CommandInjection),
    ("cp.execFile", crate::role_map::SinkLabel::CommandInjection),
    ("proc.exec", crate::role_map::SinkLabel::CommandInjection),
    (
        "childProcess.exec",
        crate::role_map::SinkLabel::CommandInjection,
    ),
    // Code Execution
    ("eval", crate::role_map::SinkLabel::CodeExecution),
    ("Function", crate::role_map::SinkLabel::CodeExecution),
    ("setTimeout", crate::role_map::SinkLabel::CodeExecution),
    ("setInterval", crate::role_map::SinkLabel::CodeExecution),
    ("runInNewContext", crate::role_map::SinkLabel::CodeExecution),
    (
        "runInThisContext",
        crate::role_map::SinkLabel::CodeExecution,
    ),
    ("require", crate::role_map::SinkLabel::CodeExecution),
    ("import", crate::role_map::SinkLabel::CodeExecution),
    // Command Injection
    ("exec", crate::role_map::SinkLabel::CommandInjection),
    ("execSync", crate::role_map::SinkLabel::CommandInjection),
    ("spawn", crate::role_map::SinkLabel::CommandInjection),
    ("spawnSync", crate::role_map::SinkLabel::CommandInjection),
    ("execFile", crate::role_map::SinkLabel::CommandInjection),
    ("execFileSync", crate::role_map::SinkLabel::CommandInjection),
    ("shelljs.exec", crate::role_map::SinkLabel::CommandInjection),
    ("execa", crate::role_map::SinkLabel::CommandInjection),
    // SQL Injection
    ("query", crate::role_map::SinkLabel::SqlInjection),
    ("execute", crate::role_map::SinkLabel::SqlInjection),
    ("executeRaw", crate::role_map::SinkLabel::SqlInjection),
    ("queryRaw", crate::role_map::SinkLabel::SqlInjection),
    ("raw", crate::role_map::SinkLabel::SqlInjection),
    ("prepare", crate::role_map::SinkLabel::SqlInjection),
    ("run", crate::role_map::SinkLabel::SqlInjection), // sqlite3/knex .run()
    ("one", crate::role_map::SinkLabel::SqlInjection), // pg-promise
    ("none", crate::role_map::SinkLabel::SqlInjection),
    // Path Traversal
    ("readFile", crate::role_map::SinkLabel::PathTraversal),
    ("readFileSync", crate::role_map::SinkLabel::PathTraversal),
    (
        "createReadStream",
        crate::role_map::SinkLabel::PathTraversal,
    ),
    ("writeFile", crate::role_map::SinkLabel::PathTraversal),
    ("unlink", crate::role_map::SinkLabel::PathTraversal),
    ("stat", crate::role_map::SinkLabel::PathTraversal),
    ("access", crate::role_map::SinkLabel::PathTraversal),
    // SSRF
    ("fetch", crate::role_map::SinkLabel::Ssrf),
    ("axios.get", crate::role_map::SinkLabel::Ssrf),
    ("axios.post", crate::role_map::SinkLabel::Ssrf),
    ("http.get", crate::role_map::SinkLabel::Ssrf),
    ("https.get", crate::role_map::SinkLabel::Ssrf),
    ("got", crate::role_map::SinkLabel::Ssrf),
    ("node-fetch", crate::role_map::SinkLabel::Ssrf),
    // Open Redirect
    ("redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("location.href", crate::role_map::SinkLabel::OpenRedirect),
    ("window.location", crate::role_map::SinkLabel::OpenRedirect),
    // XSS
    ("innerHTML", crate::role_map::SinkLabel::XssDom),
    ("outerHTML", crate::role_map::SinkLabel::XssDom),
    ("document.write", crate::role_map::SinkLabel::XssDom),
    ("document.writeln", crate::role_map::SinkLabel::XssDom),
    (
        "dangerouslySetInnerHTML",
        crate::role_map::SinkLabel::XssDom,
    ),
    // MongoDB / ORM
    ("updateOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("updateMany", crate::role_map::SinkLabel::NoSqlInjection),
    ("insertOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("insertMany", crate::role_map::SinkLabel::NoSqlInjection),
    ("deleteOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("deleteMany", crate::role_map::SinkLabel::NoSqlInjection),
    ("findOne", crate::role_map::SinkLabel::NoSqlInjection),
    ("find", crate::role_map::SinkLabel::NoSqlInjection), // collection.find / mongoose find
    ("findById", crate::role_map::SinkLabel::NoSqlInjection),
    (
        "findByIdAndUpdate",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    (
        "findByIdAndDelete",
        crate::role_map::SinkLabel::NoSqlInjection,
    ),
    ("findAll", crate::role_map::SinkLabel::NoSqlInjection),
    ("destroy", crate::role_map::SinkLabel::NoSqlInjection), // sequelize Model.destroy
    // Storage Write
    ("setItem", crate::role_map::SinkLabel::StorageWrite),
    // Log Leak
    // SSTI - Template engine renders
    ("ejs.render", crate::role_map::SinkLabel::TemplateSsti),
    ("ejs.renderFile", crate::role_map::SinkLabel::TemplateSsti),
    ("pug.compile", crate::role_map::SinkLabel::TemplateSsti),
    ("pug.render", crate::role_map::SinkLabel::TemplateSsti),
    (
        "handlebars.compile",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    (
        "handlebars.render",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    ("nunjucks.render", crate::role_map::SinkLabel::TemplateSsti),
    (
        "nunjucks.renderString",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    (
        "nunjucks.renderFile",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    ("marko.render", crate::role_map::SinkLabel::TemplateSsti),
    ("eta.render", crate::role_map::SinkLabel::TemplateSsti),
    ("swig.render", crate::role_map::SinkLabel::TemplateSsti),
    ("liquid.render", crate::role_map::SinkLabel::TemplateSsti),
    ("mustache.render", crate::role_map::SinkLabel::TemplateSsti),
    ("jade.render", crate::role_map::SinkLabel::TemplateSsti),
    (
        "react-dom/server.renderToString",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    (
        "vue-server-renderer.renderToString",
        crate::role_map::SinkLabel::TemplateSsti,
    ),
    // Insecure Deserialization
    ("serialize", crate::role_map::SinkLabel::UnsafeDeserialize),
    ("deserialize", crate::role_map::SinkLabel::UnsafeDeserialize),
    ("yaml.load", crate::role_map::SinkLabel::UnsafeDeserialize),
    (
        "js-yaml.load",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "msgpack.decode",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    (
        "msgpack.unpack",
        crate::role_map::SinkLabel::UnsafeDeserialize,
    ),
    // Prototype Pollution
    (
        "Object.assign",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    ("_.merge", crate::role_map::SinkLabel::PrototypePollution),
    (
        "lodash.merge",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    (
        "_.defaultsDeep",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    ("_.set", crate::role_map::SinkLabel::PrototypePollution),
    ("_.unset", crate::role_map::SinkLabel::PrototypePollution),
    (
        "lodash.unset",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    ("unset", crate::role_map::SinkLabel::PrototypePollution),
    ("_.omit", crate::role_map::SinkLabel::PrototypePollution),
    (
        "lodash.omit",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    ("omit", crate::role_map::SinkLabel::PrototypePollution),
    ("$.extend", crate::role_map::SinkLabel::PrototypePollution),
    (
        "jQuery.extend",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    (
        "angular.merge",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    (
        "setPrototypeOf",
        crate::role_map::SinkLabel::PrototypePollution,
    ),
    // XXE
    ("DOMParser", crate::role_map::SinkLabel::Xxe),
    // JWT: jwt.sign kept (tainted payload signed into a token is worth
    // flagging); verify/decode removed, they are validators, not sinks.
    ("jwt.sign", crate::role_map::SinkLabel::Jwt),
    // Cloudflare Workers / Prisma
    ("c.redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("env.KV.put", crate::role_map::SinkLabel::StorageWrite),
    ("KVNamespace.put", crate::role_map::SinkLabel::StorageWrite),
    (
        "KVNamespace.delete",
        crate::role_map::SinkLabel::StorageWrite,
    ),
    ("env.DB.prepare", crate::role_map::SinkLabel::SqlInjection),
    ("res.send", crate::role_map::SinkLabel::XssReflected),
    ("res.json", crate::role_map::SinkLabel::ResponseLeak),
    ("res.redirect", crate::role_map::SinkLabel::OpenRedirect),
    ("res.render", crate::role_map::SinkLabel::TemplateSsti),
    ("revalidatePath", crate::role_map::SinkLabel::StorageWrite),
    (
        "prisma.queryRawUnsafe",
        crate::role_map::SinkLabel::SqlInjection,
    ),
    (
        "prisma.executeRawUnsafe",
        crate::role_map::SinkLabel::SqlInjection,
    ),
    ("R2Bucket.put", crate::role_map::SinkLabel::StorageWrite),
    (
        "D1Database.prepare",
        crate::role_map::SinkLabel::SqlInjection,
    ),
    ("DurableObjectStub.fetch", crate::role_map::SinkLabel::Ssrf),
    ("Queue.send", crate::role_map::SinkLabel::Ssrf),
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
