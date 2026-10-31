#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing
/**
 * Exa-backed web search for agent and contributor workflows.
 *
 * Frensense's knowledge lanes (corpus families, packgen vocabulary) are
 * curated from what real code actually does — advisories, vendor docs, and
 * post-mortems that explain why a sink is dangerous. This helper fetches
 * those pages: one Exa search per query, each hit returned with highlights,
 * so an agent can read the relevant passage instead of a whole page.
 *
 * The API key comes from the environment only (`EXA_API_KEY`); it is never
 * read from a file, logged, or written anywhere.
 *
 * Usage:
 *
 *   EXA_API_KEY=... node scripts/exa-search/search.mjs "tree-sitter query cursor API"
 *   node --env-file=.env scripts/exa-search/search.mjs "SSRF in URL parsers" --num-results 3
 *   node --env-file=.env scripts/exa-search/search.mjs "prototype pollution fix" --json
 *
 * Options:
 *   --num-results <n>   hits to return (default: 5, max: 25)
 *   --domain <d>        restrict to a domain; repeatable
 *   --json              emit the raw Exa results as JSON
 *   --help              print this help
 */

import process from "node:process";
import Exa from "exa-js";

const DEFAULT_NUM_RESULTS = 5;
const MAX_NUM_RESULTS = 25;

function printHelp() {
  process.stdout.write(
    [
      "Usage: exa-search <query> [--num-results <n>] [--domain <d>]... [--json]",
      "",
      "Searches the web through Exa and prints each hit with highlights.",
      "Requires EXA_API_KEY in the environment (see .env.example).",
      "",
    ].join("\n"),
  );
}

function parseArgs(argv) {
  const opts = { queryParts: [], numResults: DEFAULT_NUM_RESULTS, domains: [], json: false };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "-h":
      case "--help":
        opts.help = true;
        break;
      case "--json":
        opts.json = true;
        break;
      case "--num-results": {
        const raw = argv[i + 1];
        i += 1;
        const parsed = Number.parseInt(raw ?? "", 10);
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > MAX_NUM_RESULTS) {
          throw new Error(
            `--num-results expects an integer between 1 and ${MAX_NUM_RESULTS}, got ${raw ?? "<missing>"}`,
          );
        }
        opts.numResults = parsed;
        break;
      }
      case "--domain": {
        const domain = argv[i + 1];
        i += 1;
        if (!domain) throw new Error("--domain expects a domain, e.g. --domain nvd.nist.gov");
        opts.domains.push(domain);
        break;
      }
      default:
        if (arg.startsWith("-")) throw new Error(`unknown option: ${arg}`);
        opts.queryParts.push(arg);
    }
  }

  opts.query = opts.queryParts.join(" ").trim();
  return opts;
}

/** Run one Exa search and return the result pages, each with highlights. */
async function search(exa, query, { numResults, domains }) {
  const results = await exa.search(query, {
    type: "auto",
    numResults,
    ...(domains.length > 0 ? { includeDomains: domains } : {}),
    contents: { highlights: true },
  });

  const pages = Array.isArray(results) ? results : (results?.results ?? []);
  return pages.map((page) => ({
    title: page.title ?? "",
    url: page.url ?? "",
    publishedDate: page.publishedDate ?? null,
    highlights: Array.isArray(page.highlights) ? page.highlights : [],
  }));
}

function render(query, pages) {
  const lines = [`${pages.length} result(s) for: ${query}`];
  for (const [index, page] of pages.entries()) {
    lines.push("", `${index + 1}. ${page.title || "(untitled)"}`, `   ${page.url}`);
    if (page.publishedDate) lines.push(`   published: ${page.publishedDate}`);
    for (const highlight of page.highlights) {
      lines.push(`   · ${highlight.replace(/\s+/g, " ").trim()}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

async function main(argv) {
  const opts = parseArgs(argv);

  if (opts.help) {
    printHelp();
    return 0;
  }
  if (!opts.query) {
    throw new Error("a search query is required, e.g. exa-search \"SSRF in URL parsers\"");
  }

  const apiKey = process.env.EXA_API_KEY;
  if (!apiKey) {
    throw new Error(
      "EXA_API_KEY is not set. Copy .env.example to .env, add your key from " +
        "https://dashboard.exa.ai, then run with `node --env-file=.env ...`.",
    );
  }

  const exa = new Exa(apiKey);
  const pages = await search(exa, opts.query, opts);

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({ query: opts.query, results: pages }, null, 2)}\n`);
  } else {
    process.stdout.write(render(opts.query, pages));
  }
  return 0;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    process.stderr.write(`exa-search: ${error?.message ?? error}\n`);
    process.exitCode = 1;
  });
