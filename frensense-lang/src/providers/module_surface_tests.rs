// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2024-2026 Friehub. All rights reserved.
// Commercial use requires a separate license: https://friehub.com/licensing

//! Module-surface extraction: what a file declares and what it exports.
//!
//! One test per language, each asserting the two answers separately - the
//! exported surface (importable symbols) and the declaration surface
//! (everything at file scope) - because the difference between them is what
//! a clean-code check reads.

use crate::registry::spec_for_ext;
use crate::spec::{Export, ItemKind, ModuleItem, Visibility};

fn parse(ext: &str, source: &str) -> (Vec<Export>, Vec<ModuleItem>) {
    let spec = spec_for_ext(ext).expect("spec");
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&spec.tree_sitter_language())
        .expect("language");
    let tree = parser.parse(source, None).expect("parse");
    (
        spec.extract_exports(tree.root_node(), source),
        spec.extract_module_items(tree.root_node(), source),
    )
}

fn export<'a>(exports: &'a [Export], name: &str) -> &'a Export {
    exports
        .iter()
        .find(|e| e.exported_name == name)
        .unwrap_or_else(|| panic!("no export '{name}' in {:?}", names(exports)))
}

fn names(exports: &[Export]) -> Vec<&str> {
    exports.iter().map(|e| e.exported_name.as_str()).collect()
}

fn item<'a>(items: &'a [ModuleItem], name: &str) -> &'a ModuleItem {
    items
        .iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("no module item '{name}' in {:?}", item_names(items)))
}

fn item_names(items: &[ModuleItem]) -> Vec<&str> {
    items.iter().map(|i| i.name.as_str()).collect()
}

#[test]
fn typescript_exports_every_declaration_form() {
    let source = r#"
export function run() {}
export async function load() {}
export const LIMIT = 10, RETRIES = 3;
export let cursor = 0;
export class Client {}
export enum Mode { A, B }
export interface Options {}
export type Id = string;
export default class Server {}
export { local as alias } from "./barrel";
export * from "./barrel";
export * as ns from "./ns";
function local() {}
"#;
    let (exports, items) = parse("ts", source);

    assert_eq!(export(&exports, "run").kind, ItemKind::Function);
    assert_eq!(export(&exports, "load").kind, ItemKind::Function);
    assert_eq!(export(&exports, "LIMIT").kind, ItemKind::Constant);
    assert_eq!(export(&exports, "RETRIES").kind, ItemKind::Constant);
    assert_eq!(export(&exports, "cursor").kind, ItemKind::Variable);
    assert_eq!(export(&exports, "Client").kind, ItemKind::Class);
    assert_eq!(export(&exports, "Mode").kind, ItemKind::Enum);
    assert_eq!(export(&exports, "Options").kind, ItemKind::Interface);
    assert_eq!(export(&exports, "Id").kind, ItemKind::Type);
    assert_eq!(export(&exports, "ns").kind, ItemKind::Module);
    assert!(exports.iter().any(|e| e.exported_name == "*"));
    assert!(exports.iter().all(|e| e.visibility == Visibility::Public));

    // `export default` publishes the name `default`, never the class's own.
    let default = export(&exports, "default");
    assert_eq!(default.local_name, "Server");
    assert_eq!(default.kind, ItemKind::Class);

    // A named re-export keeps both names and remembers the module.
    let alias = export(&exports, "alias");
    assert_eq!(alias.local_name, "local");
    assert_eq!(alias.from_module.as_deref(), Some("./barrel"));

    // Re-exports and barrels declare nothing locally, so they are not items.
    assert!(items.iter().all(|i| i.name != "alias" && i.name != "*"));
    // Unexported declarations never reach the export list.
    assert!(!names(&exports).contains(&"local"));
}

#[test]
fn rust_separates_pub_from_crate_visibility() {
    let source = r#"
pub fn serve() {}
pub(crate) fn internal() {}
fn helper() {}

pub struct Config;
struct Private;

pub mod outer {
    pub fn nested() {}
    pub(crate) fn partly() {}
    fn hidden() {}
}
"#;
    let (exports, items) = parse("rs", source);

    // Only root-level `pub` is importable by path.
    assert!(names(&exports).contains(&"serve"));
    assert!(names(&exports).contains(&"Config"));
    assert!(names(&exports).contains(&"outer"));
    assert!(!names(&exports).contains(&"internal"));
    assert!(!names(&exports).contains(&"nested"));

    assert_eq!(item(&items, "serve").visibility, Visibility::Public);
    assert_eq!(item(&items, "internal").visibility, Visibility::Internal);
    assert_eq!(item(&items, "helper").visibility, Visibility::Private);
    assert_eq!(item(&items, "Config").kind, ItemKind::Struct);
    assert_eq!(item(&items, "outer").kind, ItemKind::Module);

    // Nested items are part of the declaration surface with their written
    // visibility, which is how an `unnecessary pub` check sees them.
    assert_eq!(item(&items, "nested").visibility, Visibility::Public);
    assert_eq!(item(&items, "partly").visibility, Visibility::Internal);
    assert_eq!(item(&items, "hidden").visibility, Visibility::Private);
}

#[test]
fn python_reads_dunder_all_then_underscore_convention() {
    let source = r#"
__all__ = ["public_api", "PublicClass"]

CONSTANT = 1
module_state = None

def public_api():
    pass

def left_out():
    pass

def _private():
    pass

class PublicClass:
    pass
"#;
    let (exports, items) = parse("py", source);

    assert_eq!(names(&exports), vec!["public_api", "PublicClass"]);
    assert_eq!(item(&items, "public_api").kind, ItemKind::Function);
    assert_eq!(item(&items, "PublicClass").kind, ItemKind::Class);
    // `__all__` is a surface, not a declaration.
    assert!(!item_names(&items).contains(&"__all__"));
    // Curated `__all__` wins over spelling: no underscore, still private.
    assert_eq!(item(&items, "left_out").visibility, Visibility::Private);
    assert_eq!(item(&items, "_private").visibility, Visibility::Private);
    assert_eq!(item(&items, "CONSTANT").kind, ItemKind::Constant);
    assert_eq!(item(&items, "CONSTANT").visibility, Visibility::Private);
    assert_eq!(item(&items, "module_state").kind, ItemKind::Variable);
}

#[test]
fn python_without_dunder_all_uses_the_underscore_convention() {
    let (exports, items) = parse("py", "def run():\n    pass\n\ndef _helper():\n    pass\n");
    assert_eq!(names(&exports), vec!["run"]);
    assert_eq!(item(&items, "_helper").visibility, Visibility::Private);
}

#[test]
fn go_exports_only_capitalized_names() {
    let source = r#"
package demo

import "fmt"

const MaxRetries = 3
const internalLimit = 9

var State = 0
var counter = 0

type Server struct{}
type hidden struct{}

func Serve() { fmt.Println("x") }
func helper() {}
func (s *Server) Start() {}
"#;
    let (exports, items) = parse("go", source);

    assert_eq!(
        names(&exports),
        vec!["MaxRetries", "State", "Server", "Serve", "Start"]
    );
    assert_eq!(item(&items, "MaxRetries").kind, ItemKind::Constant);
    assert_eq!(item(&items, "State").kind, ItemKind::Variable);
    assert_eq!(item(&items, "Server").kind, ItemKind::Type);
    assert_eq!(item(&items, "Serve").kind, ItemKind::Function);
    assert_eq!(
        item(&items, "internalLimit").visibility,
        Visibility::Private
    );
    assert_eq!(item(&items, "counter").visibility, Visibility::Private);
    assert_eq!(item(&items, "hidden").visibility, Visibility::Private);
}

#[test]
fn c_treats_static_as_the_only_private_linkage() {
    let source = r#"
#include <stdio.h>

static int helper(int x) { return x; }
int serve(int x) { return helper(x); }

static int state = 0;
int counter = 0;

typedef struct point { int x, y; } Point;
struct opaque { int v; };
"#;
    let (exports, items) = parse("c", source);

    assert!(names(&exports).contains(&"serve"));
    assert!(names(&exports).contains(&"counter"));
    assert!(!names(&exports).contains(&"helper"));
    assert!(!names(&exports).contains(&"state"));

    assert_eq!(item(&items, "serve").kind, ItemKind::Function);
    assert_eq!(item(&items, "serve").visibility, Visibility::Public);
    assert_eq!(item(&items, "helper").visibility, Visibility::Private);
    assert_eq!(item(&items, "counter").kind, ItemKind::Variable);
    assert_eq!(item(&items, "state").visibility, Visibility::Private);
    assert_eq!(item(&items, "Point").kind, ItemKind::Type);
}
