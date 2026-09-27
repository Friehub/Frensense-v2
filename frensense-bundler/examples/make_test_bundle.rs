fn main() {
    use frensense_engine::analysis::taint::facts::LearnedFactEntry;
    let facts = vec![
        LearnedFactEntry::Source {
            pattern: "random.randint".into(),
        },
        LearnedFactEntry::Source {
            pattern: "random.random".into(),
        },
        LearnedFactEntry::Source {
            pattern: "random.choice".into(),
        },
        LearnedFactEntry::Source {
            pattern: "secrets.token_hex".into(),
        },
        LearnedFactEntry::Source {
            pattern: "secrets.token_bytes".into(),
        },
        // CWE-611 XXE sinks (also bundle-learnable)
        LearnedFactEntry::Sink {
            call: "parse".into(),
            dangerous_args: [0].into_iter().collect(),
            binding_args_safe: false,
        },
        LearnedFactEntry::Sink {
            call: "fromstring".into(),
            dangerous_args: [0].into_iter().collect(),
            binding_args_safe: false,
        },
        LearnedFactEntry::Sink {
            call: "iterparse".into(),
            dangerous_args: [0].into_iter().collect(),
            binding_args_safe: false,
        },
        // CWE-22 extras
        LearnedFactEntry::Sink {
            call: "codecs.open".into(),
            dangerous_args: [0].into_iter().collect(),
            binding_args_safe: false,
        },
    ];
    let payload = frensense_bundler::format::BundlePayload {
        patterns: vec![],
        learned_facts: facts,
    };
    let bytes = frensense_bundler::format::write_bundle(&payload, 0).expect("write");
    std::fs::write("/tmp/cwe-bundle.frc", &bytes).expect("write file");
    let loaded = frensense_bundler::format::load_bundle(&bytes).expect("reload");
    println!("bundle OK: {} learned facts", loaded.learned_facts.len());
}
