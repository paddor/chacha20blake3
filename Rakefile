# frozen_string_literal: true

require "bundler/gem_tasks"
require "rb_sys/extensiontask"
require "minitest/test_task"

GEMSPEC = Gem::Specification.load("chacha20blake3.gemspec") ||
          abort("Could not load chacha20blake3.gemspec")

RbSys::ExtensionTask.new("chacha20blake3", GEMSPEC) do |ext|
  ext.lib_dir = "lib/chacha20blake3"
end

Minitest::TestTask.create(:test) do |t|
  t.libs       << "lib" << "test"
  t.test_globs  = ["test/test_*.rb"]
end

desc "Run Rust unit tests"
task :cargo_test do
  # --lib skips doc-tests; those conflict due to our crate name matching
  # the upstream chacha20-blake3 dependency's rlib artifact name.
  sh "RUBY=#{RbConfig.ruby} cargo test --lib --manifest-path ext/chacha20blake3/Cargo.toml"
end

desc "Run Clippy lints"
task :clippy do
  sh "cargo clippy --manifest-path ext/chacha20blake3/Cargo.toml -- -D warnings"
end

desc "Format Rust code"
task :fmt do
  sh "cargo fmt --manifest-path ext/chacha20blake3/Cargo.toml"
end

desc "Run benchmarks (compiles first)"
task bench: :compile do
  sh "ruby benchmarks/bench.rb"
end

desc "Run all tests (Ruby + Rust)"
task test_all: [:test, :cargo_test]

task build: :compile
task default: [:compile, :test]
