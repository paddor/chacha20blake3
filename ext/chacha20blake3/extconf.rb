# frozen_string_literal: true

require "mkmf"
require "rb_sys/mkmf"

create_rust_makefile("chacha20blake3/chacha20blake3") do |r|
  r.profile = ENV.fetch("RB_SYS_CARGO_PROFILE", :release).to_sym
  # Workaround: the upstream chacha crate is missing #[target_feature(enable = "avx2")]
  # annotations, so the compiler can't auto-vectorize the XOR/keystream loops without this.
  # Remove when https://github.com/skerkour/chacha20-blake3/pull/12 is merged.
  r.extra_rustflags = ["-C", "target-cpu=native"]
end
