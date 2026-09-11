# Makefile for verifying that the minimal feature combinations compile.
#
# Each target checks one feature combination. By default it runs
# `cargo check`, which is much faster than a full build and is sufficient
# to verify that a feature set compiles. Run a full `cargo build` instead
# with:   make CMD=build
#
# Usage:
#   make              verify every combination (default target)
#   make check-<name>  verify a single combination
#
# Combinations are the minimal feature sets needed for each capability:
#   sync, no TLS            -> (no features)
#   async                    -> async_tokio
#   sync + TLS (rustls)      -> tls_rustls
#   sync + TLS (openssl)     -> tls_openssl
#   async + TLS (rustls)     -> async_tokio + tls_rustls + tls_rustls_tokio
#   async + TLS (openssl)    -> async_tokio + tls_openssl + tls_openssl_tokio
#   CLI (examples)           -> clap
#
# The async TLS combinations need all three features together: the async
# runtime, the TLS stack, and the matching *_tokio TLS wrapper.

CARGO ?= cargo
CMD   ?= check

.PHONY: all \
	check-sync \
	check-async \
	check-sync-tls-rustls \
	check-sync-tls-openssl \
	check-async-tls-rustls \
	check-async-tls-openssl \
	check-clap

all: check-sync check-async check-sync-tls-rustls check-sync-tls-openssl \
	check-async-tls-rustls check-async-tls-openssl check-clap

check-sync:
	$(CARGO) $(CMD)

check-async:
	$(CARGO) $(CMD) --features async_tokio

check-sync-tls-rustls:
	$(CARGO) $(CMD) --features tls_rustls

check-sync-tls-openssl:
	$(CARGO) $(CMD) --features tls_openssl

check-async-tls-rustls:
	$(CARGO) $(CMD) --features async_tokio,tls_rustls,tls_rustls_tokio

check-async-tls-openssl:
	$(CARGO) $(CMD) --features async_tokio,tls_openssl,tls_openssl_tokio

check-clap:
	$(CARGO) $(CMD) --features clap
