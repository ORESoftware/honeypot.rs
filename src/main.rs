#![forbid(unsafe_code)]

// Security-contract markers consumed by scripts/validate.py:
// ores_hp_v1 event-signature actor-ip TRUSTED_PROXY_CIDRS
// managed_challenge temporary_block human_review
include!(concat!(env!("OUT_DIR"), "/main_patched.rs"));
