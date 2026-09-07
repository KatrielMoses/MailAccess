# Phase 0 — Pre-existing Test Failure Catalogue

_Captured 2026-09-05 · v0.14.4 · hermetic per-file run (network blocked, 45s/test, 90s/file)._

This is the **known baseline** the CI gate diffs against. A PR fails only on failures **not** listed here (`eval/harness/gate.py`). Buckets are a heuristic first pass; the `real` bucket is the human-review set.

## Totals

- Test files run: **197** (155 clean, 39 with failures)
- Passing tests (approx, summed per file): **2637**
- Failing/erroring nodeids catalogued: **279**
- Files that hung (killed, env/network): **3**

### By classification

| bucket | count | meaning |
|---|---|---|
| env-only | 233 | network/DNS/timeout or missing optional dep — not a code defect |
| pre-existing-known | 1 | known-broken imports/collection; stable pre-existing |
| real | 25 | assertion/type/value failures in tool logic — REVIEW |
| unclassified | 20 | no clear signal — review |

## Hung files (env-only)

These files did not terminate under a blocked network and were killed. Treated as env/network noise; a NEW hung file fails the gate.

- `tests/test_domain_harvest_orchestrator.py`
- `tests/test_email_search_dork_module.py`
- `tests/test_smtp_verifier.py`

## `real` + `unclassified` — human-review candidates

| bucket | nodeid | reason (truncated) |
|---|---|---|
| unclassified | `tests/test_cli_audit_0105_fixes.py::test_investigate_rejects_empty_local_part` | assert 2 == 1 |
| unclassified | `tests/test_cli_audit_0105_fixes.py::test_investigate_rejects_no_at_symbol` | assert 2 == 1 |
| unclassified | `tests/test_cli_audit_0105_fixes.py::test_investigate_rejects_no_domain_dot` | assert 2 == 1 |
| unclassified | `tests/test_cli_audit_0105_fixes.py::test_investigate_rejects_spaces_in_email` | assert 2 == 1 |
| real | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types0-kwargs0-1-0.95-HIGH]` | AssertionError: assert 'CONFIRMED' == 'HIGH' |
| real | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types10-kwargs10-1-1.5-HIGH]` | AssertionError: assert 'CONFIRMED' == 'HIGH' |
| real | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types2-kwargs2-1-0.75-MEDIUM]` | AssertionError: assert 'LIKELY' == 'MEDIUM' |
| unclassified | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types3-kwargs3-1-0.72-MEDIUM]` | assert 0.6 == 0.72 Â± 7.2e-07 |
| real | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types4-kwargs4-1-1.5-HIGH]` | AssertionError: assert 'CONFIRMED' == 'HIGH' |
| real | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types6-kwargs6-1-0.975-HIGH]` | AssertionError: assert 'CONFIRMED' == 'HIGH' |
| unclassified | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types7-kwargs7-1-1.305-HIGH]` | assert 1.0799999999999998 == 1.305 Â± 1.3e-06 |
| real | `tests/test_confidence_model_phase2.py::test_scoring_examples_all_correct[source_types9-kwargs9-1-0.75-MEDIUM]` | AssertionError: assert 'LIKELY' == 'MEDIUM' |
| real | `tests/test_dom_extraction_fix.py::test_heading_fallback_skips_non_person_headings` | AssertionError: assert 'Frequently Asked Questions' not in ['John Smith', 'Frequently Asked Question |
| unclassified | `tests/test_domain_discovery.py` |  |
| real | `tests/test_domain_harvester.py::test_all_sources_empty_returns_success` | KeyError: 'subdomains_found' |
| real | `tests/test_domain_harvester.py::test_module_metadata_keys_present` | AssertionError: assert 'subdomains_found' in {'domain': 'corp.com', 'sources_probed': ['bufferoverun |
| real | `tests/test_domain_harvester.py::test_sources_return_subdomains_creates_findings` | KeyError: 'subdomains_found' |
| real | `tests/test_email_confidence.py::test_permutation_unverified_weight_is_zero` | KeyError: 'permutation_unverified' |
| unclassified | `tests/test_email_search_dork_cse.py::test_cse_skipped_gracefully_when_no_key` | assert None is False |
| unclassified | `tests/test_email_search_dork_cse.py::test_cse_used_when_key_configured` | assert None is True |
| unclassified | `tests/test_employee_name_discovery_module.py::test_company_page_four_token_name_demoted` | assert 0.216 == 0.36 |
| unclassified | `tests/test_employee_name_discovery_module.py::test_company_page_three_token_name_demoted` | assert 0.216 == 0.36 |
| unclassified | `tests/test_employee_name_discovery_module.py::test_company_page_two_token_name_keeps_full_confidence` | assert 0.36 == 0.6 |
| real | `tests/test_employee_name_discovery_module.py::test_discover_names_for_tests_pure_helper` | AssertionError: assert 0.57 >= 0.85 |
| real | `tests/test_employee_name_discovery_module.py::test_multi_source_names_get_confidence_boost` | AssertionError: Alice Pham |
| real | `tests/test_harvest_output_phase1.py::test_suggested_next_steps_mentions_new_flags` | AssertionError: Phase 1 regression: --verify-smtp hint should appear when unverified patterns exist: |
| real | `tests/test_harvest_runtime_controls.py::test_google_timeout_path_export_has_honest_provider_statuses` | AssertionError: assert 'checked' not in {'candidates_routed': 3, 'candidates': 3, 'provider': 'googl |
| real | `tests/test_harvest_runtime_controls.py::test_provider_dispatch_candidates_routed_counts_unique_candidates` | AssertionError: assert 'checked' not in {'candidates_routed': 2, 'candidates': 2, 'provider': 'm365' |
| unclassified | `tests/test_hunter_client.py::test_empty_email_dropped_from_results` | assert 0 == 1 |
| real | `tests/test_hunter_client.py::test_high_confidence_hunter_result_mapped_correctly` | AssertionError: assert 0 == 2 |
| real | `tests/test_ml_name_classifier_cli.py::test_enable_ml_is_on_only_for_the_harvest_and_shows_off_hint` | AttributeError: 'types.SimpleNamespace' object has no attribute 'metadata' |
| real | `tests/test_ml_name_classifier_cli.py::test_ml_off_summary_hints_when_names_were_found` | AttributeError: 'types.SimpleNamespace' object has no attribute 'metadata' |
| real | `tests/test_name_quality_phase4.py::test_name_discovery_applies_penalty_to_result` | AssertionError: assert 0.252 == 0.42 |
| real | `tests/test_name_quality_phase4.py::test_name_discovery_clean_name_full_confidence` | AssertionError: assert 0.42 == 0.7 |
| unclassified | `tests/test_pattern_and_verify.py::test_metadata_reports_counts` | assert True is False |
| unclassified | `tests/test_pattern_and_verify.py::test_runs_when_module_enabled` | assert True is False |
| real | `tests/test_pattern_and_verify.py::test_smtp_verification_default_is_off` | AssertionError: assert True is False |
| real | `tests/test_pattern_generation_phase3.py::test_probe_budget_downgrade_high_to_medium` | AssertionError: assert 6 == 3 |
| real | `tests/test_phase3_p1_p7_features.py::TestHunterCircuitBreaker::test_circuit_breaker_durable_across_calls` | KeyError: 'calls' |
| unclassified | `tests/test_phases.py::test_dag_is_tuple_of_nine_phases` | assert 10 == 9 |
| unclassified | `tests/test_pivot_thresholds.py::test_low_confidence_name_still_triggers_pivot` | assert 0 == 1 |
| unclassified | `tests/test_pivot_thresholds.py::test_name_with_title_gets_all_11_templates` | IndexError: list index out of range |
| unclassified | `tests/test_pivot_thresholds.py::test_name_without_title_gets_3_templates` | IndexError: list index out of range |
| real | `tests/test_pivot_thresholds.py::test_pattern_candidates_shown_when_no_emails` | AssertionError: assert 'PATTERN CANDIDATES (unverified)' in 'â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ |
| unclassified | `tests/test_wayback_domain_harvest.py::test_429_respected_with_retry_after` | assert 1 == 2 |

<details><summary>Full env-only + pre-existing list</summary>

| bucket | nodeid |
|---|---|
| env-only | `tests/test_auto_export.py::test_cached_result_still_writes_json` |
| env-only | `tests/test_auto_export.py::test_explicit_export_writes_both_paths` |
| env-only | `tests/test_auto_export.py::test_files_older_than_30_days_deleted` |
| env-only | `tests/test_auto_export.py::test_json_written_automatically_without_flag` |
| env-only | `tests/test_auto_export.py::test_list_results_for_domain_orders_newest_first` |
| env-only | `tests/test_auto_export.py::test_no_export_flag_from_cli_skips_default` |
| env-only | `tests/test_auto_export.py::test_no_export_flag_skips_all_files` |
| env-only | `tests/test_auto_export.py::test_no_export_overrides_explicit_export_path` |
| env-only | `tests/test_auto_export.py::test_old_files_cleaned_up_beyond_50` |
| env-only | `tests/test_auto_export.py::test_path_printed_at_end_of_harvest` |
| env-only | `tests/test_auto_export.py::test_prune_stale_results_helper` |
| env-only | `tests/test_auto_export.py::test_results_dir_created_with_0700_when_possible` |
| env-only | `tests/test_auto_export.py::test_results_dir_creates_with_0700_when_possible` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_as_jsonable_returns_dicts` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_by_domain_case_insensitive` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_cache_corrupt_json_refetches` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_cache_expired_refetches` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_cache_round_trip` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_get_top_filters_empty_domains` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_load_caches_in_memory` |
| env-only | `tests/test_breach_corpus.py::test_breach_corpus_load_sorts_by_severity_desc` |
| env-only | `tests/test_breach_corpus.py::test_freedom_hosting_onion_is_excluded_from_probe_targets` |
| env-only | `tests/test_breach_normalizer.py::test_alias_empty_catalog_logs_warning` |
| env-only | `tests/test_breach_normalizer.py::test_alias_missing_logs_warning` |
| env-only | `tests/test_cc_index_client.py::test_persisted_collection_cache_is_loaded` |
| env-only | `tests/test_cli_audit_0105_fixes.py::test_export_absolute_path_used_as_is` |
| env-only | `tests/test_cli_audit_0105_fixes.py::test_export_creates_parent_directory_if_missing` |
| env-only | `tests/test_cli_audit_0105_fixes.py::test_export_resolves_relative_to_cwd` |
| env-only | `tests/test_cli_audit_0105_fixes.py::test_platform_audit_works_as_installed_command` |
| env-only | `tests/test_cli_audit_0105_fixes.py::test_platform_audit_works_with_no_db` |
| env-only | `tests/test_common_names.py::test_common_username_matches_exact_and_normalized_variants` |
| env-only | `tests/test_common_names.py::test_corpus_is_loaded_only_once` |
| env-only | `tests/test_common_names.py::test_empty_inputs_return_false[\t\n]` |
| env-only | `tests/test_common_names.py::test_empty_inputs_return_false[]` |
| env-only | `tests/test_common_names.py::test_loads_corpus_and_matches_exact_names` |
| env-only | `tests/test_common_names.py::test_maigret_finding_downgrades_common_username` |
| env-only | `tests/test_common_names.py::test_malformed_corpus_fails_silently` |
| env-only | `tests/test_common_names.py::test_missing_corpus_fails_silently` |
| env-only | `tests/test_config.py::test_cors_origins_parsing[CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]\n-expected0]` |
| env-only | `tests/test_config.py::test_cors_origins_parsing[CORS_ORIGINS=\n-expected3]` |
| env-only | `tests/test_config.py::test_cors_origins_parsing[CORS_ORIGINS=http://localhost:3000,http://localhost:5173\n-expected2]` |
| env-only | `tests/test_config.py::test_cors_origins_parsing[CORS_ORIGINS=http://localhost:3000\n-expected1]` |
| env-only | `tests/test_config.py::test_mapping_fields_never_crash_and_fall_back_to_empty_dict[MODULE_TIMEOUT_OVERRIDES=\n-module_timeout_overrides]` |
| env-only | `tests/test_config.py::test_mapping_fields_never_crash_and_fall_back_to_empty_dict[MODULE_TIMEOUT_OVERRIDES=not-json\n-module_timeout_overrides]` |
| env-only | `tests/test_config.py::test_mapping_fields_never_crash_and_fall_back_to_empty_dict[RATE_LIMIT_DELAYS=not-json\n-rate_limit_delays]` |
| env-only | `tests/test_config.py::test_mapping_fields_never_crash_and_fall_back_to_empty_dict[RATE_LIMIT_OVERRIDES={}\n-rate_limit_overrides]` |
| env-only | `tests/test_demotion_log.py::test_count_recent_by_action` |
| env-only | `tests/test_demotion_log.py::test_demotion_log_path_is_under_home` |
| env-only | `tests/test_demotion_log.py::test_env_override_skips_demotion` |
| env-only | `tests/test_demotion_log.py::test_log_demotion_creates_jsonl` |
| env-only | `tests/test_demotion_log.py::test_log_event_appends` |
| env-only | `tests/test_demotion_log.py::test_log_event_creates_parent_dirs` |
| env-only | `tests/test_demotion_log.py::test_log_event_rejects_unknown_action` |
| env-only | `tests/test_demotion_log.py::test_log_event_uses_default_reversible_via` |
| env-only | `tests/test_demotion_log.py::test_log_upgrade_event` |
| env-only | `tests/test_demotion_log.py::test_read_recent_events_filters_by_since` |
| env-only | `tests/test_demotion_log.py::test_read_recent_events_handles_missing_file` |
| env-only | `tests/test_demotion_log.py::test_read_recent_events_returns_all_when_no_since` |
| env-only | `tests/test_demotion_log.py::test_read_recent_events_skips_malformed_lines` |
| env-only | `tests/test_disposable_domains.py::test_corpus_is_loaded_only_once` |
| env-only | `tests/test_disposable_domains.py::test_disposable_domain_matches_corpus_case_insensitively` |
| env-only | `tests/test_disposable_domains.py::test_disposable_email[-False]` |
| env-only | `tests/test_disposable_domains.py::test_disposable_email[user@gmail.com-False]` |
| env-only | `tests/test_disposable_domains.py::test_disposable_email[user@mailinator.com-True]` |
| env-only | `tests/test_disposable_domains.py::test_extract_domain[@example.com-]` |
| env-only | `tests/test_disposable_domains.py::test_extract_domain[User@EXAMPLE.COM-example.com]` |
| env-only | `tests/test_disposable_domains.py::test_extract_domain[not-an-email-]` |
| env-only | `tests/test_disposable_domains.py::test_extract_domain[user@-]` |
| env-only | `tests/test_disposable_domains.py::test_extract_domain[user@@example.com-]` |
| env-only | `tests/test_disposable_domains.py::test_extract_domain[user@example.com-example.com]` |
| env-only | `tests/test_disposable_domains.py::test_maigret_finding_downgrades_disposable_email` |
| env-only | `tests/test_disposable_domains.py::test_maigret_finding_preserves_both_fp_warnings` |
| env-only | `tests/test_disposable_domains.py::test_malformed_corpus_fails_open` |
| env-only | `tests/test_disposable_domains.py::test_missing_corpus_fails_open` |
| env-only | `tests/test_export_termination.py::test_budget_timeout_export_reflects_partial_state` |
| env-only | `tests/test_export_termination.py::test_clean_completion_export_reflects_final_result` |
| env-only | `tests/test_export_termination.py::test_cli_export_survives_harvest_exception` |
| env-only | `tests/test_export_termination.py::test_cli_export_survives_soft_kill` |
| env-only | `tests/test_export_termination.py::test_google_export_telemetry_split` |
| env-only | `tests/test_export_termination.py::test_soft_kill_export_reflects_in_memory_state` |
| env-only | `tests/test_export_termination.py::test_stage_exception_after_verification_still_exports` |
| env-only | `tests/test_harvest_cache.py::test_atomic_write_no_partial_reads` |
| env-only | `tests/test_harvest_cache.py::test_cache_expired_returns_none` |
| env-only | `tests/test_harvest_cache.py::test_cache_hit_returns_result` |
| env-only | `tests/test_harvest_cache.py::test_cache_miss_returns_none` |
| env-only | `tests/test_harvest_cache.py::test_cache_version_mismatch_returns_none` |
| env-only | `tests/test_harvest_cache.py::test_cache_written_after_harvest` |
| env-only | `tests/test_harvest_cache.py::test_cached_result_shows_cache_banner` |
| env-only | `tests/test_harvest_cache.py::test_clear_all_cache_preserves_non_harvest_cache_files` |
| env-only | `tests/test_harvest_cache.py::test_clear_all_cache_removes_all_files` |
| env-only | `tests/test_harvest_cache.py::test_clear_cache_removes_domain_file` |
| env-only | `tests/test_harvest_cache.py::test_force_flag_bypasses_cache` |
| env-only | `tests/test_harvest_cache.py::test_list_domains_ignores_non_harvest_cache_files` |
| env-only | `tests/test_harvest_cli_command.py::test_export_writes_to_current_working_directory` |
| env-only | `tests/test_harvest_cli_command.py::test_export_writes_to_explicit_path` |
| env-only | `tests/test_harvest_cli_command.py::test_resolve_export_path_bare_filename_routes_to_cwd` |
| env-only | `tests/test_harvest_cli_command.py::test_resolve_export_path_keeps_explicit_path` |
| env-only | `tests/test_harvest_cli_command.py::test_s11_csv_export_extension_writes_csv` |
| env-only | `tests/test_harvest_cli_command.py::test_s11_json_export_extension_writes_json` |
| env-only | `tests/test_harvest_cli_command.py::test_s11_ndjson_export_extension_writes_ndjson` |
| env-only | `tests/test_harvest_cli_command.py::test_s11_unknown_extension_yields_clear_error` |
| env-only | `tests/test_harvest_cli_command.py::test_s12_json_export_has_schema_version_top_level` |
| env-only | `tests/test_harvest_runtime_controls.py::test_termination_handler_fires_once_for_every_exit_mode[clean]` |
| env-only | `tests/test_harvest_runtime_controls.py::test_termination_handler_fires_once_for_every_exit_mode[exception]` |
| env-only | `tests/test_harvest_runtime_controls.py::test_termination_handler_fires_once_for_every_exit_mode[soft_kill]` |
| env-only | `tests/test_harvest_runtime_controls.py::test_termination_handler_fires_once_for_every_exit_mode[timeout]` |
| env-only | `tests/test_hunter_io.py::test_domain_search_401_logs_and_stops` |
| env-only | `tests/test_hunter_io.py::test_domain_search_maps_hunter_70_to_high` |
| env-only | `tests/test_hunter_io.py::test_domain_search_maps_hunter_90_to_verified` |
| env-only | `tests/test_hunter_io.py::test_domain_search_maps_hunter_below_70_to_low` |
| env-only | `tests/test_hunter_io.py::test_domain_search_pattern_emitted_to_signal_pool` |
| env-only | `tests/test_hunter_io.py::test_domain_search_pattern_mapping_first` |
| env-only | `tests/test_hunter_io.py::test_domain_search_pattern_mapping_first_last` |
| env-only | `tests/test_hunter_io.py::test_domain_search_returns_emails_with_confidence` |
| env-only | `tests/test_hunter_io.py::test_domain_search_skipped_without_api_key` |
| env-only | `tests/test_hunter_io.py::test_email_verify_deliverable_high_score` |
| env-only | `tests/test_hunter_io.py::test_email_verify_deliverable_low_score` |
| env-only | `tests/test_hunter_io.py::test_email_verify_risky_returns_low_confidence` |
| env-only | `tests/test_hunter_io.py::test_email_verify_skipped_without_api_key` |
| env-only | `tests/test_hunter_io.py::test_email_verify_undeliverable_marks_not_found` |
| env-only | `tests/test_hunter_io.py::test_email_verify_unknown_returns_inconclusive` |
| env-only | `tests/test_hunter_io.py::test_hunter_source_weights_registered` |
| env-only | `tests/test_hunter_io.py::test_rate_limit_429_returns_empty` |
| env-only | `tests/test_hunter_io.py::test_usage_counter_increments_on_search` |
| env-only | `tests/test_hunter_io.py::test_usage_counter_resets_on_month_boundary` |
| env-only | `tests/test_hunter_io.py::test_usage_skip_at_25_searches` |
| env-only | `tests/test_hunter_io.py::test_usage_warning_at_23_searches` |
| env-only | `tests/test_live_log.py::test_alog_event_uses_to_thread` |
| env-only | `tests/test_live_log.py::test_log_contains_cache_event_on_cache_hit` |
| env-only | `tests/test_live_log.py::test_log_contains_found_events_per_email` |
| env-only | `tests/test_live_log.py::test_log_contains_module_started_and_completed` |
| env-only | `tests/test_live_log.py::test_log_contains_saved_event` |
| env-only | `tests/test_live_log.py::test_log_contains_smtp_probe_results` |
| env-only | `tests/test_live_log.py::test_log_contains_start_end_events` |
| env-only | `tests/test_live_log.py::test_log_file_written_alongside_json` |
| env-only | `tests/test_live_log.py::test_log_write_does_not_block_harvest` |
| env-only | `tests/test_live_log.py::test_no_export_skips_log_file` |
| env-only | `tests/test_live_progress.py::test_latest_finds_shows_last_5_only` |
| env-only | `tests/test_live_progress.py::test_live_log_file_written_to_results_dir` |
| env-only | `tests/test_live_progress.py::test_live_ticker_updates_on_signal_pool_emit` |
| env-only | `tests/test_live_progress.py::test_progress_callback_called_during_module_execution` |
| pre-existing-known | `tests/test_name_quality_phase4.py::test_name_discovery_module_imports_penalty` |
| env-only | `tests/test_new_sources.py::test_cidr_file_written_to_results_dir` |
| env-only | `tests/test_new_sources.py::test_cidrs_txt_written_with_real_prefixes` |
| env-only | `tests/test_nexfil_loader.py::test_loader_handles_malformed_json` |
| env-only | `tests/test_nexfil_loader.py::test_loader_handles_missing_file` |
| env-only | `tests/test_nexfil_loader.py::test_loader_logs_skipped_count` |
| env-only | `tests/test_nexfil_loader.py::test_loader_skips_missing_error_type` |
| env-only | `tests/test_nexfil_loader.py::test_loader_skips_missing_url` |
| env-only | `tests/test_nexfil_loader.py::test_loader_skips_unsupported_error_type` |
| env-only | `tests/test_platform_audit_cli.py::test_audit_summary_includes_auto_demotion_counts` |
| env-only | `tests/test_platform_audit_cli.py::test_classify_demote` |
| env-only | `tests/test_platform_audit_cli.py::test_classify_keep` |
| env-only | `tests/test_platform_audit_cli.py::test_classify_priority_skip_beats_demote` |
| env-only | `tests/test_platform_audit_cli.py::test_classify_skip` |
| env-only | `tests/test_platform_audit_cli.py::test_classify_watch_borderline` |
| env-only | `tests/test_platform_audit_cli.py::test_classify_watch_low_data` |
| env-only | `tests/test_platform_audit_cli.py::test_export_bare_filename_routes_to_cwd` |
| env-only | `tests/test_platform_audit_cli.py::test_export_includes_auto_demotion_summary` |
| env-only | `tests/test_platform_audit_cli.py::test_export_with_empty_db_still_writes_report` |
| env-only | `tests/test_platform_audit_cli.py::test_export_writes_valid_json` |
| env-only | `tests/test_platform_audit_cli.py::test_min_probes_filters_out_low_data` |
| env-only | `tests/test_platform_audit_cli.py::test_min_probes_zero_handles_gracefully` |
| env-only | `tests/test_platform_audit_cli.py::test_no_data_message_when_db_empty` |
| env-only | `tests/test_platform_audit_cli.py::test_platform_audit_lists_all_four_statuses` |
| env-only | `tests/test_platform_audit_cli.py::test_platform_audit_runs_without_arguments` |
| env-only | `tests/test_platform_audit_cli.py::test_platform_audit_shows_version_when_db_empty` |
| env-only | `tests/test_platform_audit_cli.py::test_platform_audit_shows_version_when_db_populated` |
| env-only | `tests/test_platform_audit_cli.py::test_platform_audit_summary_line` |
| env-only | `tests/test_platform_audit_cli.py::test_recommend_skip_emits_override_instructions` |
| env-only | `tests/test_platform_audit_cli.py::test_recommend_skip_filters_to_skip_only` |
| env-only | `tests/test_platform_audit_cli.py::test_show_demotions_export_writes_event_payload` |
| env-only | `tests/test_platform_audit_cli.py::test_show_demotions_flag_renders_empty_when_no_events` |
| env-only | `tests/test_platform_audit_cli.py::test_show_demotions_flag_renders_only_demoted_platforms` |
| env-only | `tests/test_platform_audit_cli.py::test_sort_hit_rate_orders_lowest_first` |
| env-only | `tests/test_platform_audit_cli.py::test_sort_invalid_value_rejected` |
| env-only | `tests/test_platform_audit_cli.py::test_top_limits_display` |
| env-only | `tests/test_reset_prober.py::test_load_signal_corpus_falls_back_to_english[None]` |
| env-only | `tests/test_reset_prober.py::test_load_signal_corpus_from_file` |
| env-only | `tests/test_role_classifier.py::test_bug7_requested_role_prefixes[abuse]` |
| env-only | `tests/test_role_classifier.py::test_bug7_requested_role_prefixes[compliance]` |
| env-only | `tests/test_role_classifier.py::test_bug7_requested_role_prefixes[noc]` |
| env-only | `tests/test_role_classifier.py::test_bug7_requested_role_prefixes[operations]` |
| env-only | `tests/test_role_classifier.py::test_bug7_requested_role_prefixes[security]` |
| env-only | `tests/test_role_classifier.py::test_bug7_requested_role_prefixes[sirt]` |
| env-only | `tests/test_role_classifier.py::test_case_insensitive_matching` |
| env-only | `tests/test_role_classifier.py::test_corpus_size_matches_loaded_entries` |
| env-only | `tests/test_role_classifier.py::test_exact_match_postmaster` |
| env-only | `tests/test_role_classifier.py::test_exact_match_role_prefix` |
| env-only | `tests/test_role_classifier.py::test_handles_missing_at_sign` |
| env-only | `tests/test_role_classifier.py::test_handles_missing_corpus_gracefully` |
| env-only | `tests/test_role_classifier.py::test_handles_none_input` |
| env-only | `tests/test_role_classifier.py::test_is_role_email_predicate` |
| env-only | `tests/test_role_classifier.py::test_long_prefix_partial_still_works` |
| env-only | `tests/test_role_classifier.py::test_m5_exact_match_still_takes_precedence` |
| env-only | `tests/test_role_classifier.py::test_m5_prefix_at_start_with_continuation` |
| env-only | `tests/test_role_classifier.py::test_m5_prefix_with_separator_still_takes_precedence` |
| env-only | `tests/test_role_classifier.py::test_m5_segment_partial_still_works` |
| env-only | `tests/test_role_classifier.py::test_m5_supportx_classified_as_partial` |
| env-only | `tests/test_role_classifier.py::test_m5_xsupport_does_NOT_match` |
| env-only | `tests/test_role_classifier.py::test_partial_match_does_not_match_word_inside` |
| env-only | `tests/test_role_classifier.py::test_partial_match_lower_confidence` |
| env-only | `tests/test_role_classifier.py::test_personal_email_not_classified_as_role` |
| env-only | `tests/test_role_classifier.py::test_prefix_match_with_dash` |
| env-only | `tests/test_role_classifier.py::test_prefix_match_with_separator` |
| env-only | `tests/test_role_classifier.py::test_prefix_match_with_underscore` |
| env-only | `tests/test_role_classifier.py::test_real_corpus_loads_in_production` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_exact_still_classified_as_role[bd@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_exact_still_classified_as_role[dev@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_exact_still_classified_as_role[hr@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_exact_still_classified_as_role[it@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_exact_still_classified_as_role[pr@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_exact_still_classified_as_role[qa@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[bdennis@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[devlin@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[hirano@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[hristo@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[itsmith@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[priya@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[qadir@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_no_separator_not_role[secundo@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_with_separator_still_role[bd.team@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_with_separator_still_role[hr.admin@example.com]` |
| env-only | `tests/test_role_classifier.py::test_short_prefix_with_separator_still_role[it.support@example.com]` |
| env-only | `tests/test_toolchain_output.py::test_all_file_paths_printed_at_end` |
| env-only | `tests/test_toolchain_output.py::test_cidrs_txt_written` |
| env-only | `tests/test_toolchain_output.py::test_emails_txt_excludes_role_accounts` |
| env-only | `tests/test_toolchain_output.py::test_emails_txt_only_high_medium_personal` |
| env-only | `tests/test_toolchain_output.py::test_markdown_report_has_all_sections` |
| env-only | `tests/test_toolchain_output.py::test_no_extras_flag_skips_supplementary` |
| env-only | `tests/test_toolchain_output.py::test_nuclei_targets_adds_http_when_port_80_open` |
| env-only | `tests/test_toolchain_output.py::test_nuclei_targets_https_preferred` |
| env-only | `tests/test_toolchain_output.py::test_nuclei_targets_reads_production_infrastructure_shape` |
| env-only | `tests/test_toolchain_output.py::test_subdomains_txt_written_one_per_line` |

</details>
