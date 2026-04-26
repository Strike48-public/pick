//! Integration tests for aggression level system
//!
//! These tests verify the complete spawn policy behavior across all aggression
//! levels, including threshold evaluation, policy overrides, and specialist
//! spawning decisions.

use pentest_core::aggression::{AggressionLevel, OverridePolicy};
use pentest_core::specialist_spawner::{
    AttackSurface, SpawnDecision, SpecialistContext, SpecialistSpawner, SpecialistType,
};

/// Helper to create a basic context with configurable endpoint count
fn create_context(endpoint_count: usize) -> SpecialistContext {
    SpecialistContext {
        targets: vec!["https://example.com".to_string()],
        initial_findings: vec![],
        concerns: vec![],
        attack_surface: AttackSurface {
            endpoint_count,
            technologies: vec![],
            auth_mechanisms: vec![],
            entry_points: vec![],
        },
    }
}

/// Helper to create a context with suspicious findings
fn create_context_with_hints(endpoint_count: usize) -> SpecialistContext {
    SpecialistContext {
        targets: vec!["https://example.com".to_string()],
        initial_findings: vec!["Suspicious SQL error messages".to_string()],
        concerns: vec!["Possible injection point".to_string()],
        attack_surface: AttackSurface {
            endpoint_count,
            technologies: vec!["PHP".to_string(), "MySQL".to_string()],
            auth_mechanisms: vec!["Cookie-based".to_string()],
            entry_points: vec!["/login".to_string(), "/search".to_string()],
        },
    }
}

#[test]
fn test_conservative_skips_small_targets() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);

    // Conservative requires 50+ endpoints for web-app
    let small_context = create_context(20);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &small_context);
    assert_eq!(
        decision,
        SpawnDecision::Skip,
        "Conservative mode should skip targets with < 50 endpoints"
    );

    // Should spawn for 50+ endpoints
    let large_context = create_context(50);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &large_context);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Conservative mode should spawn for targets with 50+ endpoints"
    );
}

#[test]
fn test_conservative_ignores_hints() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);

    // Conservative does NOT spawn on hints alone (spawn_on_hints=false)
    let context_with_hints = create_context_with_hints(20);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &context_with_hints);
    assert_eq!(
        decision,
        SpawnDecision::Skip,
        "Conservative mode should not spawn on hints when below threshold"
    );
}

#[test]
fn test_balanced_spawns_on_moderate_targets() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);

    // Balanced requires 20+ endpoints for web-app
    let small_context = create_context(10);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &small_context);
    assert_eq!(
        decision,
        SpawnDecision::Skip,
        "Balanced mode should skip targets with < 20 endpoints"
    );

    // Should spawn for 20+ endpoints
    let moderate_context = create_context(20);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &moderate_context);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Balanced mode should spawn for targets with 20+ endpoints"
    );
}

#[test]
fn test_balanced_spawns_on_hints() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);

    // Balanced DOES spawn on hints (spawn_on_hints=true)
    let context_with_hints = create_context_with_hints(10);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &context_with_hints);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Balanced mode should spawn on hints even when below threshold"
    );
}

#[test]
fn test_aggressive_spawns_liberally() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);

    // Aggressive requires only 5+ endpoints for web-app
    let tiny_context = create_context(3);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &tiny_context);
    assert_eq!(
        decision,
        SpawnDecision::Skip,
        "Aggressive mode should skip targets with < 5 endpoints"
    );

    // Should spawn for 5+ endpoints
    let small_context = create_context(5);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &small_context);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Aggressive mode should spawn for targets with 5+ endpoints"
    );

    // Should definitely spawn with hints
    let context_with_hints = create_context_with_hints(3);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &context_with_hints);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Aggressive mode should spawn on hints regardless of threshold"
    );
}

#[test]
fn test_maximum_spawns_everything() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);

    // Maximum spawns for ANY target (threshold = 1)
    let minimal_context = create_context(1);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &minimal_context);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Maximum mode should spawn for any target (1+ endpoints)"
    );

    // Even with zero endpoints, should spawn on hints
    let hints_only = create_context_with_hints(0);
    let decision = spawner.should_spawn(SpecialistType::WebApp, &hints_only);
    assert_eq!(
        decision,
        SpawnDecision::Spawn,
        "Maximum mode should spawn on hints even with 0 endpoints"
    );
}

#[test]
fn test_api_specialist_thresholds() {
    // API thresholds are different from web-app thresholds

    // Conservative: 30+ for API (vs 50+ for web-app)
    let conservative = SpecialistSpawner::new(AggressionLevel::Conservative);
    let context_25 = create_context(25);
    let decision = conservative.should_spawn(SpecialistType::Api, &context_25);
    assert_eq!(decision, SpawnDecision::Skip);
    let context_30 = create_context(30);
    let decision = conservative.should_spawn(SpecialistType::Api, &context_30);
    assert_eq!(decision, SpawnDecision::Spawn);

    // Balanced: 15+ for API (vs 20+ for web-app)
    let balanced = SpecialistSpawner::new(AggressionLevel::Balanced);
    let context_10 = create_context(10);
    let decision = balanced.should_spawn(SpecialistType::Api, &context_10);
    assert_eq!(decision, SpawnDecision::Skip);
    let context_15 = create_context(15);
    let decision = balanced.should_spawn(SpecialistType::Api, &context_15);
    assert_eq!(decision, SpawnDecision::Spawn);

    // Aggressive: 5+ for API (same as web-app)
    let aggressive = SpecialistSpawner::new(AggressionLevel::Aggressive);
    let context_5 = create_context(5);
    let decision = aggressive.should_spawn(SpecialistType::Api, &context_5);
    assert_eq!(decision, SpawnDecision::Spawn);
}

#[test]
fn test_binary_and_ai_always_spawn() {
    // Binary and AI security specialists spawn for any target
    // (they are triggered by specific conditions, not endpoint counts)

    let conservative = SpecialistSpawner::new(AggressionLevel::Conservative);
    let minimal_context = create_context(1);

    let binary_decision = conservative.should_spawn(SpecialistType::Binary, &minimal_context);
    assert_eq!(
        binary_decision,
        SpawnDecision::Spawn,
        "Binary specialist should always spawn when needed"
    );

    let ai_decision = conservative.should_spawn(SpecialistType::AiSecurity, &minimal_context);
    assert_eq!(
        ai_decision,
        SpawnDecision::Spawn,
        "AI security specialist should always spawn when needed"
    );
}

#[test]
fn test_override_policy_conservative_upgrade_only() {
    let override_policy = AggressionLevel::Conservative.allows_overrides();
    assert_eq!(override_policy, OverridePolicy::UpgradeOnly);
    assert!(
        override_policy.can_upgrade(),
        "Conservative should allow upgrading (spawn MORE)"
    );
    assert!(
        !override_policy.can_downgrade(),
        "Conservative should not allow downgrading (spawn FEWER)"
    );
}

#[test]
fn test_override_policy_balanced_both() {
    let override_policy = AggressionLevel::Balanced.allows_overrides();
    assert_eq!(override_policy, OverridePolicy::Both);
    assert!(
        override_policy.can_upgrade(),
        "Balanced should allow upgrading"
    );
    assert!(
        override_policy.can_downgrade(),
        "Balanced should allow downgrading"
    );
}

#[test]
fn test_override_policy_aggressive_downgrade_only() {
    let override_policy = AggressionLevel::Aggressive.allows_overrides();
    assert_eq!(override_policy, OverridePolicy::DowngradeOnly);
    assert!(
        !override_policy.can_upgrade(),
        "Aggressive should not allow upgrading (already aggressive)"
    );
    assert!(
        override_policy.can_downgrade(),
        "Aggressive should allow downgrading (skip trivial targets)"
    );
}

#[test]
fn test_override_policy_maximum_none() {
    let override_policy = AggressionLevel::Maximum.allows_overrides();
    assert_eq!(override_policy, OverridePolicy::None);
    assert!(
        !override_policy.can_upgrade(),
        "Maximum should not allow any overrides"
    );
    assert!(
        !override_policy.can_downgrade(),
        "Maximum should not allow any overrides"
    );
}

#[test]
fn test_cost_multipliers_increase_with_aggression() {
    assert_eq!(AggressionLevel::Conservative.cost_multiplier(), 1.0);
    assert!(AggressionLevel::Balanced.cost_multiplier() > 1.0);
    assert!(
        AggressionLevel::Aggressive.cost_multiplier() > AggressionLevel::Balanced.cost_multiplier()
    );
    assert!(
        AggressionLevel::Maximum.cost_multiplier() > AggressionLevel::Aggressive.cost_multiplier()
    );
}

#[test]
fn test_policy_guidelines_format() {
    // Verify that policy guidelines are generated correctly for each level
    let conservative = AggressionLevel::Conservative.spawn_policy();
    let guidelines = conservative.to_guidelines(AggressionLevel::Conservative);
    assert!(
        guidelines.contains("Conservative Mode"),
        "Guidelines should include mode name"
    );
    assert!(
        guidelines.contains("50"),
        "Guidelines should include web-app threshold"
    );
    assert!(
        guidelines.contains("30"),
        "Guidelines should include api threshold"
    );

    let balanced = AggressionLevel::Balanced.spawn_policy();
    let guidelines = balanced.to_guidelines(AggressionLevel::Balanced);
    assert!(guidelines.contains("Balanced Mode"));
    assert!(guidelines.contains("20"));
    assert!(guidelines.contains("15"));

    let aggressive = AggressionLevel::Aggressive.spawn_policy();
    let guidelines = aggressive.to_guidelines(AggressionLevel::Aggressive);
    assert!(guidelines.contains("Aggressive Mode"));
    assert!(guidelines.contains("5"));

    let maximum = AggressionLevel::Maximum.spawn_policy();
    let guidelines = maximum.to_guidelines(AggressionLevel::Maximum);
    assert!(guidelines.contains("Maximum Mode"));
    assert!(guidelines.contains("Maximum coverage"));
}

#[test]
fn test_spawner_returns_correct_override_flag() {
    let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);

    // Conservative can upgrade - agent could override Skip to Spawn with justification
    assert!(spawner.can_override_to_spawn());
    assert!(!spawner.can_override_to_skip());

    let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
    // Balanced can do both
    assert!(spawner.can_override_to_spawn());
    assert!(spawner.can_override_to_skip());

    let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);
    // Aggressive can only downgrade
    assert!(!spawner.can_override_to_spawn());
    assert!(spawner.can_override_to_skip());

    let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);
    // Maximum cannot override at all
    assert!(!spawner.can_override_to_spawn());
    assert!(!spawner.can_override_to_skip());
}
