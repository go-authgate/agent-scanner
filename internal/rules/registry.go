package rules

// DefaultRules returns all built-in security rules.
func DefaultRules() []Rule {
	return []Rule{
		// Warnings
		&SuspiciousTriggerWords{},
		&TooManyEntities{},
		&HardcodedSecrets{},
		&InsecureCredentials{},
		&FinancialExecution{},
		&UntrustedContent{},
		&ExternalDependencies{},
		&SystemModification{},
		// Critical - local heuristic checks
		&CrossServerReference{},
		&MaliciousCodePatterns{},
		&SuspiciousURLs{},
		// Toxic flows
		&DataLeakFlow{},
		&DestructiveFlow{},
	}
}
