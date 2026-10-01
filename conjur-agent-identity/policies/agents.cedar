@id("agent_read_team_scope")
permit (
    principal is Agent,
    action == Action::"read",
    resource is Tool
)
when {
    principal.team == resource.team &&
    principal.tenant == resource.tenant &&
    principal.environment == resource.environment &&
    context.delegationValid &&
    context.records <= 10 &&
    context.tenant == resource.tenant &&
    context.environment == resource.environment
};

@id("deny_blocked_tool")
forbid (
    principal is Agent,
    action,
    resource is Tool
)
when {
    resource.blocked
};

@id("deny_production_resource")
forbid (
    principal is Agent,
    action,
    resource is Tool
)
when {
    resource.environment == "prod" || resource.environment == "production"
};

@id("deny_cross_scope")
forbid (
    principal is Agent,
    action,
    resource is Tool
)
when {
    principal.tenant != resource.tenant ||
    principal.environment != resource.environment ||
    context.tenant != resource.tenant ||
    context.environment != resource.environment
};
