@{
    # Lint to Error + Warning. The tool is read-only, so the state-changing
    # ShouldProcess rule is not applicable.
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
