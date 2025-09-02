#region ExpandImportsInline
function ExpandImportsInline {
    <#
    .SYNOPSIS
        Expands dot-sourced imports by replacing them with actual file content.

    .DESCRIPTION
        This function replaces dot-sourced imports (. ./orc_*.ps1) with actual file content.
        It processes imports up to 3 times to handle nested dependencies.
        This creates a self-contained script with all dependencies embedded inline.

    .PARAMETER ScriptContent
        The script content containing imports to process

    .OUTPUTS
        String containing the processed script content with imports replaced
    #>

    param (
        [Parameter(Mandatory=$true)]
        [string]$ScriptContent
    )

    try {
        DebugMessage "Expanding imports inline..."

        $processedContent = $ScriptContent

        # Process imports up to 3 times to handle nested dependencies
        for ($iteration = 1; $iteration -le 3; $iteration++) {
            DebugMessage "Expanding imports - iteration $iteration"

            # Find all orc_* files and replace the dot-sourcing lines with their content
            $orcFiles = Get-ChildItem -Path $PSScriptRoot -Filter "orc_*.ps1"
            $importsProcessed = 0

            foreach ($orcFile in $orcFiles) {
                $importPattern = ". ./$($orcFile.Name)"

                if ($processedContent.Contains($importPattern)) {
                    try {
                        $orcContent = Get-Content -Path $orcFile.FullName -Raw
                        $replacementContent = "#region $($orcFile.Name)`n$orcContent`n#endregion $($orcFile.Name)`n"

                        $processedContent = $processedContent.Replace($importPattern, $replacementContent)
                        $importsProcessed++

                        DebugMessage "Replaced import for $($orcFile.Name)"
                    }
                    catch {
                        WarningMessage "Failed to process import for $($orcFile.Name): $_"
                    }
                }
            }

            DebugMessage "Iteration $iteration completed. Processed $importsProcessed imports."

            # If no imports were processed in this iteration, we can break early
            if ($importsProcessed -eq 0) {
                DebugMessage "No more imports to process. Breaking early."
                break
            }
        }

        DebugMessage "Import expansion completed successfully."
        return $processedContent
    }
    catch {
        ErrorMessage "Failed to expand imports inline: $_"
        return $ScriptContent
    }
}
#endregion ExpandImportsInline
