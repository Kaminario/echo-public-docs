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
            
            $lines = $processedContent.Split([System.Environment]::NewLine)
            $newLines = [System.Collections.Generic.List[string]]::new()
            $importsProcessed = 0

            foreach ($line in $lines) {
                if ($line -match "^\s*\.\s+(\./orc_[\w-]+\.ps1)\s*$") {
                    $fileName = $matches[1]
                    $filePath = Join-Path $PSScriptRoot $fileName
                    
                    if (Test-Path $filePath) {
                        $orcContent = Get-Content -Path $filePath -Raw
                        $newLines.Add("#region $fileName`n$orcContent`n#endregion $fileName`n")
                        $importsProcessed++
                        DebugMessage "Expanded import for $fileName"
                    } else {
                        WarningMessage "Could not find import file: $fileName. Keeping original import line."
                        $newLines.Add($line)
                    }
                } else {
                    $newLines.Add($line)
                }
            }

            $processedContent = $newLines -join [System.Environment]::NewLine
            
            DebugMessage "Iteration $iteration completed. Processed $importsProcessed imports."

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
