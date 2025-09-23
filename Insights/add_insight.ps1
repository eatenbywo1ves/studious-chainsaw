# PowerShell Script to Add New Insights
# Usage: .\add_insight.ps1 -Title "Your Insight Title" -Category "Technical" -Description "Your description"

param(
    [Parameter(Mandatory=$true)]
    [string]$Title,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Technical", "Problem-Solving", "Data-Analysis", "Tool-Workflow", "Documentation")]
    [string]$Category,

    [Parameter(Mandatory=$true)]
    [string]$Description,

    [string[]]$KeyPoints = @(),

    [string]$Impact = "",

    [string[]]$Tags = @()
)

$insightsFile = "C:\Users\Corbin\Insights\KEY_INSIGHTS.md"
$date = Get-Date -Format "yyyy-MM-dd"

# Read current file to get insight count
$content = Get-Content $insightsFile -Raw
$insightCount = ([regex]::Matches($content, "#### Insight #(\d+)")).Count + 1

# Map categories to emojis
$categoryMap = @{
    "Technical" = "🧠 Technical Insights"
    "Problem-Solving" = "💡 Problem-Solving Insights"
    "Data-Analysis" = "📊 Data & Analysis Insights"
    "Tool-Workflow" = "🔧 Tool & Workflow Insights"
    "Documentation" = "📝 Documentation & Communication"
}

# Build key points string
$keyPointsStr = ""
if ($KeyPoints.Count -gt 0) {
    $keyPointsStr = ($KeyPoints | ForEach-Object { "  - $_" }) -join "`n"
} else {
    $keyPointsStr = "  - [Add key point]"
}

# Build tags string
$tagsStr = ""
if ($Tags.Count -gt 0) {
    $tagsStr = "- **Tags**: " + ($Tags | ForEach-Object { "#$_" }) -join " "
}

# Create new insight entry
$newInsight = @"

### Date: $date

#### Insight #${insightCount}: $Title
- **Category**: $($categoryMap[$Category])
- **Description**: $Description
- **Key Points**:
$keyPointsStr
- **Impact**: $Impact
$tagsStr
"@

# Find insertion point (before the Quick Add Template)
$insertMarker = "## Quick Add Template"
$insertIndex = $content.IndexOf($insertMarker)

if ($insertIndex -gt 0) {
    # Insert the new insight
    $newContent = $content.Insert($insertIndex - 5, $newInsight + "`n`n---`n")

    # Update statistics
    $newContent = $newContent -replace "Total Insights: \d+", "Total Insights: $insightCount"
    $newContent = $newContent -replace "Last Updated: \d{4}-\d{2}-\d{2}", "Last Updated: $date"

    # Update tag index if tags provided
    if ($Tags.Count -gt 0) {
        $indexMarker = "## Index by Tags"
        $indexIndex = $newContent.IndexOf($indexMarker)
        if ($indexIndex -gt 0) {
            $endOfIndex = $newContent.Length
            foreach ($tag in $Tags) {
                $tagLine = "- #${tag}: Insight #$insightCount"
                $existingTag = $newContent -match "- #${tag}:"
                if ($existingTag) {
                    # Append to existing tag line
                    $newContent = $newContent -replace "(- #${tag}:.*)", "`$1, Insight #$insightCount"
                } else {
                    # Add new tag line before end of document
                    $newContent = $newContent + "`n$tagLine"
                }
            }
        }
    }

    # Write updated content
    Set-Content -Path $insightsFile -Value $newContent

    Write-Host "✅ Insight #$insightCount added successfully!" -ForegroundColor Green
    Write-Host "📁 Location: $insightsFile" -ForegroundColor Cyan
} else {
    Write-Host "❌ Error: Could not find insertion point in insights file" -ForegroundColor Red
}