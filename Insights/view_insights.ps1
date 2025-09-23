# PowerShell Script to View and Search Insights
# Usage: .\view_insights.ps1 [-Search "keyword"] [-Category "Technical"] [-Tag "tag"]

param(
    [string]$Search = "",
    [string]$Category = "",
    [string]$Tag = "",
    [switch]$Stats,
    [switch]$Recent,
    [int]$Last = 5
)

$insightsFile = "C:\Users\Corbin\Insights\KEY_INSIGHTS.md"

if (-not (Test-Path $insightsFile)) {
    Write-Host "Insights file not found at: $insightsFile" -ForegroundColor Red
    exit
}

$content = Get-Content $insightsFile -Raw

if ($Stats) {
    Write-Host "`nINSIGHTS STATISTICS" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor DarkGray

    # Extract stats
    $totalMatch = $content | Select-String -Pattern "Total Insights: (\d+)"
    if ($totalMatch) {
        Write-Host "Total Insights: $($totalMatch.Matches[0].Groups[1].Value)" -ForegroundColor Green
    }

    $updateMatch = $content | Select-String -Pattern "Last Updated: (.*)"
    if ($updateMatch) {
        Write-Host "Last Updated: $($updateMatch.Matches[0].Groups[1].Value)" -ForegroundColor Yellow
    }

    # Count by category
    $categories = @{
        "Technical" = ($content | Select-String -Pattern "\*\*Category\*\*:.*Technical" -AllMatches).Matches.Count
        "Problem-Solving" = ($content | Select-String -Pattern "\*\*Category\*\*:.*Problem-Solving" -AllMatches).Matches.Count
        "Data and Analysis" = ($content | Select-String -Pattern "\*\*Category\*\*:.*Data.*Analysis" -AllMatches).Matches.Count
        "Tool and Workflow" = ($content | Select-String -Pattern "\*\*Category\*\*:.*Tool.*Workflow" -AllMatches).Matches.Count
        "Documentation" = ($content | Select-String -Pattern "\*\*Category\*\*:.*Documentation" -AllMatches).Matches.Count
    }

    Write-Host "`nBy Category:" -ForegroundColor Cyan
    foreach ($cat in $categories.GetEnumerator() | Sort-Object Value -Descending) {
        if ($cat.Value -gt 0) {
            Write-Host "  $($cat.Key): $($cat.Value)" -ForegroundColor White
        }
    }
    exit
}

if ($Recent) {
    Write-Host "`nRECENT INSIGHTS (Last $Last)" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor DarkGray

    # Extract all insights
    $insightMatches = $content | Select-String -Pattern "#### Insight #(\d+): (.*)" -AllMatches
    $insights = $insightMatches.Matches
    $startIndex = [Math]::Max(0, $insights.Count - $Last)

    for ($i = $insights.Count - 1; $i -ge $startIndex; $i--) {
        $match = $insights[$i]
        Write-Host "`nInsight #$($match.Groups[1].Value): " -NoNewline -ForegroundColor Yellow
        Write-Host $match.Groups[2].Value -ForegroundColor White

        # Find and display the description
        $insightNum = $match.Groups[1].Value
        $descPattern = "Insight #$insightNum.*?Description\*\*: (.*)"
        $descMatch = $content | Select-String -Pattern $descPattern
        if ($descMatch) {
            Write-Host "  $($descMatch.Matches[0].Groups[1].Value)" -ForegroundColor Gray
        }
    }
    exit
}

# Search functionality
if ($Search -ne "" -or $Category -ne "" -or $Tag -ne "") {
    Write-Host "`nSEARCH RESULTS" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor DarkGray

    # Split content into individual insights
    $insightSections = $content -split "#### Insight #"
    $found = 0

    foreach ($section in $insightSections) {
        if ($section -match "^\d+:") {
            $show = $true

            # Filter by search term
            if ($Search -ne "" -and $section -notlike "*$Search*") {
                $show = $false
            }

            # Filter by category
            if ($Category -ne "" -and $section -notlike "*$Category*") {
                $show = $false
            }

            # Filter by tag
            if ($Tag -ne "" -and $section -notlike "*#$Tag*") {
                $show = $false
            }

            if ($show) {
                $found++
                # Extract and display insight details
                $lines = $section -split "`n"
                $title = $lines[0]
                Write-Host "`nInsight: $title" -ForegroundColor Yellow

                foreach ($line in $lines) {
                    if ($line -like "*Description*:*") {
                        $desc = $line -replace ".*Description\*\*: ", ""
                        Write-Host "  Description: $desc" -ForegroundColor Gray
                    }
                    if ($line -like "*Category*:*") {
                        $cat = $line -replace ".*Category\*\*: ", ""
                        Write-Host "  Category: $cat" -ForegroundColor Cyan
                    }
                    if ($line -like "*Tags*:*") {
                        $tags = $line -replace ".*Tags\*\*: ", ""
                        Write-Host "  Tags: $tags" -ForegroundColor Magenta
                    }
                }
            }
        }
    }

    Write-Host "`nFound $found matching insight(s)" -ForegroundColor Green
} else {
    # Show full file
    Write-Host $content
}

Write-Host "`nTips:" -ForegroundColor Yellow
Write-Host "  - Use -Stats to see statistics" -ForegroundColor Gray
Write-Host "  - Use -Recent to see recent insights" -ForegroundColor Gray
Write-Host "  - Use -Search 'keyword' to search" -ForegroundColor Gray
Write-Host "  - Use -Category 'Technical' to filter by category" -ForegroundColor Gray
Write-Host "  - Use -Tag 'tagname' to filter by tag" -ForegroundColor Gray