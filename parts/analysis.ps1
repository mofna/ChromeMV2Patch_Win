function ConvertTo-Pattern {
    param([Parameter(Mandatory = $true)][string]$Text)

    $tokens = @($Text.Trim() -split '\s+' | Where-Object { $_ })
    $result = New-Object 'int[]' $tokens.Count
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($tokens[$i] -eq '??') {
            $result[$i] = -1
        } else {
            $result[$i] = [Convert]::ToInt32($tokens[$i], 16)
        }
    }
    return ,$result
}

function ConvertTo-ConcreteBytes {
    param([Parameter(Mandatory = $true)][string]$Text)

    $pattern = ConvertTo-Pattern $Text
    if (@($pattern | Where-Object { $_ -lt 0 }).Count -gt 0) {
        throw "RAM patch bytes must not contain wildcards: $Text"
    }
    return ,([byte[]]$pattern)
}

function Test-BytesAt {
    param(
        [byte[]]$Bytes,
        [long]$Offset,
        [int[]]$Pattern
    )

    if ($Offset -lt 0 -or ($Offset + $Pattern.Length) -gt $Bytes.LongLength) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if ($Pattern[$i] -ge 0 -and $Bytes[$Offset + $i] -ne $Pattern[$i]) {
            return $false
        }
    }
    return $true
}

function Get-HexBytes {
    param([byte[]]$Bytes)
    return (($Bytes | ForEach-Object { $_.ToString('X2') }) -join ' ')
}

function Get-PeInfo {
    param([byte[]]$Bytes)

    if ($Bytes.Length -lt 0x100 -or $Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) {
        throw 'Target is not a valid PE file (missing MZ header).'
    }
    $peOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($peOffset -lt 0 -or ($peOffset + 24) -gt $Bytes.Length -or
        $Bytes[$peOffset] -ne 0x50 -or $Bytes[$peOffset + 1] -ne 0x45 -or
        $Bytes[$peOffset + 2] -ne 0 -or $Bytes[$peOffset + 3] -ne 0) {
        throw 'Target is not a valid PE file (missing PE header).'
    }

    $machine = [BitConverter]::ToUInt16($Bytes, $peOffset + 4)
    $sectionCount = [BitConverter]::ToUInt16($Bytes, $peOffset + 6)
    $optionalSize = [BitConverter]::ToUInt16($Bytes, $peOffset + 20)
    $sectionTable = $peOffset + 24 + $optionalSize
    $ranges = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $entry = $sectionTable + (40 * $i)
        if (($entry + 40) -gt $Bytes.Length) {
            throw 'PE section table is truncated.'
        }
        $virtualAddress = [BitConverter]::ToUInt32($Bytes, $entry + 12)
        $rawSize = [BitConverter]::ToUInt32($Bytes, $entry + 16)
        $rawOffset = [BitConverter]::ToUInt32($Bytes, $entry + 20)
        $characteristics = [BitConverter]::ToUInt32($Bytes, $entry + 36)
        if (($characteristics -band 0x20000000) -ne 0 -and $rawSize -gt 0 -and
            ([long]$rawOffset + $rawSize) -le $Bytes.LongLength) {
            $ranges += [pscustomobject]@{
                Start = [long]$rawOffset
                Length = [long]$rawSize
                VirtualAddress = [long]$virtualAddress
            }
        }
    }
    if ($ranges.Count -eq 0) {
        throw 'PE file has no executable sections.'
    }
    return [pscustomobject]@{ Machine = [int]$machine; ExecutableRanges = $ranges }
}

function ConvertTo-PeRva {
    param(
        $PeInfo,
        [long]$FileOffset,
        [int]$Length
    )

    $ranges = @($PeInfo.ExecutableRanges | Where-Object {
        $FileOffset -ge $_.Start -and
        ($FileOffset + $Length) -le ($_.Start + $_.Length)
    })
    if ($ranges.Count -ne 1) {
        throw "Patch offset 0x$($FileOffset.ToString('X')) is not in exactly one executable PE section."
    }
    return [long]$ranges[0].VirtualAddress + $FileOffset - $ranges[0].Start
}

function Read-StreamRange {
    param(
        [IO.FileStream]$Stream,
        [long]$Offset,
        [int]$Count
    )

    if ($Offset -lt 0 -or $Count -lt 0 -or ($Offset + $Count) -gt $Stream.Length) {
        return $null
    }
    $result = New-Object 'byte[]' $Count
    $Stream.Position = $Offset
    $read = 0
    while ($read -lt $Count) {
        $countRead = $Stream.Read($result, $read, $Count - $read)
        if ($countRead -le 0) { return $null }
        $read += $countRead
    }
    return ,$result
}

function Get-PeStreamInfo {
    param([IO.FileStream]$Stream)

    $dos = Read-StreamRange $Stream 0 64
    if (-not $dos -or $dos[0] -ne 0x4D -or $dos[1] -ne 0x5A) {
        throw 'Target is not a valid PE file (missing MZ header).'
    }
    $peOffset = [BitConverter]::ToInt32($dos, 0x3C)
    $coff = Read-StreamRange $Stream $peOffset 24
    if (-not $coff -or $coff[0] -ne 0x50 -or $coff[1] -ne 0x45 -or
        $coff[2] -ne 0 -or $coff[3] -ne 0) {
        throw 'Target is not a valid PE file (missing PE header).'
    }

    $machine = [BitConverter]::ToUInt16($coff, 4)
    $sectionCount = [BitConverter]::ToUInt16($coff, 6)
    $optionalSize = [BitConverter]::ToUInt16($coff, 20)
    if ($sectionCount -eq 0 -or $sectionCount -gt 96) {
        throw 'PE section count is invalid.'
    }
    $sectionBytes = Read-StreamRange $Stream `
        ([long]$peOffset + 24 + $optionalSize) (40 * $sectionCount)
    if (-not $sectionBytes) { throw 'PE section table is truncated.' }

    $ranges = @()
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $entry = 40 * $i
        $rawSize = [BitConverter]::ToUInt32($sectionBytes, $entry + 16)
        $rawOffset = [BitConverter]::ToUInt32($sectionBytes, $entry + 20)
        $characteristics = [BitConverter]::ToUInt32($sectionBytes, $entry + 36)
        if (($characteristics -band 0x20000000) -ne 0 -and $rawSize -gt 0 -and
            ([long]$rawOffset + $rawSize) -le $Stream.Length) {
            $ranges += [pscustomobject]@{ Start = [long]$rawOffset; Length = [long]$rawSize; VirtualAddress = [long][BitConverter]::ToUInt32($sectionBytes, $entry + 12) }
        }
    }
    if ($ranges.Count -eq 0) { throw 'PE file has no executable sections.' }
    $imageBase = [uint64]0
    if ($machine -eq 0x8664) {
        $optional = Read-StreamRange $Stream ($peOffset + 24) $optionalSize
        if ($null -eq $optional -or $optional.Length -lt 32 -or [BitConverter]::ToUInt16($optional, 0) -ne 0x20b) { throw 'Invalid x64 optional header.' }
        $imageBase = [BitConverter]::ToUInt64($optional, 24)
    }
    return [pscustomobject]@{ Machine = [int]$machine; ExecutableRanges = $ranges; ImageBase = $imageBase }
}

function Test-PatternCompatibility {
    param(
        [int[]]$Concrete,
        [int[]]$Pattern
    )

    if ($Concrete.Length -ne $Pattern.Length -or
        @($Concrete | Where-Object { $_ -lt 0 }).Count -gt 0) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if ($Pattern[$i] -ge 0 -and $Concrete[$i] -ne $Pattern[$i]) {
            return $false
        }
    }
    return $true
}

function Test-StreamPattern {
    param(
        [IO.FileStream]$Stream,
        [long]$Offset,
        [int[]]$Pattern
    )

    $bytes = Read-StreamRange $Stream $Offset $Pattern.Length
    return ($null -ne $bytes -and (Test-BytesAt $bytes 0 $Pattern))
}

function Test-StreamMaskedPattern {
    param(
        [IO.FileStream]$Stream,
        [long]$Offset,
        $Pattern
    )

    $bytes = Read-StreamRange $Stream $Offset $Pattern.Length
    return ($null -ne $bytes -and (Test-MaskedBytesAt $bytes 0 $Pattern))
}

function Test-ConcreteMaskedPattern {
    param(
        [int[]]$Concrete,
        $Pattern
    )

    if ($Concrete.Length -ne $Pattern.Length -or
        @($Concrete | Where-Object { $_ -lt 0 }).Count -gt 0) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if (($Concrete[$i] -band $Pattern.Masks[$i]) -ne $Pattern.Values[$i]) {
            return $false
        }
    }
    return $true
}

function Test-ExecutableRange {
    param(
        $PeInfo,
        [long]$Offset,
        [int]$Length
    )

    return @($PeInfo.ExecutableRanges | Where-Object {
        $Offset -ge $_.Start -and
        ($Offset + $Length) -le ($_.Start + $_.Length)
    }).Count -eq 1
}

function ConvertTo-MaskedPattern {
    param([Parameter(Mandatory = $true)][string]$Text)

    $tokens = @($Text.Trim() -split '\s+' | Where-Object { $_ })
    $values = New-Object 'byte[]' $tokens.Count
    $masks = New-Object 'byte[]' $tokens.Count
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        if ($tokens[$i] -eq '??') { continue }
        if ($tokens[$i] -notmatch '^([0-9A-Fa-f]{2})(?:/([0-9A-Fa-f]{2}))?$') {
            throw "Invalid masked-pattern token: $($tokens[$i])"
        }
        $mask = if ($Matches[2]) {
            [Convert]::ToByte($Matches[2], 16)
        } else { [byte]0xFF }
        $masks[$i] = $mask
        $values[$i] = [Convert]::ToByte($Matches[1], 16) -band $mask
    }
    return [pscustomobject]@{
        Values = $values
        Masks = $masks
        Length = $values.Length
    }
}

function Test-MaskedBytesAt {
    param(
        [byte[]]$Bytes,
        [long]$Offset,
        $Pattern
    )

    if ($Offset -lt 0 -or ($Offset + $Pattern.Length) -gt $Bytes.LongLength) {
        return $false
    }
    for ($i = 0; $i -lt $Pattern.Length; $i++) {
        if (($Bytes[$Offset + $i] -band $Pattern.Masks[$i]) -ne
            $Pattern.Values[$i]) {
            return $false
        }
    }
    return $true
}

function Get-VariantPatchPatterns {
    param($Rule, $Variant)

    $originalText = if ($Variant.ContainsKey('Original')) {
        $Variant.Original
    } else { $Rule.Original }
    $replacementText = if ($Variant.ContainsKey('Replacement')) {
        $Variant.Replacement
    } else { $Rule.Replacement }
    $original = ConvertTo-MaskedPattern $originalText
    $replacement = ConvertTo-MaskedPattern $replacementText
    if ($original.Length -ne $replacement.Length -or
        @($replacement.Masks | Where-Object { $_ -ne 0xFF }).Count -gt 0) {
        throw "Rule '$($Rule.Name)' must have an equal-length concrete replacement."
    }
    return [pscustomobject]@{
        Original = $original
        Replacement = $replacement
    }
}

function Get-MaskedRuleResult {
    param(
        [byte[]]$Bytes,
        $Rule,
        $PeInfo
    )

    $classified = @()
    $seen = @{}
    $variantIndex = 0
    foreach ($variant in @($Rule.Variants)) {
        $patch = Get-VariantPatchPatterns $Rule $variant
        $original = $patch.Original
        $replacement = $patch.Replacement
        $pattern = ConvertTo-MaskedPattern $variant.Pattern
        $patchOffset = [int]$variant.PatchOffset
        if (($patchOffset + $original.Length) -gt $pattern.Length) {
            throw "Rule '$($Rule.Name)' patch range is outside variant $variantIndex."
        }
        $contextValues = New-Object 'byte[]' $pattern.Length
        $contextMasks = New-Object 'byte[]' $pattern.Length
        [Array]::Copy($pattern.Values, $contextValues, $pattern.Length)
        [Array]::Copy($pattern.Masks, $contextMasks, $pattern.Length)
        for ($i = 0; $i -lt $original.Length; $i++) {
            $contextMasks[$patchOffset + $i] = 0
            $contextValues[$patchOffset + $i] = 0
        }

        foreach ($range in $PeInfo.ExecutableRanges) {
            foreach ($match in [BinaryPatternScanner]::FindMasked(
                $Bytes, $contextValues, $contextMasks,
                $range.Start, $range.Length)) {
                $valid = $true
                if ($variant.ContainsKey('RequiredPattern')) {
                    $required = ConvertTo-MaskedPattern $variant.RequiredPattern
                    $valid = Test-MaskedBytesAt $Bytes `
                        ($match + [long]$variant.RequiredPatternOffset) $required
                }
                if ($valid -and $variant.ContainsKey('EqualBytes')) {
                    foreach ($pair in @($variant.EqualBytes)) {
                        $offsets = @([string]$pair -split ':')
                        if ($offsets.Count -ne 2 -or
                            $Bytes[$match + [int]$offsets[0]] -ne
                            $Bytes[$match + [int]$offsets[1]]) {
                            $valid = $false
                            break
                        }
                    }
                }
                if (-not $valid) { continue }

                $patchAt = $match + $patchOffset
                $key = $patchAt.ToString('X')
                if ($seen.ContainsKey($key)) { continue }
                $state = 'Unknown'
                if (Test-MaskedBytesAt $Bytes $patchAt $original) {
                    $state = 'Original'
                } elseif (Test-MaskedBytesAt $Bytes $patchAt $replacement) {
                    $state = 'Patched'
                }
                $classified += [pscustomobject]@{
                    MatchOffset = $match
                    PatchOffset = $patchAt
                    State = $state
                    Variant = $variantIndex
                    OriginalPattern = $original.Values
                    ReplacementPattern = $replacement.Values
                }
                $seen[$key] = $true
            }
        }
        $variantIndex++
    }

    return [pscustomobject]@{
        Name = $Rule.Name
        Description = $Rule.Description
        MatchCount = $classified.Count
        Candidates = $classified
        Rule = $Rule
    }
}

function Get-RuleResult {
    param(
        [byte[]]$Bytes,
        $Rule,
        $PeInfo
    )

    if ($Rule.ContainsKey('Variants')) {
        return Get-MaskedRuleResult $Bytes $Rule $PeInfo
    }

    $pattern = ConvertTo-Pattern $Rule.Pattern
    $original = ConvertTo-Pattern $Rule.Original
    $replacement = ConvertTo-Pattern $Rule.Replacement
    if ($original.Length -ne $replacement.Length) {
        throw "Rule '$($Rule.Name)' changes the instruction length."
    }
    if (($Rule.PatchOffset + $original.Length) -gt $pattern.Length) {
        throw "Rule '$($Rule.Name)' patch range is outside its signature."
    }

    $context = New-Object 'int[]' $pattern.Length
    [Array]::Copy($pattern, $context, $pattern.Length)
    for ($i = 0; $i -lt $original.Length; $i++) {
        $context[$Rule.PatchOffset + $i] = -1
    }

    $matches = New-Object System.Collections.Generic.List[long]
    foreach ($range in $PeInfo.ExecutableRanges) {
        foreach ($match in [BinaryPatternScanner]::Find(
            $Bytes, $context, $range.Start, $range.Length)) {
            $matches.Add($match)
        }
    }

    $classified = @()
    foreach ($match in $matches) {
        if ($Rule.ContainsKey('RequiredPattern')) {
            $required = ConvertTo-Pattern $Rule.RequiredPattern
            if (-not (Test-BytesAt $Bytes `
                ($match + [long]$Rule.RequiredPatternOffset) $required)) {
                continue
            }
        }
        $patchAt = $match + [long]$Rule.PatchOffset
        $state = 'Unknown'
        if (Test-BytesAt $Bytes $patchAt $original) {
            $state = 'Original'
        } elseif (Test-BytesAt $Bytes $patchAt $replacement) {
            $state = 'Patched'
        } elseif ($Rule.ContainsKey('AcceptedReplacements')) {
            foreach ($acceptedText in $Rule.AcceptedReplacements) {
                $accepted = ConvertTo-Pattern $acceptedText
                if ($accepted.Length -eq $replacement.Length -and
                    (Test-BytesAt $Bytes $patchAt $accepted)) {
                    $state = 'PatchedLegacy'
                    break
                }
            }
        }
        $classified += [pscustomobject]@{
            MatchOffset = $match
            PatchOffset = $patchAt
            State = $state
        }
    }

    return [pscustomobject]@{
        Name = $Rule.Name
        Description = $Rule.Description
        MatchCount = $classified.Count
        Candidates = $classified
        Rule = $Rule
        OriginalPattern = $original
        ReplacementPattern = $replacement
    }
}

function Get-ExpectedMatchCount {
    param($Rule)
    if ($Rule.ContainsKey('ExpectedMatches')) {
        return [int]$Rule.ExpectedMatches
    }
    return 1
}

function Get-RuleState {
    param($RuleResult)

    if ($RuleResult.MatchCount -ne (Get-ExpectedMatchCount $RuleResult.Rule)) {
        return 'Invalid'
    }
    $states = @($RuleResult.Candidates.State | Select-Object -Unique)
    if ($states.Count -ne 1 -or $states[0] -eq 'Unknown') {
        return 'Invalid'
    }
    return $states[0]
}

function Get-ByteArraySha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '')
    } finally {
        $sha.Dispose()
    }
}

function Read-ExclusiveStreamBytes {
    param([IO.FileStream]$Stream)
    if ($Stream.Length -gt [int]::MaxValue) {
        throw 'DLL is too large for this patcher.'
    }
    $result = New-Object 'byte[]' ([int]$Stream.Length)
    $Stream.Position = 0
    $read = 0
    while ($read -lt $result.Length) {
        $count = $Stream.Read($result, $read, $result.Length - $read)
        if ($count -le 0) {
            throw 'Unexpected end of file while reading the locked DLL.'
        }
        $read += $count
    }
    return ,$result
}

function Open-Mv2PrivateDllWrite {
    param([string]$Path, [string]$ExpectedHash)
    $Path = [IO.Path]::GetFullPath($Path)
    if ($ExpectedHash -notmatch '^[0-9a-fA-F]{64}$' -or
        ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'A verified ordinary DLL is required.'
    }
    # Read/delete sharing permits name replacement while another component maps
    # a hardlink. Never obtain write access to the shared file's data.
    $source = [IO.File]::Open($Path, 'Open', 'Read', ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
    $temporary = $null; $backup = $null
    try {
        if ([Mv2FileIdentity]::Links($source) -gt 1) {
            $before = Read-ExclusiveStreamBytes $source
            if ((Get-ByteArraySha256 $before) -ne $ExpectedHash) { throw 'The shared DLL changed before preparation.' }
            $identity = [Mv2FileIdentity]::Id($source)
            $suffix = '.mv2-private-' + [guid]::NewGuid().ToString('N')
            $temporary = $Path + $suffix + '.tmp'; $backup = $Path + $suffix + '.backup'
            $output = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
            try { $output.Write($before, 0, $before.Length); $output.Flush($true) } finally { $output.Dispose() }
            Set-Acl -LiteralPath $temporary -AclObject (Get-Acl -LiteralPath $Path)
            if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $ExpectedHash) { throw 'Private DLL copy verification failed.' }
            $check = [IO.File]::Open($Path, 'Open', 'Read', ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
            try { if ([Mv2FileIdentity]::Id($check) -ne $identity) { throw 'The DLL path changed during preparation.' } }
            finally { $check.Dispose() }
            [IO.File]::Replace($temporary, $Path, $backup)
            $check = [IO.File]::Open($backup, 'Open', 'Read', ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
            try { if ([Mv2FileIdentity]::Id($check) -ne $identity) { throw "The DLL was concurrently replaced. Preserved files require review: $Path ; $backup" } }
            finally { $check.Dispose() }
            if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $ExpectedHash) { throw "The independent DLL changed. Original link retained: $backup" }
            # This only deletes our extra name. Other hardlinks and existing
            # mapped images still refer to the unchanged original file.
            [IO.File]::Delete($backup); $backup = $null
        }
    } catch {
        if ($backup -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $Path)) {
            [IO.File]::Move($backup, $Path)
        }
        throw
    } finally {
        $source.Dispose()
        if ($temporary -and (Test-Path -LiteralPath $temporary)) {
            try { [IO.File]::Delete($temporary) } catch { Write-Warning "Unused private DLL copy retained: $temporary" }
        }
    }
    $locked = [IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
    try {
        if ([Mv2FileIdentity]::Links($locked) -ne 1) { throw 'The writable DLL is still shared; no bytes were changed.' }
        if ((Get-ByteArraySha256 (Read-ExclusiveStreamBytes $locked)) -ne $ExpectedHash) {
            throw 'Target changed between analysis and exclusive lock acquisition; retry.'
        }
        return $locked
    } catch { $locked.Dispose(); throw }
}

function Get-ProfileResult {
    param(
        [byte[]]$Bytes,
        $Profile,
        $PeInfo
    )

    $results = @()
    foreach ($rule in $Profile.Rules) {
        $results += Get-RuleResult $Bytes $rule $PeInfo
    }
    return [pscustomobject]@{
        Profile = $Profile
        Rules = $results
        IsValid = @($results | Where-Object {
            (Get-RuleState $_) -ne 'Invalid'
        }).Count -eq $results.Count
    }
}

function Resolve-TargetAnalysis {
    param(
        [string]$Path,
        [byte[]]$Bytes,
        [string]$CatalogPath
    )

    $catalog = Import-PowerShellDataFile -LiteralPath $CatalogPath
    if ($catalog.SchemaVersion -ne 1) {
        throw "Unsupported signature catalog schema: $($catalog.SchemaVersion)"
    }
    $peInfo = Get-PeInfo $Bytes
    $profiles = @($catalog.Profiles | Where-Object {
        [int]$_.Machine -eq $peInfo.Machine
    })
    $profileResults = @($profiles | ForEach-Object {
        Get-ProfileResult $Bytes $_ $peInfo
    })
    $validProfiles = @($profileResults | Where-Object IsValid)
    if ($validProfiles.Count -ne 1) {
        $details = foreach ($profileResult in $profileResults) {
            foreach ($ruleResult in $profileResult.Rules) {
                if ((Get-RuleState $ruleResult) -eq 'Invalid') {
                    '{0}/{1}: matches={2}/{3}, states={4}' -f
                        $profileResult.Profile.Id, $ruleResult.Name,
                        $ruleResult.MatchCount, (Get-ExpectedMatchCount $ruleResult.Rule),
                        (($ruleResult.Candidates | ForEach-Object { $_.State }) -join ',')
                }
            }
        }
        throw "No unique supported signature profile matched. The target was not modified.`n$($details -join "`n")"
    }

    return Complete-TargetAnalysis $Path $peInfo $validProfiles[0] (Get-ByteArraySha256 $Bytes)
}

function Complete-TargetAnalysis {
    param([string]$Path,$peInfo,$selected,[string]$hash)
    $states = @($selected.Rules | ForEach-Object { Get-RuleState $_ })
    $allOriginal = @($states | Where-Object { $_ -eq 'Original' }).Count -eq $states.Count
    $allPatched = @($states | Where-Object {
        $_ -in @('Patched', 'PatchedLegacy')
    }).Count -eq $states.Count
    $allLegacyPatched = @($selected.Rules | Where-Object {
        $legacy = if ($_.Rule.ContainsKey('LegacyState')) {
            [string]$_.Rule.LegacyState
        } else { 'Patched' }
        if ($legacy -eq 'Original') {
            (Get-RuleState $_) -eq 'Original'
        } elseif ($legacy -eq 'Patched') {
            (Get-RuleState $_) -in @('Patched', 'PatchedLegacy')
        } else {
            throw "Rule '$($_.Name)' has unsupported LegacyState '$legacy'."
        }
    }).Count -eq $selected.Rules.Count
    if (-not $allOriginal -and -not $allPatched -and -not $allLegacyPatched) {
        throw "A partial or mixed patch was detected. The target was not modified: $($states -join ', ')"
    }

    $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $publicResult = [pscustomobject]@{
        Target = $Path
        ProductName = $version.ProductName
        ProductVersion = $version.ProductVersion
        FileVersion = $version.FileVersion
        Machine = ('0x{0:X4}' -f $peInfo.Machine)
        Profile = $selected.Profile.Id
        SHA256 = $hash
        State = $(if ($allOriginal) {
            'Patchable'
        } elseif ($allPatched) {
            'AlreadyPatched'
        } else {
            'UpgradeRequired'
        })
        Rules = @($selected.Rules | ForEach-Object {
            [pscustomobject]@{
                Name = $_.Name
                Offsets = @($_.Candidates | ForEach-Object {
                    '0x{0:X}' -f $_.PatchOffset
                })
                State = Get-RuleState $_
            }
        })
    }
    return [pscustomobject]@{
        Public = $publicResult
        Selected = $selected
        AllOriginal = $allOriginal
        AllPatched = $allPatched
        AllLegacyPatched = $allLegacyPatched
        Version = $version
        Hash = $hash
    }
}

function New-PatchedBytes {
    param(
        [byte[]]$Bytes,
        $SelectedProfile
    )
    $patched = New-Object 'byte[]' $Bytes.Length
    [Array]::Copy($Bytes, $patched, $Bytes.Length)
    $receiptPatches = @()
    foreach ($ruleResult in $SelectedProfile.Rules) {
        foreach ($candidate in $ruleResult.Candidates) {
            $offset = [long]$candidate.PatchOffset
            $original = @(if ($candidate.PSObject.Properties.Name -contains
                'OriginalPattern') {
                $candidate.OriginalPattern
            } else { $ruleResult.OriginalPattern })
            $replacement = @(if ($candidate.PSObject.Properties.Name -contains
                'ReplacementPattern') {
                $candidate.ReplacementPattern
            } else { $ruleResult.ReplacementPattern })
            $before = New-Object 'byte[]' $original.Length
            [Array]::Copy($patched, $offset, $before, 0, $before.Length)
            for ($i = 0; $i -lt $replacement.Length; $i++) {
                if ($replacement[$i] -ge 0) {
                    $patched[$offset + $i] = [byte]$replacement[$i]
                }
            }
            $after = New-Object 'byte[]' $before.Length
            [Array]::Copy($patched, $offset, $after, 0, $after.Length)
            $changed = $false
            for ($i = 0; $i -lt $before.Length; $i++) {
                if ($before[$i] -ne $after[$i]) {
                    $changed = $true
                    break
                }
            }
            if ($changed) {
                $receiptPatches += [pscustomobject]@{
                    Name = $ruleResult.Name
                    Offset = $offset
                    Before = Get-HexBytes $before
                    After = Get-HexBytes $after
                }
            }
        }
    }
    return [pscustomobject]@{ Bytes = $patched; Patches = $receiptPatches }
}

function Assert-GoogleChromeStopped {
    if (Get-Process chrome -ErrorAction SilentlyContinue) {
        throw 'Close every Google Chrome window and background process before this operation.'
    }
}

function Assert-BrowserStopped {
    param([string]$ExecutablePath)

    $name = [IO.Path]::GetFileNameWithoutExtension($ExecutablePath)
    if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
        throw "Close every '$name' browser window and background process before this operation."
    }
}

function Copy-BackupDirectory {
    param(
        [string]$Source,
        [string]$Destination
    )
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) `
        -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

function Get-BrowserUserDataRoot {
    param(
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [string]$DefaultPath
    )

    $values = @()
    for ($i = 0; $i -lt @($Arguments).Count; $i++) {
        if ($Arguments[$i] -eq '--user-data-dir') {
            if (($i + 1) -ge $Arguments.Count -or
                [string]::IsNullOrWhiteSpace($Arguments[$i + 1])) {
                throw '--user-data-dir requires a path argument.'
            }
            $values += $Arguments[++$i]
        } elseif ($Arguments[$i].StartsWith(
            '--user-data-dir=', [StringComparison]::Ordinal)) {
            $values += $Arguments[$i].Substring('--user-data-dir='.Length)
        }
    }
    if ($values.Count -gt 1) {
        throw 'Specify --user-data-dir only once.'
    }
    if ($values.Count -eq 0) {
        if ([string]::IsNullOrWhiteSpace($DefaultPath)) {
            throw 'The profile path for this browser is unknown. Add --user-data-dir to the RAM launch arguments or disable -BackupProfile.'
        }
        return $DefaultPath
    }
    if ([string]::IsNullOrWhiteSpace($values[0])) {
        throw '--user-data-dir requires a non-empty path.'
    }

    $path = [Environment]::ExpandEnvironmentVariables([string]$values[0])
    if (-not [IO.Path]::IsPathRooted($path)) {
        $path = Join-Path $WorkingDirectory $path
    }
    return [IO.Path]::GetFullPath($path)
}

function New-ChromeExtensionBackup {
    param(
        [string]$BackupDirectory,
        [string]$UserDataRoot,
        [string]$BrowserExecutable
    )

    if ($BrowserExecutable) {
        Assert-BrowserStopped $BrowserExecutable
    } else {
        Assert-GoogleChromeStopped
    }
    if ([string]::IsNullOrWhiteSpace($UserDataRoot)) {
        $UserDataRoot = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
    }
    $extensionBackup = Join-Path $BackupDirectory 'extensions'
    New-Item -ItemType Directory -Path $extensionBackup -Force | Out-Null

    $inventory = [ordered]@{
        SchemaVersion = 1
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        UserDataRoot = $UserDataRoot
        Profiles = @()
    }
    $storeRoots = @(
        'Local Extension Settings',
        'Sync Extension Settings',
        'Managed Extension Settings',
        'Storage\ext'
    )
    $totalExtensions = 0

    if (Test-Path -LiteralPath $UserDataRoot) {
        $localStatePath = Join-Path $UserDataRoot 'Local State'
        if (-not (Test-Path -LiteralPath $localStatePath)) {
            throw "Chrome Local State was not found: $localStatePath"
        }
        $localState = [IO.File]::ReadAllText(
            $localStatePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        foreach ($profileName in @(
            $localState.profile.info_cache.PSObject.Properties.Name)) {
            $profile = Get-Item -LiteralPath (Join-Path $UserDataRoot $profileName) `
                -ErrorAction SilentlyContinue
            if (-not $profile) { continue }
            $securePreferences = Join-Path $profile.FullName 'Secure Preferences'
            $extensionsRoot = Join-Path $profile.FullName 'Extensions'
            $ids = @()
            if (Test-Path -LiteralPath $extensionsRoot) {
                $ids += @(Get-ChildItem -LiteralPath $extensionsRoot -Directory |
                    Select-Object -ExpandProperty Name)
            }
            foreach ($storeRoot in $storeRoots) {
                $path = Join-Path $profile.FullName $storeRoot
                if (Test-Path -LiteralPath $path) {
                    $ids += @(Get-ChildItem -LiteralPath $path -Directory |
                        Select-Object -ExpandProperty Name)
                }
            }

            $settings = $null
            $registeredIds = @()
            if (Test-Path -LiteralPath $securePreferences) {
                try {
                    $secure = [IO.File]::ReadAllText(
                        $securePreferences, [Text.Encoding]::UTF8) | ConvertFrom-Json
                    $settings = $secure.extensions.settings
                    if ($settings) {
                        $registeredIds = @($settings.PSObject.Properties.Name)
                        $ids += $registeredIds
                    }
                } catch {
                    throw "Could not read extension inventory: $securePreferences"
                }
            }

            $extensionRecords = @()
            foreach ($id in @($ids | Where-Object { $_ -match '^[a-p]{32}$' } |
                Sort-Object -Unique)) {
                $setting = if ($settings) {
                    $property = $settings.PSObject.Properties[$id]
                    if ($property) { $property.Value }
                }
                $location = $null
                if ($setting -and $setting.PSObject.Properties['location']) {
                    $location = [int]$setting.location
                }
                if ($location -in @(5, 10)) { continue }

                $body = Join-Path $extensionsRoot $id
                $stores = @()
                if (Test-Path -LiteralPath $body) {
                    $relative = Join-Path (Join-Path 'profiles' $profile.Name) `
                        (Join-Path 'Extensions' $id)
                    Copy-BackupDirectory $body (Join-Path $extensionBackup $relative)
                    $stores += [ordered]@{
                        Kind = 'Body'
                        BackupRelativePath = $relative
                        TargetRelativePath = Join-Path $profile.Name `
                            (Join-Path 'Extensions' $id)
                    }
                }
                foreach ($storeRoot in $storeRoots) {
                    $source = Join-Path (Join-Path $profile.FullName $storeRoot) $id
                    if (-not (Test-Path -LiteralPath $source)) { continue }
                    $relative = Join-Path (Join-Path 'profiles' $profile.Name) `
                        (Join-Path $storeRoot $id)
                    Copy-BackupDirectory $source (Join-Path $extensionBackup $relative)
                    $stores += [ordered]@{
                        Kind = 'Settings'
                        BackupRelativePath = $relative
                        TargetRelativePath = Join-Path $profile.Name `
                            (Join-Path $storeRoot $id)
                    }
                }

                $manifest = $null
                $versions = @()
                if (Test-Path -LiteralPath $body) {
                    $versionDirectories = @(Get-ChildItem -LiteralPath $body -Directory |
                        Sort-Object Name -Descending)
                    $versions = @($versionDirectories.Name)
                    if ($versionDirectories.Count -gt 0) {
                        $manifestPath = Join-Path $versionDirectories[0].FullName 'manifest.json'
                        if (Test-Path -LiteralPath $manifestPath) {
                            try {
                                $manifest = [IO.File]::ReadAllText(
                                    $manifestPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
                            } catch {}
                        }
                    }
                }
                if (-not $manifest -and $setting -and
                    $setting.PSObject.Properties['manifest']) {
                    $manifest = $setting.manifest
                }
                $extensionRecords += [ordered]@{
                    Id = $id
                    Name = if ($manifest -and $manifest.PSObject.Properties['name']) {
                        [string]$manifest.name
                    } else { $id }
                    ManifestVersion = if ($manifest -and
                        $manifest.PSObject.Properties['manifest_version']) {
                        [int]$manifest.manifest_version
                    } else { $null }
                    Versions = $versions
                    ReinstallUrl = if ($registeredIds -contains $id -or
                        (Test-Path -LiteralPath $body)) {
                        "https://chromewebstore.google.com/detail/$id"
                    } else { $null }
                    IncognitoEnabled = if ($setting -and
                        $setting.PSObject.Properties['incognito']) {
                        [bool]$setting.incognito
                    } else { $false }
                    AllowFileAccess = if ($setting -and
                        $setting.PSObject.Properties['newAllowFileAccess']) {
                        [bool]$setting.newAllowFileAccess
                    } else { $false }
                    Stores = $stores
                }
            }

            if ($extensionRecords.Count -gt 0) {
                $profileBackup = Join-Path (Join-Path $extensionBackup 'profiles') `
                    $profile.Name
                if (Test-Path -LiteralPath $securePreferences) {
                    New-Item -ItemType Directory -Path $profileBackup -Force | Out-Null
                    Copy-Item -LiteralPath $securePreferences -Destination `
                        (Join-Path $profileBackup 'Secure Preferences.snapshot') -Force
                }
                $inventory.Profiles += [ordered]@{
                    Directory = $profile.Name
                    Extensions = $extensionRecords
                }
                $totalExtensions += $extensionRecords.Count
            }
        }
    }

    $inventoryPath = Join-Path $extensionBackup 'inventory.json'
    $inventory | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $inventoryPath -Encoding UTF8
    return [pscustomobject]@{
        Path = $extensionBackup
        Inventory = $inventoryPath
        ProfileCount = $inventory.Profiles.Count
        ExtensionCount = $totalExtensions
    }
}

function New-ChromeProfileBackup {
    param(
        [string]$BackupDirectory,
        [string]$UserDataRoot,
        [string]$BrowserExecutable
    )

    if ($BrowserExecutable) {
        Assert-BrowserStopped $BrowserExecutable
    } else {
        Assert-GoogleChromeStopped
    }
    if ([string]::IsNullOrWhiteSpace($UserDataRoot)) {
        $UserDataRoot = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'
    }
    $extensionBackup = New-ChromeExtensionBackup $BackupDirectory $UserDataRoot `
        $BrowserExecutable
    $settingsRoot = Join-Path $BackupDirectory 'profile-settings'
    New-Item -ItemType Directory -Path $settingsRoot -Force | Out-Null

    $files = @()
    $localStatePath = Join-Path $UserDataRoot 'Local State'
    if (Test-Path -LiteralPath $localStatePath -PathType Leaf) {
        $localStateBackup = Join-Path $settingsRoot 'Local State'
        Copy-Item -LiteralPath $localStatePath -Destination $localStateBackup -Force
        $files += [ordered]@{
            SourceRelativePath = 'Local State'
            BackupRelativePath = 'profile-settings\Local State'
        }
        $localState = [IO.File]::ReadAllText(
            $localStatePath, [Text.Encoding]::UTF8) | ConvertFrom-Json
        $profileNames = @($localState.profile.info_cache.PSObject.Properties.Name)
    } else {
        $profileNames = @()
    }

    foreach ($profileName in $profileNames) {
        foreach ($name in @('Preferences', 'Secure Preferences')) {
            $source = Join-Path (Join-Path $UserDataRoot $profileName) $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { continue }
            $destinationDirectory = Join-Path $settingsRoot $profileName
            New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
            Copy-Item -LiteralPath $source -Destination `
                (Join-Path $destinationDirectory $name) -Force
            $files += [ordered]@{
                SourceRelativePath = Join-Path $profileName $name
                BackupRelativePath = Join-Path `
                    (Join-Path 'profile-settings' $profileName) $name
            }
        }
    }

    $manifest = [ordered]@{
        SchemaVersion = 1
        CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
        UserDataRoot = $UserDataRoot
        Files = $files
        ExtensionInventoryPath = $extensionBackup.Inventory
        ProfileCount = $profileNames.Count
        ExtensionCount = $extensionBackup.ExtensionCount
    }
    $manifestPath = Join-Path $BackupDirectory 'profile-backup.json'
    $manifest | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Limit-Mv2Backups (Split-Path -Parent $BackupDirectory) $BackupDirectory
    return [pscustomobject]@{
        Path = $BackupDirectory
        Manifest = $manifestPath
        ProfileCount = $profileNames.Count
        ExtensionCount = $extensionBackup.ExtensionCount
        Inventory = $extensionBackup.Inventory
    }
}

function Invoke-ExtensionRestore {
    param(
        [string]$ReceiptPath,
        [string]$CatalogPath
    )

    Assert-GoogleChromeStopped
    $resolvedReceipt = (Resolve-Path -LiteralPath $ReceiptPath).Path
    $record = Get-Content -Raw -LiteralPath $resolvedReceipt | ConvertFrom-Json
    if (-not $record.PSObject.Properties['ExtensionInventoryPath']) {
        throw 'This receipt predates extension backups. Use a receipt created by the updated script.'
    }
    $inventoryPath = (Resolve-Path -LiteralPath $record.ExtensionInventoryPath).Path
    $inventory = Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json
    if ($inventory.SchemaVersion -ne 1) {
        throw "Unsupported extension backup schema: $($inventory.SchemaVersion)"
    }

    $applicationRoot = Resolve-ChromeApplicationRoot $null
    $currentDll = Get-LatestChromeDll $applicationRoot
    $analysis = Resolve-TargetAnalysis $currentDll `
        ([IO.File]::ReadAllBytes($currentDll)) $CatalogPath
    if (-not $analysis.AllPatched) {
        throw 'Apply the MV2 patch to the current Chrome version before -RestoreExt.'
    }

    $restoredStores = 0
    $existingStores = 0
    foreach ($profile in @($inventory.Profiles)) {
        foreach ($extension in @($profile.Extensions)) {
            foreach ($store in @($extension.Stores | Where-Object Kind -eq 'Settings')) {
                $source = Join-Path (Split-Path -Parent $inventoryPath) `
                    $store.BackupRelativePath
                $destination = Join-Path $inventory.UserDataRoot $store.TargetRelativePath
                if (Test-Path -LiteralPath $destination) {
                    $existingStores++
                    continue
                }
                Copy-BackupDirectory $source $destination
                $restoredStores++
            }
        }
    }

    $chromeExe = Join-Path $applicationRoot 'chrome.exe'
    $openedPages = 0
    foreach ($profile in @($inventory.Profiles)) {
        $urls = @($profile.Extensions.ReinstallUrl | Where-Object { $_ } |
            Sort-Object -Unique)
        if ($urls.Count -eq 0) { continue }
        $arguments = @(
            "--profile-directory=`"$($profile.Directory)`"",
            '--no-first-run'
        ) + $urls
        Start-Process -FilePath $chromeExe -ArgumentList $arguments
        $openedPages += $urls.Count
    }

    return [pscustomobject]@{
        Receipt = $resolvedReceipt
        RestoredSettingStores = $restoredStores
        ExistingSettingStores = $existingStores
        ReinstallPagesOpened = $openedPages
        ExtensionBodies = Split-Path -Parent $inventoryPath
    }
}

function Invoke-ExtensionProtectedSettingsRestore {
    param([string]$ReceiptPath)

    $resolvedReceipt = (Resolve-Path -LiteralPath $ReceiptPath).Path
    $record = Get-Content -Raw -LiteralPath $resolvedReceipt | ConvertFrom-Json
    if (-not $record.PSObject.Properties['ExtensionInventoryPath']) {
        throw 'This receipt predates extension backups. Use a newer receipt.'
    }
    $inventoryPath = (Resolve-Path -LiteralPath $record.ExtensionInventoryPath).Path
    $inventory = Get-Content -Raw -LiteralPath $inventoryPath | ConvertFrom-Json
    $chromeExe = Join-Path (Resolve-ChromeApplicationRoot $null) 'chrome.exe'
    $settings = @()
    $missingExtensions = 0

    foreach ($profile in @($inventory.Profiles)) {
        $snapshotSettings = $null
        $snapshotPath = Join-Path (Split-Path -Parent $inventoryPath) `
            (Join-Path 'profiles' (Join-Path $profile.Directory `
                'Secure Preferences.snapshot'))
        if (Test-Path -LiteralPath $snapshotPath) {
            try {
                $snapshot = [IO.File]::ReadAllText(
                    $snapshotPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
                $snapshotSettings = $snapshot.extensions.settings
            } catch {
                throw "Could not read protected extension settings: $snapshotPath"
            }
        }
        $urls = @()
        foreach ($extension in @($profile.Extensions)) {
            $incognitoProperty = $extension.PSObject.Properties['IncognitoEnabled']
            $fileAccessProperty = $extension.PSObject.Properties['AllowFileAccess']
            $snapshotSetting = if ($snapshotSettings) {
                $property = $snapshotSettings.PSObject.Properties[$extension.Id]
                if ($property) { $property.Value }
            }
            if (-not $incognitoProperty -and $snapshotSetting) {
                $incognitoProperty = $snapshotSetting.PSObject.Properties['incognito']
            }
            if (-not $fileAccessProperty -and $snapshotSetting) {
                $fileAccessProperty = `
                    $snapshotSetting.PSObject.Properties['newAllowFileAccess']
            }
            if (-not $incognitoProperty -and -not $fileAccessProperty) { continue }
            $incognito = $incognitoProperty -and [bool]$incognitoProperty.Value
            $fileAccess = $fileAccessProperty -and [bool]$fileAccessProperty.Value
            if (-not $incognito -and -not $fileAccess) { continue }

            $installedPath = Join-Path $inventory.UserDataRoot `
                (Join-Path $profile.Directory (Join-Path 'Extensions' $extension.Id))
            if (-not (Test-Path -LiteralPath $installedPath)) {
                $missingExtensions++
                continue
            }
            $url = "chrome://extensions/?id=$($extension.Id)"
            $urls += $url
            $settings += [pscustomobject]@{
                Profile = $profile.Directory
                Id = $extension.Id
                Name = $extension.Name
                IncognitoEnabled = [bool]$incognito
                AllowFileAccess = [bool]$fileAccess
                SettingsUrl = $url
            }
        }
        if ($urls.Count -gt 0) {
            $arguments = @(
                "--profile-directory=`"$($profile.Directory)`"",
                '--no-first-run'
            ) + @($urls | Sort-Object -Unique)
            Start-Process -FilePath $chromeExe -ArgumentList $arguments
        }
    }

    if ($settings.Count -eq 0 -and $missingExtensions -eq 0) {
        throw 'This backup contains no protected extension settings to restore.'
    }
    return [pscustomobject]@{
        Receipt = $resolvedReceipt
        SettingsPagesOpened = $settings.Count
        MissingExtensionsSkipped = $missingExtensions
        RequiredSettings = $settings
    }
}

function Get-LatestTargetReceipt {
    param(
        [string]$BackupBase,
        [string]$Path,
        [string]$FileVersion
    )

    if ([string]::IsNullOrWhiteSpace($BackupBase) -or
        -not (Test-Path -LiteralPath $BackupBase -PathType Container)) {
        return $null
    }
    $targetPath = [IO.Path]::GetFullPath($Path)
    $matches = Get-ChildItem -LiteralPath $BackupBase -Directory | ForEach-Object {
        $receiptPath = Join-Path $_.FullName 'receipt.json'
        if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { return }
        try {
            $record = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json
            if ($record.SchemaVersion -eq 1 -and $record.State -eq 'Applied' -and
                $record.AppliedUtc -and $record.TargetPath -and $record.Profile -and
                $record.FileVersion -eq $FileVersion -and
                [string]::Equals([IO.Path]::GetFullPath([string]$record.TargetPath),
                    $targetPath, [StringComparison]::OrdinalIgnoreCase)) {
                [pscustomobject]@{
                    Path = (Resolve-Path -LiteralPath $receiptPath).Path
                    AppliedUtc = [DateTimeOffset]$record.AppliedUtc
                    Record = $record
                }
            }
        } catch {
            Write-Verbose "Ignoring invalid target receipt: $receiptPath"
        }
    }
    return $matches | Sort-Object AppliedUtc -Descending | Select-Object -First 1
}

function Test-SemanticReceiptPatch {
    param(
        [IO.FileStream]$Stream,
        $PeInfo,
        $Rule,
        $Patch
    )

    $before = ConvertTo-Pattern ([string]$Patch.Before)
    $after = ConvertTo-Pattern ([string]$Patch.After)
    $patchAt = [long]$Patch.Offset

    $matches = 0
    foreach ($variant in @($Rule.Variants)) {
        $patch = Get-VariantPatchPatterns $Rule $variant
        $original = $patch.Original
        $replacement = $patch.Replacement
        if (-not (Test-ConcreteMaskedPattern $before $original) -or
            -not (Test-ConcreteMaskedPattern $after $replacement) -or
            -not (Test-StreamPattern $Stream $patchAt $after)) {
            continue
        }
        $pattern = ConvertTo-MaskedPattern $variant.Pattern
        $patchOffset = [int]$variant.PatchOffset
        if (($patchOffset + $original.Length) -gt $pattern.Length) { continue }
        $matchAt = $patchAt - $patchOffset
        if (-not (Test-ExecutableRange $PeInfo $matchAt $pattern.Length)) { continue }

        $contextValues = New-Object 'byte[]' $pattern.Length
        $contextMasks = New-Object 'byte[]' $pattern.Length
        [Array]::Copy($pattern.Values, $contextValues, $pattern.Length)
        [Array]::Copy($pattern.Masks, $contextMasks, $pattern.Length)
        for ($i = 0; $i -lt $original.Length; $i++) {
            $contextValues[$patchOffset + $i] = 0
            $contextMasks[$patchOffset + $i] = 0
        }
        $context = [pscustomobject]@{
            Values = $contextValues
            Masks = $contextMasks
            Length = $pattern.Length
        }
        $observed = Read-StreamRange $Stream $matchAt $pattern.Length
        if ($null -eq $observed -or
            -not (Test-MaskedBytesAt $observed 0 $context)) { continue }

        if ($variant.ContainsKey('RequiredPattern')) {
            $required = ConvertTo-MaskedPattern $variant.RequiredPattern
            $requiredAt = $matchAt + [long]$variant.RequiredPatternOffset
            if (-not (Test-ExecutableRange $PeInfo $requiredAt $required.Length) -or
                -not (Test-StreamMaskedPattern $Stream $requiredAt $required)) {
                continue
            }
        }
        $equal = $true
        if ($variant.ContainsKey('EqualBytes')) {
            foreach ($pair in @($variant.EqualBytes)) {
                $offsets = @([string]$pair -split ':')
                if ($offsets.Count -ne 2 -or
                    $observed[[int]$offsets[0]] -ne $observed[[int]$offsets[1]]) {
                    $equal = $false
                    break
                }
            }
        }
        if ($equal) { $matches++ }
    }
    return $matches -eq 1
}

function Get-ReceiptPatchedAnalysis {
    param(
        [string]$Path,
        [string]$BackupBase,
        [string]$CatalogPath
    )

    try {
        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $receipt = Get-LatestTargetReceipt $BackupBase $Path $version.FileVersion
        if (-not $receipt) { return $null }
        $record = $receipt.Record
        if (-not $record.Patches -or
            [string]$record.PatchedSHA256 -notmatch '^[0-9A-Fa-f]{64}$') {
            return $null
        }

        $catalog = Import-PowerShellDataFile -LiteralPath $CatalogPath
        if ($catalog.SchemaVersion -ne 1) { return $null }
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open,
            [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $peInfo = Get-PeStreamInfo $stream
            $receiptPatches = @($record.Patches)
            $receiptOffsets = @($receiptPatches | ForEach-Object { [long]$_.Offset })
            if (@($receiptOffsets | Select-Object -Unique).Count -ne
                $receiptOffsets.Count) {
                return $null
            }
            $compatible = @()
            foreach ($profile in $catalog.Profiles) {
                if ([int]$profile.Machine -ne $peInfo.Machine) { continue }
                $expectedTotal = 0
                $ruleResults = @()
                $profileValid = $true
                foreach ($rule in $profile.Rules) {
                    $expected = Get-ExpectedMatchCount $rule
                    $expectedTotal += $expected
                    $patches = @($receiptPatches | Where-Object { $_.Name -eq $rule.Name })
                    if ($patches.Count -ne $expected) {
                        $profileValid = $false
                        break
                    }

                    if ($rule.ContainsKey('Variants')) {
                        $offsets = @()
                        foreach ($patch in $patches) {
                            if (-not (Test-SemanticReceiptPatch $stream $peInfo `
                                $rule $patch)) {
                                $profileValid = $false
                                break
                            }
                            $offsets += '0x{0:X}' -f [long]$patch.Offset
                        }
                        if (-not $profileValid) { break }
                        $ruleResults += [pscustomobject]@{
                            Name = $rule.Name
                            Offsets = $offsets
                            State = 'Patched'
                        }
                        continue
                    }

                    $pattern = ConvertTo-Pattern $rule.Pattern
                    $original = ConvertTo-Pattern $rule.Original
                    $replacement = ConvertTo-Pattern $rule.Replacement
                    if ($original.Length -ne $replacement.Length -or
                        ($rule.PatchOffset + $original.Length) -gt $pattern.Length) {
                        $profileValid = $false
                        break
                    }
                    $context = New-Object 'int[]' $pattern.Length
                    [Array]::Copy($pattern, $context, $pattern.Length)
                    for ($i = 0; $i -lt $original.Length; $i++) {
                        $context[$rule.PatchOffset + $i] = -1
                    }

                    $offsets = @()
                    foreach ($patch in $patches) {
                        $patchAt = [long]$patch.Offset
                        $matchAt = $patchAt - [long]$rule.PatchOffset
                        $before = ConvertTo-Pattern ([string]$patch.Before)
                        $after = ConvertTo-Pattern ([string]$patch.After)
                        if (-not (Test-PatternCompatibility $before $original) -or
                            -not (Test-PatternCompatibility $after $replacement) -or
                            -not (Test-ExecutableRange $peInfo $matchAt $pattern.Length) -or
                            -not (Test-StreamPattern $stream $matchAt $context) -or
                            -not (Test-StreamPattern $stream $patchAt $after)) {
                            $profileValid = $false
                            break
                        }
                        if ($rule.ContainsKey('RequiredPattern')) {
                            $required = ConvertTo-Pattern $rule.RequiredPattern
                            $requiredAt = $matchAt + [long]$rule.RequiredPatternOffset
                            if (-not (Test-ExecutableRange $peInfo $requiredAt $required.Length) -or
                                -not (Test-StreamPattern $stream $requiredAt $required)) {
                                $profileValid = $false
                                break
                            }
                        }
                        $offsets += '0x{0:X}' -f $patchAt
                    }
                    if (-not $profileValid) { break }
                    $ruleResults += [pscustomobject]@{
                        Name = $rule.Name
                        Offsets = $offsets
                        State = 'Patched'
                    }
                }
                if ($profileValid -and $receiptPatches.Count -eq $expectedTotal) {
                    $compatible += [pscustomobject]@{
                        Profile = $profile
                        Rules = $ruleResults
                    }
                }
            }
            if ($compatible.Count -ne 1 -or
                $compatible[0].Profile.Id -ne [string]$record.Profile) {
                return $null
            }

            return [pscustomobject]@{
                Target = $Path
                ProductName = $version.ProductName
                ProductVersion = $version.ProductVersion
                FileVersion = $version.FileVersion
                Machine = ('0x{0:X4}' -f $peInfo.Machine)
                Profile = $compatible[0].Profile.Id
                SHA256 = $null
                State = 'AlreadyPatched'
                Rules = $compatible[0].Rules
                Verification = 'ReceiptFastPath'
                ReceiptSHA256 = ([string]$record.PatchedSHA256).ToUpperInvariant()
            }
        } finally {
            if ($stream) { $stream.Dispose() }
        }
    } catch {
        Write-Verbose "Receipt fast path was not usable: $($_.Exception.Message)"
        return $null
    }
}
function Get-Mv2NativeRules {
    param([IO.FileStream]$Stream,$PeInfo,[string[]]$RuleNames)
    Set-StrictMode -Off
    $supported=@('skip-startup-disable','allow-install-policy-inline','allow-enable-and-report','allow-enable-policy-inline','allow-install','ignore-mv2-disable-reason-at-runtime')
    if(!$RuleNames.Count) {$RuleNames=$supported}
    if(@($RuleNames | Where-Object {$_ -notin $supported}).Count -or @($RuleNames | Sort-Object -Unique).Count -ne $RuleNames.Count) {throw 'Invalid native rule selection'}
    $traceReasons='ignore-mv2-disable-reason-at-runtime' -in $RuleNames
    $traceOriginal=@($RuleNames | Where-Object {$_ -in @('skip-startup-disable','allow-install-policy-inline')}).Count -gt 0
    $traceAdditional=@($RuleNames | Where-Object {$_ -in @('allow-enable-and-report','allow-enable-policy-inline','allow-install')}).Count -gt 0
    $traceManifests=$traceOriginal -or $traceAdditional
    $calleeCache=@{}
    $pe=$PeInfo; $imageBase=[uint64]$PeInfo.ImageBase; $Inspect=$false
    $nativeState=@{offset=0L;lo=[uint64]0;hi=[uint64]0;cache=@{};decodeCount=0;engine=$null}
    $dumpRoot=Join-Path ([IO.Path]::GetTempPath()) ('ChromiumMV2Trace-'+[guid]::NewGuid())
    New-Item -ItemType Directory -Path $dumpRoot | Out-Null
function Native-Next([uint64]$at,[hashtable]$state) {
    for($n=0;$n -lt 16;$n++) {
        $ins=Next-Real $at
        if($ins.Op -in @('mov','lea') -and $ins.Args -match '^(r\w+|e\w+),') {Apply-Copy $ins $state; $at=$ins.End; continue}
        if($ins.Op -eq 'xor' -and $ins.Args -match '^(e\w+|r[0-9]+d),\1$') {$state[(Canonical-Register $Matches[1])]='0'; $at=$ins.End; continue}
        return $ins
    }
    throw 'Extra copy budget exceeded'
}
function Native-ByteRegister([string]$reg) {
    $map=@{al='rax';cl='rcx';dl='rdx';bl='rbx';sil='rsi';dil='rdi';bpl='rbp';spl='rsp'}
    if($map.ContainsKey($reg)) {return $map[$reg]}
    if($reg -match '^(r[0-9]+)b$') {return $Matches[1]}
    throw 'Unsupported byte register'
}
function Native-FalseReturn([uint64]$at,[hashtable]$state) {
    $local=$state.Clone(); $ins=Native-Next $at $local
    if($ins.Op -ne 'ret' -or (Resolve-Value 'eax' $local) -ne '0') {throw 'No side-effect-free false return'}
    return $ins.Address
}
function Native-BranchPatch($guard) {
    $size=[int]($guard.End-$guard.Address); $raw=[byte[]]::new($size)
    if($guard.Op -eq 'jle') {for($i=0;$i -lt $size;$i++) {$raw[$i]=0x90}}
    elseif($guard.Op -eq 'jg' -and $size -eq 2) {$raw[0]=0xeb; $raw[1]=[byte](($guard.Target-$guard.End) -band 255)}
    elseif($guard.Op -eq 'jg' -and $size -eq 6) {
        $raw[0]=0x90; $raw[1]=0xe9
        [Array]::Copy([BitConverter]::GetBytes([int]($guard.Target-$guard.End)),0,$raw,2,4)
    } else {throw 'Unsupported extra branch encoding'}
    return ,$raw
}
function Native-TypeSet($first,[hashtable]$state,[uint64]$normal) {
    $branch=Next-Real $first.End
    if($first.Args -match '^(.+),8$' -and $branch.Op -eq 'ja') {
        $origin=Resolve-Value $Matches[1] $state
        if((Next-Real $branch.Target).Address -ne $normal) {throw 'Type range does not reject to normal path'}
        $mask=Next-Real $branch.End
        if($mask.Op -ne 'mov' -or $mask.Args -notmatch '^(e\w+|r[0-9]+d),10Ah$' -or (Canonical-Register $Matches[1]) -eq 'rax') {throw 'Unknown type bit mask'}
        $maskReg=Canonical-Register $Matches[1]; Apply-Copy $mask $state
        $bt=Next-Real $mask.End
        if($bt.Op -ne 'bt' -or $bt.Args -notmatch '^([^,]+),([^,]+)$') {throw 'No bounded type bit test'}
        if((Canonical-Register $Matches[1]) -ne $maskReg -or (Resolve-Value $Matches[2] $state) -ne $origin) {throw 'Type bit index changed'}
        $reject=Next-Real $bt.End
        if($reject.Op -ne 'jae' -or (Next-Real $reject.Target).Address -ne $normal) {throw 'Type bit rejection changed'}
        return [pscustomobject]@{Origin=$origin;Entry=(Next-Real $reject.End).Address;Offsets=@($first.Address);BitSet=$true}
    }
    $seen=@{}; $origin=$null; $entry=$null; $at=$first.Address; $offsets=@(); $equalState=$null
    for($i=0;$i -lt 3;$i++) {
        $cmp=Native-Next $at $state
        if($cmp.Op -ne 'cmp' -or $cmp.Args -notmatch '^(.+),(1|3|8)$') {throw 'Incomplete type membership'}
        $value=$Matches[2]; $valueOrigin=Resolve-Value $Matches[1] $state
        if($seen.ContainsKey($value) -or ($origin -and $origin -ne $valueOrigin)) {throw 'Type membership value mismatch'}
        $origin=$valueOrigin; $seen[$value]=$true; $offsets+=$cmp.Address
        $j=Next-Real $cmp.End
        if($j.Op -notin @('je','jne')) {throw 'Unsupported type equality'}
        $equal=if($j.Op -eq 'je') {$j.Target} else {$j.End}
        $other=if($j.Op -eq 'jne') {$j.Target} else {$j.End}
        $equal=(Next-Real $equal).Address
        if($entry -and $entry -ne $equal) {throw 'Type alternatives enter different paths'}
        $entry=$equal; $at=$other
        if($null -eq $equalState) {$equalState=$state.Clone()}
        else {
            foreach($key in @(@($equalState.Keys)+@($state.Keys) | Sort-Object -Unique)) {
                if((Resolve-Value $key $equalState) -ne (Resolve-Value $key $state)) {throw 'Type alternatives carry different values'}
            }
        }
    }
    if((Next-Real $at).Address -ne $normal) {throw 'Excluded type does not reach the normal path'}
    return [pscustomobject]@{Origin=$origin;Entry=$entry;Offsets=$offsets;BitSet=$false}
}
function Native-PolicyEffect([uint64]$bad,[uint64]$good,[uint64]$normal,[hashtable]$state) {
    $normalState=$state.Clone(); $normalJoin=Native-Next $normal $normalState
    if($normalJoin.Address -ne $good) {throw 'Policy normal path does not join cleanup'}
    $reason=Next-Real $bad
    if($reason.Op -ne 'mov' -or $reason.Args -notmatch '^(e\w+|r[0-9]+d),800000h$') {throw 'No MV2 disable reason'}
    $reasonReg=$Matches[1]
    $nullCheck=Next-Real $reason.End
    if($nullCheck.Op -ne 'test' -or $nullCheck.Args -notmatch '^(r\w+),\1$') {throw 'No reason-output null check'}
    $pointer=$Matches[1]; $skip=Next-Real $nullCheck.End
    if($skip.Op -ne 'je') {throw 'Reason output null branch changed'}
    $write=Next-Real $skip.End
    if($write.Op -ne 'mov' -or $write.Args -ne "dword ptr [$pointer],$reasonReg") {throw 'Reason output write changed'}
    $set=Next-Real $write.End
    if((Next-Real $skip.Target).Address -ne $set.Address -or $set.Op -ne 'mov' -or $set.Args -notmatch '^([^,]+),1$') {throw 'Policy result flag changed'}
    $resultReg=Native-ByteRegister $Matches[1]
    if((Resolve-Value $resultReg $normalState) -ne '0' -or (Resolve-Value $resultReg $state) -ne '0') {throw 'Policy unaffected result is not zero'}
    if((Next-Real $set.End).Address -ne $good) {throw 'Policy effect does not rejoin cleanup'}
    # One fall-through epilogue is checked; conditional cleanup/cookie paths are retained, not proved.
    $at=$good; $returned=$false; $copyFound=$false
    for($i=0;$i -lt 24;$i++) {
        $ins=Read-Instruction $at; $at=$ins.End
        if($ins.Op -eq 'ret') {$returned=$true; break}
        if($ins.Op -eq 'call' -or $ins.Op -eq 'jmp') {throw 'Unknown policy epilogue'}
        if($ins.Op -eq 'mov' -and $ins.Args -match '^eax,([^,]+)$') {
            if((Canonical-Register $Matches[1]) -ne $resultReg) {throw 'Policy returns a different value'}
            $copyFound=$true
        }
        if($ins.Op -notin @('cmp','test','push','pop','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+),') {
            if((Canonical-Register $Matches[1]) -eq $resultReg) {throw 'Policy result overwritten before return'}
            if($copyFound -and (Canonical-Register $Matches[1]) -eq 'rax' -and $ins.Args -notmatch '^eax,') {throw 'Policy return register overwritten'}
        }
    }
    if(!$returned -or !$copyFound) {throw 'No bounded policy result return'}
    return [pscustomobject]@{ReasonOffset=$nativeState.offset+$reason.Address-$nativeState.lo;WriteOffset=$nativeState.offset+$write.Address-$nativeState.lo;CleanupRva=$good-$imageBase}
}
function Native-Manifest([uint64]$Address) {
    $state=@{}; $first=Native-Next $Address $state
    if($first.Op -ne 'cmp' -or $first.Args -notmatch '^(.+),2$') {throw 'No extra manifest comparison'}
    $manifest=Resolve-Value $Matches[1] $state; $prefixState=$state.Clone()
    $guard=Next-Real $first.End
    if($guard.Op -eq 'jg') {$normal=(Next-Real $guard.Target).Address; $at=$guard.End}
    elseif($guard.Op -eq 'jle') {$normal=(Next-Real $guard.End).Address; $at=$guard.Target}
    else {throw 'Unsupported extra manifest guard'}
    $override=$null; $ins=Native-Next $at $state
    if($ins.Op -eq 'cmp' -and $ins.Args -match '^(byte ptr \[.+\]),0$') {
        $overrideOrigin=Resolve-Value $Matches[1] $state
        $branch=Next-Real $ins.End
        if($branch.Op -notin @('je','jne')) {throw 'Unsupported object override'}
        $override=if($branch.Op -eq 'jne') {$branch.Target} else {$branch.End}
        $at=if($branch.Op -eq 'je') {$branch.Target} else {$branch.End}
        $ins=Native-Next $at $state
    }
    $typeState=$state.Clone(); $type=Native-TypeSet $ins $typeState $normal
    # Equality arms in the supported type chain have no copies; do not carry mismatch-arm state into them.
    if($type.BitSet) {$state=$typeState}
    $locationStart=$type.Entry
    if($override -and (Next-Real $override).Address -ne $locationStart) {throw 'Override bypasses the location filter'}
    $cmp=Native-Next $locationStart $state
    $locationOrigin=$null; $locations=@{}; $byteValues=@{}; $good=$null; $bad=$null; $policy=$false
    for($i=0;$i -lt 2;$i++) {
        if($cmp.Op -ne 'cmp' -or $cmp.Args -notmatch '^(.+),(5|0Ah)$') {throw 'No extra location comparison'}
        $value=$Matches[2]; $origin=Resolve-Value $Matches[1] $state
        if($locations.ContainsKey($value) -or ($locationOrigin -and $origin -ne $locationOrigin)) {throw 'Extra location value mismatch'}
        $locationOrigin=$origin; $locations[$value]=$cmp.Address
        $next=Next-Real $cmp.End
        if($next.Op -eq 'setne') {
            if($i -gt 0 -and $policy) {throw 'Mixed location encodings'}
            $byteValues[$next.Args]=$value
            $state[(Native-ByteRegister $next.Args)]='partial-byte-write'
            $at=$next.End
        } elseif($next.Op -in @('je','jne')) {
            if($byteValues.Count) {throw 'Mixed location encodings'}
            $policy=$true
            $equal=if($next.Op -eq 'je') {$next.Target} else {$next.End}
            $other=if($next.Op -eq 'jne') {$next.Target} else {$next.End}
            $equal=(Next-Real $equal).Address
            if($good -and $good -ne $equal) {throw 'Policy location exclusions disagree'}
            $good=$equal; $at=$other
        } else {throw 'Unsupported extra location result'}
        if($i -eq 0) {$cmp=Native-Next $at $state}
    }
    if($locationOrigin -eq $manifest -or $locationOrigin -eq $type.Origin -or $manifest -eq $type.Origin) {throw 'Aliased predicate inputs'}
    $memoryLocation=$locationOrigin -like 'dword ptr *'
    if($manifest -like 'dword ptr *') {
        if($type.Origin -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$') {throw 'Unknown type object'}
        $object=$Matches[1]
        if($locationOrigin -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$' -or $Matches[1] -ne $object) {throw 'Extra fields come from different objects'}
    } elseif(!$memoryLocation -and ($manifest -notmatch '^low32\(r\w+\)$' -or $type.Origin -notmatch '^low32\(r\w+\)$' -or $locationOrigin -notmatch '^low32\(r\w+\)$')) {throw 'Unknown direct predicate inputs'}
    $evidence=$null
    if($policy) {
        if(!$memoryLocation) {throw 'Policy location has no object origin'}
        $bad=(Next-Real $at).Address
        $evidence=Native-PolicyEffect $bad $good $normal $state
        $name='allow-enable-policy-inline'
    } else {
        $combine=Next-Real $at
        if($combine.Op -ne 'and' -or $combine.Args -notmatch '^([^,]+),([^,]+)$') {throw 'Location booleans are not intersected'}
        $dest=$Matches[1]; $src=$Matches[2]
        if(!$byteValues.ContainsKey($dest) -or !$byteValues.ContainsKey($src) -or $byteValues[$dest] -eq $byteValues[$src]) {throw 'Location conjunction lost an input'}
        $ret=Next-Real $combine.End
        if($dest -ne 'al') {
            if($ret.Op -ne 'mov' -or $ret.Args -ne "al,$dest") {throw 'Location conjunction is not returned'}
            $ret=Next-Real $ret.End
        }
        if($ret.Op -ne 'ret') {throw 'Boolean predicate has extra effects'}
        $normalRet=Native-FalseReturn $normal $prefixState
        if($normalRet -ne $ret.Address) {throw 'Boolean outcomes do not share their return'}
        $name=if($memoryLocation) {'allow-enable-and-report'} else {'allow-install'}
        $evidence=[pscustomobject]@{ReturnRva=$ret.Address-$imageBase;TypeBitSet=$type.BitSet}
    }
    return [pscustomobject]@{Name=$name;Offset=$nativeState.offset;PatchOffset=$nativeState.offset+$guard.Address-$nativeState.lo;
        Replacement=(Native-BranchPatch $guard);ExtraEvidence=$evidence;Manifest=$manifest;Type=$type.Origin;Location=$locationOrigin;
        FiveOffset=$nativeState.offset+$locations['5']-$nativeState.lo;TenOffset=$nativeState.offset+$locations['0Ah']-$nativeState.lo;
        TypeOffsets=@($type.Offsets | ForEach-Object {$nativeState.offset+$_-$nativeState.lo});CallRva=$null;NormalCallRva=$null}
}
function Native-Integer([string]$text) {
    if($text -match '^([0-9a-f]+)h$') {return [long][Convert]::ToUInt64($Matches[1],16)}
    if($text -match '^\d+$') {return [long]$text}
    throw 'Unknown integer'
}
function Native-Scalar([string]$text,[hashtable]$registers) {
    if($text -eq 'al') {if(!$registers.ContainsKey('rax')) {throw 'Undefined scalar return'}; return [long]$registers.rax -band 255}
    if($text -match '^(r\w+|e\w+)$') {
        $reg=Canonical-Register $text
        if(!$registers.ContainsKey($reg)) {throw 'Undefined scalar input'}
        $value=[long]$registers[$reg]
        if($text -match '^(e\w+|r[0-9]+d)$') {$value=$value -band 0xffffffffL}
        return $value
    }
    return Native-Integer $text
}
function Native-EvaluateValidator([uint64]$entry,[long]$value) {
    $registers=@{rcx=($value -band 0xffffffffL)}; $at=$entry; $seen=@{}; $equal=$null; $less=$null; $unsignedLess=$null; $carry=$null
    for($step=0;$step -lt 64;$step++) {
        if($seen.ContainsKey($at)) {throw 'Validator execution cycle'}; $seen[$at]=$true
        $ins=Read-Instruction $at; $at=$ins.End; $parts=$ins.Args.Split(',')
        switch($ins.Op) {
            'ret' {return Native-Scalar 'al' $registers}
            'nop' {}
            'jmp' {$at=$ins.Target}
            'mov' {
                $scalar=Native-Scalar $parts[1] $registers
                $dest=if($parts[0] -eq 'al') {'rax'} else {Canonical-Register $parts[0]}
                $registers[$dest]=$scalar
            }
            'xor' {$registers[(Canonical-Register $parts[0])]=0L; $equal=$true; $less=$false; $unsignedLess=$false; $carry=$false}
            'cmp' {
                $left=(Native-Scalar $parts[0] $registers) -band 0xffffffffL
                $right=(Native-Scalar $parts[1] $registers) -band 0xffffffffL
                $signedLeft=if($left -ge 0x80000000L) {$left-0x100000000L} else {$left}
                $signedRight=if($right -ge 0x80000000L) {$right-0x100000000L} else {$right}
                $equal=$left -eq $right; $less=$signedLeft -lt $signedRight; $unsignedLess=$left -lt $right; $carry=$unsignedLess
            }
            'bt' {
                $bits=Native-Scalar $parts[0] $registers
                $width=if($parts[0] -match '^(e\w+|r[0-9]+d)$') {32} else {64}
                $bit=(Native-Scalar $parts[1] $registers) -band ($width-1)
                $carry=($bits -band (1L -shl $bit)) -ne 0
            }
            default {
                $take=switch($ins.Op) {
                    'je' {$equal} 'jne' {!$equal} 'jg' {!$equal -and !$less} 'jle' {$equal -or $less}
                    'ja' {!$equal -and !$unsignedLess} 'jbe' {$equal -or $unsignedLess} 'jae' {!$carry} 'jb' {$carry}
                    default {throw 'Unknown scalar validator instruction'}
                }
                if($null -eq $take) {throw 'Undefined validator flags'}
                if($take) {$at=$ins.Target}
            }
        }
    }
    throw 'Validator execution budget exceeded'
}
function Native-Validator([uint64]$entry) {
    # Accept only a finite, side-effect-free integer decision graph. Sentinel checks supplement its shape.
    $colors=@{}; $pending=[Collections.Generic.Stack[object]]::new(); $pending.Push(@($entry,$false))
    $hasMv2=$false; $hasTrue=$false; $hasFalse=$false; $returns=0
    while($pending.Count) {
        $item=$pending.Pop(); $at=[uint64]$item[0]
        if($item[1]) {$colors[$at]=2; continue}
        if($colors[$at] -eq 1) {throw 'Validator graph has a cycle'}
        if($colors[$at] -eq 2) {continue}
        if($colors.Count -ge 96) {throw 'Validator graph budget exceeded'}
        $colors[$at]=1; $ins=Read-Instruction $at; $edges=@($ins.End)
        $pending.Push(@($at,$true))
        switch($ins.Op) {
            'ret' {$returns++; $edges=@()}
            'nop' {}
            'mov' {
                if($ins.Args -match '^al,([01])$') {if($Matches[1] -eq '1') {$hasTrue=$true} else {$hasFalse=$true}}
                elseif($ins.Args -eq 'ecx,ecx') {}
                elseif($ins.Args -match '^(rdx|edx|r8|r8d|r9|r9d),[0-9a-f]+h?$') {}
                else {throw 'Validator has an unknown move'}
            }
            'xor' {if($ins.Args -ne 'eax,eax') {throw 'Validator has an unknown write'}; $hasFalse=$true}
            'cmp' {if($ins.Args -notmatch '^ecx,([0-9a-f]+h?)$') {throw 'Validator compares an unknown input'}; if((Native-Integer $Matches[1]) -eq 0x800000) {$hasMv2=$true}}
            'bt' {if($ins.Args -notmatch '^(rdx|edx|r8|r8d|r9|r9d),(rcx|ecx)$') {throw 'Validator has an unknown bit test'}}
            'jmp' {$edges=@($ins.Target)}
            default {if($ins.Op -notin @('je','jne','jg','jle','ja','jbe','jae','jb')) {throw 'Validator has effects or unsupported instructions'}; $edges+=,$ins.Target}
        }
        foreach($edge in $edges) {$pending.Push(@([uint64]$edge,$false))}
    }
    if(!$hasMv2 -or !$hasTrue -or !$hasFalse -or !$returns) {throw 'Not a reason validator shape'}
    $samples=@()
    foreach($sample in @(0L,1L,3L,6L,0x800000L,0x2000000L,0x7fffffffL,0x80000000L,0xffffffffL)) {
        $wanted=if($sample -in @(0L,1L,0x800000L,0x2000000L)) {1} else {0}
        $got=Native-EvaluateValidator $entry $sample
        if($got -ne $wanted) {throw "Reason validator sentinel mismatch: $sample"}
        $samples+=[pscustomobject]@{Input=$sample;Return=$got}
    }
    return [pscustomobject]@{Kind='reason-validator';Instructions=$colors.Count;Samples=$samples}
}
function Native-Callee([uint64]$rva,[string]$kind) {
    $cacheKey=$kind+':'+$rva
    if($calleeCache.ContainsKey($cacheKey)) {return $calleeCache[$cacheKey]}
    $saved=$nativeState.Clone()
    try {
        $section=@($pe.ExecutableRanges | Where-Object {$rva -ge $_.VirtualAddress -and $rva -lt $_.VirtualAddress+$_.Length})
        if($section.Count -ne 1) {throw 'Extra callee is not executable'}
        $calleeOffset=$section[0].Start+$rva-$section[0].VirtualAddress
        if($kind -eq 'reason-insert') {
            if((Native-FunctionSpan $calleeOffset).Begin -ne $imageBase+$rva) {throw 'Reason callee does not start at a runtime function boundary'}
            $calleeCache[$cacheKey]=Test-Callee $rva $kind
            return $calleeCache[$cacheKey]
        }
        # The pure validator is a leaf function and has no x64 runtime-function entry.
        $range=@($pe.ExecutableRanges | Where-Object {$rva -ge $_.VirtualAddress -and $rva+4096 -le $_.VirtualAddress+$_.Length})
        if($range.Count -ne 1) {throw 'Extra callee is outside executable sections'}
        $nativeState.offset=[long]($range[0].Start+$rva-$range[0].VirtualAddress)
        $nativeState.lo=$imageBase+$rva; $nativeState.hi=$nativeState.lo+4096; $nativeState.cache=@{}
        $path=Join-Path $dumpRoot 'validator.dmp'
        Write-NativeDump $path ([long[]]@($nativeState.offset)) ([uint64[]]@($nativeState.lo))
        $nativeState.engine=[Mv2NativeDisassembler]::new($path)
        try {$calleeCache[$cacheKey]=Native-Validator $nativeState.lo; return $calleeCache[$cacheKey]} finally {$nativeState.engine.Dispose()}
    } finally {foreach($key in $saved.Keys) {$nativeState[$key]=$saved[$key]}}
}
function Native-FunctionSpan([long]$offset) {
    if(!$nativeState.runtimeFunctions) {
        $dos=Read-StreamRange $Stream 0 64; $peAt=[BitConverter]::ToInt32($dos,60)
        $header=Read-StreamRange $Stream $peAt 264
        $count=[BitConverter]::ToUInt16($header,6); $optional=[BitConverter]::ToUInt16($header,20)
        if($count -lt 1 -or $count -gt 96 -or $optional -lt 144) {throw 'Invalid runtime directory header'}
        $sections=Read-StreamRange $Stream ($peAt+24+$optional) (40*$count)
        $rva=[BitConverter]::ToUInt32($header,160); $size=[BitConverter]::ToUInt32($header,164)
        if(!$rva -or !$size -or $size%12 -or $size -gt 32MB) {throw 'Invalid runtime directory size'}
        $matches=@(for($i=0;$i -lt $sections.Length;$i+=40) {
            $begin=[BitConverter]::ToUInt32($sections,$i+12); $length=[BitConverter]::ToUInt32($sections,$i+16)
            if($rva -ge $begin -and [long]$rva+$size -le [long]$begin+$length) {[long][BitConverter]::ToUInt32($sections,$i+20)+$rva-$begin}
        })
        if($matches.Count -ne 1) {throw 'Runtime directory is not file-backed'}
        $nativeState.runtimeFunctions=Read-StreamRange $Stream $matches[0] $size
        if(!$nativeState.runtimeFunctions) {throw 'Truncated runtime directory'}
    }
    $data=$nativeState.runtimeFunctions; $rva=ConvertTo-PeRva $pe $offset 1
    $lo=0; $hi=[int]($data.Length/12)-1
    while($lo -le $hi) {
        $mid=[int][Math]::Floor(($lo+$hi)/2); $begin=[BitConverter]::ToUInt32($data,12*$mid); $end=[BitConverter]::ToUInt32($data,12*$mid+4)
        if($rva -lt $begin) {$hi=$mid-1} elseif($rva -ge $end) {$lo=$mid+1} else {
            if($end -le $begin -or $end-$begin -gt 4096) {throw 'Reason function exceeds bounded window'}
            $range=@($pe.ExecutableRanges | Where-Object {$begin -ge $_.VirtualAddress -and $begin+4096 -le $_.VirtualAddress+$_.Length})
            if($range.Count -ne 1) {throw 'Reason function is not executable'}
            return [pscustomobject]@{Offset=[long]($range[0].Start+$begin-$range[0].VirtualAddress);Begin=$imageBase+$begin;End=$imageBase+$end}
        }
    }
    throw 'Reason candidate has no runtime function boundary'
}
function Native-ReasonOutput($span,[string]$output) {
    if($output -notin @('rbx','rbp','rsi','rdi','r12','r13','r14','r15')) {throw 'Reason output is not preserved across calls'}
    $state=@{rcx='arg1';rdx='arg2';r8='arg3';r9='arg4'}; $xmm=@{}; $zeros16=@{}; $zeros8=@{}; $lengthReads=@{}; $prefixCalls=@()
    $at=$span.Begin; $binding=$null; $origin=$null
    for($i=0;$i -lt 64;$i++) {
        $ins=Read-Instruction $at; $at=$ins.End
        if($ins.Op -match '^j' -or $ins.Op -eq 'ret') {break}
        if($ins.Op -eq 'call') {
            $prefixCalls+=[pscustomobject]@{Rva=$ins.Target-$imageBase;This=$state['rcx'];Output=$state['rdx'];Key=$state['r8']}
            foreach($r in @('rax','rcx','rdx','r8','r9','r10','r11')) {$state[$r]='unknown-call'}; continue
        }
        if($ins.Op -eq 'xorps' -and $ins.Args -match '^(xmm\d+),\1$') {$xmm[$Matches[1]]=$true; continue}
        if($ins.Op -in @('movups','movaps') -and $ins.Args -match '^xmmword ptr (\[[^\]]+\]),(xmm\d+)$') {
            $where=Resolve-Value $Matches[1] $state; if($xmm[$Matches[2]]) {$zeros16[$where]=$ins.Address}; continue
        }
        if($ins.Op -eq 'mov' -and $ins.Args -match '^qword ptr (\[[^\]]+\]),([^,]+)$') {
            $where=Resolve-Value $Matches[1] $state; $value=Resolve-Value $Matches[2] $state
            if($value -eq '0') {$zeros8[$where]=$ins.Address}; continue
        }
        if($ins.Op -in @('mov','lea') -and $ins.Args -match '^(r\w+|e\w+),') {
            if($ins.Op -eq 'mov') {$value=Resolve-Value $ins.Args.Split(',')[1] $state; if($value -like 'qword ptr *+8]') {$lengthReads[$value]=$ins.Address}}
            $dest=Canonical-Register $Matches[1]; Apply-Copy $ins $state
            if($dest -eq $output) {if($binding) {throw 'Reason output is rebound'}; $binding=$ins.Address; $origin=$state[$output]}
        } elseif($ins.Op -eq 'xor' -and $ins.Args -match '^([^,]+),\1$') {$state[(Canonical-Register $Matches[1])]='0'}
        elseif($ins.Op -notin @('push','cmp','test','nop') -and $ins.Args -match '^([re][a-z0-9]+),') {
            $dest=Canonical-Register $Matches[1]
            if($dest -ne 'rsp') {$state[$dest]='unknown-write'}
        }
    }
    if(!$binding -or $origin -notin @('arg1','arg2') -or $state[$output] -ne $origin -or
        !$zeros16.ContainsKey('[{'+$origin+'}]') -or !$zeros8.ContainsKey('[{'+$origin+'}+10h]')) {throw 'Reason output is not an initialized caller-owned set'}
    $role=$null
    if($prefixCalls.Count -eq 0 -and $origin -eq 'arg1' -and $lengthReads.ContainsKey('qword ptr [{arg2}+8]')) {$role='set-to-set'}
    elseif($prefixCalls.Count -eq 1 -and $origin -eq 'arg2') {
        $source=$prefixCalls[0]; $local=$source.Output
        if($source.This -eq 'arg1' -and $source.Key -eq 'arg3' -and $local -match '^\[rsp\+[0-9a-f]+h\]$' -and
            $zeros16.ContainsKey('[{'+$local+'}]') -and $zeros8.ContainsKey('[{'+$local+'}+10h]') -and $lengthReads.ContainsKey('qword ptr [{'+$local+'}+8]')) {$role='read-then-collapse'}
    }
    if(!$role) {throw 'Reason caller input/output roles disagree'}
    # Decode the bounded function, requiring the same preserved output and a pointer-return epilogue.
    $at=$span.Begin; $returnCopy=$null; $ret=$null; $afterCopy=$false
    while($at -lt $span.End) {
        $ins=Read-Instruction $at; $at=$ins.End
        if($ins.Op -eq 'mov' -and $ins.Args -eq "rax,$output") {
            if($returnCopy) {throw 'Multiple reason return copies'}; $returnCopy=$ins.Address; $afterCopy=$true; continue
        }
        if($ins.Op -eq 'ret') {
            if(!$afterCopy -or $ret) {throw 'Reason function does not return its output pointer'}
            $ret=$ins.Address; $afterCopy=$false; continue
        }
        if($afterCopy -and !($ins.Op -in @('pop','nop') -or ($ins.Op -eq 'add' -and $ins.Args -match '^rsp,') -or ($ins.Op -in @('movaps','movups') -and $ins.Args -match '^xmm\d+,xmmword ptr \[rsp'))) {throw 'Reason pointer return has unknown effects'}
        if($ins.Address -ne $binding -and $ins.Op -notin @('push','pop','cmp','test','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+),') {
            if((Canonical-Register $Matches[1]) -eq $output) {throw 'Caller-owned reason output was overwritten'}
        }
    }
    if(!$returnCopy -or !$ret) {throw 'No caller-owned set return'}
    return [pscustomobject]@{Kind='caller-owned-set-return';Role=$role;Argument=$origin;OutputRegister=$output;FunctionRva=$span.Begin-$imageBase;SourceCalls=$prefixCalls;
        BindingOffset=$span.Offset+$binding-$span.Begin;ReturnOffset=$span.Offset+$returnCopy-$span.Begin;
        Zero16Offset=$span.Offset+$zeros16['[{'+$origin+'}]']-$span.Begin;Zero8Offset=$span.Offset+$zeros8['[{'+$origin+'}+10h]']-$span.Begin}
}
function Native-Reason([uint64]$Address) {
    $span=Native-FunctionSpan $nativeState.offset
    $saved=$nativeState.Clone(); $window=[long]$span.Offset
    try {
        $nativeState.offset=$window; $nativeState.lo=$span.Begin; $nativeState.hi=$span.End; $nativeState.cache=@{}
        $path=Join-Path $dumpRoot 'reason.dmp'
        Write-NativeDump $path ([long[]]@($window)) ([uint64[]]@($nativeState.lo))
        $nativeState.engine=[Mv2NativeDisassembler]::new($path)
        try {
            $entry=Read-Instruction $Address
            if($entry.Op -ne 'mov' -or $entry.Args -notmatch '^ecx,(e\w+|r[0-9]+d)$') {throw 'No reason-validation argument'}
            $reasonReg=$Matches[1]; $reasonCanonical=Canonical-Register $reasonReg
            $call=Next-Real $entry.End
            if($call.Op -ne 'call' -or !$call.Target) {throw 'No direct reason validator'}
            $test=Next-Real $call.End; $j=Next-Real $test.End
            if($test.Op -ne 'test' -or $test.Args -ne 'al,al' -or $j.Op -notin @('je','jne')) {throw 'Reason validation result is not tested'}
            $valid=if($j.Op -eq 'jne') {$j.Target} else {$j.End}
            $invalid=if($j.Op -eq 'je') {$j.Target} else {$j.End}
            $bad=Next-Real $invalid
            if($bad.Op -ne 'mov' -or $bad.Args -notmatch '^(dword ptr \[rsp\+[0-9a-f]+h\]),2000000h$') {throw 'Unknown reason is not stored in a stack slot'}
            $slot=$Matches[1]
            $good=Next-Real $valid
            if($good.Op -ne 'mov' -or $good.Args -ne "$slot,$reasonReg") {throw 'Valid reason does not use the same slot and value'}
            $join=(Next-Real $bad.End).Address
            if((Next-Real $good.End).Address -ne $join) {throw 'Reason stores do not converge'}
            $setup=Read-CallSetup $join
            foreach($reg in @('rcx','rdx','r8','r9')) {if($setup.State[$reg] -notmatch '^r\w+$') {throw 'Unknown reason insertion argument'}}
            if($setup.State['r8'] -ne $setup.State['r9'] -or $setup.State['rcx'] -eq $setup.State['rdx']) {throw 'Reason insertion arguments disagree'}
            $outputEvidence=Native-ReasonOutput $span $setup.State['rcx']
            $advance=Next-Real $setup.Call.End
            if($advance.Op -ne 'add' -or $advance.Args -notmatch '^(r\w+),4$') {throw 'Reason iterator stride changed'}
            $iterator=$Matches[1]; $limit=Next-Real $advance.End; $repeat=Next-Real $limit.End
            if($limit.Op -ne 'cmp' -or $limit.Args -notmatch '^([^,]+),([^,]+)$' -or $iterator -notin @($Matches[1],$Matches[2]) -or $Matches[1] -eq $Matches[2] -or $repeat.Op -ne 'jne') {throw 'No bounded reason iterator comparison'}
            $load=Next-Real $repeat.Target
            if($load.Op -ne 'mov' -or $load.Args -notmatch ('^'+[regex]::Escape($reasonReg)+',dword ptr \[([^\]]+)\]$')) {throw 'Reason loop has no element load'}
            $addressRegs=$Matches[1].Split('+')
            if($addressRegs.Count -gt 2 -or $iterator -notin $addressRegs -or @($addressRegs | Where-Object {$_ -notin @('rbx','rbp','rsi','rdi','r12','r13','r14','r15')}).Count -or (Next-Real $load.End).Address -ne $entry.Address) {throw 'Reason loop does not reload the validated element'}
            # Require a visible, unmodified LEA tying the insertion key pointer to the written slot.
            $pointer=$setup.State['r8']; $slotAddress=$slot.Substring('dword ptr '.Length); $bound=$false
            for($at=$nativeState.lo;$at -lt $load.Address;$at++) {
                try {
                    $decoded=$nativeState.engine.Decode($at)
                    if($decoded.Text -notmatch '\slea\s+' -or !$decoded.Text.EndsWith("$pointer,$slotAddress")) {continue}
                    $lea=Read-Instruction $at
                } catch {continue}
                if($lea.Op -ne 'lea' -or $lea.Args -ne "$pointer,$slotAddress") {continue}
                $p=$lea.End; $safe=$true
                for($n=0;$n -lt 48 -and $p -lt $load.Address;$n++) {
                    $ins=Read-Instruction $p
                    if($ins.Op -eq 'call' -or $ins.Op -eq 'jmp' -or $ins.Op -match '^(ret|int)$') {$safe=$false; break}
                    if($ins.Op -notin @('cmp','test','push','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+)(?:,|$)') {
                        if((Canonical-Register $Matches[1]) -eq $pointer) {$safe=$false; break}
                    }
                    $p=$ins.End
                }
                if($safe -and $p -eq $load.Address) {$bound=$true; break}
            }
            if(!$bound) {throw 'Reason stack key pointer is not bound in the local context'}
            $regs=@('rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15')
            $id=[Array]::IndexOf($regs,$reasonCanonical)
            if($id -lt 0 -or $reasonCanonical -in @('rax','rcx','rdx','r8','r9','r10','r11','rsp')) {throw 'Reason value is not in a preserved register'}
            $replacement=[Collections.Generic.List[byte]]::new()
            if($id -ge 8) {$replacement.Add(0x41)}
            $replacement.Add(0x81); $replacement.Add([byte](0xf8+($id-band 7)))
            $replacement.AddRange([BitConverter]::GetBytes([int]0x800000)); $replacement.AddRange([byte[]]@(0x0f,0x95,0xc0))
            $relValid=[long]$good.Address-([long]$Address+$replacement.Count+2)
            if($relValid -lt -128 -or $relValid -gt 127) {throw 'Reason valid branch exceeds short range'}
            $replacement.Add(0x75); $replacement.Add([byte]($relValid-band 255))
            $relSkip=[long]$advance.Address-([long]$Address+$replacement.Count+2)
            if($relSkip -lt -128 -or $relSkip -gt 127) {throw 'Reason skip branch exceeds short range'}
            $replacement.Add(0xeb); $replacement.Add([byte]($relSkip-band 255))
            if($Address+$replacement.Count -ge [Math]::Min($good.Address,$join)) {throw 'Reason patch overlaps a live destination'}
            $record=[pscustomobject]@{Name='ignore-mv2-disable-reason-at-runtime';Offset=[long]$saved.offset;PatchOffset=[long]$saved.offset;
                Replacement=$replacement.ToArray();CallRva=$null;NormalCallRva=$null;
                ExtraEvidence=[pscustomobject]@{ReasonRegister=$reasonReg;Slot=$slot;ValidatorRva=$call.Target-$imageBase;InsertRva=$setup.Call.Target-$imageBase;
                    LoopRva=$load.Address-$imageBase;ContinueRva=$advance.Address-$imageBase;Validator=$null;Insert=$null;Output=$outputEvidence};
                UnknownStoreOffset=$window+$bad.Address-$nativeState.lo;ValidStoreOffset=$window+$good.Address-$nativeState.lo;
                CallOffset=$window+$call.Address-$nativeState.lo;AdvanceOffset=$window+$advance.Address-$nativeState.lo;
                InsertSetupOffset=$window+$join-$nativeState.lo;LoopOffset=$window+$load.Address-$nativeState.lo}
        } finally {$nativeState.engine.Dispose(); $nativeState.engine=$null}
        $record.ExtraEvidence.Validator=Native-Callee $record.ExtraEvidence.ValidatorRva 'reason-validator'
        $record.ExtraEvidence.Insert=Native-Callee $record.ExtraEvidence.InsertRva 'reason-insert'
        return $record
    } finally {foreach($key in $saved.Keys) {$nativeState[$key]=$saved[$key]}}
}
function Read-Instruction([uint64]$Address) {
    if($Address -lt $nativeState.lo -or $Address -ge $nativeState.hi) { throw 'Trace leaves bounded snippet' }
    if($nativeState.cache.ContainsKey($Address)) { return $nativeState.cache[$Address] }
    if($nativeState.cache.Count -ge 128) { throw 'Instruction budget exceeded' }
    $decoded=$nativeState.engine.Decode($Address)
    if($decoded.End -gt $nativeState.hi) { throw 'Truncated instruction' }
    $nativeState.cache[$Address]=$decoded; $nativeState.decodeCount++
    return $decoded
}

function Read-Linear([uint64]$Address,[int]$Count) {
    $seen=@{}
    for($n=0;$n -lt $Count;$n++) {
        if($seen.ContainsKey($Address)) { throw 'Loop rejected' }; $seen[$Address]=$true
        $ins=Read-Instruction $Address
        if($ins.Op -eq 'jmp') { $Address=[uint64]$ins.Target; continue }
        $ins
        if($ins.Op -match '^(ret|int)') { break }
        $Address=$ins.End
    }
}

function Canonical-Register([string]$reg) {
    switch -Regex ($reg) {
        '^e(ax|bx|cx|dx|si|di|bp|sp)$' { return 'r'+$reg.Substring(1) }
        '^(r[0-9]+)d$' { return $Matches[1] }
        '^r(ax|bx|cx|dx|si|di|bp|sp|[0-9]+)$' { return $reg }
        default { throw "Unsupported register: $reg" }
    }
}
function Resolve-Value([string]$arg,[hashtable]$state) {
    if($arg -match '^(r\w+|e\w+)$') {
        $r=Canonical-Register $arg
        $value=if($state.ContainsKey($r)) {$state[$r]} else {$r}
        if($arg -match '^(e\w+|r[0-9]+d)$' -and $value -notmatch '^(dword ptr |low32\(|[0-9a-f]+h?$)') {return "low32($value)"}
        return $value
    }
    if($arg -match '^(?:(?:qword|dword|byte) ptr )?\[.*\]$') {
        return [regex]::Replace($arg,'\br(?:[0-9]+|ax|bx|cx|dx|si|di|bp|sp)\b',{
            param($m) if($state.ContainsKey($m.Value)) {'{'+$state[$m.Value]+'}'} else {$m.Value}
        })
    }
    if($arg -match '^[0-9a-f]+h?$') {return $arg}
    throw "Unsupported value: $arg"
}
function Apply-Copy($ins,[hashtable]$state) {
    if($ins.Op -eq 'nop') {return}
    if($ins.Op -notin @('mov','lea') -or $ins.Args -notmatch '^(r\w+|e\w+),(.+)$') {throw "Unsupported copy: $($ins.Text)"}
    $dest=Canonical-Register $Matches[1]; $src=$Matches[2]
    $value=Resolve-Value $src $state
    if($ins.Op -eq 'lea' -and $src -notmatch '^\[') {throw 'Unsupported LEA'}
    if($ins.Args.Split(',')[0] -match '^(e\w+|r[0-9]+d)$' -and $value -notmatch '^(dword ptr |low32\(|[0-9a-f]+h?$)') {$value="low32($value)"}
    $state[$dest]=$value
}
function Next-Real([uint64]$at) {
    $seen=@{}
    for($i=0;$i -lt 12;$i++) {
        if($seen.ContainsKey($at)) {throw 'Jump cycle'}; $seen[$at]=$true
        $ins=Read-Instruction $at
        if($ins.Op -eq 'jmp') {$at=[uint64]$ins.Target}
        elseif($ins.Op -eq 'nop') {$at=$ins.End}
        else {return $ins}
    }
    throw 'Jump budget exceeded'
}
function Flow-StackOperand([string]$arg,[int]$sp) {
    if($arg -notmatch '^(?:(qword|dword) ptr )?\[rsp(?:\+([0-9a-f]+)(h)?)?\]$') {return $null}
    $width=switch($Matches[1]) {'qword' {8} 'dword' {4} default {0}}
    $disp=0
    if($Matches[2]) {$disp=if($Matches[3]) {[Convert]::ToInt32($Matches[2],16)} else {[int]$Matches[2]}}
    return [pscustomobject]@{Offset=$sp+$disp;Width=$width}
}
function Flow-Copy($ins,$frame) {
    $parts=$ins.Args.Split(','); if($parts.Count -ne 2) {throw 'Unsupported flow copy'}
    $dest=$parts[0]; $src=$parts[1]
    $slot=Flow-StackOperand $dest $frame.SP
    if($slot -and $slot.Width -gt 0) {
        if($ins.Op -ne 'mov' -or $slot.Offset -lt $frame.SP -or $slot.Offset+$slot.Width -gt 0) {throw 'Store is not in freshly allocated scratch stack'}
        if($src -notmatch '^(r\w+|e\w+|[0-9a-f]+h?)$') {throw 'Unsupported stack store source'}
        $value=Resolve-Value $src $frame.State
        foreach($key in @($frame.Slots.Keys)) {
            $old=$frame.Slots[$key]
            if($slot.Offset -lt $key+$old.Width -and $key -lt $slot.Offset+$slot.Width) {$frame.Slots.Remove($key)}
        }
        $frame.Slots[$slot.Offset]=[pscustomobject]@{Width=$slot.Width;Value=$value}
        $frame.Spills++
        return
    }
    if($dest -notmatch '^(r\w+|e\w+)$' -or (Canonical-Register $dest) -eq 'rsp') {throw 'Unknown memory write or stack-pointer overwrite'}
    $sourceSlot=Flow-StackOperand $src $frame.SP
    if($sourceSlot -and $ins.Op -eq 'mov' -and $sourceSlot.Width -gt 0) {
        if(!$frame.Slots.ContainsKey($sourceSlot.Offset) -or $frame.Slots[$sourceSlot.Offset].Width -ne $sourceSlot.Width) {throw 'Stack reload has no intact matching store'}
        $value=$frame.Slots[$sourceSlot.Offset].Value
        if($dest -match '^(e\w+|r[0-9]+d)$' -and $value -notmatch '^(dword ptr |low32\(|[0-9a-f]+h?$)') {$value="low32($value)"}
        $frame.State[(Canonical-Register $dest)]=$value
        return
    }
    if($src -match '\brsp\b') {
        if(!$sourceSlot -or $ins.Op -ne 'lea') {throw 'Unknown stack read or stack address escape'}
        if($sourceSlot.Offset -lt 0) {throw 'Scratch stack address escapes into a register'}
        $canonical='[rsp+'+$sourceSlot.Offset.ToString('X')+'h]'
        $copy=[pscustomobject]@{Op='lea';Args="$dest,$canonical";Text=$ins.Text}
        Apply-Copy $copy $frame.State
        return
    }
    # A pointer to scratch storage cannot be created, and indirect writes are rejected above.
    Apply-Copy $ins $frame.State
}
function Read-CallSetup([uint64]$at) {
    # ponytail: finite call-setup CFG only, no loops, no calls before scratch is released.
    # Existing-frame spills and escaped/aliased stack slots need liveness/alias analysis later.
    $pending=[Collections.Generic.Stack[object]]::new()
    $pending.Push([pscustomobject]@{At=$at;State=@{};Slots=@{};SP=0;Seen=@{};Items=@();Spills=0;Steps=0})
    $leaves=@(); $forks=0; $steps=0
    while($pending.Count) {
        $f=$pending.Pop()
        while($true) {
            if(++$steps -gt 128 -or ++$f.Steps -gt 48) {throw 'Call-setup instruction budget exceeded'}
            if($f.Seen.ContainsKey($f.At)) {throw 'Call-setup cycle'}
            $f.Seen[$f.At]=$true
            $ins=Read-Instruction $f.At; $f.Items+=,$ins
            if($ins.Op -eq 'jmp') {$f.At=[uint64]$ins.Target; continue}
            if($ins.Op -eq 'nop') {$f.At=$ins.End; continue}
            if($ins.Op -match '^j') {
                if(++$forks -gt 7) {throw 'Call-setup path budget exceeded'}
                $pending.Push([pscustomobject]@{At=[uint64]$ins.Target;State=$f.State.Clone();Slots=$f.Slots.Clone();SP=$f.SP;Seen=$f.Seen.Clone();Items=@($f.Items);Spills=$f.Spills;Steps=$f.Steps})
                $f.At=$ins.End; continue
            }
            if($ins.Op -eq 'call') {
                if(!$ins.Target) {throw 'Indirect call rejected'}
                if($f.SP -ne 0 -or $f.Slots.Count) {throw 'Scratch stack live across call'}
                $leaves+=,[pscustomobject]@{Call=$ins;State=$f.State;Items=$f.Items;After=(Next-Real $ins.End);Spills=$f.Spills}
                break
            }
            if($ins.Op -in @('sub','add') -and $ins.Args -match '^rsp,([0-9a-f]+)(h)?$') {
                $amount=if($Matches[2]) {[Convert]::ToInt32($Matches[1],16)} else {[int]$Matches[1]}
                if($amount -le 0 -or $amount%16) {throw 'Unsupported scratch allocation alignment'}
                $f.SP+=if($ins.Op -eq 'sub') {-$amount} else {$amount}
                if($f.SP -gt 0 -or $f.SP -lt -256) {throw 'Scratch stack allocation budget exceeded'}
                foreach($key in @($f.Slots.Keys)) {if($key -lt $f.SP) {$f.Slots.Remove($key)}}
            } elseif($ins.Op -in @('cmp','test') -and $ins.Args -match '^[re][a-z0-9]+,(?:[re][a-z0-9]+|[0-9a-f]+h?)$') {
                # Both outcomes are explored; no assumption about the value of this condition.
            } elseif($ins.Op -in @('mov','lea')) {Flow-Copy $ins $f}
            else {throw "Unsupported call-setup instruction: $($ins.Text)"}
            $f.At=$ins.End
        }
    }
    if(!$leaves.Count) {throw 'No bounded direct call'}
    $first=$leaves[0]
    foreach($leaf in $leaves) {
        if($leaf.Call.Address -ne $first.Call.Address) {throw 'Paths reach different calls'}
        foreach($key in @(@($first.State.Keys)+@($leaf.State.Keys) | Sort-Object -Unique)) {
            if((Resolve-Value $key $first.State) -ne (Resolve-Value $key $leaf.State)) {throw "Path-dependent register value: $key"}
        }
    }
    $first | Add-Member NoteProperty Paths $leaves.Count
    $first | Add-Member NoteProperty TotalSpills (($leaves | Measure-Object Spills -Sum).Sum)
    return $first
}
function Classify-Candidate([uint64]$Address) {
    $state=@{}; $first=Next-Real $Address
    if($first.Op -ne 'cmp' -or $first.Args -notmatch '^(.+),2$') {throw 'No manifest comparison'}
    $manifest=Resolve-Value $Matches[1] $state
    $guard=Next-Real $first.End
    if($guard.Op -eq 'jg') {$normal=Next-Real ([uint64]$guard.Target); $at=$guard.End}
    elseif($guard.Op -eq 'jle') {$normal=Next-Real $guard.End; $at=[uint64]$guard.Target}
    else {throw 'Unsupported manifest guard'}
    $location=@{}; $typeValue=$null; $typeOther=$null; $overrideTarget=$null; $locationEntry=$null; $seen=@{}
    for($i=0;$i -lt 32;$i++) {
        $ins=Next-Real $at
        if($seen.ContainsKey($ins.Address)) {throw 'Predicate cycle'}; $seen[$ins.Address]=$true
        if($ins.Op -in @('mov','lea')) {Apply-Copy $ins $state; $at=$ins.End; continue}
        if($ins.Op -ne 'cmp' -or $ins.Args -notmatch '^(.+),(0|1|5|0Ah)$') {throw 'Unsupported predicate'}
        $operand=$Matches[1]; $value=$Matches[2]; $origin=Resolve-Value $operand $state
        $branch=Next-Real $ins.End
        if($branch.Op -notin @('je','jne')) {throw 'Predicate is not equality'}
        $equal=if($branch.Op -eq 'je') {[uint64]$branch.Target} else {$branch.End}
        $other=if($branch.Op -eq 'jne') {[uint64]$branch.Target} else {$branch.End}
        if($value -eq '0') {
            if($overrideTarget -or $operand -notlike 'byte ptr *' -or $typeValue -or $location.Count) {throw 'Unexpected override'}
            $overrideTarget=$other; $at=$equal; continue
        }
        if($value -eq '1') {
            if($typeValue -or $location.Count) {throw 'Duplicate or late type predicate'}
            $typeValue=$origin; $typeOther=(Next-Real $other).Address; $at=$equal; $afterType=(Next-Real $equal).Address; continue
        }
        if(!$typeValue -or $location.ContainsKey($value)) {throw 'Missing type or duplicate location'}
        if(!$locationEntry) {$locationEntry=$ins.Address}
        if((Next-Real $equal).Address -ne $normal.Address) {throw 'Unaffected destinations differ'}
        $location[$value]=[pscustomobject]@{Origin=$origin;Compare=$ins;Branch=$branch}
        $at=$other
        if($location.Count -eq 2) {break}
    }
    if($location.Count -ne 2 -or $location['5'].Origin -ne $location['0Ah'].Origin -or
        $location['5'].Origin -eq $typeValue -or $typeValue -eq $manifest) {throw 'Predicate value flow mismatch'}
    # The two enum fields must originate from the same object, even after register copies.
    if($manifest -like 'dword ptr *') {
        if($location['5'].Origin -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$') {throw 'Unknown location object'}
        $locationObject=$Matches[1]
        if($typeValue -notmatch '^dword ptr \[\{(.+)\}\+[0-9a-f]+h\]$' -or $Matches[1] -ne $locationObject) {throw 'Type and location come from different objects'}
    } elseif($location['5'].Origin -notmatch '^dword ptr \[r\w+\+[0-9a-f]+h\]$' -or $typeValue -notmatch '^low32\(r\w+\)$') {
        throw 'Unknown live-in predicate values'
    }
    # Register-form predicates have live-in values whose definitions precede this window.
    # Keep their distinct-value checks and require the same caller/callee evidence below.
    if($overrideTarget -and (Next-Real $overrideTarget).Address -ne $afterType) {throw 'Override does not join location check'}
    $effect=Read-CallSetup $at
    if($typeOther -eq $effect.Items[0].Address) {throw 'Type exclusion enters MV2 effect'}
    $unaffected=@(Read-Linear $normal.Address 10)
    $kind=$null; $normalCall=$null
    # Keep tree-node and result-use checks; argument instruction order is no longer fixed.
    if($unaffected[0].Op -eq 'mov' -and $unaffected[0].Args -match '^(r\w+),qword ptr \[(r\w+)\+8\]$') {
        $loaded=$Matches[1]; $node=$Matches[2]
        if($unaffected[1].Op -ne 'test' -or $unaffected[1].Args -ne "$loaded,$loaded" -or
            @($unaffected | Where-Object {$_.Op -eq 'jne' -and $_.Target -lt $_.Address}).Count -eq 0 -or
            $effect.State['r8'] -ne "[$node+38h]" -or
            $effect.State['rcx'] -notmatch '^r\w+$' -or $effect.State['rdx'] -notmatch '^r\w+$' -or
            $effect.State['rcx'] -eq $effect.State['rdx'] -or $effect.After.Address -ne $normal.Address) {throw 'Startup argument or continuation mismatch'}
        $kind='skip-startup-disable'
    } else {
        $normalCall=Read-CallSetup $normal.Address
        if($effect.State['rcx'] -notmatch '^\[rsp\+[0-9a-f]+h\]$' -or
            $effect.State['rdx'] -notmatch '^[0-9a-f]+h$' -or
            $normalCall.State['r8'] -ne $effect.State['rcx'] -or
            $normalCall.State['rcx'] -notmatch '^r\w+$' -or $normalCall.State['rdx'] -notmatch '^r\w+$' -or
            $normalCall.Call.Target -eq $effect.Call.Target) {throw 'Install argument flow mismatch'}
        $postBad=@(Read-Linear $effect.Call.End 3)
        $postGood=@(Read-Linear $normalCall.Call.End 3)
        if($postBad[0].Op -ne 'lea' -or $postGood[0].Op -ne 'lea' -or
            $postBad[0].Args -notmatch '^(r\w+),\[rsp\+[0-9a-f]+h\]$') {throw 'No bounded false result storage'}
        $badreg=$Matches[1]
        if($postGood[0].Args -notmatch '^(r\w+),\[rsp\+[0-9a-f]+h\]$') {throw 'No bounded returned result storage'}
        $goodreg=$Matches[1]
        if($postBad[1].Op -ne 'mov' -or $postBad[1].Args -ne "byte ptr [$badreg-8],0" -or
            $postGood[1].Op -ne 'mov' -or $postGood[1].Args -ne "byte ptr [$goodreg-8],al") {throw 'Return value/false result mismatch'}
        $kind='allow-install-policy-inline'
    }
    if($Inspect) {@($nativeState.cache.Values | Sort-Object Address) | ForEach-Object {$_.Text} | Out-Host}
    $patchAt=$nativeState.offset+$guard.Address-$Address
    $length=[int]($guard.End-$guard.Address)
    $replacement=[byte[]]::new($length)
    if($guard.Op -eq 'jle') {for($i=0;$i -lt $length;$i++) {$replacement[$i]=0x90}}
    elseif($length -eq 2) {$replacement[0]=0xeb; $replacement[1]=[byte](($guard.Target-$guard.End) -band 255)}
    elseif($length -eq 6) {
        $replacement[0]=0xe9; [Array]::Copy([BitConverter]::GetBytes([int]($guard.Target-($guard.Address+5))),0,$replacement,1,4); $replacement[5]=0x90
    } else {throw 'Unsupported patch encoding'}
    [pscustomobject]@{
        Name=$kind;Offset=$nativeState.offset;PatchOffset=$patchAt;Replacement=@($replacement);
        UnaffectedRva=($normal.Address-$imageBase);AffectedRva=($effect.Items[0].Address-$imageBase);
        CallRva=($effect.Call.Target-$imageBase);CallOffset=($nativeState.offset+$effect.Call.Address-$Address);
        NormalCallRva=if($normalCall) {$normalCall.Call.Target-$imageBase} else {$null};
        FlowPaths=$effect.Paths;FlowSpills=$effect.TotalSpills;Arguments=$effect.State;PredicateLocation=$location['5'].Origin;PredicateType=$typeValue;
        FiveOffset=($nativeState.offset+$location['5'].Compare.Address-$Address);
        TenOffset=($nativeState.offset+$location['0Ah'].Compare.Address-$Address);
        Decoded=$nativeState.cache.Count
    }
}
function Test-Callee([uint64]$rva,[string]$kind) {
    $range=@($pe.ExecutableRanges | Where-Object {$rva -ge $_.VirtualAddress -and $rva+4096 -le $_.VirtualAddress+$_.Length})
    if($range.Count -ne 1) {throw 'Call target outside executable section'}
    $nativeState.offset=[long]($range[0].Start+$rva-$range[0].VirtualAddress)
    $nativeState.lo=$imageBase+$rva; $nativeState.hi=$nativeState.lo+4096; $nativeState.cache=@{}
    $path=Join-Path $dumpRoot 'callee.dmp'
    Write-NativeDump $path ([long[]]@($nativeState.offset)) ([uint64[]]@($nativeState.lo))
    $nativeState.engine=[Mv2NativeDisassembler]::new($path)
    $state=@{}; $at=$nativeState.lo; $facts=@{}; $items=@(); $returned=$false
    try {
        # ponytail: inspect one linear prefix through its first RET, max 64 instructions.
        # This is extra structural evidence, not a proof of all callee paths or identity.
        for($i=0;$i -lt 64;$i++) {
            $ins=Read-Instruction $at; $items+=$ins.Text; $at=$ins.End
            if($ins.Op -eq 'ret') {$returned=$true; break}
            if($ins.Op -eq 'call') {
                if($ins.Target -and $state['r8'] -eq 'low32(rdx)' -and $state['rdx'] -eq 'rcx') {$facts.ForwardResource=$true}
                foreach($r in @('rax','rcx','rdx','r8','r9','r10','r11')) {$state[$r]='unknown-call'}
                continue
            }
            if($ins.Op -eq 'mov' -and $ins.Args -match '^(.+),(.+)$') {
                $dest=$Matches[1]; $src=$Matches[2]
                try {$origin=Resolve-Value $src $state} catch {$origin='unknown'}
                if($origin -eq 'qword ptr [rcx]') {$facts.VectorBegin=$true}; if($origin -eq 'qword ptr [rcx+8]') {$facts.VectorLength=$true}; if($origin -in @('dword ptr [r8]','dword ptr [{r8}]')) {$facts.IntKey=$true}; if($origin -eq 'qword ptr [rdx+8]' -or $origin -eq 'qword ptr [{rdx}+8]') {$facts.TreeRoot=$true}
                if($origin -eq 'qword ptr [r8]' -or $origin -eq 'qword ptr [{r8}]') {$facts.Key=$true}
                if($origin -match '^qword ptr \[rdx\+') {$facts.PolicyObject=$true}
                if($dest -match '^(r\w+|e\w+)$') {
                    try {$state[(Canonical-Register $dest)]=$origin} catch {}
                } else {
                    try {$where=Resolve-Value $dest $state} catch {$where='unknown'}
                    if($where -eq 'qword ptr [{rdx}]') {$facts.VectorResult=$true}; if($where -eq 'byte ptr [{rdx}+8]' -and $src -eq 'al' -and $state['rax'] -eq '0') {$facts.VectorFlag=$true}; if($where -eq 'qword ptr [{rcx}]') {$facts.WriteNode=$true}
                    if($where -eq 'byte ptr [{rcx}+8]' -and $src -eq 'al' -and $state['rax'] -eq '0') {$facts.WriteInserted=$true}
                    if($where -eq 'qword ptr [{rcx}+10h]' -and $src -eq '0') {$facts.ClearString=$true}
                }
                continue
            }
            if($ins.Op -eq 'xor' -and $ins.Args -match '^([^,]+),\1$') {
                try {$state[(Canonical-Register $Matches[1])]='0'} catch {}
            } elseif($ins.Op -notin @('push','pop','cmp','test','nop') -and $ins.Op -notmatch '^j' -and $ins.Args -match '^([re][a-z0-9]+),') {
                try {$state[(Canonical-Register $Matches[1])]='unknown-write'} catch {}
            }
            if($ins.Op -eq 'lea' -and $ins.Args -match '\*4\]') {$facts.Scale4=$true}; if($ins.Op -eq 'cmp' -and $ins.Args -match '^dword ptr \[.+\],(r\w+d)$' -and (Resolve-Value $Matches[1] $state) -in @('dword ptr [r8]','dword ptr [{r8}]')) {$facts.CompareKey=$true}; if($ins.Op -eq 'cmp' -and $ins.Args -match ',5$') {$facts.ComponentPolicy=$true}
        }
        $facts.ReturnsOutput=$state['rax'] -eq 'rcx'
        if(!$returned) {throw 'Callee return outside instruction budget'}
        $accepted=switch($kind) {
            'skip-startup-disable' {$facts.TreeRoot -and $facts.Key -and $facts.WriteNode -and $facts.WriteInserted -and $facts.ReturnsOutput}
            'allow-install-policy-inline' {$facts.ForwardResource -and $facts.ClearString -and $facts.ReturnsOutput}
            'normal-policy' {$facts.PolicyObject -and $facts.ComponentPolicy}
'reason-insert' {$facts.VectorBegin -and $facts.VectorLength -and $facts.IntKey -and $facts.Scale4 -and $facts.CompareKey -and $facts.VectorResult -and $facts.VectorFlag -and $state['rax'] -eq 'rdx'}
        }
        if(!$accepted) {throw "Callee shape mismatch: $kind / $($facts | ConvertTo-Json -Compress)"}
        return [pscustomobject]@{Rva=$rva;Kind=$kind;Facts=$facts;Instructions=$items}
    } finally {$nativeState.engine.Dispose()}
}

    function Write-NativeDump([string]$path,[long[]]$offsets,[uint64[]]$addresses) {
        $packed=[byte[]]::new(4096*$offsets.Count); $local=[long[]]::new($offsets.Count)
        for($i=0;$i -lt $offsets.Count;$i++) {
            $part=Read-StreamRange $Stream $offsets[$i] 4096
            if($null -eq $part) {throw 'Truncated native snippet'}
            $local[$i]=4096*$i; [Array]::Copy($part,0,$packed,4096*$i,4096)
        }
        [Mv2SnippetDump]::Write($path,$packed,$local,$addresses,$imageBase)
    }
    try {
        $seeds=[Collections.Generic.HashSet[long]]::new(); $block=4MB
        $buffer=[byte[]]::new($block+4097)
        foreach($range in $pe.ExecutableRanges) {
            $end=$range.Start+$range.Length
            for($core=$range.Start;$core -lt $end;$core+=$block) {
                $coreEnd=[Math]::Min($end,$core+$block); $begin=[Math]::Max($range.Start,$core-1)
                $count=[int]([Math]::Min($end,$coreEnd+4096)-$begin)
                $Stream.Position=$begin; $read=0
                while($read -lt $count) {$n=$Stream.Read($buffer,$read,$count-$read); if($n -le 0) {throw 'Short native scan read'}; $read+=$n}
                $hits=@()
                if($traceManifests) {$hits+=[Mv2SmallScan]::Seeds($buffer,0,$count)}
                if($traceReasons) {$hits+=[Mv2SmallScan]::Reasons($buffer,$count)}
                foreach($hit in $hits) {
                    $absolute=$begin+$hit
                    if($absolute -ge $core -and $absolute -lt $coreEnd) {[void]$seeds.Add($absolute)}
                }
                if($seeds.Count -gt 64) {throw 'Native candidate budget exceeded'}
            }
        }
        $offsets=@($seeds | Sort-Object)
        if(!$offsets.Count) {throw 'No bounded native candidates'}
        # Release streamed scan buffers before DbgEng's native allocations overlap them.
        $buffer=$null
        if($RuleNames.Count -lt $supported.Count) {[GC]::Collect()}
        $addresses=@(foreach($off in $offsets) {$imageBase+[uint64](ConvertTo-PeRva $pe $off 4096)})
        $dump=Join-Path $dumpRoot 'candidates.dmp'
        $results=@(); $rejected=@(); $reasonSeeds=@()
        if($traceManifests) {
        Write-NativeDump $dump ([long[]]$offsets) ([uint64[]]$addresses)
        $nativeState.engine=[Mv2NativeDisassembler]::new($dump)
        try {
            for($c=0;$c -lt $offsets.Count;$c++) {
                $nativeState.offset=[long]$offsets[$c]; $nativeState.lo=[uint64]$addresses[$c]; $nativeState.hi=$nativeState.lo+4096; $nativeState.cache=@{}
                try {
                    if((Read-Instruction $nativeState.lo).Op -eq 'mov') {
                        if($traceReasons) {$reasonSeeds+=@{Offset=$nativeState.offset;Address=$nativeState.lo}}
                    } else {
                        $item=$null
                        if($traceOriginal) {try {$item=Classify-Candidate $nativeState.lo} catch {}}
                        if(!$item -and $traceAdditional) {$item=Native-Manifest $nativeState.lo}
                        if($item -and $item.Name -in $RuleNames) {$results+=$item}
                    }
                }
                catch {$rejected+=[pscustomobject]@{Offset=$nativeState.offset;Reason=$_.Exception.Message}}
            }
        } finally {$nativeState.engine.Dispose(); $nativeState.engine=$null}
        } else {
            for($c=0;$c -lt $offsets.Count;$c++) {$reasonSeeds+=@{Offset=$offsets[$c];Address=$addresses[$c]}}
        }
        foreach($seed in $reasonSeeds) {
            $nativeState.offset=$seed.Offset; $nativeState.lo=$seed.Address; $nativeState.hi=$seed.Address+4096; $nativeState.cache=@{}
            try {$results+=Native-Reason $seed.Address}
            catch {$rejected+=[pscustomobject]@{Offset=$seed.Offset;Reason=$_.Exception.Message}}
        }
        # Keep diagnostics, but only caller-owned set returns now reach this list.
        $reasonResults=@($results | Where-Object Name -eq 'ignore-mv2-disable-reason-at-runtime')
        if($reasonResults.Count -eq 2) {
            $evidence=@($reasonResults.ExtraEvidence)
            if((@($evidence.Output.Role | Sort-Object) -join ',') -ne 'read-then-collapse,set-to-set' -or
                @($evidence.ValidatorRva | Sort-Object -Unique).Count -ne 1 -or @($evidence.InsertRva | Sort-Object -Unique).Count -ne 1) {throw 'Reason pair has inconsistent roles or callees'}
        }
        if($VerbosePreference -ne 'SilentlyContinue') {$rejected | ForEach-Object {Write-Verbose ("Native candidate {0}: {1}" -f $_.Offset,$_.Reason)}}
        foreach($name in $RuleNames) {
            if(@($results | Where-Object Name -eq $name).Count -ne $(if($name -in @('allow-enable-and-report','ignore-mv2-disable-reason-at-runtime')) {2} else {1})) {throw "Non-unique native result for $name"}
        }
        foreach($result in $results | Where-Object {$_.Name -in @('skip-startup-disable','allow-install-policy-inline')}) {
            $evidence=@(Test-Callee $result.CallRva $result.Name)
            if($result.NormalCallRva) {$evidence+=Test-Callee $result.NormalCallRva 'normal-policy'}
            $result | Add-Member NoteProperty CalleeEvidence $evidence
        }
        return $results
    } finally {
        foreach($name in @('candidates.dmp','callee.dmp','reason.dmp','validator.dmp')) {
            $file=Join-Path $dumpRoot $name
            if([IO.File]::Exists($file)) {[IO.File]::Delete($file)}
        }
        [IO.Directory]::Delete($dumpRoot)
    }
}

function Get-Mv2StreamRuleResults {
    param([IO.FileStream]$Stream,$Profile,$PeInfo)
    $patterns=@(); $hits=@{}; $window=4096
    foreach($rule in $Profile.Rules) {
        $hits[$rule.Name]=[Collections.Generic.HashSet[long]]::new()
        $variants=if($rule.ContainsKey('Variants')) {@($rule.Variants)} else {@($rule)}
        foreach($variant in $variants) {
            $pattern=ConvertTo-MaskedPattern $variant.Pattern
            $patch=Get-VariantPatchPatterns $rule $variant
            $at=[int]$variant.PatchOffset
            if($at -lt 0 -or $at+$patch.Original.Length -gt $pattern.Length -or $pattern.Length -gt $window) {throw 'Invalid streamed pattern window'}
            if($variant.ContainsKey('RequiredPattern') -and ($variant.RequiredPatternOffset -lt 0 -or
                $variant.RequiredPatternOffset+(ConvertTo-MaskedPattern $variant.RequiredPattern).Length -gt $window)) {throw 'Required pattern exceeds streamed window'}
            for($i=0;$i -lt $patch.Original.Length;$i++) {$pattern.Values[$at+$i]=0; $pattern.Masks[$at+$i]=0}
            $patterns+=[pscustomobject]@{Name=$rule.Name;Values=$pattern.Values;Masks=$pattern.Masks}
        }
    }
    $block=4MB; $buffer=[byte[]]::new($block+$window)
    foreach($range in $PeInfo.ExecutableRanges) {
        $end=$range.Start+$range.Length
        for($begin=$range.Start;$begin -lt $end;$begin+=$block) {
            $coreEnd=[Math]::Min($end,$begin+$block)
            $count=[int]([Math]::Min($end,$coreEnd+$window)-$begin)
            $Stream.Position=$begin; $read=0
            while($read -lt $count) {$n=$Stream.Read($buffer,$read,$count-$read); if($n -le 0) {throw 'Short pattern scan read'}; $read+=$n}
            foreach($pattern in $patterns) {
                foreach($hit in [Mv2SmallScan]::Masked($buffer,$pattern.Values,$pattern.Masks,$count)) {
                    if($begin+$hit -lt $coreEnd) {[void]$hits[$pattern.Name].Add($begin+$hit)}
                }
                if($hits[$pattern.Name].Count -gt 1024) {throw 'Pattern candidate budget exceeded'}
            }
        }
    }
    foreach($rule in $Profile.Rules) {
        $candidates=@(); $seen=@{}
        foreach($hit in ($hits[$rule.Name] | Sort-Object)) {
            $range=@($PeInfo.ExecutableRanges | Where-Object {$hit -ge $_.Start -and $hit -lt $_.Start+$_.Length})
            if($range.Count -ne 1) {throw 'Ambiguous candidate section'}
            $count=[int][Math]::Min($window,$Stream.Length-$hit)
            $part=Read-StreamRange $Stream $hit $count
            $localPe=[pscustomobject]@{ExecutableRanges=@([pscustomobject]@{Start=0L;Length=[long][Math]::Min($count,$range[0].Start+$range[0].Length-$hit)})}
            $validated=Get-RuleResult $part $rule $localPe
            foreach($candidate in $validated.Candidates | Where-Object MatchOffset -eq 0) {
                $candidate.MatchOffset+=$hit; $candidate.PatchOffset+=$hit
                if(!$seen.ContainsKey($candidate.PatchOffset) -or ($rule.ContainsKey('Variants') -and $candidate.Variant -lt $seen[$candidate.PatchOffset].Variant)) {
                    $seen[$candidate.PatchOffset]=$candidate
                }
            }
        }
        # Keep original variant precedence when different signatures share a patch site.
        $candidates=@(if($rule.ContainsKey('Variants')) {$seen.Values | Sort-Object Variant,MatchOffset} else {$seen.Values | Sort-Object MatchOffset})
        $result=[pscustomobject]@{Name=$rule.Name;Description=$rule.Description;MatchCount=$candidates.Count;Candidates=$candidates;Rule=$rule}
        if(!$rule.ContainsKey('Variants')) {
            $result | Add-Member NoteProperty OriginalPattern (ConvertTo-Pattern $rule.Original)
            $result | Add-Member NoteProperty ReplacementPattern (ConvertTo-Pattern $rule.Replacement)
        }
        $result
    }
}

function Resolve-TargetStreamAnalysis {
    param([string]$Path,[string]$CatalogPath)
    $catalog=Import-PowerShellDataFile -LiteralPath $CatalogPath
    if($catalog.SchemaVersion -ne 1) {throw 'Unsupported signature catalog schema'}
    $stream=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        $pe=Get-PeStreamInfo $stream
        $profiles=@($catalog.Profiles | Where-Object {[int]$_.Machine -eq $pe.Machine})
        $profileResults=@(); $nativeEvidence=@()
        foreach($profile in $profiles) {
            $rules=@(Get-Mv2StreamRuleResults $stream $profile $pe)
            $bad=@($rules | Where-Object {(Get-RuleState $_) -eq 'Invalid'})
            $nativeNames=@('skip-startup-disable','allow-install-policy-inline','allow-enable-and-report','allow-enable-policy-inline','allow-install','ignore-mv2-disable-reason-at-runtime')
            # Never use tracing to excuse mixed bytes, duplicate signatures, or a broken unrelated rule.
            if($profile.Id -eq 'chromium-x64-manifest-v2-semantic' -and $rules.Count -eq 6 -and $bad.Count -gt 0 -and
                @($bad | Where-Object {$_.Name -notin $nativeNames -or $_.MatchCount -ne 0}).Count -eq 0 -and
                @($rules | Where-Object {$_.Name -notin $nativeNames -and (Get-RuleState $_) -ne 'Original'}).Count -eq 0 -and
                @($rules | Where-Object {$_.Name -in $nativeNames -and $_.MatchCount -gt 0 -and (Get-RuleState $_) -ne 'Original'}).Count -eq 0) {
                try {
                    $native=@(Get-Mv2NativeRules $stream $pe -RuleNames @($bad.Name))
                    foreach($group in $native | Group-Object Name) {
                        $matching=@($rules | Where-Object Name -eq $group.Name)[0]
                        if($group.Count -ne (Get-ExpectedMatchCount $matching.Rule)) {throw 'Native count disagreement'}
                        if($matching.MatchCount -gt 0 -and
                            ((@($matching.Candidates.PatchOffset | Sort-Object) -join ',') -ne (@($group.Group.PatchOffset | Sort-Object) -join ','))) {throw 'Native/signature set disagreement'}
                    }
                    foreach($group in $native | Group-Object Name) {
                        $matching=@($rules | Where-Object Name -eq $group.Name)[0]
                        if($matching.MatchCount -ne 0) {continue}
                        $candidates=@(foreach($item in $group.Group) {
                            $before=Read-StreamRange $stream $item.PatchOffset $item.Replacement.Count
                            if($null -eq $before) {throw 'Truncated native patch'}
                            [pscustomobject]@{MatchOffset=[long]$item.Offset;PatchOffset=[long]$item.PatchOffset;
                                State='Original';Variant=-1;OriginalPattern=$before;ReplacementPattern=[byte[]]$item.Replacement}
                        })
                        $matching.Candidates=$candidates; $matching.MatchCount=$candidates.Count
                        $nativeEvidence+=@($group.Group)
                    }
                } catch {Write-Verbose "Bounded trace rejected: $($_.Exception.Message)"}
            }
            $profileResults+=[pscustomobject]@{Profile=$profile;Rules=$rules;IsValid=@($rules | Where-Object {(Get-RuleState $_) -eq 'Invalid'}).Count -eq 0}
        }
        $valid=@($profileResults | Where-Object IsValid)
        if($valid.Count -ne 1) {
            $details=@($profileResults | ForEach-Object {$p=$_; foreach($r in $p.Rules) {if((Get-RuleState $r) -eq 'Invalid') {"$($p.Profile.Id)/$($r.Name): matches=$($r.MatchCount)/$(Get-ExpectedMatchCount $r.Rule)"}}})
            $failure = [InvalidOperationException]::new("No unique supported signature profile matched. The target was not modified.`n$($details -join "`n")")
            # Only missing patterns permit an unpatched launch. Mixed bytes and ambiguous matches still fail.
            $failure.Data['Mv2PatternsMissing'] = $valid.Count -eq 0 -and $profileResults.Count -eq 1 -and
                @($profileResults[0].Rules | Where-Object { $_.MatchCount -gt (Get-ExpectedMatchCount $_.Rule) -or @($_.Candidates | Where-Object State -ne 'Original').Count -gt 0 }).Count -eq 0
            throw $failure
        }
        $stream.Position=0; $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')} finally {$sha.Dispose()}
        $analysis=Complete-TargetAnalysis $Path $pe $valid[0] $hash
        $analysis | Add-Member NoteProperty PeInfo $pe
        $analysis | Add-Member NoteProperty NativeEvidence $nativeEvidence
        $analysis.Public | Add-Member NoteProperty Detector $(if($nativeEvidence.Count) {'StreamAndBoundedTrace'} else {'StreamMasked'})
        return $analysis
    } finally {$stream.Dispose()}
}

function New-StreamPatchPlan {
    param([string]$Path,$Analysis)
    $stream=[IO.File]::Open($Path,'Open','Read','Read')
    try {
        $stream.Position=0; $sha=[Security.Cryptography.SHA256]::Create()
        try {$hash=([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','')} finally {$sha.Dispose()}
        if($hash -ne $Analysis.Hash) {throw 'Target changed between analysis and planning'}
        $patches=@(); $occupied=@{}
        foreach($rule in $Analysis.Selected.Rules) {
            foreach($candidate in $rule.Candidates) {
                $replacement=@(if($candidate.PSObject.Properties.Name -contains 'ReplacementPattern') {$candidate.ReplacementPattern} else {$rule.ReplacementPattern})
                $before=Read-StreamRange $stream $candidate.PatchOffset $replacement.Count
                if($null -eq $before) {throw 'Truncated patch bytes'}
                $after=[byte[]]$before.Clone()
                for($i=0;$i -lt $replacement.Count;$i++) {
                    $at=[long]$candidate.PatchOffset+$i
                    if($occupied.ContainsKey($at)) {throw 'Overlapping patch plan'}; $occupied[$at]=$true
                    if($replacement[$i] -ge 0) {$after[$i]=[byte]$replacement[$i]}
                }
                if(($before -join ',') -ne ($after -join ',')) {
                    $patches+=[pscustomobject]@{Name=$rule.Name;Offset=[long]$candidate.PatchOffset;Before=(Get-HexBytes $before);After=(Get-HexBytes $after)}
                }
            }
        }
        return [pscustomobject]@{Patches=$patches}
    } finally {$stream.Dispose()}
}

function Get-Mv2NativeReceiptAnalysis {
    param([string]$Path,[string]$BackupBase,[string]$CatalogPath,[ref]$VerifiedRecord)
    try {
        $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $candidate=Get-LatestTargetReceipt $BackupBase $Path $version.FileVersion
        $record=if($candidate) {$candidate.Record} else {$null}
        if((-not $record -or $record.PSObject.Properties.Name -notcontains 'NativeTrace' -or $record.NativeTrace -ne $true) -and (Test-Path -LiteralPath ($Path+'.mv2-receipt.json'))) {
            $record=Get-Content -LiteralPath ($Path+'.mv2-receipt.json') -Raw | ConvertFrom-Json
        }
        if(-not $record -or $record.PSObject.Properties.Name -notcontains 'NativeTrace' -or $record.NativeTrace -ne $true) {return $null}
        if($record.SchemaVersion -ne 1 -or $record.State -ne 'Applied' -or $record.FileVersion -ne $version.FileVersion -or
            [IO.Path]::GetFullPath($record.TargetPath) -ne [IO.Path]::GetFullPath($Path) -or
            -not (Test-Path -LiteralPath $record.BackupPath -PathType Leaf)) {return $null}
        if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $record.PatchedSHA256) {return $null}
        # Recompute the original's bounded evidence and patch plan; a receipt alone is not authority.
        $analysis=Resolve-TargetStreamAnalysis $record.BackupPath $CatalogPath
        if(-not $analysis.AllOriginal -or $analysis.Hash -ne $record.OriginalSHA256 -or $analysis.Selected.Profile.Id -ne $record.Profile) {return $null}
        $plan=New-StreamPatchPlan $record.BackupPath $analysis
        if($plan.Patches.Count -ne @($record.Patches).Count) {return $null}
        foreach($patch in $plan.Patches) {
            $matches=@($record.Patches | Where-Object {$_.Name -eq $patch.Name -and $_.Offset -eq $patch.Offset -and $_.Before -eq $patch.Before -and $_.After -eq $patch.After})
            if($matches.Count -ne 1) {return $null}
        }
        # Hash the complete original with only the recomputed patches projected into each block.
        $source=[IO.File]::Open($record.BackupPath,'Open','Read','Read')
        $sha=[Security.Cryptography.SHA256]::Create()
        try {
            $buffer=[byte[]]::new(4MB); $offset=0L
            while(($n=$source.Read($buffer,0,$buffer.Length)) -gt 0) {
                foreach($patch in $plan.Patches) {
                    $after=ConvertTo-ConcreteBytes $patch.After
                    $first=[Math]::Max($offset,[long]$patch.Offset)
                    $last=[Math]::Min($offset+$n,[long]$patch.Offset+$after.Length)
                    if($last -gt $first) {[Array]::Copy($after,$first-$patch.Offset,$buffer,$first-$offset,$last-$first)}
                }
                [void]$sha.TransformBlock($buffer,0,$n,$buffer,0); $offset+=$n
            }
            [void]$sha.TransformFinalBlock([byte[]]@(),0,0)
            $projected=([BitConverter]::ToString($sha.Hash)).Replace('-','')
        } finally {$sha.Dispose(); $source.Dispose()}
        if($projected -ne $record.PatchedSHA256 -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $projected) {return $null}
        $result=$analysis.Public
        $result.Target=[IO.Path]::GetFullPath($Path); $result.SHA256=$projected; $result.State='AlreadyPatched'
        foreach($rule in $result.Rules) {$rule.State='Patched'}
        $result | Add-Member NoteProperty Verification 'NativeReceiptVerified'
        if($null -ne $VerifiedRecord) {$VerifiedRecord.Value=$record}
        return $result
    } catch {Write-Verbose "Native receipt was not usable: $($_.Exception.Message)"; return $null}
}

function Invoke-PatchTarget {
    param(
        [string]$Path,
        [switch]$InPlace,
        [string]$OutputPath,
        [string]$BackupBase,
        [string]$CatalogPath,
        [switch]$BackupExtensions
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    Assert-NoMv2Proxy $resolved
    $resolvedCatalog = (Resolve-Path -LiteralPath $CatalogPath).Path
    $nativeReceipt = $null
    $fastAnalysis = Get-Mv2NativeReceiptAnalysis $resolved $BackupBase $resolvedCatalog -VerifiedRecord ([ref]$nativeReceipt)
    if (-not $fastAnalysis) { $fastAnalysis = Get-ReceiptPatchedAnalysis $resolved $BackupBase $resolvedCatalog }
    if ($fastAnalysis) {
        if ($OutputPath) {
            Copy-Item -LiteralPath $resolved -Destination $OutputPath
            if ($nativeReceipt) {
                $outputFull = if (Test-Path -LiteralPath $OutputPath -PathType Container) {
                    Join-Path ([IO.Path]::GetFullPath($OutputPath)) ([IO.Path]::GetFileName($resolved))
                } else { [IO.Path]::GetFullPath($OutputPath) }
                if ((Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash -ne $nativeReceipt.PatchedSHA256) { throw 'Copied output hash verification failed.' }
                $nativeReceipt.TargetPath = $outputFull
                $nativeReceipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($outputFull+'.mv2-receipt.json') -Encoding UTF8
            }
        }
        return $fastAnalysis
    }
    $analysis = Resolve-TargetStreamAnalysis $resolved $resolvedCatalog
    if (-not $InPlace -and [string]::IsNullOrWhiteSpace($OutputPath)) {
        return $analysis.Public
    }
    if ($analysis.AllPatched) {
        if ($OutputPath) {
            Copy-Item -LiteralPath $resolved -Destination $OutputPath
        }
        return $analysis.Public
    }

    # Disk writes keep the existing verified backup/rollback transaction.
    $bytes = [IO.File]::ReadAllBytes($resolved)
    if ((Get-ByteArraySha256 $bytes) -ne $analysis.Hash) { throw 'Target changed after streamed analysis; retry.' }
    $patchData = New-PatchedBytes $bytes $analysis.Selected
    $patchedHash = Get-ByteArraySha256 $patchData.Bytes
    if ($OutputPath) {
        $outputFull = [IO.Path]::GetFullPath($OutputPath)
        [IO.File]::WriteAllBytes($outputFull, $patchData.Bytes)
        if ((Get-FileHash -LiteralPath $outputFull -Algorithm SHA256).Hash -ne $patchedHash) {
            throw 'Output hash verification failed.'
        }
        if ($analysis.NativeEvidence.Count -gt 0) {
            [pscustomobject]@{
                SchemaVersion=1;State='Applied';NativeTrace=$true;TargetPath=$outputFull;BackupPath=$resolved;
                FileVersion=$analysis.Version.FileVersion;Profile=$analysis.Selected.Profile.Id;
                OriginalSHA256=$analysis.Hash;PatchedSHA256=$patchedHash;Patches=$patchData.Patches
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath ($outputFull+'.mv2-receipt.json') -Encoding UTF8
        }
        return [pscustomobject]@{
            Target = $resolved
            Output = $outputFull
            Profile = $analysis.Selected.Profile.Id
            OriginalSHA256 = $analysis.Hash
            PatchedSHA256 = $patchedHash
            PatchCount = $patchData.Patches.Count
        }
    }

    $locked = $null
    try {
        try {
            $locked = Open-Mv2PrivateDllWrite $resolved $analysis.Hash
        } catch {
            throw "Target DLL could not be prepared: $resolved. $($_.Exception.Message)"
        }
        $lockedBytes = Read-ExclusiveStreamBytes $locked
        if ((Get-ByteArraySha256 $lockedBytes) -ne $analysis.Hash) {
            throw 'Target changed between analysis and exclusive lock acquisition; retry.'
        }

        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmssZ')
        $safeProduct = if ($analysis.Version.ProductName) {
            $analysis.Version.ProductName -replace '[^A-Za-z0-9._-]', '_'
        } else { 'Chromium' }
        $safeVersion = if ($analysis.Version.FileVersion) {
            $analysis.Version.FileVersion -replace '[^A-Za-z0-9._-]', '_'
        } else { 'unknown' }
        $backupDirectory = Join-Path $BackupBase (
            "{0}_{1}_{2}" -f $safeProduct, $safeVersion, $timestamp)
        New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
        $backupPath = Join-Path $backupDirectory ([IO.Path]::GetFileName($resolved))
        [IO.File]::WriteAllBytes($backupPath, $lockedBytes)
        if ((Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ne $analysis.Hash) {
            throw 'Backup hash verification failed. The target was not modified.'
        }

        $extensionBackup = $null
        if ($BackupExtensions -and $analysis.Version.ProductName -eq 'Google Chrome') {
            $extensionBackup = New-ChromeExtensionBackup $backupDirectory
        }

        $receiptPath = Join-Path $backupDirectory 'receipt.json'
        $receipt = [ordered]@{
            SchemaVersion = 1
            State = 'Prepared'
            Tool = 'chromium_mv2_patch.ps1'
            AppliedUtc = (Get-Date).ToUniversalTime().ToString('o')
            TargetPath = $resolved
            BackupPath = $backupPath
            ProductName = $analysis.Version.ProductName
            ProductVersion = $analysis.Version.ProductVersion
            FileVersion = $analysis.Version.FileVersion
            Profile = $analysis.Selected.Profile.Id
            OriginalSHA256 = $analysis.Hash
            PatchedSHA256 = $patchedHash
            OriginalSignatureStatus = [string](
                Get-AuthenticodeSignature -LiteralPath $backupPath).Status
            ExtensionBackupPath = if ($extensionBackup) { $extensionBackup.Path } else { $null }
            ExtensionInventoryPath = if ($extensionBackup) { $extensionBackup.Inventory } else { $null }
            ExtensionBackupProfileCount = if ($extensionBackup) {
                $extensionBackup.ProfileCount
            } else { 0 }
            ExtensionBackupExtensionCount = if ($extensionBackup) {
                $extensionBackup.ExtensionCount
            } else { 0 }
            Patches = $patchData.Patches
            NativeTrace = ($analysis.NativeEvidence.Count -gt 0)
        }
        $receipt | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath $receiptPath -Encoding UTF8

        $writeStarted = $false
        try {
            $locked.Position = 0
            $writeStarted = $true
            $locked.Write($patchData.Bytes, 0, $patchData.Bytes.Length)
            $locked.SetLength($patchData.Bytes.Length)
            $locked.Flush($true)
            $writtenBytes = Read-ExclusiveStreamBytes $locked
            if ((Get-ByteArraySha256 $writtenBytes) -ne $patchedHash) {
                throw 'Post-write verification failed.'
            }
            if ($analysis.NativeEvidence.Count -gt 0) {
                # Reconstruct the verified original in the readback buffer; disk bytes are untouched.
                foreach ($patch in $patchData.Patches) {
                    $after = ConvertTo-ConcreteBytes $patch.After
                    if (-not (Test-BytesAt $writtenBytes $patch.Offset ([int[]]$after))) { throw 'Native readback differs from verified plan.' }
                    $before = ConvertTo-ConcreteBytes $patch.Before
                    [Array]::Copy($before, 0, $writtenBytes, $patch.Offset, $before.Length)
                }
                if ((Get-ByteArraySha256 $writtenBytes) -ne $analysis.Hash) { throw 'Native readback has changes outside the verified plan.' }
            } else {
                $writtenAnalysis = Resolve-TargetAnalysis $resolved $writtenBytes $CatalogPath
                if (-not $writtenAnalysis.AllPatched) { throw 'Post-write rule verification failed.' }
            }
            $receipt.State = 'Applied'
            $receipt | ConvertTo-Json -Depth 6 |
                Set-Content -LiteralPath $receiptPath -Encoding UTF8
        } catch {
            $patchFailure = $_.Exception
            if ($writeStarted) {
                try {
                    $locked.Position = 0
                    $locked.Write($lockedBytes, 0, $lockedBytes.Length)
                    $locked.SetLength($lockedBytes.Length)
                    $locked.Flush($true)
                    $restoredBytes = Read-ExclusiveStreamBytes $locked
                    if ((Get-ByteArraySha256 $restoredBytes) -ne $analysis.Hash) {
                        throw 'Rollback hash verification failed.'
                    }
                } catch {
                    throw "Patch failed: $($patchFailure.Message) Automatic rollback also failed: $($_.Exception.Message) Restore from: $backupPath"
                }
                $receipt.State = 'RolledBack'
                $receipt['Failure'] = $patchFailure.Message
                try {
                    $receipt | ConvertTo-Json -Depth 6 |
                        Set-Content -LiteralPath $receiptPath -Encoding UTF8
                } catch {}
            }
            throw $patchFailure
        }

        Limit-Mv2Backups $BackupBase $backupDirectory
        return [pscustomobject]@{
            Target = $resolved
            Profile = $analysis.Selected.Profile.Id
            OriginalSHA256 = $analysis.Hash
            PatchedSHA256 = $patchedHash
            Backup = $backupPath
            Receipt = $receiptPath
            PatchCount = $patchData.Patches.Count
            ExtensionBackup = if ($extensionBackup) { $extensionBackup.Path } else { $null }
            ExtensionCount = if ($extensionBackup) {
                $extensionBackup.ExtensionCount
            } else { 0 }
        }
    } finally {
        if ($locked) { $locked.Dispose() }
    }
}

function Get-LatestBackupReceipt {
    param([string]$BackupBase)

    if (-not (Test-Path -LiteralPath $BackupBase -PathType Container)) {
        throw "Backup directory was not found: $BackupBase"
    }
    $latest = Get-ChildItem -LiteralPath $BackupBase -Directory | ForEach-Object {
        $path = Join-Path $_.FullName 'receipt.json'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $record = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
                if ($record.SchemaVersion -eq 1 -and $record.State -eq 'Applied' -and
                    $record.AppliedUtc) {
                    [pscustomobject]@{
                        Path = (Resolve-Path -LiteralPath $path).Path
                        AppliedUtc = [DateTimeOffset]$record.AppliedUtc
                    }
                }
            } catch {
                Write-Verbose "Ignoring invalid backup receipt: $path"
            }
        }
    } | Sort-Object AppliedUtc -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No completed backup receipt was found under: $BackupBase"
    }
    return $latest.Path
}

function Invoke-ReceiptRestore {
    param(
        [string]$ReceiptPath,
        [string]$RequestedRoot
    )
    $resolvedReceipt = (Resolve-Path -LiteralPath $ReceiptPath).Path
    $record = Get-Content -Raw -LiteralPath $resolvedReceipt | ConvertFrom-Json
    if ($record.SchemaVersion -ne 1) {
        throw "Unsupported receipt schema: $($record.SchemaVersion)"
    }
    $recordedTarget = [IO.Path]::GetFullPath([string]$record.TargetPath)
    $targetPath = if ($record.ProductName -eq 'Google Chrome') {
        Get-LatestChromeDll (Resolve-ChromeApplicationRoot $RequestedRoot)
    } else {
        (Resolve-Path -LiteralPath $recordedTarget).Path
    }
    $targetPath = (Resolve-Path -LiteralPath $targetPath).Path
    Assert-NoMv2Proxy $targetPath
    $backupPath = (Resolve-Path -LiteralPath $record.BackupPath).Path
    $backupBytes = [IO.File]::ReadAllBytes($backupPath)
    if ((Get-ByteArraySha256 $backupBytes) -ne $record.OriginalSHA256) {
        throw 'Backup hash does not match the receipt.'
    }
    $backupMachine = (Get-PeInfo $backupBytes).Machine

    $locked = $null
    try {
        try {
            $locked = Open-Mv2PrivateDllWrite $targetPath $record.PatchedSHA256
        } catch {
            throw "Target DLL could not be prepared: $targetPath. $($_.Exception.Message)"
        }
        $current = Read-ExclusiveStreamBytes $locked
        $currentMachine = (Get-PeInfo $current).Machine
        if ($currentMachine -ne $backupMachine) {
            throw ('Backup and current Chrome architectures differ ' +
                "(backup=0x$($backupMachine.ToString('X4')), " +
                "current=0x$($currentMachine.ToString('X4'))). Refusing to restore.")
        }
        if ((Get-ByteArraySha256 $current) -ne $record.PatchedSHA256) {
            throw ("Current Chrome DLL does not match this receipt; refusing to overwrite it. " +
                "Receipt target: $recordedTarget Current target: $targetPath")
        }
        $locked.Position = 0
        $locked.Write($backupBytes, 0, $backupBytes.Length)
        $locked.SetLength($backupBytes.Length)
        $locked.Flush($true)
        $verified = Read-ExclusiveStreamBytes $locked
        if ((Get-ByteArraySha256 $verified) -ne $record.OriginalSHA256) {
            throw 'Post-restore hash verification failed.'
        }
    } finally {
        if ($locked) { $locked.Dispose() }
    }
    return [pscustomobject]@{
        Target = $targetPath
        RestoredSHA256 = $record.OriginalSHA256
        Signature = (Get-AuthenticodeSignature -LiteralPath $targetPath).Status
        Receipt = $resolvedReceipt
    }
}
