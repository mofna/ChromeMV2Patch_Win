@{
    SchemaVersion = 1
    Profiles = @(
        @{
            Id = 'chromium-x64-manifest-v2-semantic'
            Description = 'Register- and displacement-normalized Chromium Windows x64 MV2 paths'
            Machine = 0x8664
            Rules = @(
                @{
                    Name = 'allow-enable-and-report'
                    Description = 'All normalized object-form predicates take their existing unaffected branch'
                    ExpectedMatches = 2
                    Original = '7F'
                    Replacement = 'EB'
                    Variants = @(
                        @{
                            Pattern = '83 78/F8 ?? 02 7F ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 40/C0 ?? 83 F8/F8 01 75 ?? 83 F8/F8 05 0F 95 C0/F8 83 F8/F8 0A 0F 95 C0/F8 20 C0/C0 C3 83 F8/F8 08 74 ?? 83 F8/F8 03 74 ?? 31 C0/C0 EB ??'
                            PatchOffset = 4
                        }
                        @{
                            Pattern = '83 78/F8 ?? 02 7F ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 80/C0 ?? ?? ?? ?? 83 F8/F8 01 75 ?? 83 F8/F8 05 0F 95 C0/F8 83 F8/F8 0A 0F 95 C0/F8 20 C0/C0 C3 83 F8/F8 08 74 ?? 83 F8/F8 03 74 ?? 31 C0/C0 EB ??'
                            PatchOffset = 4
                        }
                        @{
                            Pattern = '40/F8 8B 40/C0 ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 40/C0 ?? 40/F8 83 F8/F8 02 7F ?? 8B 40/C0 ?? 83 F8/F8 01 75 ?? 83 F8/F8 05 0F 95 C0/F8 83 F8/F8 0A 0F 95 C0/F8 20 C0/C0 C3 B8/F8 03 00 00 00 EB ?? 83 F8/F8 08 74 ?? 83 F8/F8 03 74 ?? 31 C0/C0 EB ??'
                            PatchOffset = 27
                        }
                    )
                }
                @{
                    Name = 'allow-enable-policy-inline'
                    Description = 'The normalized inline predicate takes its existing unaffected branch'
                    Original = '0F 8F'
                    Replacement = '90 E9'
                    Variants = @(
                        @{
                            Pattern = '83 78/F8 ?? 02 0F 8F ?? ?? ?? ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 40/C0 ?? 83 F8/F8 01 75 ?? 31 C0/C0 83 F8/F8 05 74 ?? 83 F8/F8 0A 75 ?? 80 7C 24 ?? 00'
                            PatchOffset = 4
                            RequiredPatternOffset = 101
                            RequiredPattern = 'B8 00 00 80 00'
                        }
                        @{
                            Pattern = '83 78/F8 ?? 02 0F 8F ?? ?? ?? ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 80/C0 ?? ?? ?? ?? 83 F8/F8 01 75 ?? 31 C0/C0 83 F8/F8 05 74 ?? 83 F8/F8 0A 75 ?? 80 7C 24 ?? 00'
                            PatchOffset = 4
                            RequiredPatternOffset = 104
                            RequiredPattern = 'B8 00 00 80 00'
                        }
                        @{
                            Pattern = '83 F8/F8 02 7F ?? 8B 40/C0 ?? 83 F8/F8 01 75 ?? 31 C0/C0 83 F8/F8 05 74 ?? 83 F8/F8 0A 75 ?? 80 7C 24 ?? 00'
                            PatchOffset = 3
                            RequiredPatternOffset = 77
                            RequiredPattern = 'B8 00 00 80 00'
                            Original = '7F'
                            Replacement = 'EB'
                        }
                    )
                }
                @{
                    Name = 'skip-startup-disable'
                    Description = 'The normalized startup predicate always takes the next-item branch'
                    Original = '7F'
                    Replacement = 'EB'
                    Variants = @(
                        @{
                            Pattern = '83 78/F8 ?? 02 7F ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 40/C0 ?? 83 F8/F8 01 0F 85 ?? ?? ?? ?? 83 F8/F8 05 74 ?? 83 F8/F8 0A 0F 85'
                            PatchOffset = 4
                        }
                        @{
                            Pattern = '83 78/F8 ?? 02 7F ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 80/C0 ?? ?? ?? ?? 83 F8/F8 01 0F 85 ?? ?? ?? ?? 83 F8/F8 05 74 ?? 83 F8/F8 0A 0F 85'
                            PatchOffset = 4
                        }
                    )
                }
                @{
                    Name = 'allow-install'
                    Description = 'The normalized three-argument predicate takes its existing false branch'
                    Original = '7F'
                    Replacement = 'EB'
                    Variants = @(
                        @{
                            Pattern = '31 C0 83 F8/F8 02 7F ?? 83 F8/F8 08 77 ?? B8/F8 0A 01 00 00 0F A3 C0/C0 73 ?? 40/F8 83 F8/F8 05 0F 95 C0/F8 40/F8 83 F8/F8 0A 0F 95 C0/F8 20 C0/C0 C3'
                            PatchOffset = 5
                        }
                        @{
                            Pattern = '83 F8/F8 02 7F ?? 40/F8 83 F8/F8 01 75 ?? 40/F8 83 F8/F8 05 0F 95 C0/F8 40/F8 83 F8/F8 0A 0F 95 C0/F8 20 C0/C0 C3 40/F8 83 F8/F8 08 74 ?? 40/F8 83 F8/F8 03 74 ?? 31 C0/C0 EB ??'
                            PatchOffset = 3
                        }
                    )
                }
                @{
                    Name = 'allow-install-policy-inline'
                    Description = 'The normalized inline predicate takes its existing unaffected branch'
                    Original = '7F'
                    Replacement = 'EB'
                    Variants = @(
                        @{
                            Pattern = '83 78/F8 ?? 02 7F ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 40/C0 ?? 83 F8/F8 01 0F 85 ?? ?? ?? ?? 83 F8/F8 05 74 ?? 83 F8/F8 0A 74 ?? 48/F8 8D'
                            PatchOffset = 4
                            RequiredPatternOffset = 84
                            RequiredPattern = '48/F8 8D ?? 24 80 00 00 00'
                        }
                        @{
                            Pattern = '83 78/F8 ?? 02 7F ?? 48/F8 8B 80/C0 ?? ?? ?? ?? 8B 40/C0 ?? 80 B8/F8 ?? ?? ?? ?? 00 75 ?? 8B 80/C0 ?? ?? ?? ?? 83 F8/F8 01 0F 85 ?? ?? ?? ?? 83 F8/F8 05 74 ?? 83 F8/F8 0A 74 ?? 48/F8 8D'
                            PatchOffset = 4
                            RequiredPatternOffset = 50
                            RequiredPattern = '48/F8 8D ?? 24 80 00 00 00'
                        }
                        @{
                            Pattern = '83 F8/F8 02 7F ?? 8B 40/C0 ?? 83 F8/F8 01 0F 85 ?? ?? ?? ?? 83 F8/F8 05 74 ?? 83 F8/F8 0A 74 ?? 48/F8 8D'
                            PatchOffset = 3
                            RequiredPatternOffset = 64
                            RequiredPattern = '48/F8 8D ?? 24 80 00 00 00'
                        }
                    )
                }
                @{
                    Name = 'ignore-mv2-disable-reason-at-runtime'
                    Description = 'The normalized collapse loop omits reason 8388608 at runtime'
                    ExpectedMatches = 2
                    Original = '89 E9 E8 ?? ?? ?? ?? 84 C0 75 0A C7 44'
                    Replacement = '81 FD 00 00 80 00 0F 95 C0 75 0A EB 1D'
                    LegacyState = 'Original'
                    Variants = @(
                        @{
                            Pattern = '89 E9 E8 ?? ?? ?? ?? 84 C0 75 0A C7 44 24 ?? 00 00 00 02 EB 04 89 6C 24 ?? 48 89 F1 48/F9 89 C2/C7 49/F9 89 C0/C7 49/F9 89 C1/C7 E8 ?? ?? ?? ?? 48/F8 83 C0/F8 04'
                            PatchOffset = 0
                            EqualBytes = @('14:24')
                        }
                    )
                }
            )
        }
    )
}
