#!/usr/bin/perl
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# deb-licenses.pl - print the license set of a Debian package.
#
# Usage: deb-licenses.pl <package doc dir>   (e.g. /usr/share/doc/foo)
#
# If <dir>/copyright is DEP-5 machine-readable, print the deduplicated set of
# its "License:" short names, with composite "X or Y" values split.
#
# A free-form copyright file (linux-firmware: a concatenation of ~100 vendor
# licences, describable neither by one name nor by a meaningful union of
# names) yields LicenseRef-<package>-copyright instead.

use strict;
use warnings;
use File::Basename;

my $dir = shift or die "Usage: $0 <package doc dir>\n";

my %seen;
if (open my $fh, '<', "$dir/copyright") {
    while (<$fh>) {
        next unless s/^License:\s*//;
        chomp;
        s/,\s*$//;
        $seen{$_}++ for split /,?\s+(?:or|and)\s+/;
    }
    close $fh;
}
$seen{ 'LicenseRef-' . basename($dir) . '-copyright' } = 1 unless %seen;

print join(" ", sort keys %seen), "\n";
