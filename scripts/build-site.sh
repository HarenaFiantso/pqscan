#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Builds the website into build/site. The page itself lives in site/. JetBrains Mono Nerd Font is
# third-party, so it is fetched here, pinned by hash, and cut down to the glyphs the page uses.

set -eu

cd "$(git rev-parse --show-toplevel)"

font_version=v3.5.1
font_hash=04d5e8f903693f9dd13e16f867e994834e681eb3c72c0d337a770dcda09010cf
font_url=https://github.com/ryanoasis/nerd-fonts/releases/download/$font_version/JetBrainsMono.tar.xz

# Latin text, the punctuation the page uses, then the Nerd Font icons and Powerline shapes.
font_unicodes=U+0020-007E,U+00A0-00FF,U+2013-2014,U+2018-201D,U+2026,U+2192,U+2264-2265,U+2713
font_icons=U+E0B0,U+F002,U+F00C,U+F013,U+F023,U+F05E,U+F071,U+F084,U+F09B,U+F0E7
font_icons=$font_icons,U+F120,U+F121,U+F126,U+F132,U+F1C0,U+F1C9

downloads=build/.downloads
tools=build/site-tools
output=build/site
archive=$downloads/JetBrainsMono-$font_version.tar.xz

sha256_of() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

fetch_font() {
    mkdir -p "$downloads"
    if [ ! -f "$archive" ]; then
        curl --fail --silent --show-error --location --output "$archive.part" "$font_url"
        mv "$archive.part" "$archive"
    fi
    if [ "$(sha256_of "$archive")" != "$font_hash" ]; then
        echo "$archive does not match its pinned hash" >&2
        exit 1
    fi
}

install_tools() {
    if [ ! -x "$tools/bin/pyftsubset" ]; then
        python3 -m venv "$tools"
        "$tools/bin/pip" install --quiet --requirement site/requirements.txt
    fi
}

subset_font() {
    "$tools/bin/pyftsubset" "$1/JetBrainsMonoNerdFontMono-$2.ttf" \
        --unicodes="$font_unicodes,$font_icons" --layout-features='*' --flavor=woff2 \
        --output-file="$output/fonts/JetBrainsMonoNF-$2.woff2"
}

build_fonts() {
    extracted=$(mktemp -d)
    trap 'rm -rf "$extracted"' EXIT
    tar -xJf "$archive" -C "$extracted"
    mkdir -p "$output/fonts"
    subset_font "$extracted" Regular
    subset_font "$extracted" Bold
    cp "$extracted/OFL.txt" "$output/fonts/OFL.txt"
}

fetch_font
install_tools
rm -rf "$output"
mkdir -p "$output"
cp site/index.html site/style.css site/main.js "$output/"
build_fonts
echo "Built $output. To preview it: python3 -m http.server --directory $output"
