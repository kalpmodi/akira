#!/usr/bin/env python3
"""Generate Akira stats bar SVG - terminal dashboard style."""
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--stars',  default='9')
parser.add_argument('--forks',  default='3')
parser.add_argument('--issues', default='0')
args, _ = parser.parse_known_args()

W, H  = 900, 80
GREEN = "#00ff41"
BG    = "#0d1117"
MONO  = "'Courier New', Courier, monospace"

STATS = [
    ("STARS",   args.stars),
    ("FORKS",   args.forks),
    ("ISSUES",  args.issues),
    ("SKILLS",  "12"),
    ("LICENSE", "MIT"),
    ("VERSION", "v1.0.0"),
    ("PRs",     "open"),
]

N   = len(STATS)
COL = W / N

lines = []
L = lines.append

L(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
L(f'  <rect width="{W}" height="{H}" fill="{BG}"/>')
L(f'  <rect x="1" y="1" width="{W-2}" height="{H-2}" fill="none" stroke="{GREEN}" stroke-width="1" opacity="0.25"/>')

# Corner accent dots
for cx, cy in [(6,6),(W-6,6),(6,H-6),(W-6,H-6)]:
    L(f'  <circle cx="{cx}" cy="{cy}" r="2" fill="{GREEN}" opacity="0.35"/>')

# Vertical separators
for i in range(1, N):
    x = round(i * COL, 1)
    L(f'  <line x1="{x}" y1="10" x2="{x}" y2="{H-10}" stroke="{GREEN}" stroke-width="0.6" opacity="0.14"/>')

# Stat items
for i, (label, value) in enumerate(STATS):
    cx = round((i + 0.5) * COL, 1)
    L(f'  <text x="{cx}" y="29" text-anchor="middle" font-family="{MONO}" font-size="8" fill="{GREEN}" opacity="0.40" letter-spacing="2">{label}</text>')
    L(f'  <text x="{cx}" y="57" text-anchor="middle" font-family="{MONO}" font-size="19" font-weight="700" fill="{GREEN}" opacity="0.92">{value}</text>')

L('</svg>')
print('\n'.join(lines))
