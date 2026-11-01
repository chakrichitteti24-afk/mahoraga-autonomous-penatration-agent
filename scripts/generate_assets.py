"""
Generate CipherFlux Labs Master SVG Logo and PNG icon variants.
"""
import os
from PIL import Image, ImageDraw, ImageFont

svg_content = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <defs>
    <linearGradient id="shieldBg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0a0e17"/>
      <stop offset="50%" stop-color="#111827"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <linearGradient id="borderGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f5ff"/>
      <stop offset="50%" stop-color="#00a8ff"/>
      <stop offset="100%" stop-color="#00ff88"/>
    </linearGradient>
    <linearGradient id="cfGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00f5ff"/>
      <stop offset="100%" stop-color="#00a8ff"/>
    </linearGradient>
    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
      <feGaussianBlur stdDeviation="8" result="blur"/>
      <feComposite in="SourceGraphic" in2="blur" operator="over"/>
    </filter>
  </defs>

  <!-- Dark Background Plate -->
  <rect width="512" height="512" rx="96" fill="#06090e"/>

  <!-- Shield Outer Glow & Border -->
  <path d="M 256 48 L 416 104 C 416 280 256 424 256 424 C 256 424 96 280 96 104 Z"
        fill="url(#shieldBg)"
        stroke="url(#borderGrad)"
        stroke-width="12"
        stroke-linejoin="round"
        filter="url(#glow)"/>

  <!-- Inner Circuit Grid Accent -->
  <path d="M 256 70 L 396 120 C 396 265 256 395 256 395 C 256 395 116 265 116 120 Z"
        fill="none"
        stroke="#1e293b"
        stroke-width="3"
        stroke-dasharray="6,6"/>

  <!-- CF Monogram -->
  <!-- Letter C -->
  <path d="M 224 168 L 168 168 C 150 168 140 178 140 196 L 140 300 C 140 318 150 328 168 328 L 224 328"
        fill="none"
        stroke="url(#cfGrad)"
        stroke-width="22"
        stroke-linecap="round"
        stroke-linejoin="round"/>

  <!-- Letter F -->
  <path d="M 256 168 L 344 168 M 256 168 L 256 328 M 256 244 L 324 244"
        fill="none"
        stroke="#00ff88"
        stroke-width="22"
        stroke-linecap="round"
        stroke-linejoin="round"/>

  <!-- Center Flux Core Node -->
  <circle cx="256" cy="244" r="10" fill="#00f5ff" filter="url(#glow)"/>
  <circle cx="256" cy="244" r="5" fill="#ffffff"/>

  <!-- Micro Flux Accents -->
  <circle cx="224" cy="168" r="6" fill="#00f5ff"/>
  <circle cx="224" cy="328" r="6" fill="#00a8ff"/>
  <circle cx="344" cy="168" r="6" fill="#00ff88"/>
  <circle cx="324" cy="244" r="6" fill="#00ff88"/>
</svg>
'''

with open("assets/cipherflux-logo.svg", "w", encoding="utf-8") as f:
    f.write(svg_content)
print("Saved assets/cipherflux-logo.svg")

def draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (6, 9, 14, 255))
    draw = ImageDraw.Draw(img)
    scale = size / 512.0

    # Draw shield polygon
    shield_pts = [
        (int(256 * scale), int(48 * scale)),
        (int(416 * scale), int(104 * scale)),
        (int(360 * scale), int(280 * scale)),
        (int(256 * scale), int(424 * scale)),
        (int(152 * scale), int(280 * scale)),
        (int(96 * scale), int(104 * scale)),
    ]
    draw.polygon(shield_pts, fill=(15, 23, 42, 255), outline=(0, 245, 255, 255), width=max(1, int(10 * scale)))

    # Inner shield accent
    inner_pts = [
        (int(256 * scale), int(80 * scale)),
        (int(380 * scale), int(124 * scale)),
        (int(330 * scale), int(260 * scale)),
        (int(256 * scale), int(380 * scale)),
        (int(182 * scale), int(260 * scale)),
        (int(132 * scale), int(124 * scale)),
    ]
    draw.polygon(inner_pts, fill=(10, 14, 23, 255), outline=(0, 168, 255, 180), width=max(1, int(4 * scale)))

    # Draw CF monogram
    c_w = max(1, int(18 * scale))
    # 'C'
    draw.line([(int(220 * scale), int(170 * scale)), (int(160 * scale), int(170 * scale))], fill=(0, 245, 255), width=c_w)
    draw.line([(int(160 * scale), int(170 * scale)), (int(160 * scale), int(320 * scale))], fill=(0, 245, 255), width=c_w)
    draw.line([(int(160 * scale), int(320 * scale)), (int(220 * scale), int(320 * scale))], fill=(0, 245, 255), width=c_w)

    # 'F'
    draw.line([(int(256 * scale), int(170 * scale)), (int(340 * scale), int(170 * scale))], fill=(0, 255, 136), width=c_w)
    draw.line([(int(256 * scale), int(170 * scale)), (int(256 * scale), int(320 * scale))], fill=(0, 255, 136), width=c_w)
    draw.line([(int(256 * scale), int(244 * scale)), (int(320 * scale), int(244 * scale))], fill=(0, 255, 136), width=c_w)

    # Core node
    r = max(2, int(8 * scale))
    cx, cy = int(256 * scale), int(244 * scale)
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(255, 255, 255), outline=(0, 245, 255), width=max(1, int(2 * scale)))

    return img

sizes = [16, 32, 48, 64, 128, 256, 512]
for s in sizes:
    icon = draw_icon(s)
    path = f"assets/icons/icon-{s}.png"
    icon.save(path)
    print(f"Generated {path}")

# Default application icon
default_icon = draw_icon(256)
default_icon.save("assets/icons/cipherflux.png")
default_icon.save("assets/cipherflux.png")
print("Saved assets/icons/cipherflux.png and assets/cipherflux.png")
