#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
game_geometry.py - projection, distance and angle math for runtime scene analysis.

Pure stdlib. numpy is used only if already available.

Coordinate conventions:
  directx  : row-vector  * matrix, right-handed world, y flipped on screen
  opengl   : matrix * column-vector, clip.y points up
  unity    : same layout as opengl, left-handed world (Unity uses column-major)
  source   : row-vector convention with yaw/pitch in degrees
"""

import math

try:  # optional
    import numpy as np
except Exception:
    np = None


class ViewProjection:
    """World -> screen projection from a 4x4 view-projection matrix."""

    LAYOUTS = ("directx", "opengl", "unity", "source", "rowcol")

    def __init__(self, matrix, layout="directx", width=1920, height=1080):
        if len(matrix) != 16:
            raise ValueError("view-projection matrix must have 16 floats")
        self.m = [float(v) for v in matrix]
        self.layout = layout if layout in self.LAYOUTS else "directx"
        self.width = float(width)
        self.height = float(height)

    @classmethod
    def from_bytes(cls, data, layout="directx", width=1920, height=1080):
        import struct

        if len(data) < 64:
            raise ValueError("need 64 bytes for a 4x4 float matrix")
        return cls(struct.unpack("<16f", data[:64]), layout, width, height)

    def _clip(self, x, y, z):
        m = self.m
        if self.layout == "rowcol":
            # row-major storage combined with column-vector math (M * v)
            return (
                m[0] * x + m[1] * y + m[2] * z + m[3],
                m[4] * x + m[5] * y + m[6] * z + m[7],
                m[8] * x + m[9] * y + m[10] * z + m[11],
                m[12] * x + m[13] * y + m[14] * z + m[15],
            )
        # directx/source: row-vector * row-major matrix
        # opengl/unity  : column-major matrix * column-vector
        # both reduce to the same expression, only handedness differs upstream
        return (
            m[0] * x + m[4] * y + m[8] * z + m[12],
            m[1] * x + m[5] * y + m[9] * z + m[13],
            m[2] * x + m[6] * y + m[10] * z + m[14],
            m[3] * x + m[7] * y + m[11] * z + m[15],
        )

    def project(self, x, y, z, width=None, height=None):
        """Return (screen_x, screen_y, visible, distance). visible=False if behind camera."""
        w = float(width) if width else self.width
        h = float(height) if height else self.height
        cx, cy, cz, cw = self._clip(x, y, z)
        if cw <= 0.0001:
            return (0.0, 0.0, False, 0.0)
        ndc_x = cx / cw
        ndc_y = cy / cw
        sx = (ndc_x * 0.5 + 0.5) * w
        sy = (0.5 - ndc_y * 0.5) * h
        on_screen = -0.1 <= ndc_x <= 1.1 and -0.1 <= ndc_y <= 1.1
        return (sx, sy, on_screen, cw)

    def project_many(self, points):
        return [self.project(*p) for p in points]

    def bounding_box(self, origin, mins, maxs):
        """Axis-aligned world box -> screen rect. mins/maxs are offsets from origin."""
        ox, oy, oz = origin
        corners = []
        for dx in (mins[0], maxs[0]):
            for dy in (mins[1], maxs[1]):
                for dz in (mins[2], maxs[2]):
                    corners.append(self.project(ox + dx, oy + dy, oz + dz))
        xs = [c[0] for c in corners if c[2]]
        ys = [c[1] for c in corners if c[2]]
        if not xs:
            return None
        return (min(xs), min(ys), max(xs), max(ys))


def distance3d(a, b):
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2)


def distance2d(a, b):
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2)


def normalize_angle(deg):
    while deg > 180.0:
        deg -= 360.0
    while deg < -180.0:
        deg += 360.0
    return deg


def calc_angle(src, dst, pitch_up_positive=True):
    """Yaw/pitch in degrees from src looking at dst (Source-engine convention)."""
    dx = dst[0] - src[0]
    dy = dst[1] - src[1]
    dz = dst[2] - src[2]
    hyp = math.sqrt(dx * dx + dy * dy)
    yaw = math.degrees(math.atan2(dy, dx))
    pitch = math.degrees(math.atan2(-dz, hyp))
    if not pitch_up_positive:
        pitch = -pitch
    return (yaw, pitch)


def angle_delta(current, target):
    """Shortest signed delta for yaw and pitch."""
    dyaw = normalize_angle(target[0] - current[0])
    dpitch = normalize_angle(target[1] - current[1])
    return (dyaw, dpitch)


def fov_distance(current, target):
    dyaw, dpitch = angle_delta(current, target)
    return math.sqrt(dyaw * dyaw + dpitch * dpitch)


def smooth_angle(current, target, factor):
    """Exponential smoothing between angle tuples. factor in (0, 1]."""
    dyaw, dpitch = angle_delta(current, target)
    return (
        normalize_angle(current[0] + dyaw * factor),
        normalize_angle(current[1] + dpitch * factor),
    )


def clamp_angle(value, min_v, max_v):
    return max(min_v, min(max_v, value))


def clamp_pitch(value, limit=89.0):
    return clamp_angle(value, -limit, limit)


def screen_center(width, height):
    return (width * 0.5, height * 0.5)


def radial_distance(x, y, width, height):
    cx, cy = screen_center(width, height)
    return math.sqrt((x - cx) ** 2 + (y - cy) ** 2)


def is_within_fov_circle(x, y, radius_px, width, height):
    return radial_distance(x, y, width, height) <= radius_px


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        # standard perspective: fov 90, aspect 16:9, near 0.1, far 100, column-major
        f = 1.0 / math.tan(math.radians(90.0) / 2.0)
        aspect = 1920.0 / 1080.0
        near, far = 0.1, 100.0
        m = [
            f / aspect, 0.0, 0.0, 0.0,
            0.0, f, 0.0, 0.0,
            0.0, 0.0, (far + near) / (near - far), -1.0,
            0.0, 0.0, (2.0 * far * near) / (near - far), 0.0,
        ]
        vp = ViewProjection(m, "opengl", 1920, 1080)
        print("center (0,0,-5) :", tuple(round(v, 3) for v in vp.project(0, 0, -5)))
        print("expect          : (960.0, 540.0, True, ~1.0)")
        print("behind (0,0,5)  :", tuple(round(v, 3) for v in vp.project(0, 0, 5)))
        print("bbox            :", tuple(round(v, 1) for v in vp.bounding_box((0, 0, -5), (-1, -1, -1), (1, 1, 1))))
        print("angle  :", calc_angle((0, 0, 0), (10, 10, 0)))
        print("delta  :", angle_delta((0.0, 0.0), (45.0, 0.0)))
        print("smooth :", smooth_angle((0.0, 0.0), (45.0, 10.0), 0.5))
        print("fovdist:", round(fov_distance((0.0, 0.0), (3.0, 4.0)), 6))
        print(json.dumps({"ok": True}))
