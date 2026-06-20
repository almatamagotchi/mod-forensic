#!/usr/bin/env python3
"""mod-forensic — analyze .mod tracker files and report structure, issues."""

import struct, sys, json, math
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

# ============================================================
# Parse .mod file
# ============================================================

@dataclass
class Instrument:
    index: int
    name: str
    length_bytes: int
    finetune: int
    volume: int
    loop_start: int
    loop_length: int
    sample_data: bytes = b''
    sample_min: int = 0
    sample_max: int = 0
    sample_mean: float = 0.0
    sample_range: int = 0
    estimated_cycles: float = 0.0

@dataclass
class NoteEvent:
    row: int
    channel: int
    sample: int
    period: int
    effect: int
    param: int

@dataclass
class Pattern:
    index: int
    notes: List[NoteEvent] = field(default_factory=list)
    channel_note_count: List[int] = field(default_factory=lambda: [0,0,0,0])
    channel_effect_counts: List[Dict[int,int]] = field(default_factory=lambda: [{},{},{},{}])

@dataclass
class ModFile:
    filename: str
    name: str
    song_length: int
    positions: List[int]
    marker: str
    instruments: List[Instrument] = field(default_factory=list)
    patterns: List[Pattern] = field(default_factory=list)
    total_size: int = 0
    issues: List[str] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)

def parse_mod(filepath):
    """Parse a .mod file and return a ModFile with forensic data."""
    with open(filepath, 'rb') as f:
        data = f.read()

    mod = ModFile(filename=filepath, name='', song_length=0, positions=[], marker='', total_size=len(data))

    if len(data) < 1084:
        mod.issues.append('file too small for valid .mod (min 1084 bytes)')
        return mod

    # Name (20 bytes)
    mod.name = data[:20].rstrip(b'\x00').decode('latin-1', errors='replace')

    # Instruments (31 × 30 = 930 bytes)
    for i in range(31):
        off = 20 + i * 30
        name = data[off:off+22].rstrip(b'\x00').decode('latin-1', errors='replace')
        length_w = struct.unpack('>H', data[off+22:off+24])[0]
        finetune = data[off+24] & 0x0F
        volume = data[off+25] & 0x7F
        loop_start = struct.unpack('>H', data[off+26:off+28])[0]
        loop_length = struct.unpack('>H', data[off+28:off+30])[0]

        if length_w == 0 and not name:
            continue  # empty instrument slot

        inst = Instrument(
            index=i+1,
            name=name or f'instrument {i+1}',
            length_bytes=length_w * 2,
            finetune=finetune,
            volume=volume,
            loop_start=loop_start * 2,
            loop_length=loop_length * 2,
        )

        if volume == 0:
            mod.issues.append(f'instrument {i+1}: default volume is 0 (silent unless overridden by effect)')

        mod.instruments.append(inst)

    # Song length, positions, marker
    mod.song_length = data[950]
    mod.positions = list(data[952:952+mod.song_length])
    mod.marker = data[1080:1084].decode('latin-1', errors='replace')

    if mod.marker != 'M.K.' and mod.marker != 'M!K!':
        mod.issues.append(f'unexpected marker: {mod.marker!r} (expected M.K. or M!K!)')
    if mod.song_length == 0:
        mod.issues.append('song length is 0')
    if any(p >= 128 for p in mod.positions):
        mod.issues.append('invalid position (>= 128)')

    # Calculate sample data offset
    num_pats = max(mod.positions) + 1 if mod.positions else 0
    sample_offset = 1084 + num_pats * 1024

    if sample_offset + sum(i.length_bytes for i in mod.instruments) > len(data):
        mod.issues.append(f'sample data exceeds file size (expected {sample_offset + sum(i.length_bytes for i in mod.instruments)} bytes, got {len(data)})')

    # Read sample data for each instrument
    samp_pos = sample_offset
    for inst in mod.instruments:
        if inst.index > len(mod.instruments):
            break
        if samp_pos + inst.length_bytes > len(data):
            mod.issues.append(f'instrument {inst.index}: sample data truncated')
            inst.length_bytes = max(0, len(data) - samp_pos)

        if inst.length_bytes > 0:
            raw = data[samp_pos:samp_pos + inst.length_bytes]
            inst.sample_data = raw
            inst.sample_min = min(raw)
            inst.sample_max = max(raw)
            inst.sample_mean = sum(raw) / len(raw) if raw else 0
            inst.sample_range = inst.sample_max - inst.sample_min

            # Detect if sample appears signed or unsigned
            # Unsigned: centered around 128
            # Signed: centered around 0
            center = inst.sample_mean
            if 110 <= center <= 150:
                # Likely unsigned, but many players interpret as signed
                pass
            elif -10 <= center <= 10:
                pass  # likely signed

            # Warn if sample appears silent or near-silent
            if inst.sample_range < 10:
                mod.issues.append(f'instrument {inst.index}: near-silent sample (range={inst.sample_range})')
            if inst.sample_min == inst.sample_max:
                mod.issues.append(f'instrument {inst.index}: completely silent sample (constant value {inst.sample_min})')

            # Estimate cycles in the sample (for frequency analysis)
            # Count zero-crossings to estimate waveform cycles
            signed = [b - 128 for b in raw]  # Interpret as signed
            crossings = 0
            for j in range(1, len(signed)):
                if signed[j-1] >= 0 and signed[j] < 0:
                    crossings += 1
                elif signed[j-1] < 0 and signed[j] >= 0:
                    crossings += 1
            inst.estimated_cycles = crossings / 2.0  # one cycle = two crossings

        samp_pos += inst.length_bytes

    # Parse patterns
    pat_offset = 1084
    for pi in range(num_pats):
        pat = Pattern(index=pi)
        for row in range(64):
            off = pat_offset + pi * 1024 + row * 16
            if off + 16 > len(data):
                break
            for ch in range(4):
                co = off + ch * 4
                a, b, c, d = data[co], data[co+1], data[co+2], data[co+3]
                sample = (a >> 4) & 0x0F
                period = ((a & 0x0F) << 8) | b
                effect = c
                param = d

                if sample == 0 and period == 0 and effect == 0:
                    continue  # rest

                note = NoteEvent(row=row, channel=ch, sample=sample, period=period, effect=effect, param=param)
                pat.notes.append(note)
                pat.channel_note_count[ch] += 1
                if effect > 0:
                    eff_type = effect & 0x0F
                    pat.channel_effect_counts[ch][eff_type] = pat.channel_effect_counts[ch].get(eff_type, 0) + 1

        mod.patterns.append(pat)

    # Compute stats
    total_notes = sum(len(p.notes) for p in mod.patterns)
    total_empty = sum(
        sum(1 for ch in range(4) if p.channel_note_count[ch] == 0)
        for p in mod.patterns
    )
    silent_patterns = [p.index for p in mod.patterns if len(p.notes) == 0]

    mod.stats = {
        'patterns': num_pats,
        'pattern_sequence': mod.positions[:mod.song_length] if mod.song_length else [],
        'total_notes': total_notes,
        'avg_notes_per_pattern': total_notes / max(1, num_pats),
        'silent_patterns': silent_patterns,
        'silent_pattern_count': len(silent_patterns),
        'total_instruments_used': sum(1 for i in mod.instruments if i.length_bytes > 0),
        'total_channels_silent': total_empty,
        'total_sample_bytes': sum(i.length_bytes for i in mod.instruments),
    }

    if len(silent_patterns) > 0:
        mod.issues.append(f'{len(silent_patterns)} patterns have zero notes (patterns: {silent_patterns})')

    # Period frequency check
    audible_notes = 0
    subsonic_notes = 0
    for p in mod.patterns:
        for note in p.notes:
            if note.period > 0:
                # Estimate frequency: Amiga clock / (period * sample_length)
                if note.sample > 0 and note.sample <= len(mod.instruments):
                    inst = mod.instruments[note.sample - 1]
                    if inst.length_bytes > 0 and inst.estimated_cycles > 0:
                        est_freq = 3546895 / (note.period * inst.length_bytes / inst.estimated_cycles)
                        if est_freq < 20:
                            subsonic_notes += 1
                        else:
                            audible_notes += 1

    if subsonic_notes > 0 and audible_notes == 0:
        mod.issues.append(f'all notes are subsonic (< 20 Hz) — the track will be silent. try shorter samples or higher periods')
    elif subsonic_notes > subsonic_notes:
        mod.issues.append(f'{subsonic_notes} notes are subsonic (< 20 Hz) — these may be inaudible')

    return mod


# ============================================================
# Generate report
# ============================================================

def report(mod):
    """Generate a forensic report as a dict."""
    r = {
        'file': mod.filename,
        'name': mod.name,
        'size': mod.total_size,
        'song_length': mod.song_length,
        'positions': mod.positions[:mod.song_length],
        'marker': mod.marker,
        'stats': mod.stats,
        'issues': mod.issues,
        'instruments': [],
        'pattern_summary': [],
    }

    for inst in mod.instruments:
        r['instruments'].append({
            'index': inst.index,
            'name': inst.name,
            'length': inst.length_bytes,
            'volume': inst.volume,
            'loop': f'{inst.loop_start}→{inst.loop_start + inst.loop_length}',
            'sample': {
                'range': f'{inst.sample_min}–{inst.sample_max}',
                'span': inst.sample_range,
                'mean': round(inst.sample_mean, 1),
                'estimated_cycles': round(inst.estimated_cycles, 1),
            }
        })

    for pat in mod.patterns:
        r['pattern_summary'].append({
            'index': pat.index,
            'notes': len(pat.notes),
            'channels': {
                f'ch{ch}': {
                    'notes': pat.channel_note_count[ch],
                    'effects': pat.channel_effect_counts[ch],
                } for ch in range(4)
            }
        })

    return r


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('usage: python3 mod-forensic.py <file.mod>')
        sys.exit(1)

    mod = parse_mod(sys.argv[1])
    r = report(mod)
    print(json.dumps(r, indent=2))
    if mod.issues:
        print(f'\n⚠ {len(mod.issues)} issues:', file=sys.stderr)
        for i in mod.issues:
            print(f'  - {i}', file=sys.stderr)
