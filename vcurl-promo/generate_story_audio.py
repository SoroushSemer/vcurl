"""
vcurl Cinematic Audio Synthesizer (42-Second Social Marketing Edition)
Generates a 42-second 6-phase story-driven electronic soundtrack aligned with video scenes:
- Phase 1 (0-7s): Threat Minor Drone & Glitch Click (Prompt Injection Hook)
- Phase 2 (7-14s): Heroic Drop & Rising Synth Lead (vcurl Zero-Knowledge Vault)
- Phase 3 (14-21s): High-Tech 16th Note Arpeggio (JIT Socket Resolution)
- Phase 4 (21-28s): Punchy Percussive Metrics Beat (Security & Latency Benchmarks)
- Phase 5 (28-35s): Uplifting Audit Stream Melodic Chords (Management Web UI)
- Phase 6 (35-42s): Triumphant Social Finale & Clean Fadeout (1-Command CTA)
"""

import math
import os
import struct
import wave


def generate_cinematic_score(output_wav_path: str, duration: float = 42.0, sample_rate: int = 44100):
    total_samples = int(sample_rate * duration)
    samples = []
    
    for i in range(total_samples):
        t = i / sample_rate
        
        # --- 6 SCENE PHASES (7 seconds per phase) ---
        
        # Phase 1: 0.0s - 7.0s (Tense / Threat Hook)
        if t < 7.0:
            sub = math.sin(2 * math.pi * 36.71 * t) * 0.4
            pulse_env = math.exp(-((t * 4) % 1) * 8)
            alarm = (math.sin(2 * math.pi * 587.33 * t) + math.sin(2 * math.pi * 830.61 * t)) * pulse_env * 0.15
            glitch = ((hash(i) % 1000) / 1000.0 - 0.5) * 0.05 if (i % 2205 == 0) else 0
            sig_left, sig_right = sub + alarm + glitch, sub - alarm + glitch

        # Phase 2: 7.0s - 14.0s (vcurl Hero Drop)
        elif t < 14.0:
            rel_t = t - 7.0
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 60 * math.exp(-beat_phase * 15)) * math.exp(-beat_phase * 8) * 0.6 if beat_phase < 0.3 else 0
            
            notes_s2 = [220.0, 277.18, 329.63, 440.0]
            curr_freq = notes_s2[int(rel_t * 2) % len(notes_s2)]
            synth_env = math.exp(-(beat_phase % 0.5) * 6)
            synth = (math.sin(2 * math.pi * curr_freq * t) + 0.5 * math.sin(2 * math.pi * (curr_freq * 2) * t)) * synth_env * 0.25
            sig_left, sig_right = kick + synth, kick + synth * 0.9

        # Phase 3: 14.0s - 21.0s (JIT Network Arpeggio)
        elif t < 21.0:
            rel_t = t - 14.0
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 65 * math.exp(-beat_phase * 15)) * math.exp(-beat_phase * 8) * 0.5 if beat_phase < 0.25 else 0
            
            snare_phase = (rel_t * 2 + 0.5) % 1
            snare_noise = ((hash(i) % 1000) / 1000.0 - 0.5) * math.exp(-snare_phase * 12) * 0.35 if snare_phase < 0.2 else 0
            
            arp_notes = [329.63, 392.00, 440.0, 493.88, 587.33, 659.25]
            arp_freq = arp_notes[int(rel_t * 8) % len(arp_notes)]
            arp_env = math.exp(-((rel_t * 8) % 1) * 12)
            arp = math.sin(2 * math.pi * arp_freq * t) * arp_env * 0.22
            sig_left, sig_right = kick + snare_noise + arp * 1.2, kick + snare_noise + arp * 0.8

        # Phase 4: 21.0s - 28.0s (Punchy Metrics Social Proof Beat)
        elif t < 28.0:
            rel_t = t - 21.0
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 75 * math.exp(-beat_phase * 18)) * math.exp(-beat_phase * 6) * 0.65 if beat_phase < 0.28 else 0
            
            # Driving synth bass accent
            bass_freq = 110.0 if (int(rel_t * 2) % 2 == 0) else 146.83
            bass = math.sin(2 * math.pi * bass_freq * t) * math.exp(-beat_phase * 5) * 0.25
            
            hat_phase = (rel_t * 4) % 1
            hat = ((hash(i) % 1000) / 1000.0 - 0.5) * math.exp(-hat_phase * 35) * 0.18 if hat_phase < 0.08 else 0
            sig_left, sig_right = kick + bass + hat, kick + bass - hat

        # Phase 5: 28.0s - 35.0s (Uplifting Audit Stream Dashboard)
        elif t < 35.0:
            rel_t = t - 28.0
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 70 * math.exp(-beat_phase * 16)) * math.exp(-beat_phase * 7) * 0.55 if beat_phase < 0.25 else 0
            
            chord_seq = [
                [293.66, 370.0, 440.0],  # D
                [220.0, 277.18, 329.63], # A
                [246.94, 293.66, 370.0], # Bm
                [196.0, 246.94, 293.66]  # G
            ]
            current_chord = chord_seq[int(rel_t / 1.75) % len(chord_seq)]
            chord_signal = sum(math.sin(2 * math.pi * f * t) for f in current_chord) * 0.11
            
            hat_phase = (rel_t * 4) % 1
            hat = ((hash(i) % 1000) / 1000.0 - 0.5) * math.exp(-hat_phase * 30) * 0.15 if hat_phase < 0.1 else 0
            sig_left, sig_right = kick + chord_signal + hat, kick + chord_signal - hat

        # Phase 6: 35.0s - 42.0s (Triumphant Social Finale & Clean Fadeout)
        else:
            rel_t = t - 35.0
            fade_out = math.exp(-rel_t * 0.6) if rel_t > 5.0 else 1.0
            
            brass_notes = [146.83, 185.00, 220.00, 277.18, 329.63]
            brass = sum(
                (math.sin(2 * math.pi * f * t) + 0.3 * math.sin(2 * math.pi * f * 2 * t))
                for f in brass_notes
            ) * 0.08 * fade_out
            
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 60 * math.exp(-beat_phase * 15)) * math.exp(-beat_phase * 6) * 0.6 * fade_out if beat_phase < 0.3 else 0
            sig_left, sig_right = (kick + brass) * fade_out, (kick + brass) * fade_out
        
        val_l = int(max(-32768, min(32767, sig_left * 24000)))
        val_r = int(max(-32768, min(32767, sig_right * 24000)))
        samples.append(struct.pack('<hh', val_l, val_r))
        
    os.makedirs(os.path.dirname(output_wav_path), exist_ok=True)
    with wave.open(output_wav_path, 'w') as wav_file:
        wav_file.setnchannels(2)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(b''.join(samples))

    print(f"Generated 42s Social Marketing Soundtrack at: {output_wav_path}")


if __name__ == "__main__":
    generate_cinematic_score("c:/Users/Soroush/Documents/vcurl/vcurl-promo/audio/cinematic_story_track.wav")
