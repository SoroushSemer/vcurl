"""
vcurl Cinematic Audio Synthesizer
Generates a 30-second 5-phase story-driven electronic soundtrack aligned with video scenes:
- Phase 1 (0-6s): Tense minor key dark drone & glitch alarm (Threat)
- Phase 2 (6-12s): Cinematic drop & rising synth lead (vcurl Zero-Knowledge Vault)
- Phase 3 (12-18s): High-tech rhythmic arpeggio & staccato pulses (SSRF Shield)
- Phase 4 (18-24s): Uplifting melodic synth drive (Real-time Audit Tracker)
- Phase 5 (24-30s): Triumphant electronic finale & clean fadeout (1-Command Setup)
"""

import math
import os
import struct
import wave


def generate_cinematic_score(output_wav_path: str, duration: float = 30.0, sample_rate: int = 44100):
    total_samples = int(sample_rate * duration)
    
    samples = []
    
    for i in range(total_samples):
        t = i / sample_rate
        
        # --- PHASE DETERMINATION ---
        # Scene 1: 0.0s - 6.0s (Tense / Threat)
        if t < 6.0:
            # Low ominous sub-bass (D minor chord D1: 36.71Hz)
            sub = math.sin(2 * math.pi * 36.71 * t) * 0.4
            # Alarm glitch pulse (D5: 587.33Hz + G#5 tritone: 830.61Hz)
            pulse_env = math.exp(-((t * 4) % 1) * 8)
            alarm = (math.sin(2 * math.pi * 587.33 * t) + math.sin(2 * math.pi * 830.61 * t)) * pulse_env * 0.15
            # Noise glitch clicks
            glitch = ((hash(i) % 1000) / 1000.0 - 0.5) * 0.05 if (i % 2205 == 0) else 0
            
            sig_left = sub + alarm + glitch
            sig_right = sub - alarm + glitch

        # Scene 2: 6.0s - 12.0s (The Hero / vcurl Vault Emergence)
        elif t < 12.0:
            rel_t = t - 6.0
            # Powerful 120 BPM Kick Drum on beats
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 60 * math.exp(-beat_phase * 15)) * math.exp(-beat_phase * 8) * 0.6 if beat_phase < 0.3 else 0
            
            # Rising Heroic Synth Lead (A Major: A3 220Hz -> C#4 277.18Hz -> E4 329.63Hz -> A4 440Hz)
            notes_s2 = [220.0, 277.18, 329.63, 440.0]
            curr_freq = notes_s2[int(rel_t * 2) % len(notes_s2)]
            synth_env = math.exp(-(beat_phase % 0.5) * 6)
            synth = (math.sin(2 * math.pi * curr_freq * t) + 0.5 * math.sin(2 * math.pi * (curr_freq * 2) * t)) * synth_env * 0.25
            
            sig_left = kick + synth
            sig_right = kick + synth * 0.9

        # Scene 3: 12.0s - 18.0s (High-Tech Network Shield & SSRF Defense)
        elif t < 18.0:
            rel_t = t - 12.0
            # Driving beat with Snare
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 65 * math.exp(-beat_phase * 15)) * math.exp(-beat_phase * 8) * 0.5 if beat_phase < 0.25 else 0
            
            # Snare on 2 and 4
            snare_phase = (rel_t * 2 + 0.5) % 1
            snare_noise = ((hash(i) % 1000) / 1000.0 - 0.5) * math.exp(-snare_phase * 12) * 0.35 if snare_phase < 0.2 else 0
            
            # Fast 16th note Arpeggio (E minor pentatonic: E4, G4, A4, B4, D5, E5)
            arp_notes = [329.63, 392.00, 440.0, 493.88, 587.33, 659.25]
            arp_freq = arp_notes[int(rel_t * 8) % len(arp_notes)]
            arp_env = math.exp(-((rel_t * 8) % 1) * 12)
            arp = math.sin(2 * math.pi * arp_freq * t) * arp_env * 0.22
            
            sig_left = kick + snare_noise + arp * 1.2
            sig_right = kick + snare_noise + arp * 0.8

        # Scene 4: 18.0s - 24.0s (Uplifting Real-Time Audit Stream)
        elif t < 24.0:
            rel_t = t - 18.0
            # Energetic Full Beat
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 70 * math.exp(-beat_phase * 16)) * math.exp(-beat_phase * 7) * 0.55 if beat_phase < 0.25 else 0
            
            # Bright Melodic Chords (D Major -> A Major -> B minor -> G Major)
            chord_seq = [
                [293.66, 370.0, 440.0],  # D
                [220.0, 277.18, 329.63], # A
                [246.94, 293.66, 370.0], # Bm
                [196.0, 246.94, 293.66]  # G
            ]
            current_chord = chord_seq[int(rel_t / 1.5) % len(chord_seq)]
            chord_signal = sum(math.sin(2 * math.pi * f * t) for f in current_chord) * 0.1
            
            # Hi-hats
            hat_phase = (rel_t * 4) % 1
            hat = ((hash(i) % 1000) / 1000.0 - 0.5) * math.exp(-hat_phase * 30) * 0.15 if hat_phase < 0.1 else 0
            
            sig_left = kick + chord_signal + hat
            sig_right = kick + chord_signal - hat

        # Scene 5: 24.0s - 30.0s (Triumphant Finale & Clean Fadeout)
        else:
            rel_t = t - 24.0
            fade_out = math.exp(-rel_t * 0.6) if rel_t > 4.0 else 1.0
            
            # Epic Orchestral Synth Brass Chord (D Major 9: D3, F#3, A3, C#4, E4)
            brass_notes = [146.83, 185.00, 220.00, 277.18, 329.63]
            brass = sum(
                (math.sin(2 * math.pi * f * t) + 0.3 * math.sin(2 * math.pi * f * 2 * t))
                for f in brass_notes
            ) * 0.08 * fade_out
            
            # Final Drum roll leading to resolution
            beat_phase = (rel_t * 2) % 1
            kick = math.sin(2 * math.pi * 60 * math.exp(-beat_phase * 15)) * math.exp(-beat_phase * 6) * 0.6 * fade_out if beat_phase < 0.3 else 0
            
            sig_left = (kick + brass) * fade_out
            sig_right = (kick + brass) * fade_out
        
        # Soft limiter / Master volume
        val_l = int(max(-32768, min(32767, sig_left * 24000)))
        val_r = int(max(-32768, min(32767, sig_right * 24000)))
        samples.append(struct.pack('<hh', val_l, val_r))
        
    os.makedirs(os.path.dirname(output_wav_path), exist_ok=True)
    with wave.open(output_wav_path, 'w') as wav_file:
        wav_file.setnchannels(2)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(b''.join(samples))

    print(f"Generated 5-Phase Story Soundtrack ({duration}s) at: {output_wav_path}")


if __name__ == "__main__":
    generate_cinematic_score("c:/Users/Soroush/Documents/vcurl/vcurl-promo/audio/cinematic_story_track.wav")
