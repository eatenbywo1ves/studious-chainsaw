const player = require('play-sound')();
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

class AudioManager {
  constructor() {
    this.muted = false;
    this.volume = 0.7;
    this.audioProfiles = new Map();
    this.soundQueue = [];
    this.isPlaying = false;
    
    this.initializeDefaultProfiles();
    this.ensureAudioDirectory();
  }

  initializeDefaultProfiles() {
    // Default profile - subtle notification sounds
    this.audioProfiles.set('default', {
      webhook_received: { frequency: 440, duration: 100, type: 'sine' },
      webhook_success: { frequency: 523, duration: 150, type: 'sine' },
      webhook_error: { frequency: 220, duration: 300, type: 'sawtooth' },
      test: { frequency: 440, duration: 200, type: 'sine' }
    });

    // Workflow profile - more melodic sounds
    this.audioProfiles.set('workflow', {
      workflow_start: { frequencies: [523, 659, 784], duration: 500, type: 'sine' },
      step_complete: { frequencies: [440, 554, 659], duration: 200, type: 'sine' },
      step_failed: { frequencies: [330, 294, 220], duration: 400, type: 'sawtooth' },
      step_progress: { frequency: 494, duration: 100, type: 'sine' },
      workflow_complete: { frequencies: [523, 659, 784, 1047], duration: 800, type: 'sine' }
    });

    // Alert profile - attention-grabbing sounds
    this.audioProfiles.set('alert', {
      critical: { frequencies: [880, 440, 880], duration: 1000, type: 'square' },
      warning: { frequencies: [660, 550], duration: 600, type: 'triangle' },
      info: { frequency: 440, duration: 300, type: 'sine' }
    });

    // Development profile - distinctive sounds for different events
    this.audioProfiles.set('development', {
      build_start: { frequency: 261, duration: 200, type: 'sine' },
      build_success: { frequencies: [261, 329, 392, 523], duration: 600, type: 'sine' },
      build_failed: { frequencies: [440, 220], duration: 800, type: 'square' },
      test_pass: { frequencies: [523, 659], duration: 300, type: 'sine' },
      test_fail: { frequencies: [330, 220], duration: 500, type: 'sawtooth' },
      deploy_start: { frequencies: [392, 494, 587], duration: 400, type: 'sine' },
      deploy_complete: { frequencies: [392, 494, 587, 784], duration: 1000, type: 'sine' },
      git_push: { frequency: 440, duration: 150, type: 'sine' },
      git_merge: { frequencies: [440, 554], duration: 300, type: 'sine' },
      pr_opened: { frequencies: [659, 784], duration: 400, type: 'sine' },
      pr_merged: { frequencies: [523, 659, 784, 1047], duration: 800, type: 'sine' }
    });

    // Monitoring profile - status-based sounds
    this.audioProfiles.set('monitoring', {
      health_check: { frequency: 440, duration: 50, type: 'sine' },
      metric_threshold: { frequencies: [550, 660], duration: 400, type: 'triangle' },
      error_spike: { frequencies: [880, 440, 880], duration: 600, type: 'square' },
      latency_warning: { frequency: 330, duration: 500, type: 'sawtooth' },
      traffic_surge: { frequencies: [440, 550, 660], duration: 300, type: 'sine' }
    });

    // Communication profile - for chat/messaging events
    this.audioProfiles.set('communication', {
      message_received: { frequency: 659, duration: 100, type: 'sine' },
      mention: { frequencies: [659, 784], duration: 200, type: 'sine' },
      dm_received: { frequencies: [523, 659], duration: 250, type: 'sine' },
      user_joined: { frequencies: [392, 523], duration: 300, type: 'sine' },
      user_left: { frequencies: [523, 392], duration: 300, type: 'sine' }
    });
  }

  ensureAudioDirectory() {
    const audioDir = path.join(__dirname, 'audio_cache');
    if (!fs.existsSync(audioDir)) {
      fs.mkdirSync(audioDir, { recursive: true });
    }
  }

  async playWebhookSound(event, profileName = 'default') {
    if (this.muted) return;

    // Determine sound based on event characteristics
    let soundType = 'webhook_received';
    
    // Check for specific patterns in the event
    if (event.body) {
      if (event.body.status === 'success' || event.body.success === true) {
        soundType = 'webhook_success';
      } else if (event.body.status === 'error' || event.body.error) {
        soundType = 'webhook_error';
      } else if (event.body.type) {
        // Try to map event type to a sound
        const eventType = event.body.type.toLowerCase();
        const profile = this.audioProfiles.get(profileName);
        if (profile && profile[eventType]) {
          soundType = eventType;
        }
      }
    }

    return this.playSound(soundType, profileName);
  }

  async playSound(soundType, profileName = 'default') {
    if (this.muted) return;

    const profile = this.audioProfiles.get(profileName) || this.audioProfiles.get('default');
    const soundConfig = profile[soundType] || profile['test'];

    // Add to queue
    this.soundQueue.push({ soundConfig, soundType, profileName });
    
    // Process queue if not already playing
    if (!this.isPlaying) {
      this.processQueue();
    }
  }

  async processQueue() {
    if (this.soundQueue.length === 0) {
      this.isPlaying = false;
      return;
    }

    this.isPlaying = true;
    const { soundConfig, soundType, profileName } = this.soundQueue.shift();

    try {
      if (soundConfig.frequencies) {
        // Play a sequence of tones
        for (const freq of soundConfig.frequencies) {
          await this.generateAndPlayTone(freq, soundConfig.duration / soundConfig.frequencies.length, soundConfig.type);
        }
      } else {
        // Play a single tone
        await this.generateAndPlayTone(soundConfig.frequency, soundConfig.duration, soundConfig.type);
      }
    } catch (error) {
      console.error('Error playing sound:', error);
    }

    // Process next sound in queue
    setTimeout(() => this.processQueue(), 50);
  }

  generateAndPlayTone(frequency, duration, waveType = 'sine') {
    return new Promise((resolve) => {
      // For Windows, use PowerShell to generate beeps
      if (process.platform === 'win32') {
        const command = `powershell -c "[console]::beep(${Math.round(frequency)}, ${Math.round(duration)})"`;
        exec(command, (error) => {
          if (error) {
            console.error('Error playing beep:', error);
            // Fallback to simple console beep
            process.stdout.write('\x07');
          }
          resolve();
        });
      } else {
        // For Unix-like systems, try to use sox or ffplay
        const durationInSeconds = duration / 1000;
        const command = `play -n synth ${durationInSeconds} ${waveType} ${frequency} vol ${this.volume} 2>/dev/null || ffplay -f lavfi -i "sine=frequency=${frequency}:duration=${durationInSeconds}" -autoexit -nodisp -loglevel quiet 2>/dev/null || echo -e "\a"`;
        
        exec(command, (error) => {
          if (error) {
            // Fallback to console beep
            process.stdout.write('\x07');
          }
          resolve();
        });
      }
    });
  }

  configureProfile(profileName, sounds) {
    if (!this.audioProfiles.has(profileName)) {
      this.audioProfiles.set(profileName, {});
    }
    
    const profile = this.audioProfiles.get(profileName);
    Object.assign(profile, sounds);
  }

  setMuted(muted) {
    this.muted = muted;
    if (muted) {
      this.soundQueue = []; // Clear queue when muting
    }
  }

  setVolume(volume) {
    this.volume = Math.max(0, Math.min(1, volume));
  }

  // Generate audio patterns for different event types
  generateAudioPattern(eventType, data = {}) {
    const patterns = {
      'rapid_success': [
        { frequency: 523, duration: 50 },
        { frequency: 659, duration: 50 },
        { frequency: 784, duration: 100 }
      ],
      'cascade_failure': [
        { frequency: 440, duration: 100 },
        { frequency: 330, duration: 100 },
        { frequency: 220, duration: 200 }
      ],
      'progress_indicator': [
        { frequency: 440, duration: 100 },
        { frequency: 494, duration: 100 },
        { frequency: 554, duration: 100 }
      ],
      'completion_fanfare': [
        { frequency: 523, duration: 200 },
        { frequency: 659, duration: 200 },
        { frequency: 784, duration: 200 },
        { frequency: 1047, duration: 400 }
      ],
      'alert_escalation': [
        { frequency: 440, duration: 200 },
        { frequency: 440, duration: 200 },
        { frequency: 880, duration: 400 }
      ]
    };

    return patterns[eventType] || patterns['progress_indicator'];
  }

  // Play custom pattern
  async playPattern(pattern) {
    if (this.muted) return;

    for (const note of pattern) {
      await this.generateAndPlayTone(
        note.frequency,
        note.duration,
        note.type || 'sine'
      );
      // Small gap between notes
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  }
}

module.exports = AudioManager;