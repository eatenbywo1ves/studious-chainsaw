const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

class AudioManager {
  constructor() {
    this.muted = false;
    this.volume = 0.7;
    this.soundQueue = [];
    this.isPlaying = false;

    // Windows Media folder path
    this.windowsMediaPath = 'C:\\Windows\\Media';

    this.initializeSoundMappings();
  }

  initializeSoundMappings() {
    // Map sound types to Windows .wav files
    this.soundMappings = {
      // Default sounds
      'webhook_received': 'Windows Notify.wav',
      'webhook_success': 'chimes.wav',
      'webhook_error': 'Windows Critical Stop.wav',
      'test': 'ding.wav',

      // Workflow sounds
      'workflow_start': 'Windows Logon.wav',
      'workflow_complete': 'tada.wav',
      'step_complete': 'Windows Notify System Generic.wav',
      'step_failed': 'Windows Error.wav',
      'step_progress': 'Windows Navigation Start.wav',

      // Development sounds
      'build_start': 'Windows Navigation Start.wav',
      'build_success': 'tada.wav',
      'build_failed': 'Windows Critical Stop.wav',
      'test_pass': 'chimes.wav',
      'test_fail': 'Windows Exclamation.wav',
      'deploy_start': 'Windows Foreground.wav',
      'deploy_complete': 'Windows Logon.wav',
      'git_push': 'Windows Notify.wav',
      'git_merge': 'chimes.wav',
      'pr_opened': 'Windows Notify Email.wav',
      'pr_merged': 'tada.wav',

      // Claude Code events
      'claude_task_start': 'Windows Foreground.wav',
      'claude_task_complete': 'chimes.wav',
      'claude_error': 'Windows Error.wav',
      'claude_tool_use': 'ding.wav',

      // Alert sounds
      'critical': 'Windows Critical Stop.wav',
      'warning': 'Windows Exclamation.wav',
      'info': 'Windows Balloon.wav',

      // Monitoring sounds
      'health_check': 'ding.wav',
      'metric_threshold': 'Windows Exclamation.wav',
      'error_spike': 'Alarm01.wav',
      'latency_warning': 'Windows Battery Low.wav',
      'traffic_surge': 'Windows Notify System Generic.wav',

      // Communication sounds
      'message_received': 'Windows Notify Messaging.wav',
      'mention': 'Windows Notify.wav',
      'dm_received': 'notify.wav',
      'user_joined': 'Windows Hardware Insert.wav',
      'user_left': 'Windows Hardware Remove.wav'
    };
  }

  async playWebhookSound(event, profileName = 'default') {
    if (this.muted) return;

    let soundType = 'webhook_received';

    if (event.body) {
      if (event.body.status === 'success' || event.body.success === true) {
        soundType = 'webhook_success';
      } else if (event.body.status === 'error' || event.body.error) {
        soundType = 'webhook_error';
      } else if (event.body.type) {
        const eventType = event.body.type.toLowerCase();
        if (this.soundMappings[eventType]) {
          soundType = eventType;
        }
      }
    }

    return this.playSound(soundType, profileName);
  }

  async playSound(soundType, profileName = 'default') {
    if (this.muted) return;

    const wavFile = this.soundMappings[soundType] || this.soundMappings['test'];

    if (!wavFile) {
      console.warn(`No sound mapping for "${soundType}", using default`);
      return;
    }

    this.soundQueue.push({ wavFile, soundType });

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
    const { wavFile, soundType } = this.soundQueue.shift();

    try {
      await this.playWavFile(wavFile);
      console.log(`Played sound: ${soundType} (${wavFile})`);
    } catch (error) {
      console.error(`Error playing sound ${soundType}:`, error.message);
    }

    // Small delay between sounds
    setTimeout(() => this.processQueue(), 100);
  }

  playWavFile(filename) {
    return new Promise((resolve, reject) => {
      const fullPath = path.join(this.windowsMediaPath, filename);

      // Check if file exists
      if (!fs.existsSync(fullPath)) {
        console.warn(`Sound file not found: ${fullPath}, trying fallback`);
        const fallbackPath = path.join(this.windowsMediaPath, 'ding.wav');
        if (fs.existsSync(fallbackPath)) {
          this.playWavFileInternal(fallbackPath, resolve, reject);
        } else {
          reject(new Error(`Sound file not found: ${filename}`));
        }
        return;
      }

      this.playWavFileInternal(fullPath, resolve, reject);
    });
  }

  playWavFileInternal(fullPath, resolve, reject) {
    if (process.platform === 'win32') {
      // Use PowerShell Media.SoundPlayer for Windows
      const escapedPath = fullPath.replace(/'/g, "''");
      const command = `powershell -NoProfile -c "(New-Object Media.SoundPlayer '${escapedPath}').PlaySync()"`;

      exec(command, { timeout: 10000 }, (error) => {
        if (error) {
          console.error('PowerShell playback error:', error.message);
          reject(error);
        } else {
          resolve();
        }
      });
    } else {
      // For Unix-like systems, try aplay, paplay, or ffplay
      const command = `aplay "${fullPath}" 2>/dev/null || paplay "${fullPath}" 2>/dev/null || ffplay -nodisp -autoexit "${fullPath}" 2>/dev/null`;

      exec(command, { timeout: 10000 }, (error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    }
  }

  // Play a custom .wav file from any path
  async playCustomSound(filePath) {
    if (this.muted) return;

    return new Promise((resolve, reject) => {
      this.playWavFileInternal(filePath, resolve, reject);
    });
  }

  configureProfile(profileName, sounds) {
    // Add custom sound mappings
    Object.assign(this.soundMappings, sounds);
  }

  setMuted(muted) {
    this.muted = muted;
    if (muted) {
      this.soundQueue = [];
    }
  }

  setVolume(volume) {
    this.volume = Math.max(0, Math.min(1, volume));
    // Note: Volume control would require more complex audio handling
  }

  // Get list of available sounds
  getAvailableSounds() {
    return Object.keys(this.soundMappings);
  }
}

module.exports = AudioManager;
