/**
 * JSON File Persistence Backend
 * Simple file-based storage using atomic writes
 */

import { promises as fs } from 'fs';
import path from 'path';
import { PersistenceBackend } from './interface.js';

export class JsonFilePersistence implements PersistenceBackend {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  async save(key: string, data: any): Promise<void> {
    const filePath = path.join(this.basePath, `${key}.json`);

    // Ensure directory exists
    await fs.mkdir(path.dirname(filePath), { recursive: true });

    // Atomic write: write to temp file, then rename
    // This prevents corruption if process crashes during write
    const tempPath = `${filePath}.tmp`;
    await fs.writeFile(tempPath, JSON.stringify(data, null, 2), 'utf-8');
    await fs.rename(tempPath, filePath);
  }

  async load(key: string): Promise<any | null> {
    try {
      const filePath = path.join(this.basePath, `${key}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      // Return null if file doesn't exist
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return null;
      }
      // Re-throw other errors (permission, invalid JSON, etc.)
      throw error;
    }
  }

  async delete(key: string): Promise<void> {
    const filePath = path.join(this.basePath, `${key}.json`);
    try {
      await fs.unlink(filePath);
    } catch (error) {
      // Ignore if file doesn't exist
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
        throw error;
      }
    }
  }

  async exists(key: string): Promise<boolean> {
    const filePath = path.join(this.basePath, `${key}.json`);
    try {
      await fs.access(filePath);
      return true;
    } catch {
      return false;
    }
  }

  async list(pattern: string): Promise<string[]> {
    try {
      // Ensure directory exists
      await fs.mkdir(this.basePath, { recursive: true });

      const files = await fs.readdir(this.basePath);
      const regex = new RegExp(pattern);

      return files
        .filter(f => f.endsWith('.json'))
        .map(f => f.replace('.json', ''))
        .filter(f => regex.test(f));
    } catch (error) {
      // Return empty list if directory doesn't exist
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }
}
