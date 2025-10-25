/**
 * Persistence Backend Interface
 * Defines the contract for storage implementations
 */

export interface PersistenceBackend {
  /**
   * Save data to persistent storage
   */
  save(key: string, data: any): Promise<void>;

  /**
   * Load data from persistent storage
   * @returns The data, or null if key doesn't exist
   */
  load(key: string): Promise<any | null>;

  /**
   * Delete data from persistent storage
   */
  delete(key: string): Promise<void>;

  /**
   * Check if a key exists in storage
   */
  exists(key: string): Promise<boolean>;

  /**
   * List all keys matching a pattern (regex)
   */
  list(pattern: string): Promise<string[]>;
}
