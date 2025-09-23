/**
 * MCP Server Generator Core
 */

import fs from 'fs-extra';
import path from 'path';
import Handlebars from 'handlebars';
import { exec } from 'child_process';
import { promisify } from 'util';
import { fileURLToPath } from 'url';

const execAsync = promisify(exec);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface GeneratorConfig {
  name?: string;
  description?: string;
  template?: string;
  features?: string[];
  language?: string;
  outputDir: string;
}

export class Generator {
  private config: GeneratorConfig;
  private templateDir: string;

  constructor(config: GeneratorConfig) {
    this.config = config;
    this.templateDir = path.join(__dirname, '..', 'templates');
  }

  async generate(): Promise<void> {
    // Ensure output directory exists
    await fs.ensureDir(this.config.outputDir);

    // Check if directory is empty
    const files = await fs.readdir(this.config.outputDir);
    if (files.length > 0 && !files.every(f => f.startsWith('.'))) {
      throw new Error('Output directory is not empty');
    }

    // Generate based on language
    switch (this.config.language) {
      case 'typescript':
        await this.generateTypeScript();
        break;
      case 'javascript':
        await this.generateJavaScript();
        break;
      case 'python':
        await this.generatePython();
        break;
      default:
        await this.generateTypeScript();
    }
  }

  private async generateTypeScript(): Promise<void> {
    const template = this.config.template || 'basic';

    // Create directory structure
    const dirs = [
      'src',
      'src/tools',
      'src/resources',
      'src/prompts',
      'src/middleware',
      'src/types',
      'test'
    ];

    for (const dir of dirs) {
      await fs.ensureDir(path.join(this.config.outputDir, dir));
    }

    // Generate package.json
    await this.generateFile('package.json.hbs', 'package.json', {
      name: this.config.name,
      description: this.config.description,
      features: this.config.features
    });

    // Generate tsconfig.json
    await this.generateFile('tsconfig.json.hbs', 'tsconfig.json');

    // Generate main server file
    await this.generateFile(`${template}/index.ts.hbs`, 'src/index.ts', {
      name: this.config.name,
      features: this.config.features
    });

    // Generate feature-specific files
    if (this.config.features?.includes('tools')) {
      await this.generateFile(`${template}/tool.ts.hbs`, 'src/tools/example.ts');
    }

    if (this.config.features?.includes('resources')) {
      await this.generateFile(`${template}/resource.ts.hbs`, 'src/resources/example.ts');
    }

    if (this.config.features?.includes('prompts')) {
      await this.generateFile(`${template}/prompt.ts.hbs`, 'src/prompts/example.ts');
    }

    if (this.config.features?.includes('auth')) {
      await this.generateFile('common/auth.ts.hbs', 'src/middleware/auth.ts');
    }

    if (this.config.features?.includes('rateLimit')) {
      await this.generateFile('common/rate-limit.ts.hbs', 'src/middleware/rate-limit.ts');
    }

    if (this.config.features?.includes('docker')) {
      await this.generateFile('Dockerfile.hbs', 'Dockerfile');
      await this.generateFile('docker-compose.yml.hbs', 'docker-compose.yml', {
        name: this.config.name
      });
    }

    // Generate README
    await this.generateFile('README.md.hbs', 'README.md', {
      name: this.config.name,
      description: this.config.description,
      features: this.config.features
    });

    // Generate .gitignore
    await this.generateFile('gitignore.hbs', '.gitignore');

    // Generate .env.example
    await this.generateFile('env.example.hbs', '.env.example');
  }

  private async generateJavaScript(): Promise<void> {
    // Similar to TypeScript but without types
    await this.generateTypeScript();

    // Remove TypeScript config
    await fs.remove(path.join(this.config.outputDir, 'tsconfig.json'));

    // Convert .ts files to .js
    // This would involve transforming the templates
  }

  private async generatePython(): Promise<void> {
    // Create Python project structure
    const dirs = [
      'src',
      'src/tools',
      'src/resources',
      'src/prompts',
      'tests'
    ];

    for (const dir of dirs) {
      await fs.ensureDir(path.join(this.config.outputDir, dir));
    }

    // Generate Python-specific files
    await this.generateFile('python/requirements.txt.hbs', 'requirements.txt');
    await this.generateFile('python/setup.py.hbs', 'setup.py', {
      name: this.config.name,
      description: this.config.description
    });
    await this.generateFile('python/main.py.hbs', 'src/main.py', {
      name: this.config.name,
      features: this.config.features
    });
  }

  private async generateFile(
    templateFile: string,
    outputFile: string,
    data?: any
  ): Promise<void> {
    const templatePath = path.join(this.templateDir, templateFile);
    const outputPath = path.join(this.config.outputDir, outputFile);

    // Check if template exists, if not use a default
    let templateContent: string;
    if (await fs.pathExists(templatePath)) {
      templateContent = await fs.readFile(templatePath, 'utf-8');
    } else {
      // Use embedded default template
      templateContent = this.getDefaultTemplate(templateFile);
    }

    const template = Handlebars.compile(templateContent);
    const content = template(data || {});

    await fs.writeFile(outputPath, content);
  }

  async addComponent(type: string, config: any): Promise<void> {
    const componentDir = path.join(this.config.outputDir, 'src', `${type}s`);
    await fs.ensureDir(componentDir);

    const outputPath = path.join(componentDir, `${config.name}.ts`);

    // Generate component based on type
    const content = this.generateComponentCode(type, config);
    await fs.writeFile(outputPath, content);

    // Update index file to export the new component
    await this.updateIndex(type, config.name);
  }

  private generateComponentCode(type: string, config: any): string {
    switch (type) {
      case 'tool':
        return `import { z } from 'zod';

export const ${config.name}Schema = z.object({
  // Define parameters here
});

export async function ${config.name}(params: z.infer<typeof ${config.name}Schema>) {
  // Implement tool logic here
  return {
    success: true,
    result: 'Tool executed successfully'
  };
}

export const ${config.name}Tool = {
  name: '${config.name}',
  description: '${config.description}',
  parameters: ${config.name}Schema,
  handler: ${config.name}
};`;

      case 'resource':
        return `export async function get${config.name}() {
  // Implement resource fetching logic here
  return {
    data: 'Resource data'
  };
}

export const ${config.name}Resource = {
  name: '${config.name}',
  uri: '${config.name.toLowerCase()}',
  description: '${config.description}',
  handler: get${config.name}
};`;

      case 'prompt':
        return `export const ${config.name}Prompt = {
  name: '${config.name}',
  description: '${config.description}',
  template: (args: any) => \`
    # ${config.name}

    Your prompt template here with \${args.variable} substitution
  \`
};`;

      default:
        return '// Component code';
    }
  }

  private async updateIndex(type: string, name: string): Promise<void> {
    const indexPath = path.join(this.config.outputDir, 'src', `${type}s`, 'index.ts');

    let content = '';
    if (await fs.pathExists(indexPath)) {
      content = await fs.readFile(indexPath, 'utf-8');
    }

    content += `\nexport * from './${name}.js';`;
    await fs.writeFile(indexPath, content);
  }

  async installDependencies(): Promise<void> {
    const command = 'npm install';
    await execAsync(command, { cwd: this.config.outputDir });
  }

  private getDefaultTemplate(templateFile: string): string {
    // Return embedded default templates
    if (templateFile === 'package.json.hbs') {
      return `{
  "name": "{{name}}",
  "version": "1.0.0",
  "description": "{{description}}",
  "type": "module",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "dev": "tsx src/index.ts",
    "start": "node dist/index.js"
  },
  "dependencies": {
    "@modelcontextprotocol/sdk": "latest",
    "@monorepo/mcp-sdk": "^1.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "tsx": "^4.0.0"
  }
}`;
    }

    // Add more default templates as needed
    return '';
  }
}