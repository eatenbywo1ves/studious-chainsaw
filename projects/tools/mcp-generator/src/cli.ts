#!/usr/bin/env node

/**
 * MCP Server Generator CLI
 */

import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';
import { Generator } from './generator.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const program = new Command();

program
  .name('mcp-gen')
  .description('Generate MCP servers with best practices')
  .version('1.0.0');

program
  .command('create [name]')
  .description('Create a new MCP server')
  .option('-t, --template <template>', 'Template to use', 'basic')
  .option('-o, --output <dir>', 'Output directory')
  .option('--no-install', 'Skip dependency installation')
  .action(async (name, options) => {
    console.log(chalk.cyan.bold('\n🚀 MCP Server Generator\n'));

    // Collect project information
    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'name',
        message: 'Server name:',
        default: name || 'my-mcp-server',
        validate: (input) => {
          if (!/^[a-z0-9-]+$/.test(input)) {
            return 'Name must contain only lowercase letters, numbers, and hyphens';
          }
          return true;
        }
      },
      {
        type: 'input',
        name: 'description',
        message: 'Description:',
        default: 'A Model Context Protocol server'
      },
      {
        type: 'list',
        name: 'template',
        message: 'Select template:',
        choices: [
          { name: 'Basic - Simple MCP server', value: 'basic' },
          { name: 'Financial - Financial tools and resources', value: 'financial' },
          { name: 'Agent - Agent-based MCP server', value: 'agent' },
          { name: 'CRUD - Database CRUD operations', value: 'crud' },
          { name: 'Custom - Start from scratch', value: 'custom' }
        ],
        when: !options.template
      },
      {
        type: 'checkbox',
        name: 'features',
        message: 'Select features:',
        choices: [
          { name: 'Tools', value: 'tools', checked: true },
          { name: 'Resources', value: 'resources', checked: true },
          { name: 'Prompts', value: 'prompts', checked: false },
          { name: 'Authentication', value: 'auth', checked: false },
          { name: 'Rate limiting', value: 'rateLimit', checked: false },
          { name: 'Caching', value: 'cache', checked: false },
          { name: 'Metrics', value: 'metrics', checked: false },
          { name: 'Docker support', value: 'docker', checked: false }
        ]
      },
      {
        type: 'list',
        name: 'language',
        message: 'Language:',
        choices: [
          { name: 'TypeScript', value: 'typescript' },
          { name: 'JavaScript', value: 'javascript' },
          { name: 'Python', value: 'python' }
        ]
      }
    ]);

    const config = {
      ...answers,
      template: answers.template || options.template,
      outputDir: options.output || path.join(process.cwd(), answers.name)
    };

    const spinner = ora('Generating MCP server...').start();

    try {
      const generator = new Generator(config);
      await generator.generate();

      spinner.succeed(chalk.green('✅ MCP server generated successfully!'));

      console.log('\n' + chalk.yellow('📁 Project structure:'));
      await printDirectoryTree(config.outputDir);

      if (options.install !== false) {
        console.log('\n' + chalk.cyan('📦 Installing dependencies...'));
        await generator.installDependencies();
        console.log(chalk.green('✅ Dependencies installed!'));
      }

      console.log('\n' + chalk.magenta.bold('🎉 Your MCP server is ready!'));
      console.log('\nNext steps:');
      console.log(chalk.gray(`  cd ${path.relative(process.cwd(), config.outputDir)}`));
      if (options.install === false) {
        console.log(chalk.gray('  npm install'));
      }
      console.log(chalk.gray('  npm run dev'));

    } catch (error) {
      spinner.fail(chalk.red('Failed to generate MCP server'));
      console.error(error);
      process.exit(1);
    }
  });

program
  .command('add <component>')
  .description('Add a component to existing MCP server')
  .option('-n, --name <name>', 'Component name')
  .action(async (component, options) => {
    const validComponents = ['tool', 'resource', 'prompt', 'middleware'];

    if (!validComponents.includes(component)) {
      console.error(chalk.red(`Invalid component: ${component}`));
      console.log('Valid components:', validComponents.join(', '));
      process.exit(1);
    }

    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'name',
        message: `${component} name:`,
        default: options.name || `my-${component}`,
        validate: (input) => {
          if (!/^[a-zA-Z][a-zA-Z0-9]*$/.test(input)) {
            return 'Name must start with a letter and contain only alphanumeric characters';
          }
          return true;
        }
      },
      {
        type: 'input',
        name: 'description',
        message: 'Description:',
        default: `A ${component} for MCP server`
      }
    ]);

    const spinner = ora(`Adding ${component}...`).start();

    try {
      const generator = new Generator({ outputDir: process.cwd() });
      await generator.addComponent(component, answers);

      spinner.succeed(chalk.green(`✅ ${component} added successfully!`));
      console.log(chalk.gray(`  Created: src/${component}s/${answers.name}.ts`));

    } catch (error) {
      spinner.fail(chalk.red(`Failed to add ${component}`));
      console.error(error);
      process.exit(1);
    }
  });

program
  .command('list-templates')
  .description('List available templates')
  .action(() => {
    console.log(chalk.cyan.bold('\n📚 Available Templates:\n'));

    const templates = [
      {
        name: 'basic',
        description: 'Simple MCP server with example tools and resources'
      },
      {
        name: 'financial',
        description: 'Financial calculations, market data, and analytics'
      },
      {
        name: 'agent',
        description: 'Agent-based server with task orchestration'
      },
      {
        name: 'crud',
        description: 'Database CRUD operations with ORM support'
      },
      {
        name: 'custom',
        description: 'Minimal template to start from scratch'
      }
    ];

    templates.forEach(t => {
      console.log(chalk.yellow(`  ${t.name}:`));
      console.log(chalk.gray(`    ${t.description}\n`));
    });
  });

async function printDirectoryTree(dir: string, prefix = '') {
  const items = await fs.readdir(dir);

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const itemPath = path.join(dir, item);
    const stats = await fs.stat(itemPath);
    const isLast = i === items.length - 1;
    const connector = isLast ? '└── ' : '├── ';

    console.log(chalk.gray(prefix + connector) + chalk.white(item));

    if (stats.isDirectory() && !item.includes('node_modules')) {
      const extension = isLast ? '    ' : '│   ';
      await printDirectoryTree(itemPath, prefix + extension);
    }
  }
}

program.parse();