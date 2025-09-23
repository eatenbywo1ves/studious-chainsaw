// TypeDoc configuration for comprehensive API documentation
module.exports = {
  // Entry points for documentation generation
  entryPoints: [
    "packages/shared/src/index.ts",
    "packages/stochastic-components/src/index.ts",
    "packages/random-walk-components/src/index.ts"
  ],

  // Output directory
  out: "docs/api",

  // Project information
  name: "Projects Monorepo API Documentation",
  includeVersion: true,
  readme: "docs/api/README.md",

  // TypeScript compilation
  tsconfig: "tsconfig.json",

  // Content filtering
  excludePrivate: true,
  excludeProtected: true,
  excludeExternals: true,
  excludeNotDocumented: false,

  // Theme and styling
  theme: "default",
  customCss: "docs/api/custom.css",

  // Plugins
  plugin: [
    "@typedoc/plugin-pages",
    "typedoc-plugin-mermaid"
  ],

  // Organization
  categorizeByGroup: true,
  categoryOrder: [
    "Components",
    "Hooks",
    "Utilities",
    "Types",
    "Constants",
    "Algorithms",
    "Other"
  ],

  // Sorting
  sort: ["source-order"],
  kindSortOrder: [
    "Reference",
    "Project",
    "Module",
    "Namespace",
    "Enum",
    "EnumMember",
    "Class",
    "Interface",
    "TypeAlias",
    "Constructor",
    "Property",
    "Variable",
    "Function",
    "Accessor",
    "Method",
    "Parameter",
    "TypeParameter",
    "TypeLiteral",
    "CallSignature",
    "ConstructorSignature",
    "IndexSignature",
    "GetSignature",
    "SetSignature"
  ],

  // Navigation
  navigation: {
    includeCategories: true,
    includeGroups: true,
    includeFolders: false
  },

  // Advanced options
  treatWarningsAsErrors: false,
  intentionallyNotExported: [
    "InternalTypes",
    "PrivateInterfaces"
  ],

  // Validation
  validation: {
    notExported: true,
    invalidLink: true,
    notDocumented: false
  },

  // Search
  searchInComments: true,
  searchInDocuments: true,

  // External documentation
  externalPattern: [
    "**/node_modules/**"
  ],

  // Git integration
  gitRevision: "main",
  gitRemote: "origin",

  // Custom options for mermaid plugin
  mermaid: {
    theme: "default"
  },

  // Pages plugin configuration
  pages: {
    groups: [
      {
        title: "Getting Started",
        pages: [
          {
            title: "Installation",
            source: "docs/installation.md"
          },
          {
            title: "Quick Start",
            source: "docs/quickstart.md"
          }
        ]
      },
      {
        title: "Guides",
        pages: [
          {
            title: "Architecture",
            source: "docs/ARCHITECTURE.md"
          },
          {
            title: "Testing",
            source: "docs/TESTING.md"
          },
          {
            title: "Troubleshooting",
            source: "docs/TROUBLESHOOTING.md"
          }
        ]
      }
    ]
  },

  // Custom formatting
  titleLink: "https://github.com/your-org/projects-monorepo",
  navigationLinks: {
    "GitHub": "https://github.com/your-org/projects-monorepo",
    "Issues": "https://github.com/your-org/projects-monorepo/issues",
    "Discussions": "https://github.com/your-org/projects-monorepo/discussions"
  },

  // SEO and meta
  htmlTitle: "Projects Monorepo API Documentation",

  // Comment parsing
  blockTags: [
    "@alpha",
    "@beta",
    "@deprecated",
    "@example",
    "@experimental",
    "@internal",
    "@override",
    "@packageDocumentation",
    "@param",
    "@privateRemarks",
    "@public",
    "@readonly",
    "@remarks",
    "@returns",
    "@sealed",
    "@see",
    "@since",
    "@throws",
    "@virtual"
  ],

  // Inline tags
  inlineTags: [
    "@defaultValue",
    "@inheritDoc",
    "@label",
    "@link",
    "@linkcode",
    "@linkplain"
  ],

  // Modifier tags
  modifierTags: [
    "@abstract",
    "@alpha",
    "@beta",
    "@deprecated",
    "@experimental",
    "@internal",
    "@override",
    "@packageDocumentation",
    "@public",
    "@readonly",
    "@sealed",
    "@virtual"
  ]
};