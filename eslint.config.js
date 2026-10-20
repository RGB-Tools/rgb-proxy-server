const tsPlugin = require("@typescript-eslint/eslint-plugin");
const tsParser = require("@typescript-eslint/parser");
const prettierRecommended = require("eslint-plugin-prettier/recommended");
const simpleImportSort = require("eslint-plugin-simple-import-sort");
const { importX } = require("eslint-plugin-import-x");
const jestPlugin = require("eslint-plugin-jest");
const { includeIgnoreFile } = require("eslint/config");
const path = require("path");

const gitignorePath = path.resolve(__dirname, ".gitignore");

module.exports = [
  includeIgnoreFile(gitignorePath, { gitignoreResolution: true }),
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 12,
        sourceType: "module",
      },
    },
    plugins: {
      "@typescript-eslint": tsPlugin,
      "simple-import-sort": simpleImportSort,
      "import-x": importX,
    },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      "simple-import-sort/imports": "error",
      "simple-import-sort/exports": "error",
      "import-x/first": "error",
      "import-x/newline-after-import": "error",
      "import-x/no-duplicates": "error",
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
  {
    files: ["test/**/*.ts"],
    ...jestPlugin.configs["flat/recommended"],
    rules: {
      ...jestPlugin.configs["flat/recommended"].rules,
      // Tests declared through a conditional alias of it, e.g. skipped where
      // a feature is unavailable
      "jest/no-standalone-expect": [
        "error",
        { additionalTestBlockFunctions: ["itIfProcFds"] },
      ],
    },
  },
  prettierRecommended,
];
