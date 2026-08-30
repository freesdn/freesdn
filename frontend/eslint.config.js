// FreeSDN frontend ESLint config.
//
// THIS IS THE CONFIG ESLINT ACTUALLY LOADS. Keep it as .js.
//
// There used to be an eslint.config.ts beside this file (plus a generated
// eslint.config.d.ts), and ESLint resolves eslint.config.js FIRST -- so the
// TypeScript one was dead weight that looked authoritative. Editing it to
// tighten a rule changed nothing, silently. The two had not drifted yet; they
// were deleted before they could.
//
// If you want the config in TypeScript again, you must also add `jiti` to
// devDependencies explicitly -- ESLint 10 needs it to load a .ts config, and it
// is currently only present as a transitive dependency, which a lockfile change
// could drop without warning.
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';
// ``storybook-static`` is build output (gitignored, like ``dist``). Without it
// here, anyone who has run ``build-storybook`` gets 13 "Definition for rule X
// was not found" errors from the bundled vendor JS and ``npm run lint`` fails
// locally for a reason that has nothing to do with their change -- which is how
// people learn to ignore lint output. CI never saw it because CI does not build
// Storybook.
export default tseslint.config({ ignores: ['dist', 'storybook-static'] }, {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
        ecmaVersion: 2020,
        globals: globals.browser,
    },
    plugins: {
        'react-hooks': reactHooks,
        'react-refresh': reactRefresh,
    },
    rules: {
        // Core React Hooks rules
        'react-hooks/rules-of-hooks': 'error',
        'react-hooks/exhaustive-deps': 'warn',
        // React Compiler rules, disabled (not using React Compiler)
        'react-hooks/set-state-in-effect': 'off',
        'react-hooks/immutability': 'off',
        'react-hooks/purity': 'off',
        'react-hooks/static-components': 'off',
        'react-hooks/set-state-in-render': 'off',
        'react-hooks/refs': 'off',
        'react-hooks/globals': 'off',
        // Fast Refresh, disabled (all warnings are standard patterns: shadcn/ui variants, hooks, colocated utils)
        'react-refresh/only-export-components': 'off',
        // Downgrade to warnings for RC, tighten to error post-release
        '@typescript-eslint/no-explicit-any': 'warn',
        '@typescript-eslint/no-unused-vars': ['warn', {
                argsIgnorePattern: '^_',
                varsIgnorePattern: '^_',
                caughtErrorsIgnorePattern: '^_',
            }],
    },
});
