export default {
  testEnvironment: 'node',
  moduleNameMapper: {
    '^mysql2/promise$': '<rootDir>/__mocks__/mysql2/promise.js',
    '^express-mysql-session$': '<rootDir>/__mocks__/express-mysql-session.js',
  },
  setupFilesAfterEnv: ['./jest/setup.js'], // Using relative path
  testMatch: ['**/__tests__/**/*.test.js'],
  // resolver: './jest-resolver.cjs', // Using the CommonJS adapter
  transform: {},
  testTimeout: 30000,
  clearMocks: true,
  resetMocks: true,
  detectOpenHandles: true,
  reporters: [
    'default',
    'jest-junit',
  ],
  globals: {
    'jest-junit': {
      outputDirectory: './reports',
      outputName: 'junit.xml',
    },
  },
};