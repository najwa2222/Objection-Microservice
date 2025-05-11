// jest-resolver.cjs
// This is a CommonJS adapter for the ES Module resolver

let resolverModule;

// Dynamically import the ES module resolver
(async () => {
  resolverModule = await import('./jest-resolver.js');
})();

// Export a CommonJS compatible resolver function
module.exports = function resolverProxy(path, options) {
  if (!resolverModule) {
    throw new Error('Resolver module not loaded yet. This is a synchronous call but the resolver is loaded asynchronously.');
  }
  return resolverModule.resolve(path, options);
};

// Export sync and async methods to match Jest's expectations
module.exports.sync = function resolveSync(path, options) {
  if (!resolverModule) {
    throw new Error('Resolver module not loaded yet. This is a synchronous call but the resolver is loaded asynchronously.');
  }
  return resolverModule.sync(path, options);
};

module.exports.async = async function resolveAsync(path, options) {
  if (!resolverModule) {
    // Wait for the resolver module to be loaded
    await new Promise(resolve => {
      const checkLoaded = () => {
        if (resolverModule) {
          resolve();
        } else {
          setTimeout(checkLoaded, 10);
        }
      };
      checkLoaded();
    });
  }
  return resolverModule.async(path, options);
};