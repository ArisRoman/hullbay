module.exports = {
  extends: ['@commitlint/config-conventional'],
  ignores: [
    (message) => /^Merge (branch|tag|pull request)/.test(message),
    (message) => message.startsWith('Revert '),
  ],
};
