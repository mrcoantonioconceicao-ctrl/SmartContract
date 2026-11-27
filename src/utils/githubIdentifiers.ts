export const GITHUB_OWNER_PATTERN = /^(?!.*--)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
export const GITHUB_REPOSITORY_NAME_PATTERN =
  /^(?!.*\.\.)(?!.*\.$)(?!.*\.git$)\.?[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}$/i;
export const GITHUB_BRANCH_NAME_PATTERN =
  /^(?!HEAD$)(?!.*\.\.)(?!.*\/\/)(?!.*\/$)(?!.*(?:^|\/)\.)(?!.*(?:^|\/)[^/]*\.lock(?:\/|$))(?!.*(?:^|\/)[^/]*\.$)(?!.*@\{)[A-Za-z0-9_@+-][A-Za-z0-9._/@+-]{0,254}$/;

export function isValidGitHubOwner(value: string): boolean {
  return GITHUB_OWNER_PATTERN.test(value);
}

export function isValidGitHubRepositoryName(value: string): boolean {
  return GITHUB_REPOSITORY_NAME_PATTERN.test(value);
}

export function isValidGitHubBranchName(value: string): boolean {
  return GITHUB_BRANCH_NAME_PATTERN.test(value);
}
