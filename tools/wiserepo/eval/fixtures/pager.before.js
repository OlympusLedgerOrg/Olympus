// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

// Fixture for eval/golden-*.json — see README.md in this directory.
export const PAGE_SIZE = 50;

export function pageCount(totalItems) {
  return Math.ceil(totalItems / PAGE_SIZE);
}

// Navigation helpers shared by the pager controls.
export const DEFAULT_PAGE = 1;

export function pageLabel(page) {
  return `Page ${page}`;
}

export function clampPage(page, lastPage) {
  if (page < 1) return 1;
  if (page > lastPage) return lastPage - 1;
  return page;
}
