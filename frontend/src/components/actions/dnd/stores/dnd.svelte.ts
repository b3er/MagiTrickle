// Source: https://github.com/thisuxhq/sveltednd
// Copyright (c) 2024 THISUX PRIVATE LIMITED

import type { DragDropState } from "../types/index.ts";

// Global DnD state using Svelte 5's state rune
export const dndState = $state<DragDropState>({
  isDragging: false,
  draggedItem: null,
  sourceContainer: "",
  targetContainer: null,
  targetElement: null,
  invalidDrop: false,
});
