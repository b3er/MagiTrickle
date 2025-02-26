export function draggable(node: HTMLDivElement, data: any) {
  node.draggable = true;

  function ondragstart(event: DragEvent) {
    const dragged_row = (event.target as HTMLElement).closest(".dropzone");
    dragged_row?.classList.add("dragging");
    event.dataTransfer?.setData("text/plain", JSON.stringify(data));
  }

  node.addEventListener("dragstart", ondragstart);

  return {
    destroy() {
      node.removeEventListener("dragstart", ondragstart);
    },
  };
}

export const dropzone = (node: HTMLDivElement, fn: (data: any, target: HTMLElement) => void) => {
  node.classList.add("dropzone");

  function ondragend(event: DragEvent) {
    const target_row = (event.target as HTMLElement).closest(".dragging");
    if (target_row) {
      target_row.classList.remove("dragging");
    }
  }

  function ondragover(event: DragEvent) {
    event.preventDefault();
    const dragged_row = (event.target as HTMLElement).closest(".dragging");
    const target_row = (event.target as HTMLElement).closest(".dropzone");
    if (target_row && target_row !== dragged_row) {
      target_row.classList.add("dragover");
    }
  }

  function ondragleave(event: DragEvent) {
    const target_row = (event.target as HTMLElement).closest(".dropzone");
    if (target_row) {
      target_row.classList.remove("dragover");
    }
  }

  function ondrop(event: DragEvent) {
    event.preventDefault();
    const target_row: HTMLElement = (event.target as HTMLElement).closest(".dropzone")!;
    if (target_row && event.dataTransfer?.getData("text/plain")) {
      target_row.classList.remove("dragover");
      const data = event.dataTransfer?.getData("text/plain");
      fn(JSON.parse(data), target_row);
    }
    event.dataTransfer?.clearData();
  }

  node.addEventListener("dragend", ondragend);
  node.addEventListener("dragover", ondragover);
  node.addEventListener("dragleave", ondragleave);
  node.addEventListener("drop", ondrop);

  return {
    destroy() {
      node.removeEventListener("dragend", ondragend);
      node.removeEventListener("dragover", ondragover);
      node.removeEventListener("dragleave", ondragleave);
      node.removeEventListener("drop", ondrop);
    },
  };
};
