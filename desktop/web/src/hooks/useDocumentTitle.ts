import { useEffect } from "react";

// useDocumentTitle sets the browser tab title for the current view and
// restores the previous title on unmount. Helps users with many tabs
// distinguish a project run from the projects list. Pass null/undefined
// to leave the existing title alone.
export function useDocumentTitle(title: string | null | undefined): void {
  useEffect(() => {
    if (!title) return;
    const prev = document.title;
    document.title = `${title} — GoLantern`;
    return () => {
      document.title = prev;
    };
  }, [title]);
}
