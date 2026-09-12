import { LuMousePointerClick, LuX } from "react-icons/lu";
import { useAppStore } from "../../store/app-store";

// Select-and-edit toggle in the preview toolbar, next to the device/code
// tabs — the "inspect element" spot users know from devtools. While select
// mode is on it becomes an explicit exit button.
export function SelectAndEditToolbarButton() {
  const { inSelectAndEditMode, toggleInSelectAndEditMode } = useAppStore();
  return (
    <button
      type="button"
      onClick={toggleInSelectAndEditMode}
      data-testid="select-edit-toggle"
      title={
        inSelectAndEditMode
          ? "Exit selection mode"
          : "Select an element in the preview to target your edit"
      }
      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors border ${
        inSelectAndEditMode
          ? "bg-blue-600 border-blue-600 text-white hover:bg-blue-700"
          : "bg-white border-gray-200 text-gray-600 hover:border-blue-300 hover:text-blue-700 dark:bg-zinc-900 dark:border-zinc-700 dark:text-zinc-300 dark:hover:border-blue-500 dark:hover:text-blue-300"
      }`}
    >
      {inSelectAndEditMode ? (
        <>
          <LuX className="w-3.5 h-3.5" />
          Exit select mode
        </>
      ) : (
        <>
          <LuMousePointerClick className="w-3.5 h-3.5" />
          Select & edit
        </>
      )}
    </button>
  );
}
