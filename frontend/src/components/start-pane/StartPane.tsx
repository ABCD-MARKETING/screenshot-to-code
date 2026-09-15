import React from "react";
import { DesignSystem, Settings } from "../../types";
import { Stack } from "../../lib/stacks";
import UnifiedInputPane from "../unified-input/UnifiedInputPane";
import { LuCode2, LuImage, LuZap } from "react-icons/lu";

interface Props {
  doCreate: (
    images: string[],
    inputMode: "image" | "video",
    textPrompt?: string,
    isAssetExtractionEnabled?: boolean
  ) => void;
  doCreateFromText: (text: string) => void;
  importFromCode: (code: string, stack: Stack) => void;
  settings: Settings;
  setSettings: React.Dispatch<React.SetStateAction<Settings>>;
  designSystems: DesignSystem[];
  onAddNewDesignSystem: () => void;
  onManageDesignSystems: () => void;
}

const features = [
  {
    icon: LuImage,
    title: "Screenshot → Code",
    description: "Upload any UI screenshot and get production-ready code instantly.",
  },
  {
    icon: LuZap,
    title: "Multiple Stacks",
    description: "React, Tailwind, HTML/CSS, Vue, and more — pick your stack.",
  },
  {
    icon: LuCode2,
    title: "AI-Powered Edits",
    description: "Iterate with natural language. Select elements and describe changes.",
  },
];

const StartPane: React.FC<Props> = ({
  doCreate,
  doCreateFromText,
  importFromCode,
  settings,
  setSettings,
  designSystems,
  onAddNewDesignSystem,
  onManageDesignSystems,
}) => {
  return (
    <div className="flex flex-col items-center w-full px-4 py-8 gap-8">
      {/* Hero */}
      <div className="flex flex-col items-center gap-3 text-center max-w-2xl">
        <div className="inline-flex items-center gap-2 rounded-full bg-blue-50 px-3 py-1 text-xs font-medium text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-100 dark:border-blue-900">
          <LuZap className="w-3 h-3" />
          AI-Powered Code Generation
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white sm:text-4xl">
          Screenshot to Code
        </h1>
        <p className="text-base text-gray-500 dark:text-zinc-400 max-w-lg">
          Turn any screenshot, mockup, or design into clean, working code in seconds.
          Upload an image or paste a URL to get started.
        </p>
      </div>

      {/* Feature strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 w-full max-w-2xl">
        {features.map(({ icon: Icon, title, description }) => (
          <div
            key={title}
            className="flex flex-col gap-1.5 rounded-lg border border-gray-100 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900"
          >
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-blue-50 dark:bg-blue-950/60">
                <Icon className="h-3.5 w-3.5 text-blue-600 dark:text-blue-400" />
              </span>
              <span className="text-sm font-semibold text-gray-800 dark:text-zinc-100">
                {title}
              </span>
            </div>
            <p className="text-xs text-gray-500 dark:text-zinc-400 leading-relaxed">
              {description}
            </p>
          </div>
        ))}
      </div>

      {/* Input */}
      <UnifiedInputPane
        doCreate={doCreate}
        doCreateFromText={doCreateFromText}
        importFromCode={importFromCode}
        settings={settings}
        setSettings={setSettings}
        designSystems={designSystems}
        onAddNewDesignSystem={onAddNewDesignSystem}
        onManageDesignSystems={onManageDesignSystems}
      />
    </div>
  );
};

export default StartPane;
