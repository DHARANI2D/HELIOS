import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// Report renderer for LLM / generated Markdown. Raw HTML in the source is not
// rendered (react-markdown's default), so model output can't inject markup.
export function Markdown({ children }: { children: string }) {
  return (
    <div className="text-sm leading-relaxed">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ node, ...p }) => <h1 className="mb-3 text-lg font-semibold" {...p} />,
          h2: ({ node, ...p }) => <h2 className="mt-5 mb-2 border-b pb-1 text-base font-semibold" {...p} />,
          h3: ({ node, ...p }) => <h3 className="mt-4 mb-1.5 text-sm font-semibold" {...p} />,
          p: ({ node, ...p }) => <p className="my-2" {...p} />,
          ul: ({ node, ...p }) => <ul className="my-2 list-disc space-y-1 pl-5" {...p} />,
          ol: ({ node, ...p }) => <ol className="my-2 list-decimal space-y-1 pl-5" {...p} />,
          code: ({ node, ...p }) => <code className="rounded bg-muted px-1 py-0.5 font-mono text-[12px] break-all" {...p} />,
          pre: ({ node, ...p }) => <pre className="my-2 overflow-x-auto rounded-md bg-muted p-3 text-xs" {...p} />,
          table: ({ node, ...p }) => (
            <div className="my-3 overflow-x-auto">
              <table className="w-full border-collapse text-xs" {...p} />
            </div>
          ),
          th: ({ node, ...p }) => <th className="border-b px-2 py-1.5 text-left font-medium" {...p} />,
          td: ({ node, ...p }) => <td className="border-b px-2 py-1.5 align-top" {...p} />,
          a: ({ node, ...p }) => <a className="underline" target="_blank" rel="noreferrer noopener" {...p} />,
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}
