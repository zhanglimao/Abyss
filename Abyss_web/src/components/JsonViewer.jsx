import React, { useState, useCallback } from 'react';
import { ChevronRight, ChevronDown, Copy, Check } from 'lucide-react';
import clsx from 'clsx';

/**
 * 递归渲染 JSON 值 - 使用 React.memo 优化性能
 */
const JsonValue = React.memo(({ value, indent }) => {
  const [expanded, setExpanded] = useState(true);

  if (value === null) {
    return <span className="text-gray-400">null</span>;
  }

  if (typeof value === 'boolean') {
    return <span className="text-purple-600">{value.toString()}</span>;
  }

  if (typeof value === 'number') {
    return <span className="text-blue-600">{value}</span>;
  }

  if (typeof value === 'string') {
    return (
      <span className="text-emerald-600">
        "{value.length > 100 ? value.slice(0, 100) + '...' : value}"
      </span>
    );
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-gray-500">[]</span>;
    }

    return (
      <ArrayNode
        value={value}
        expanded={expanded}
        onToggle={() => setExpanded(!expanded)}
        indent={indent}
      />
    );
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) {
      return <span className="text-gray-500">{'{}'}</span>;
    }

    return (
      <ObjectNode
        value={value}
        expanded={expanded}
        onToggle={() => setExpanded(!expanded)}
        indent={indent}
      />
    );
  }

  return <span>{String(value)}</span>;
});

JsonValue.displayName = 'JsonValue';

/**
 * 渲染对象节点
 */
const ObjectNode = React.memo(({ value, expanded, onToggle, indent }) => {
  const keys = Object.keys(value);
  const preview = `{${keys.length} items}`;

  return (
    <span>
      <span
        className="inline-flex items-center cursor-pointer hover:bg-light-bgSecondary rounded px-0.5"
        onClick={onToggle}
      >
        {expanded ? <ChevronDown size={12} className="text-gray-400 mr-0.5" /> : <ChevronRight size={12} className="text-gray-400 mr-0.5" />}
        <span className="text-gray-600">{'{'}</span>
        <span className="text-gray-400 text-xs ml-1">{preview}</span>
      </span>

      {expanded && (
        <div>
          {keys.map((key, index) => (
            <div key={key} style={{ paddingLeft: `${(indent + 1) * 16}px` }}>
              <span className="text-amber-600">"{key}"</span>
              <span className="text-gray-600">: </span>
              <JsonValue value={value[key]} indent={indent + 1} />
              {index < keys.length - 1 && <span className="text-gray-400">,</span>}
            </div>
          ))}
          <div style={{ paddingLeft: `${indent * 16}px` }}>
            <span className="text-gray-600">{'}'}</span>
          </div>
        </div>
      )}

      {!expanded && <span className="text-gray-600">{'}'}</span>}
    </span>
  );
});

ObjectNode.displayName = 'ObjectNode';

/**
 * 渲染数组节点
 */
const ArrayNode = React.memo(({ value, expanded, onToggle, indent }) => {
  const preview = `[${value.length} items]`;

  return (
    <span>
      <span
        className="inline-flex items-center cursor-pointer hover:bg-light-bgSecondary rounded px-0.5"
        onClick={onToggle}
      >
        {expanded ? <ChevronDown size={12} className="text-gray-400 mr-0.5" /> : <ChevronRight size={12} className="text-gray-400 mr-0.5" />}
        <span className="text-gray-600">{'['}</span>
        <span className="text-gray-400 text-xs ml-1">{preview}</span>
      </span>

      {expanded && (
        <div>
          {value.map((item, index) => (
            <div key={index} style={{ paddingLeft: `${(indent + 1) * 16}px` }}>
              <JsonValue value={item} indent={indent + 1} />
              {index < value.length - 1 && <span className="text-gray-400">,</span>}
            </div>
          ))}
          <div style={{ paddingLeft: `${indent * 16}px` }}>
            <span className="text-gray-600">{']'}</span>
          </div>
        </div>
      )}

      {!expanded && <span className="text-gray-600">{']'}</span>}
    </span>
  );
});

ArrayNode.displayName = 'ArrayNode';

/**
 * JSON 可视化组件 - 支持语法高亮和节点折叠
 * 使用 React.memo 和稳定的 key 来保持展开状态
 */
const JsonViewer = ({ data }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(async () => {
    await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [data]);

  return (
    <div className="relative">
      {/* 工具栏 */}
      <div className="flex items-center justify-between mb-2 pb-2 border-b border-light-border">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-light-textMuted">JSON</span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2 py-1 text-xs text-light-textMuted hover:text-primary-600 transition-colors"
          title="复制 JSON"
        >
          {copied ? (
            <>
              <Check size={14} className="text-emerald-500" />
              <span className="text-emerald-600">已复制</span>
            </>
          ) : (
            <>
              <Copy size={14} />
              <span>复制</span>
            </>
          )}
        </button>
      </div>

      {/* JSON 内容 */}
      <div className="font-mono text-xs leading-relaxed overflow-auto max-h-[calc(100vh-450px)]">
        <JsonValue value={data} indent={0} />
      </div>
    </div>
  );
};

export default React.memo(JsonViewer);
