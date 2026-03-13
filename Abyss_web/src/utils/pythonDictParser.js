/**
 * 增强的 Python 字典解析器
 * 专门处理 WebSocket 返回的复杂数据格式
 */

/**
 * 解析 Python 字典字符串为 JavaScript 对象
 * @param {string} dictString - Python 字典格式的字符串
 * @returns {object} JavaScript 对象
 */
export function parsePythonDict(dictString) {
  if (!dictString || typeof dictString !== 'string') {
    return null;
  }

  try {
    // 尝试直接解析为 JSON（如果是标准 JSON 格式）
    return JSON.parse(dictString);
  } catch (e) {
    // 使用更强大的 Python 字典解析策略
    return parseComplexPythonDict(dictString);
  }
}

/**
 * 解析 Python 类实例
 * 例如：HumanMessage(content='...', id='...')
 */
function parsePythonClassInstance(content) {
  const result = {};
  
  try {
    // 提取 key=value 对
    // 处理字符串值
    const stringKVRegex = /(\w+)=('([^']*(?:\\'[^']*)*)'|"([^"]*(?:\\"[^"]*)*)")/g;
    let match;
    
    while ((match = stringKVRegex.exec(content)) !== null) {
      const key = match[1];
      const value = match[3] !== undefined ? match[3] : match[4];
      // 处理转义字符
      result[key] = value.replace(/\\'/g, "'").replace(/\\"/g, '"');
    }
    
    // 处理非字符串值（数字、布尔值、null、嵌套对象等）
    const nonStringKVRegex = /(\w+)=([^,'"]+\[[\s\S]*?\]|[^,'"]+\{[\s\S]*?\}|\d+|true|false|null|None)/g;
    while ((match = nonStringKVRegex.exec(content)) !== null) {
      const key = match[1];
      let value = match[2];
      
      if (value === 'None') value = null;
      else if (value === 'true') value = true;
      else if (value === 'false') value = false;
      else if (value === 'null') value = null;
      else if (!isNaN(Number(value))) value = Number(value);
      else {
        // 尝试解析复杂对象（列表、字典）
        try {
          value = value.replace(/None/g, 'null');
          value = value.replace(/True/g, 'true');
          value = value.replace(/False/g, 'false');
          value = JSON.parse(value);
        } catch (e) {
          // 保持原样
        }
      }
      
      if (!(key in result)) {
        result[key] = value;
      }
    }
    
    return result;
  } catch (e) {
    console.error('解析 Python 类实例失败:', e);
    return null;
  }
}

/**
 * 解析复杂的 Python 字典
 * 使用递归下降解析器处理嵌套对象、数组、转义字符等
 */
function parseComplexPythonDict(dictString) {
  let json = dictString.trim();
  let pos = 0;

  try {
    // 跳过开头的 { 之前的内容（如果有）
    while (pos < json.length && json[pos] !== '{') {
      pos++;
    }
    
    if (pos >= json.length) return null;
    
    const result = parseValue(json);
    return result;
  } catch (e) {
    console.error('复杂字典解析失败:', e.message);
    return null;
  }
}

/**
 * 解析一个值（对象、数组、字符串、数字等）
 */
function parseValue(str) {
  skipWhitespace(str);
  
  if (str[pos] === '{') {
    return parseObject(str);
  } else if (str[pos] === '[') {
    return parseArray(str);
  } else if (str[pos] === "'" || str[pos] === '"') {
    return parseString(str);
  } else {
    return parseLiteral(str);
  }
}

/**
 * 跳过空白字符
 */
function skipWhitespace(str) {
  while (pos < str.length && /\s/.test(str[pos])) {
    pos++;
  }
}

/**
 * 解析对象
 */
function parseObject(str) {
  const result = {};
  pos++; // 跳过 {
  skipWhitespace(str);
  
  if (str[pos] === '}') {
    pos++;
    return result;
  }
  
  while (pos < str.length) {
    skipWhitespace(str);
    
    // 解析键
    const key = parseString(str);
    skipWhitespace(str);
    
    // 跳过 :
    if (str[pos] === ':') pos++;
    skipWhitespace(str);
    
    // 解析值
    const value = parseValue(str);
    result[key] = value;
    
    skipWhitespace(str);
    
    // 检查是否有更多键值对
    if (str[pos] === ',') {
      pos++;
    } else if (str[pos] === '}') {
      pos++;
      break;
    }
  }
  
  return result;
}

/**
 * 解析数组
 */
function parseArray(str) {
  const result = [];
  pos++; // 跳过 [
  skipWhitespace(str);
  
  if (str[pos] === ']') {
    pos++;
    return result;
  }
  
  while (pos < str.length) {
    skipWhitespace(str);
    const value = parseValue(str);
    result.push(value);
    skipWhitespace(str);
    
    if (str[pos] === ',') {
      pos++;
    } else if (str[pos] === ']') {
      pos++;
      break;
    }
  }
  
  return result;
}

/**
 * 解析字符串（支持单引号和双引号）
 */
function parseString(str) {
  const quote = str[pos];
  if (quote !== "'" && quote !== '"') {
    throw new Error('Expected string');
  }
  
  pos++; // 跳过开引号
  let result = '';
  
  while (pos < str.length) {
    const char = str[pos];
    
    if (char === '\\') {
      pos++;
      const escaped = str[pos];
      if (escaped === 'n') result += '\n';
      else if (escaped === 't') result += '\t';
      else if (escaped === 'r') result += '\r';
      else if (escaped === "'") result += "'";
      else if (escaped === '"') result += '"';
      else if (escaped === '\\') result += '\\';
      else result += escaped;
      pos++;
    } else if (char === quote) {
      pos++; // 跳过闭引号
      break;
    } else {
      result += char;
      pos++;
    }
  }
  
  return result;
}

/**
 * 解析字面量（数字、布尔值、null）
 */
function parseLiteral(str) {
  let literal = '';
  
  while (pos < str.length && 
         str[pos] !== ',' && 
         str[pos] !== '}' && 
         str[pos] !== ']' &&
         !/\s/.test(str[pos])) {
    literal += str[pos];
    pos++;
  }
  
  if (literal === 'None' || literal === 'null') return null;
  if (literal === 'True' || literal === 'true') return true;
  if (literal === 'False' || literal === 'false') return false;
  
  const num = Number(literal);
  if (!isNaN(num)) return num;
  
  return literal;
}

/**
 * 替换 Python 类实例为 JSON 对象
 * 例如：ToolMessage(content='...', name='...') -> {"content": "...", "name": "..."}
 */
function replaceClassInstancesWithJson(json) {
  const classTypes = ['HumanMessage', 'AIMessage', 'ToolMessage'];
  
  for (const className of classTypes) {
    const regex = new RegExp(`${className}\\(([^)]*(?:\\([^)]*\\)[^)]*)*)\\)`, 'g');
    
    json = json.replace(regex, (match, content) => {
      const parsed = parsePythonClassInstance(content);
      return JSON.stringify(parsed);
    });
  }
  
  return json;
}

/**
 * 转换 Python 字符串表示为 JSON 格式
 * 处理单引号、双引号、转义字符等
 */
function convertPythonStringsToJson(json) {
  const result = [];
  let i = 0;
  let inString = false;
  let stringChar = null;
  let currentString = '';
  let isStringValue = false; // 标记当前字符串是否是值（而不是键）
  let expectValue = false; // 标记是否期望一个值（在:之后）
  
  while (i < json.length) {
    const char = json[i];
    const prevChar = i > 0 ? json[i - 1] : '';
    const nextChar = i < json.length - 1 ? json[i + 1] : '';
    
    // 检查是否进入字符串
    if (!inString && (char === '"' || char === "'")) {
      // 检查前面是否是键的模式（即后面会跟:）
      // 简单判断：如果前面是"或刚经过, {，可能是键
      const lookAhead = json.slice(i + 1, Math.min(i + 50, json.length));
      const isKey = lookAhead.match(/^[^:'"]*:\s*['"{\d\w]/);
      
      inString = true;
      stringChar = char;
      isStringValue = !isKey;
      currentString = '';
      i++;
      continue;
    }
    
    // 在字符串内部
    if (inString) {
      // 检查转义字符
      if (char === '\\' && prevChar !== '\\\\') {
        currentString += char;
        i++;
        if (i < json.length) {
          currentString += json[i];
        }
        i++;
        continue;
      }
      
      // 检查字符串结束
      if (char === stringChar) {
        inString = false;
        
        if (isStringValue) {
          // 字符串值：用双引号包裹，处理内部引号
          const processed = processStringValue(currentString);
          result.push(processed);
        } else {
          // 键：直接用双引号
          result.push('"' + currentString + '"');
        }
        
        stringChar = null;
        currentString = '';
        i++;
        continue;
      }
      
      currentString += char;
      i++;
      continue;
    }
    
    // 不在字符串中
    result.push(char);
    
    // 检查是否刚经过冒号（期望值）
    if (char === ':') {
      expectValue = true;
    }
    
    i++;
  }
  
  return result.join('');
}

/**
 * 处理字符串值
 * 转义特殊字符，转换引号
 */
function processStringValue(str) {
  // 转义双引号
  let processed = str.replace(/"/g, '\\"');
  
  // 转义反斜杠（但保留 \\n 等转义序列）
  // processed = processed.replace(/\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})/g, '\\\\');
  
  // 保留 \n \t 等转义序列，但确保它们被正确格式化
  processed = processed.replace(/\\n/g, '\\n');
  processed = processed.replace(/\\t/g, '\\t');
  processed = processed.replace(/\\r/g, '\\r');
  
  return '"' + processed + '"';
}

/**
 * 简化的解析器 - 使用正则表达式提取关键字段
 * 适用于格式相对固定的数据
 */
export function parsePythonDictWithRegex(dictString) {
  if (!dictString || typeof dictString !== 'string') {
    return null;
  }
  
  const result = {};
  
  try {
    // 提取顶层字段
    const fields = {
      task_id: /'task_id'\s*:\s*'([^']+)'/,
      subagent: /'subagent'\s*:\s*(None|'([^']+)')/,
      type: /'type'\s*:\s*'([^']+)'/,
      content: /'content'\s*:\s*'((?:[^'\\]|\\.)*)'/,
      id: /'id'\s*:\s*'([^']+)'/,
      name: /'name'\s*:\s*'([^']+)'/,
      tool_call_id: /'tool_call_id'\s*:\s*'([^']+)'/,
    };
    
    for (const [key, regex] of Object.entries(fields)) {
      const match = dictString.match(regex);
      if (match) {
        if (key === 'subagent') {
          result[key] = match[1] === 'None' ? null : match[2];
        } else {
          result[key] = match[1];
        }
      }
    }
    
    // 处理 tool_calls 数组（复杂嵌套）
    const toolCallsMatch = dictString.match(/'tool_calls'\s*:\s*(\[.*?\])/s);
    if (toolCallsMatch) {
      result.tool_calls = parseToolCalls(toolCallsMatch[1]);
    }
    
    return Object.keys(result).length > 0 ? result : null;
  } catch (e) {
    console.error('正则解析失败:', e);
    return null;
  }
}

/**
 * 解析 tool_calls 数组
 */
function parseToolCalls(arrayStr) {
  const result = [];
  
  // 提取每个工具调用对象
  const toolCallRegex = /'name'\s*:\s*'([^']+)'.*?'args'\s*:\s*({[^}]+}).*?'id'\s*:\s*'([^']+)'/gs;
  let match;
  
  while ((match = toolCallRegex.exec(arrayStr)) !== null) {
    result.push({
      name: match[1],
      args: parseNestedDict(match[2]),
      id: match[3],
      type: 'tool_call',
    });
  }
  
  return result;
}

/**
 * 解析嵌套字典（简化版）
 */
function parseNestedDict(dictStr) {
  const result = {};
  
  // 提取键值对
  const kvRegex = /'(\w+)'\s*:\s*(?:'([^']*)'|"([^"]*)"|(\d+)|(true|false|null)|({[^}]*})|\[(.*?)\])/g;
  let match;
  
  while ((match = kvRegex.exec(dictStr)) !== null) {
    const key = match[1];
    const value = match[2] ?? match[3] ?? match[4] ?? match[5] ?? match[6] ?? match[7] ?? null;
    result[key] = value;
  }
  
  return result;
}
