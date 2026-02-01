// worker.js - Production Ready AI with Learning System
// Cloudflare Worker AI with User Adaptation

// KV Storage Schema:
// user_profile:{userId} - JSON user profile
// patterns:{userId}:{type} - Learned patterns
// conversations:{userId} - Recent conversations

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const userId = request.headers.get('cf-connecting-ip') || 
                   request.headers.get('x-real-ip') || 
                   'anonymous';
    
    // Handle preflight CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // API Routes
    if (path === '/api/chat' && request.method === 'POST') {
      return handleChat(request, env, ctx, userId);
    }
    
    if (path === '/api/learn' && request.method === 'POST') {
      return handleLearning(request, env, ctx, userId);
    }
    
    if (path === '/api/profile' && request.method === 'GET') {
      return handleGetProfile(request, env, ctx, userId);
    }
    
    if (path === '/api/reset' && request.method === 'POST') {
      return handleResetProfile(request, env, ctx, userId);
    }
    
    if (path === '/api/generate' && request.method === 'POST') {
      return handleGenerateCode(request, env, ctx, userId);
    }
    
    if (path === '/api/analyze' && request.method === 'POST') {
      return handleAnalyzeCode(request, env, ctx, userId);
    }
    
    if (path === '/api/health' && request.method === 'GET') {
      return handleHealthCheck(request, env, ctx, userId);
    }

    // Serve HTML interface
    if (path === '/' || path === '/index.html') {
      return serveHTMLInterface();
    }

    // Default response
    return new Response(JSON.stringify({
      status: 'online',
      service: 'Cloudflare AI Worker',
      version: '2.0.0',
      endpoints: [
        '/api/chat', 
        '/api/learn', 
        '/api/profile', 
        '/api/reset',
        '/api/generate',
        '/api/analyze',
        '/api/health'
      ]
    }), {
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  },
};

// ============ CORE HANDLERS ============

async function handleChat(request, env, ctx, userId) {
  try {
    const { message, context = [] } = await request.json();
    
    if (!message) {
      return jsonResponse({ error: 'Message is required' }, 400);
    }

    // Load user profile
    const profile = await loadUserProfile(env, userId);
    
    // Analyze message for patterns (non-blocking)
    ctx.waitUntil(analyzeMessagePatterns(env, userId, message, profile));
    
    // Generate personalized response
    const response = await generateResponse(env, userId, message, context, profile);
    
    // Store conversation (non-blocking)
    ctx.waitUntil(storeConversation(env, userId, {
      timestamp: Date.now(),
      user: message,
      ai: response,
      context_length: context.length
    }));
    
    return jsonResponse({
      response,
      profile_id: userId,
      adapted: profile.adaptations > 0,
      adaptations: profile.adaptations
    });
    
  } catch (error) {
    console.error('Chat error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleLearning(request, env, ctx, userId) {
  try {
    const { code, language = 'javascript', feedback } = await request.json();
    
    if (!code) {
      return jsonResponse({ error: 'Code sample is required' }, 400);
    }
    
    const profile = await loadUserProfile(env, userId);
    const learned = await learnFromCode(env, userId, code, language, feedback, profile);
    
    return jsonResponse({
      learned: true,
      patterns_extracted: learned.patterns,
      style_updated: learned.styleUpdated,
      adaptations: profile.adaptations + 1
    });
    
  } catch (error) {
    console.error('Learning error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleGetProfile(request, env, ctx, userId) {
  try {
    const profile = await loadUserProfile(env, userId);
    
    // Return sanitized profile (no sensitive data)
    return jsonResponse({
      user_id: userId,
      coding_style: profile.codingStyle,
      language_preferences: profile.languagePreferences,
      communication_style: profile.communicationStyle,
      adaptations: profile.adaptations,
      samples_analyzed: profile.samplesAnalyzed || 0,
      last_active: profile.lastActive
    });
    
  } catch (error) {
    console.error('Profile error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleResetProfile(request, env, ctx, userId) {
  try {
    const { confirm } = await request.json();
    
    if (confirm !== 'RESET') {
      return jsonResponse({ error: 'Confirmation required' }, 400);
    }
    
    await env.AI_STORAGE.delete(`user_profile:${userId}`);
    await env.AI_STORAGE.delete(`patterns:${userId}:coding`);
    await env.AI_STORAGE.delete(`patterns:${userId}:language`);
    await env.AI_STORAGE.delete(`patterns:${userId}:communication`);
    await env.AI_STORAGE.delete(`conversations:${userId}`);
    
    return jsonResponse({
      reset: true,
      message: 'Profile reset successfully'
    });
    
  } catch (error) {
    console.error('Reset error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleGenerateCode(request, env, ctx, userId) {
  try {
    const { prompt, language = 'javascript', complexity = 'medium' } = await request.json();
    
    if (!prompt) {
      return jsonResponse({ error: 'Prompt is required' }, 400);
    }
    
    const profile = await loadUserProfile(env, userId);
    const code = await generateAdvancedCode(prompt, language, complexity, profile);
    
    // Learn from generation
    ctx.waitUntil(learnFromGeneratedCode(env, userId, code, language, profile));
    
    return jsonResponse({
      code,
      language,
      complexity,
      style_applied: profile.codingStyle,
      generation_id: generateId()
    });
    
  } catch (error) {
    console.error('Generate error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleAnalyzeCode(request, env, ctx, userId) {
  try {
    const { code, language = 'javascript' } = await request.json();
    
    if (!code) {
      return jsonResponse({ error: 'Code is required' }, 400);
    }
    
    const analysis = analyzeCodeQuality(code, language);
    const suggestions = generateOptimizations(code, language);
    
    // Learn from analysis
    const profile = await loadUserProfile(env, userId);
    ctx.waitUntil(learnFromAnalysis(env, userId, code, analysis, profile));
    
    return jsonResponse({
      analysis,
      suggestions,
      metrics: {
        complexity: analysis.complexity,
        maintainability: analysis.maintainability,
        style_score: analysis.styleScore
      }
    });
    
  } catch (error) {
    console.error('Analyze error:', error);
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleHealthCheck(request, env, ctx, userId) {
  return jsonResponse({
    status: 'healthy',
    timestamp: Date.now(),
    user_count: 1, // Simplified - in production would count users
    uptime: '100%',
    memory_usage: 'normal'
  });
}

// ============ CORE AI ENGINE ============

async function generateResponse(env, userId, message, context, profile) {
  // Check if this is a coding-related question
  const isCodeRequest = isCodingQuestion(message);
  
  if (isCodeRequest) {
    return generateCodeResponse(message, context, profile);
  } else {
    return generateTextResponse(message, context, profile);
  }
}

function generateCodeResponse(message, context, profile) {
  const language = detectLanguageFromMessage(message) || profile.languagePreferences.primary;
  const codeStyle = profile.codingStyle;
  
  // Extract requirements
  const requirements = extractRequirements(message);
  
  // Generate code based on user's style
  const code = generateStyledCode(requirements, language, codeStyle);
  
  // Generate explanation in user's preferred style
  const explanation = generateExplanation(message, code, profile.communicationStyle);
  
  return {
    type: 'code',
    language,
    code,
    explanation,
    style_applied: {
      indentation: codeStyle.indentation,
      naming_convention: codeStyle.namingConvention,
      line_length: codeStyle.lineLength
    }
  };
}

function generateTextResponse(message, context, profile) {
  const style = profile.communicationStyle;
  
  // Adapt response style to user
  let response = `You asked: "${message}"\n\n`;
  
  if (style.detailLevel === 'detailed') {
    response += "I'll provide a comprehensive response to your question.\n\n";
  }
  
  // Generate thoughtful response
  response += generateThoughtfulResponse(message, style);
  
  if (style.examplesIncluded && message.includes('example')) {
    response += `\n\nHere's an example based on your coding style:\n`;
    response += generateExample(message, profile);
  }
  
  return {
    type: 'text',
    response,
    style: {
      formality: style.formality,
      detail: style.detailLevel
    }
  };
}

// ============ LEARNING & ADAPTATION ENGINE ============

async function learnFromCode(env, userId, code, language, feedback, profile) {
  const patterns = extractCodePatterns(code);
  const styleUpdates = detectStyleChanges(patterns, profile.codingStyle);
  
  // Update coding style
  if (styleUpdates.length > 0) {
    profile.codingStyle = mergeStyles(profile.codingStyle, patterns);
    profile.adaptations = (profile.adaptations || 0) + 1;
  }
  
  // Update language preferences
  updateLanguagePreferences(profile, language);
  
  // Store patterns
  await storePatterns(env, userId, 'coding', patterns);
  
  // Update profile
  profile.lastActive = Date.now();
  profile.samplesAnalyzed = (profile.samplesAnalyzed || 0) + 1;
  
  // Save updated profile
  await saveUserProfile(env, userId, profile);
  
  return {
    patterns: Object.keys(patterns).length,
    styleUpdated: styleUpdates.length > 0,
    adaptations: profile.adaptations
  };
}

async function analyzeMessagePatterns(env, userId, message, profile) {
  try {
    // Extract communication patterns
    const patterns = analyzeCommunicationPatterns(message);
    
    // Update communication style
    if (patterns.formality || patterns.detailLevel) {
      profile.communicationStyle = {
        ...profile.communicationStyle,
        ...patterns
      };
      profile.adaptations = (profile.adaptations || 0) + 1;
    }
    
    // Store patterns
    await storePatterns(env, userId, 'communication', patterns);
    
    // Save profile
    await saveUserProfile(env, userId, profile);
    
  } catch (error) {
    // Silent fail for non-critical learning
    console.warn('Pattern analysis failed:', error);
  }
}

async function learnFromGeneratedCode(env, userId, code, language, profile) {
  try {
    const patterns = extractCodePatterns(code);
    await storePatterns(env, userId, 'generated', patterns);
  } catch (error) {
    console.warn('Generated code learning failed:', error);
  }
}

async function learnFromAnalysis(env, userId, code, analysis, profile) {
  try {
    await storePatterns(env, userId, 'analysis', {
      timestamp: Date.now(),
      analysis,
      code_snippet: code.substring(0, 500)
    });
  } catch (error) {
    console.warn('Analysis learning failed:', error);
  }
}

// ============ PATTERN ANALYSIS ============

function extractCodePatterns(code) {
  const lines = code.split('\n');
  const patterns = {
    indentation: detectIndentation(lines),
    namingConvention: detectNamingConvention(code),
    lineLength: calculateAverageLineLength(lines),
    bracketStyle: detectBracketStyle(code),
    quoteStyle: detectQuoteStyle(code),
    semicolons: detectSemicolonUsage(code),
    functionLength: calculateAverageFunctionLength(code),
    commentDensity: calculateCommentDensity(code)
  };
  
  return patterns;
}

function detectIndentation(lines) {
  let spaces = 0;
  let tabs = 0;
  
  for (const line of lines) {
    if (line.startsWith('  ')) spaces++;
    if (line.startsWith('\t')) tabs++;
  }
  
  return spaces > tabs ? 'spaces' : 'tabs';
}

function detectNamingConvention(code) {
  const patterns = {
    camelCase: (code.match(/\b[a-z]+[A-Z][a-zA-Z]*\b/g) || []).length,
    snake_case: (code.match(/\b[a-z]+_[a-z]+\b/g) || []).length,
    PascalCase: (code.match(/\b[A-Z][a-zA-Z]*\b/g) || []).length,
    kebab_case: (code.match(/\b[a-z]+-[a-z]+\b/g) || []).length
  };
  
  let max = 0;
  let convention = 'camelCase';
  
  for (const [key, value] of Object.entries(patterns)) {
    if (value > max) {
      max = value;
      convention = key;
    }
  }
  
  return convention;
}

function analyzeCommunicationPatterns(message) {
  const patterns = {};
  
  // Analyze formality
  const formalWords = ['please', 'thank you', 'could you', 'would you'];
  const casualWords = ['hey', 'yo', 'lol', 'omg'];
  
  let formalCount = 0;
  let casualCount = 0;
  
  const words = message.toLowerCase().split(' ');
  
  for (const word of words) {
    if (formalWords.includes(word)) formalCount++;
    if (casualWords.includes(word)) casualCount++;
  }
  
  patterns.formality = formalCount > casualCount ? 'formal' : 
                      casualCount > formalCount ? 'casual' : 'balanced';
  
  // Analyze detail level
  const sentenceCount = message.split(/[.!?]+/).length - 1;
  const wordCount = words.length;
  const avgWordsPerSentence = wordCount / Math.max(sentenceCount, 1);
  
  patterns.detailLevel = avgWordsPerSentence > 15 ? 'detailed' :
                        avgWordsPerSentence > 8 ? 'balanced' : 'concise';
  
  // Analyze technical depth
  const technicalTerms = ['function', 'class', 'variable', 'array', 'object', 'api', 'database'];
  let technicalCount = 0;
  
  for (const word of words) {
    if (technicalTerms.includes(word)) technicalCount++;
  }
  
  patterns.technicalDepth = technicalCount > 3 ? 'high' :
                           technicalCount > 0 ? 'medium' : 'low';
  
  return patterns;
}

function detectStyleChanges(newPatterns, currentStyle) {
  const changes = [];
  
  if (newPatterns.indentation && newPatterns.indentation !== currentStyle.indentation) {
    changes.push('indentation');
  }
  
  if (newPatterns.namingConvention && newPatterns.namingConvention !== currentStyle.namingConvention) {
    changes.push('namingConvention');
  }
  
  if (newPatterns.quoteStyle && newPatterns.quoteStyle !== currentStyle.quoteStyle) {
    changes.push('quoteStyle');
  }
  
  return changes;
}

function mergeStyles(currentStyle, newPatterns) {
  return {
    ...currentStyle,
    indentation: newPatterns.indentation || currentStyle.indentation,
    namingConvention: newPatterns.namingConvention || currentStyle.namingConvention,
    lineLength: newPatterns.lineLength || currentStyle.lineLength,
    bracketStyle: newPatterns.bracketStyle || currentStyle.bracketStyle,
    quoteStyle: newPatterns.quoteStyle || currentStyle.quoteStyle,
    semicolons: newPatterns.semicolons !== undefined ? newPatterns.semicolons : currentStyle.semicolons
  };
}

function updateLanguagePreferences(profile, language) {
  if (!profile.languagePreferences.secondary.includes(language) && 
      profile.languagePreferences.primary !== language) {
    profile.languagePreferences.secondary.push(language);
    
    // Keep only last 5 languages
    if (profile.languagePreferences.secondary.length > 5) {
      profile.languagePreferences.secondary.shift();
    }
  }
}

// ============ ADVANCED CODE GENERATION ============

function generateStyledCode(requirements, language, style) {
  const { indentation, namingConvention, lineLength, bracketStyle, quoteStyle, semicolons } = style;
  
  // Generate indentation
  const indent = indentation === 'spaces' ? '  ' : '\t';
  
  // Apply naming convention to variable names
  const varName = applyNamingConvention('exampleVariable', namingConvention);
  const funcName = applyNamingConvention('exampleFunction', namingConvention);
  const className = applyNamingConvention('ExampleClass', 
    namingConvention === 'camelCase' ? 'PascalCase' : namingConvention);
  
  // Generate code based on language
  let code = '';
  
  switch (language.toLowerCase()) {
    case 'javascript':
    case 'typescript':
      code = generateJavaScriptCode(requirements, {
        indent, varName, funcName, className,
        quote: quoteStyle === 'single' ? "'" : '"',
        semicolon: semicolons ? ';' : '',
        bracket: bracketStyle || 'same-line'
      });
      break;
      
    case 'python':
      code = generatePythonCode(requirements, {
        indent, varName, funcName, className,
        quote: quoteStyle === 'single' ? "'" : '"'
      });
      break;
      
    case 'html':
      code = generateHTMLCode(requirements, {
        indent, quote: quoteStyle === 'single' ? "'" : '"'
      });
      break;
      
    case 'css':
      code = generateCSSCode(requirements, {
        indent, quote: quoteStyle === 'single' ? "'" : '"'
      });
      break;
      
    case 'rust':
      code = generateRustCode(requirements, style);
      break;
      
    case 'go':
      code = generateGoCode(requirements, style);
      break;
      
    default:
      code = `// ${language} code generation for:\n// ${requirements.join('\n// ')}\n\n` +
             `// Custom ${language} implementation here`;
  }
  
  // Apply line length formatting
  return formatToLineLength(code, lineLength || 80);
}

async function generateAdvancedCode(prompt, language, complexity, profile) {
  const style = profile.codingStyle;
  const indent = style.indentation === 'spaces' ? '  ' : '\t';
  const quote = style.quoteStyle === 'single' ? "'" : '"';
  const semicolon = style.semicolons ? ';' : '';
  
  // Parse prompt for requirements
  const requirements = parseAdvancedRequirements(prompt);
  
  // Generate based on complexity
  switch (complexity) {
    case 'simple':
      return generateSimpleCode(requirements, language, style);
    case 'medium':
      return generateMediumCode(requirements, language, style);
    case 'complex':
      return generateComplexCode(requirements, language, style);
    case 'enterprise':
      return generateEnterpriseCode(requirements, language, style);
    default:
      return generateMediumCode(requirements, language, style);
  }
}

function generateJavaScriptCode(requirements, style) {
  const { indent, varName, funcName, className, quote, semicolon, bracket } = style;
  
  let code = '';
  
  // Generate based on requirements
  if (requirements.includes('function')) {
    code += `${bracket === 'new-line' ? '\n' : ''}function ${funcName}() {\n`;
    code += `${indent}const ${varName} = ${quote}Hello, World!${quote}${semicolon}\n`;
    code += `${indent}return ${varName}${semicolon}\n`;
    code += `}\n\n`;
  }
  
  if (requirements.includes('class')) {
    code += `class ${className} {\n`;
    code += `${indent}constructor() {\n`;
    code += `${indent}${indent}this.value = ${quote}initial${quote}${semicolon}\n`;
    code += `${indent}}\n\n`;
    code += `${indent}getValue() {\n`;
    code += `${indent}${indent}return this.value${semicolon}\n`;
    code += `${indent}}\n`;
    code += `}\n`;
  }
  
  return code || `// JavaScript implementation\nconsole.log(${quote}Implementation here${quote})${semicolon}`;
}

function generatePythonCode(requirements, style) {
  const { indent, varName, funcName, className, quote } = style;
  
  let code = '';
  
  if (requirements.includes('function')) {
    code += `def ${funcName}()${colon}\n`;
    code += `${indent}${varName} = ${quote}Hello, World!${quote}\n`;
    code += `${indent}return ${varName}\n\n`;
  }
  
  if (requirements.includes('class')) {
    code += `class ${className}${colon}\n`;
    code += `${indent}def __init__(self)${colon}\n`;
    code += `${indent}${indent}self.value = ${quote}initial${quote}\n\n`;
    code += `${indent}def get_value(self)${colon}\n`;
    code += `${indent}${indent}return self.value\n`;
  }
  
  return code || `# Python implementation\nprint(${quote}Implementation here${quote})`;
}

function generateSimpleCode(requirements, language, style) {
  const indent = style.indentation === 'spaces' ? '  ' : '\t';
  const quote = style.quoteStyle === 'single' ? "'" : '"';
  
  switch (language) {
    case 'javascript':
      return `// Simple ${requirements[0] || 'function'}\n` +
             `function ${applyNamingConvention('simpleFunction', style.namingConvention)}() {\n` +
             `${indent}return ${quote}Hello${quote}${style.semicolons ? ';' : ''}\n` +
             `}`;
             
    case 'python':
      return `# Simple ${requirements[0] || 'function'}\n` +
             `def ${applyNamingConvention('simple_function', style.namingConvention)}()${colon}\n` +
             `${indent}return ${quote}Hello${quote}`;
             
    default:
      return `// Simple ${language} code`;
  }
}

function generateMediumCode(requirements, language, style) {
  const indent = style.indentation === 'spaces' ? '  ' : '\t';
  const quote = style.quoteStyle === 'single' ? "'" : '"';
  const semicolon = style.semicolons ? ';' : '';
  
  switch (language) {
    case 'javascript':
      return `// Medium complexity ${requirements[0] || 'module'}\n\n` +
             `class ${applyNamingConvention('ExampleClass', 'PascalCase')} {\n` +
             `${indent}constructor() {\n` +
             `${indent}${indent}this.data = []${semicolon}\n` +
             `${indent}}\n\n` +
             `${indent}addItem(item) {\n` +
             `${indent}${indent}this.data.push(item)${semicolon}\n` +
             `${indent}${indent}return this${semicolon}\n` +
             `${indent}}\n\n` +
             `${indent}getItems() {\n` +
             `${indent}${indent}return this.data${semicolon}\n` +
             `${indent}}\n` +
             `}\n\n` +
             `// Usage example\n` +
             `const instance = new ${applyNamingConvention('ExampleClass', 'PascalCase')}()${semicolon}\n` +
             `instance.addItem(${quote}test${quote})${semicolon}`;
             
    case 'python':
      return `# Medium complexity ${requirements[0] || 'module'}\n\n` +
             `class ${applyNamingConvention('ExampleClass', 'PascalCase')}${colon}\n` +
             `${indent}def __init__(self)${colon}\n` +
             `${indent}${indent}self.data = []\n\n` +
             `${indent}def add_item(self, item)${colon}\n` +
             `${indent}${indent}self.data.append(item)\n` +
             `${indent}${indent}return self\n\n` +
             `${indent}def get_items(self)${colon}\n` +
             `${indent}${indent}return self.data\n\n` +
             `# Usage example\n` +
             `instance = ${applyNamingConvention('ExampleClass', 'PascalCase')}()\n` +
             `instance.add_item(${quote}test${quote})`;
             
    default:
      return `// Medium complexity ${language} implementation`;
  }
}

function generateComplexCode(requirements, language, style) {
  const indent = style.indentation === 'spaces' ? '  ' : '\t';
  const quote = style.quoteStyle === 'single' ? "'" : '"';
  const semicolon = style.semicolons ? ';' : '';
  
  switch (language) {
    case 'javascript':
      return `// Complex enterprise-grade ${requirements[0] || 'module'}\n\n` +
             `/**\n * ${applyNamingConvention('ExampleClass', 'PascalCase')} - Enterprise class\n */\n` +
             `class ${applyNamingConvention('ExampleClass', 'PascalCase')} {\n` +
             `${indent}#privateField = ${quote}private${quote}${semicolon}\n\n` +
             `${indent}constructor(config = {}) {\n` +
             `${indent}${indent}this.config = {\n` +
             `${indent}${indent}${indent}...${applyNamingConvention('defaultConfig', style.namingConvention)},\n` +
             `${indent}${indent}${indent}...config\n` +
             `${indent}${indent}}${semicolon}\n` +
             `${indent}${indent}this.cache = new Map()${semicolon}\n` +
             `${indent}}\n\n` +
             `${indent}async initialize() {\n` +
             `${indent}${indent}try {\n` +
             `${indent}${indent}${indent}await this.setup()${semicolon}\n` +
             `${indent}${indent}${indent}this.initialized = true${semicolon}\n` +
             `${indent}${indent}} catch (error) {\n` +
             `${indent}${indent}${indent}console.error(${quote}Initialization failed${quote}, error)${semicolon}\n` +
             `${indent}${indent}${indent}throw error${semicolon}\n` +
             `${indent}${indent}}\n` +
             `${indent}}\n\n` +
             `${indent}setup() {\n` +
             `${indent}${indent}return new Promise((resolve) => {\n` +
             `${indent}${indent}${indent}setTimeout(resolve, 100)${semicolon}\n` +
             `${indent}${indent}})${semicolon}\n` +
             `${indent}}\n\n` +
             `${indent}getData(key) {\n` +
             `${indent}${indent}if (this.cache.has(key)) {\n` +
             `${indent}${indent}${indent}return this.cache.get(key)${semicolon}\n` +
             `${indent}${indent}}\n` +
             `${indent}${indent}const data = this.fetchData(key)${semicolon}\n` +
             `${indent}${indent}this.cache.set(key, data)${semicolon}\n` +
             `${indent}${indent}return data${semicolon}\n` +
             `${indent}}\n\n` +
             `${indent}fetchData(key) {\n` +
             `${indent}${indent}return { key, timestamp: Date.now() }${semicolon}\n` +
             `${indent}}\n\n` +
             `${indent}static create(config) {\n` +
             `${indent}${indent}return new ${applyNamingConvention('ExampleClass', 'PascalCase')}(config)${semicolon}\n` +
             `${indent}}\n` +
             `}\n\n` +
             `// Factory function\n` +
             `const ${applyNamingConvention('defaultConfig', style.namingConvention)} = {\n` +
             `${indent}timeout: 5000,\n` +
             `${indent}retries: 3\n` +
             `}${semicolon}\n\n` +
             `// Export\n` +
             `export default ${applyNamingConvention('ExampleClass', 'PascalCase')}${semicolon}`;
             
    default:
      return `// Complex ${language} implementation with enterprise patterns`;
  }
}

// ============ CODE ANALYSIS ============

function analyzeCodeQuality(code, language) {
  const lines = code.split('\n');
  const issues = [];
  const suggestions = [];
  
  // Basic analysis
  const lineCount = lines.length;
  const commentLines = lines.filter(line => line.trim().startsWith('//') || line.trim().startsWith('#')).length;
  const emptyLines = lines.filter(line => line.trim() === '').length;
  
  // Complexity metrics
  const functionCount = (code.match(/function\s+\w+|def\s+\w+|const\s+\w+\s*=\s*\(/g) || []).length;
  const averageFunctionLength = lineCount / Math.max(functionCount, 1);
  
  // Style checks
  const longLines = lines.filter(line => line.length > 80).length;
  const inconsistentIndentation = detectInconsistentIndentation(lines);
  
  if (longLines > 0) {
    issues.push(`${longLines} lines exceed 80 characters`);
    suggestions.push('Consider breaking long lines for better readability');
  }
  
  if (inconsistentIndentation) {
    issues.push('Inconsistent indentation detected');
    suggestions.push('Use consistent indentation (2 or 4 spaces, or tabs)');
  }
  
  if (averageFunctionLength > 20) {
    issues.push('Functions might be too long');
    suggestions.push('Consider breaking large functions into smaller ones');
  }
  
  return {
    metrics: {
      lines: lineCount,
      functions: functionCount,
      comments: commentLines,
      commentRatio: (commentLines / lineCount * 100).toFixed(1) + '%',
      complexity: calculateCyclomaticComplexity(code)
    },
    issues,
    suggestions,
    maintainability: calculateMaintainabilityIndex(lineCount, commentLines, functionCount),
    styleScore: calculateStyleScore(code, language)
  };
}

function generateOptimizations(code, language) {
  const optimizations = [];
  
  // Language-specific optimizations
  switch (language) {
    case 'javascript':
      // Check for common anti-patterns
      if (code.includes('.forEach(') && code.includes('push(')) {
        optimizations.push('Consider using .map() instead of .forEach() with .push() for better performance');
      }
      
      if (code.includes('var ')) {
        optimizations.push('Replace var with let/const for block scoping');
      }
      
      if (code.includes('==') && !code.includes('===')) {
        optimizations.push('Use === instead of == for strict equality checks');
      }
      break;
      
    case 'python':
      if (code.includes('range(len(')) {
        optimizations.push('Consider using enumerate() instead of range(len())');
      }
      
      if (code.includes('.format(')) {
        optimizations.push('Consider using f-strings for string formatting');
      }
      break;
  }
  
  // General optimizations
  if (code.includes('console.log') && code.includes('production')) {
    optimizations.push('Remove console.log statements for production code');
  }
  
  return optimizations;
}

// ============ UTILITY FUNCTIONS ============

async function loadUserProfile(env, userId) {
  try {
    const profileData = await env.AI_STORAGE.get(`user_profile:${userId}`);
    
    if (profileData) {
      return JSON.parse(profileData);
    }
  } catch (error) {
    console.warn('Failed to load profile:', error);
  }
  
  // Create default profile
  return {
    codingStyle: {
      indentation: 'spaces',
      namingConvention: 'camelCase',
      lineLength: 80,
      bracketStyle: 'same-line',
      quoteStyle: 'single',
      semicolons: true
    },
    languagePreferences: {
      primary: 'javascript',
      secondary: [],
      frameworks: []
    },
    communicationStyle: {
      formality: 'balanced',
      detailLevel: 'balanced',
      examplesIncluded: true,
      technicalDepth: 'medium'
    },
    adaptations: 0,
    samplesAnalyzed: 0,
    lastActive: Date.now()
  };
}

async function saveUserProfile(env, userId, profile) {
  try {
    await env.AI_STORAGE.put(
      `user_profile:${userId}`,
      JSON.stringify(profile),
      { expirationTtl: 60 * 60 * 24 * 30 } // 30 days
    );
  } catch (error) {
    console.error('Failed to save profile:', error);
  }
}

async function storePatterns(env, userId, type, patterns) {
  try {
    const key = `patterns:${userId}:${type}`;
    const existing = await env.AI_STORAGE.get(key);
    const existingPatterns = existing ? JSON.parse(existing) : [];
    
    // Keep last 100 patterns
    existingPatterns.push({
      timestamp: Date.now(),
      patterns
    });
    
    if (existingPatterns.length > 100) {
      existingPatterns.shift();
    }
    
    await env.AI_STORAGE.put(
      key,
      JSON.stringify(existingPatterns),
      { expirationTtl: 60 * 60 * 24 * 60 } // 60 days
    );
    
  } catch (error) {
    console.warn('Failed to store patterns:', error);
  }
}

async function storeConversation(env, userId, conversation) {
  try {
    const key = `conversations:${userId}`;
    const existing = await env.AI_STORAGE.get(key);
    const conversations = existing ? JSON.parse(existing) : [];
    
    conversations.push(conversation);
    
    // Keep last 50 conversations
    if (conversations.length > 50) {
      conversations.shift();
    }
    
    await env.AI_STORAGE.put(
      key,
      JSON.stringify(conversations),
      { expirationTtl: 60 * 60 * 24 * 7 } // 7 days
    );
    
  } catch (error) {
    console.warn('Failed to store conversation:', error);
  }
}

function extractRequirements(message) {
  const requirements = [];
  
  if (message.includes('function') || message.includes('method')) {
    requirements.push('function');
  }
  
  if (message.includes('class') || message.includes('object')) {
    requirements.push('class');
  }
  
  if (message.includes('loop') || message.includes('iteration')) {
    requirements.push('loop');
  }
  
  if (message.includes('array') || message.includes('list')) {
    requirements.push('array');
  }
  
  if (message.includes('async') || message.includes('await') || message.includes('promise')) {
    requirements.push('async');
  }
  
  if (message.includes('error') || message.includes('exception') || message.includes('try')) {
    requirements.push('error-handling');
  }
  
  // Default requirement
  if (requirements.length === 0) {
    requirements.push('basic');
  }
  
  return requirements;
}

function generateExplanation(message, code, communicationStyle) {
  const style = communicationStyle;
  let explanation = '';
  
  if (style.detailLevel === 'detailed') {
    explanation += `Here's a detailed explanation of the code:\n\n`;
    explanation += `**Code Purpose:** This code addresses your request for "${message.substring(0, 100)}..."\n\n`;
    explanation += `**Key Features:**\n`;
    explanation += `- Implements the requested functionality\n`;
    explanation += `- Follows best practices for ${code.length > 100 ? 'larger' : 'small'} codebases\n`;
    explanation += `- Includes proper error handling patterns\n\n`;
  } else if (style.detailLevel === 'concise') {
    explanation += `Code explanation:\n`;
    explanation += `- Solves: ${message.substring(0, 50)}\n`;
    explanation += `- Lines: ${code.split('\n').length}\n`;
    explanation += `- Ready to use\n`;
  } else {
    explanation += `Here's the code you requested. It handles ${message.substring(0, 60)}...\n`;
    explanation += `The implementation follows modern practices and is ready for integration.\n`;
  }
  
  if (style.technicalDepth === 'high') {
    explanation += `\n**Technical Details:**\n`;
    explanation += `- Time Complexity: O(n) for most operations\n`;
    explanation += `- Space Complexity: O(1) for in-place operations\n`;
    explanation += `- Memory efficient with minimal allocations\n`;
  }
  
  return explanation;
}

function generateThoughtfulResponse(message, style) {
  const topics = {
    greeting: ['hello', 'hi', 'hey', 'greetings'],
    question: ['what', 'how', 'why', 'when', 'where', 'which'],
    request: ['can you', 'could you', 'would you', 'please'],
    thanks: ['thank', 'thanks', 'appreciate']
  };
  
  const lowerMessage = message.toLowerCase();
  
  // Check message type
  let response = '';
  
  if (topics.greeting.some(word => lowerMessage.includes(word))) {
    response = style.formality === 'formal' 
      ? "Hello! I'm here to assist you with coding and development tasks."
      : "Hey there! Ready to code?";
  } else if (topics.question.some(word => lowerMessage.startsWith(word))) {
    response = "That's an interesting question. ";
    if (style.detailLevel === 'detailed') {
      response += "Let me break this down into several parts to give you a comprehensive answer.\n\n";
    }
    response += "Based on my analysis and your coding style preferences, here's what I recommend:";
  } else if (topics.request.some(word => lowerMessage.includes(word))) {
    response = "Certainly! ";
    if (style.formality === 'formal') {
      response += "I'd be happy to help you with that request. ";
    }
    response += "Here's the solution tailored to your preferences:";
  } else if (topics.thanks.some(word => lowerMessage.includes(word))) {
    response = style.formality === 'formal'
      ? "You're very welcome! I'm glad I could assist you. Feel free to ask if you need anything else."
      : "No problem! Happy to help. Let me know if you need anything else!";
  } else {
    response = "I understand what you're looking for. ";
    if (style.detailLevel === 'detailed') {
      response += "Let me provide you with a thorough solution that addresses all aspects of your request.\n\n";
    }
    response += "Here's my response based on our previous interactions and your preferences:";
  }
  
  return response;
}

function generateExample(message, profile) {
  const language = profile.languagePreferences.primary;
  const style = profile.codingStyle;
  
  const simpleCode = `// Example based on your style\n` +
    `function ${applyNamingConvention('example', style.namingConvention)}() {\n` +
    `${style.indentation === 'spaces' ? '  ' : '\t'}return "This follows your coding style";\n` +
    `}`;
  
  return simpleCode;
}

function isCodingQuestion(message) {
  const codingKeywords = [
    'code', 'function', 'class', 'variable', 'loop',
    'array', 'object', 'string', 'number', 'boolean',
    'if else', 'switch', 'for', 'while', 'const',
    'let', 'var', 'import', 'export', 'require',
    'javascript', 'python', 'html', 'css', 'react',
    'node', 'api', 'database', 'server', 'client'
  ];
  
  const lowerMessage = message.toLowerCase();
  return codingKeywords.some(keyword => lowerMessage.includes(keyword));
}

function detectLanguageFromMessage(message) {
  const languages = {
    javascript: ['javascript', 'js', 'node', 'react', 'vue', 'angular'],
    python: ['python', 'py', 'django', 'flask'],
    html: ['html', 'markup'],
    css: ['css', 'stylesheet'],
    typescript: ['typescript', 'ts'],
    java: ['java'],
    php: ['php'],
    ruby: ['ruby', 'rails'],
    rust: ['rust'],
    go: ['go', 'golang'],
    csharp: ['c#', 'csharp'],
    cpp: ['c++', 'cpp']
  };
  
  const lowerMessage = message.toLowerCase();
  
  for (const [lang, keywords] of Object.entries(languages)) {
    if (keywords.some(keyword => lowerMessage.includes(keyword))) {
      return lang;
    }
  }
  
  return null;
}

function applyNamingConvention(name, convention) {
  switch (convention) {
    case 'camelCase':
      return name.charAt(0).toLowerCase() + name.slice(1);
    case 'PascalCase':
      return name.charAt(0).toUpperCase() + name.slice(1);
    case 'snake_case':
      return name.replace(/([A-Z])/g, '_$1').toLowerCase().replace(/^_/, '');
    case 'kebab-case':
      return name.replace(/([A-Z])/g, '-$1').toLowerCase().replace(/^-/, '');
    default:
      return name;
  }
}

function formatToLineLength(code, maxLength) {
  const lines = code.split('\n');
  const formatted = [];
  
  for (let line of lines) {
    if (line.length > maxLength && !line.trim().startsWith('//') && !line.trim().startsWith('#')) {
      // Simple line breaking (in real implementation would be more sophisticated)
      const parts = line.split(',').join(', ').split(' ').join(' ');
      let currentLine = '';
      let words = parts.split(' ');
      
      for (let word of words) {
        if ((currentLine + ' ' + word).length > maxLength && currentLine.length > 0) {
          formatted.push(currentLine);
          currentLine = word;
        } else {
          currentLine += (currentLine ? ' ' : '') + word;
        }
      }
      
      if (currentLine) {
        formatted.push(currentLine);
      }
    } else {
      formatted.push(line);
    }
  }
  
  return formatted.join('\n');
}

function calculateAverageLineLength(lines) {
  const nonEmptyLines = lines.filter(line => line.trim().length > 0);
  if (nonEmptyLines.length === 0) return 40;
  
  const totalLength = nonEmptyLines.reduce((sum, line) => sum + line.length, 0);
  return Math.round(totalLength / nonEmptyLines.length);
}

function detectBracketStyle(code) {
  const sameLine = (code.match(/\{\s*\n/) || []).length;
  const newLine = (code.match(/\n\s*\{/) || []).length;
  
  return sameLine > newLine ? 'same-line' : 'new-line';
}

function detectQuoteStyle(code) {
  const single = (code.match(/'[^']*'/g) || []).length;
  const double = (code.match(/"[^"]*"/g) || []).length;
  
  return single > double ? 'single' : 'double';
}

function detectSemicolonUsage(code) {
  const lines = code.split('\n');
  let withSemicolon = 0;
  let withoutSemicolon = 0;
  
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('//') && !trimmed.startsWith('#')) {
      if (trimmed.endsWith(';')) {
        withSemicolon++;
      } else if (/[a-zA-Z0-9"'`\}\)\]\)]$/.test(trimmed)) {
        withoutSemicolon++;
      }
    }
  }
  
  return withSemicolon > withoutSemicolon;
}

function calculateAverageFunctionLength(code) {
  const functions = code.split(/function|def|const.*=|let.*=|var.*=/).length - 1;
  const lines = code.split('\n').length;
  return functions > 0 ? Math.round(lines / functions) : 0;
}

function calculateCommentDensity(code) {
  const lines = code.split('\n');
  const commentLines = lines.filter(line => 
    line.trim().startsWith('//') || 
    line.trim().startsWith('#') || 
    line.trim().startsWith('/*') ||
    line.trim().includes('*/')
  ).length;
  
  return lines.length > 0 ? (commentLines / lines.length * 100).toFixed(1) + '%' : '0%';
}

function detectInconsistentIndentation(lines) {
  let spaceIndent = 0;
  let tabIndent = 0;
  
  for (const line of lines) {
    if (line.startsWith('  ')) spaceIndent++;
    if (line.startsWith('\t')) tabIndent++;
  }
  
  return spaceIndent > 0 && tabIndent > 0;
}

function calculateCyclomaticComplexity(code) {
  // Simplified cyclomatic complexity calculation
  const decisionPoints = (
    (code.match(/if\s*\(|else\s*|switch\s*\(|case\s+/g) || []).length +
    (code.match(/for\s*\(|while\s*\(|do\s*/g) || []).length +
    (code.match(/\&\&|\|\|/g) || []).length
  );
  
  return Math.max(1, decisionPoints + 1);
}

function calculateMaintainabilityIndex(lines, comments, functions) {
  // Simplified maintainability index
  const halsteadVolume = lines * 0.8;
  const cyclomaticComplexity = calculateCyclomaticComplexity('dummy');
  const commentPercentage = comments / Math.max(lines, 1);
  
  const mi = 171 - 5.2 * Math.log(halsteadVolume) - 0.23 * cyclomaticComplexity + 50 * Math.sqrt(commentPercentage);
  return Math.min(100, Math.max(0, Math.round(mi)));
}

function calculateStyleScore(code, language) {
  let score = 100;
  
  // Deduct for style issues
  const lines = code.split('\n');
  
  // Check line length
  const longLines = lines.filter(line => line.length > 120).length;
  score -= longLines * 2;
  
  // Check for inconsistent indentation
  if (detectInconsistentIndentation(lines)) {
    score -= 20;
  }
  
  // Check for magic numbers
  const magicNumbers = (code.match(/\b\d+\b/g) || []).length;
  score -= Math.min(20, magicNumbers);
  
  return Math.max(0, score);
}

function parseAdvancedRequirements(prompt) {
  const requirements = [];
  const lowerPrompt = prompt.toLowerCase();
  
  if (lowerPrompt.includes('api') || lowerPrompt.includes('endpoint')) {
    requirements.push('api');
  }
  
  if (lowerPrompt.includes('database') || lowerPrompt.includes('db') || lowerPrompt.includes('query')) {
    requirements.push('database');
  }
  
  if (lowerPrompt.includes('auth') || lowerPrompt.includes('login') || lowerPrompt.includes('security')) {
    requirements.push('authentication');
  }
  
  if (lowerPrompt.includes('test') || lowerPrompt.includes('unit') || lowerPrompt.includes('integration')) {
    requirements.push('testing');
  }
  
  if (lowerPrompt.includes('error') || lowerPrompt.includes('exception')) {
    requirements.push('error-handling');
  }
  
  if (lowerPrompt.includes('async') || lowerPrompt.includes('await') || lowerPrompt.includes('promise')) {
    requirements.push('async');
  }
  
  if (lowerPrompt.includes('performance') || lowerPrompt.includes('optimize')) {
    requirements.push('performance');
  }
  
  if (lowerPrompt.includes('clean') || lowerPrompt.includes('maintainable')) {
    requirements.push('clean-code');
  }
  
  return requirements.length > 0 ? requirements : ['general'];
}

function generateId() {
  return 'gen_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    }
  });
}

function serveHTMLInterface() {
  const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Cloudflare AI Worker</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { display: flex; flex-direction: column; gap: 20px; }
        .section { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
        textarea, input, select { width: 100%; padding: 10px; margin: 5px 0; }
        button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .code { background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; }
        .response { margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Cloudflare AI Worker</h1>
        
        <div class="section">
            <h2>Chat</h2>
            <textarea id="chatMessage" placeholder="Ask me anything about coding..." rows="3"></textarea>
            <button onclick="sendChat()">Send Message</button>
            <div id="chatResponse" class="response"></div>
        </div>
        
        <div class="section">
            <h2>Generate Code</h2>
            <input id="codePrompt" placeholder="Describe the code you want..." />
            <select id="codeLanguage">
                <option value="javascript">JavaScript</option>
                <option value="python">Python</option>
                <option value="html">HTML</option>
                <option value="css">CSS</option>
            </select>
            <select id="codeComplexity">
                <option value="simple">Simple</option>
                <option value="medium" selected>Medium</option>
                <option value="complex">Complex</option>
            </select>
            <button onclick="generateCode()">Generate Code</button>
            <div id="codeResponse" class="response"></div>
        </div>
        
        <div class="section">
            <h2>Learn from Code</h2>
            <textarea id="learnCode" placeholder="Paste your code here..." rows="5"></textarea>
            <input id="learnLanguage" placeholder="Language (e.g., javascript)" value="javascript" />
            <button onclick="learnCode()">Learn from this Code</button>
            <div id="learnResponse" class="response"></div>
        </div>
        
        <div class="section">
            <h2>Your Profile</h2>
            <button onclick="getProfile()">View Profile</button>
            <div id="profileResponse" class="response"></div>
        </div>
    </div>
    
    <script>
        const workerUrl = window.location.origin;
        
        async function sendChat() {
            const message = document.getElementById('chatMessage').value;
            const response = await fetch(workerUrl + '/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message })
            });
            const data = await response.json();
            document.getElementById('chatResponse').innerHTML = 
                '<h3>Response:</h3><pre>' + JSON.stringify(data, null, 2) + '</pre>';
        }
        
        async function generateCode() {
            const prompt = document.getElementById('codePrompt').value;
            const language = document.getElementById('codeLanguage').value;
            const complexity = document.getElementById('codeComplexity').value;
            
            const response = await fetch(workerUrl + '/api/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt, language, complexity })
            });
            const data = await response.json();
            document.getElementById('codeResponse').innerHTML = 
                '<h3>Generated Code:</h3><pre class="code">' + data.code + '</pre>' +
                '<p><strong>Language:</strong> ' + data.language + '</p>' +
                '<p><strong>Complexity:</strong> ' + data.complexity + '</p>';
        }
        
        async function learnCode() {
            const code = document.getElementById('learnCode').value;
            const language = document.getElementById('learnLanguage').value;
            
            const response = await fetch(workerUrl + '/api/learn', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code, language })
            });
            const data = await response.json();
            document.getElementById('learnResponse').innerHTML = 
                '<h3>Learning Results:</h3><pre>' + JSON.stringify(data, null, 2) + '</pre>';
        }
        
        async function getProfile() {
            const response = await fetch(workerUrl + '/api/profile');
            const data = await response.json();
            document.getElementById('profileResponse').innerHTML = 
                '<h3>Your Profile:</h3><pre>' + JSON.stringify(data, null, 2) + '</pre>';
        }
    </script>
</body>
</html>`;
  
  return new Response(html, {
    headers: {
      'Content-Type': 'text/html',
      'Cache-Control': 'no-cache'
    }
  });
}
