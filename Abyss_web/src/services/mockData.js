/**
 * Mock 数据服务 - 用于前端开发和测试
 * 根据关键信息示例数据设计，支持 13 个核心信息模块
 */

import { generateTimestampId } from '../utils/idGenerator.js';
import { getExtractedTestData } from '../utils/testData.js';

// 获取测试数据（已提取 data 字段，模拟响应拦截器处理后的数据）
const testData = getExtractedTestData();

// ==================== 模拟任务数据 ====================
export const mockTasks = [
  {
    id: 'task-001',
    name: '2024 年 Q1 内网安全评估',
    target: 'example.com',
    description: '对 example.com 进行全面渗透测试，包括信息收集、漏洞扫描和横向移动',
    status: 'running',
    progress: 65,
    scope: 'example.com 及其子域名，内网 192.168.1.0/24',
    tools: ['nmap', 'nikto', 'sqlmap', 'git-dumper'],
    createdAt: '2024-01-15T09:00:00Z',
    updatedAt: '2024-01-15T10:30:00Z',
  },
];

// ==================== 1. 信息收集（侦察）数据 ====================
export const mockReconnaissance = {
  domains: [
    {
      domain: 'example.com',
      subdomains: ['www', 'mail', 'blog', 'admin', 'dev'],
      ips: ['93.184.216.34'],
      notes: '主域名解析到一个共享 IP，子域名通过证书透明度日志和 DNS 爆破发现',
    },
    {
      domain: 'admin.example.com',
      subdomains: [],
      ips: ['192.168.1.105'],
      notes: '内部管理后台域名，仅内网可访问',
    },
  ],
  ipAddresses: [
    {
      ip: '93.184.216.34',
      hostname: 'example.com',
      is_alive: true,
      os: 'Linux (疑似 Ubuntu 20.04)',
      mac: 'N/A',
      notes: 'TTL 值为 64，推测为 Linux 系统',
    },
    {
      ip: '192.168.1.105',
      hostname: 'internal-db.example.com',
      is_alive: true,
      os: 'Windows Server 2019',
      mac: '00:50:56:89:AB:CD',
      notes: '内部网络发现的数据库服务器，MAC 地址识别为 VMware 虚拟机',
    },
    {
      ip: '192.168.1.120',
      hostname: 'HR-PC-01',
      is_alive: true,
      os: 'Windows 10',
      mac: '00:50:56:89:EF:01',
      notes: '人力资源部门工作站',
    },
  ],
  whoisInfo: [
    {
      target: 'example.com',
      registrar: 'Example Registrar Inc.',
      emails: ['admin@example.com', 'hostmaster@example.com'],
      nameservers: ['ns1.example.com', 'ns2.example.com'],
      created_date: '2000-01-01',
      expiry_date: '2025-01-01',
    },
  ],
};

// ==================== 2. 端口与服务数据 ====================
export const mockServices = [
  {
    ip: '93.184.216.34',
    hostname: 'example.com',
    port: 22,
    protocol: 'tcp',
    state: 'open',
    service: 'ssh',
    version: 'OpenSSH 7.6p1 Ubuntu 4ubuntu0.5',
    banner: 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5',
    cpe: 'cpe:/a:openbsd:openssh:7.6',
    notes: '支持密码和密钥登录，未发现高危漏洞',
  },
  {
    ip: '93.184.216.34',
    hostname: 'example.com',
    port: 80,
    protocol: 'tcp',
    state: 'open',
    service: 'http',
    version: 'nginx 1.18.0',
    banner: '',
    cpe: 'cpe:/a:nginx:nginx:1.18.0',
    notes: '重定向到 https://example.com',
  },
  {
    ip: '93.184.216.34',
    hostname: 'example.com',
    port: 443,
    protocol: 'tcp',
    state: 'open',
    service: 'https',
    version: 'nginx 1.18.0',
    banner: '',
    cpe: 'cpe:/a:nginx:nginx:1.18.0',
    notes: '主站点',
  },
  {
    ip: '192.168.1.105',
    hostname: 'internal-db.example.com',
    port: 3306,
    protocol: 'tcp',
    state: 'open',
    service: 'mysql',
    version: 'MySQL 5.7.35',
    banner: '',
    cpe: 'cpe:/a:mysql:mysql:5.7.35',
    notes: '内部数据库，存在弱口令',
  },
];

// ==================== 3. Web 应用数据 ====================
export const mockWebApplications = [
  {
    url: 'https://example.com',
    ip: '93.184.216.34',
    port: 443,
    https: true,
    status_code: 200,
    server: 'nginx/1.18.0',
    title: 'Example Corp - Official Site',
    technologies: ['jQuery', 'Bootstrap', 'Google Analytics'],
    frameworks: ['React'],
    cms: 'Custom',
    login_panel: false,
    directories: ['/images', '/css', '/js', '/api', '/backup'],
    files: ['/robots.txt', '/sitemap.xml', '/.git/HEAD'],
    parameters: ['id', 'page', 'user'],
    headers: { Server: 'nginx/1.18.0', 'X-Powered-By': 'Express' },
    notes: '发现/.git/目录泄露，可能包含源代码',
  },
  {
    url: 'https://admin.example.com/login',
    ip: '93.184.216.34',
    port: 443,
    https: true,
    status_code: 200,
    server: 'nginx/1.18.0',
    title: 'Admin Login',
    technologies: [],
    frameworks: [],
    cms: '',
    login_panel: true,
    directories: [],
    files: [],
    parameters: ['username', 'password', 'csrf_token'],
    headers: {},
    notes: '管理后台登录页面，存在 CSRF token',
  },
];

// ==================== 4. 漏洞数据 ====================
export const mockVulnerabilities = [
  {
    id: 'VULN-001',
    name: 'Git 源代码泄露',
    severity: 'high',
    type: '信息泄露',
    status: 'confirmed',
    affected: {
      target: '93.184.216.34',
      url: 'https://example.com/.git/',
      parameter: 'N/A',
      component: 'Git',
      version: 'N/A',
    },
    description: 'Web 根目录下的 .git 文件夹被公开访问，导致项目源代码泄露。',
    impact: '攻击者可以下载完整的源代码，分析其中的业务逻辑、数据库连接字符串、API 密钥等敏感信息。',
    poc: '使用 git-dumper 工具成功下载了整个 .git 目录。',
    evidence: '成功获取到 database.php 文件，其中包含数据库连接凭证。',
    cve: 'N/A',
    cwe: 'CWE-540',
    cvss: 7.5,
    remediation: '删除 Web 目录下的 .git 文件夹，或配置 Web 服务器阻止访问。',
    references: ['https://github.com/arthaud/git-dumper'],
    discovered_date: '2024-05-20',
    discovered_by: '张安全',
    notes: '泄露的代码中包含数据库地址为 192.168.1.105',
  },
  {
    id: 'VULN-002',
    name: 'MySQL 弱口令',
    severity: 'critical',
    type: '弱口令',
    status: 'exploited',
    affected: {
      target: '192.168.1.105',
      url: '',
      parameter: 'N/A',
      component: 'MySQL',
      version: '5.7.35',
    },
    description: '数据库使用弱口令，攻击者可以直接登录。',
    impact: '攻击者可以获取数据库完全控制权，窃取或篡改数据。',
    poc: '使用泄露的凭证直接登录成功。',
    evidence: 'db_user / EncryptedPassword123',
    cve: 'N/A',
    cwe: 'CWE-521',
    cvss: 9.8,
    remediation: '修改强密码，限制数据库访问 IP。',
    references: [],
    discovered_date: '2024-05-20',
    discovered_by: '张安全',
    notes: '',
  },
];

// ==================== 5. 凭证数据 ====================
export const mockCredentials = [
  {
    id: 'CRED-DB-001',
    type: 'database',
    status: 'valid',
    target: {
      service: 'mysql',
      host: '192.168.1.105',
      port: 3306,
      domain: '',
    },
    auth: {
      username: 'db_user',
      password: 'EncryptedPassword123',
      hash: '',
      hash_type: '',
      private_key: '',
      certificate: '',
    },
    source: '从泄露的源代码 database.php 文件中提取',
    discovered_date: '2024-05-20',
    notes: '该凭证用于连接内部数据库服务器',
  },
  {
    id: 'CRED-SYS-001',
    type: 'system',
    status: 'valid',
    target: {
      service: 'Windows',
      host: '192.168.1.120',
      port: 3389,
      domain: 'EXAMPLE',
    },
    auth: {
      username: 'admin',
      password: 'Summer2024!',
      hash: '',
      hash_type: '',
      private_key: '',
      certificate: '',
    },
    source: '密码破解',
    discovered_date: '2024-05-21',
    notes: '域管理员凭证',
  },
];

// ==================== 6. 漏洞利用数据 ====================
export const mockExploitation = {
  sessions: [
    {
      id: 'SESS-SHELL-001',
      vuln_id: 'VULN-001',
      target: '192.168.1.105',
      exploit_used: {
        name: 'MySQL 弱口令/凭证复用',
        tool: 'mysql client',
        command: 'mysql -h 192.168.1.105 -u db_user -p',
        payload: "SELECT 'Hello World' INTO OUTFILE '/tmp/test.txt';",
      },
      access: {
        shell_type: 'SQL Shell',
        ip: '192.168.1.105',
        port: 3306,
        user: 'db_user',
        privileges: 'SELECT, INSERT, UPDATE, DELETE, FILE',
      },
      timestamp: '2024-05-20 14:30:00',
      notes: '利用泄露的数据库凭证成功登录内部 MySQL 服务器',
    },
  ],
};

// ==================== 7. 权限提升数据 ====================
export const mockPrivilegeEscalation = [
  {
    session_id: 'SESS-SHELL-001',
    host: '192.168.1.105',
    initial_user: 'db_user',
    initial_privileges: '数据库用户，FILE 权限',
    target_user: 'SYSTEM',
    method: '通过 MySQL 的 FILE 权限向启动目录写入 webshell',
    exploit_name: 'MySQL UDF 提权',
    exploit_file: 'raptor_udf2.c',
    command: 'gcc -g -c raptor_udf2.c; ...; mysql -u db_user -p < foo.sql',
    success: true,
    final_user: 'SYSTEM',
    final_privileges: 'Windows 系统权限',
    timestamp: '2024-05-20 15:45:00',
    notes: '通过 MySQL UDF 提权，成功获得 Windows Server 2019 的 SYSTEM shell',
  },
];

// ==================== 8. 横向移动数据 ====================
export const mockLateralMovement = {
  pivoting: [
    {
      session_id: 'SESS-SHELL-001',
      pivot_type: '端口转发',
      local_port: 1080,
      remote_host: '192.168.1.1',
      remote_port: 3389,
      command: 'netsh interface portproxy add v4tov4 ...',
      accessible_networks: ['192.168.1.0/24', '10.0.0.0/8'],
      notes: '通过已攻陷的数据库服务器建立端口转发',
    },
  ],
  movement: [
    {
      session_id: 'SESS-SHELL-001',
      method: 'PsExec',
      credentials_id: 'CRED-DB-001',
      source_host: '192.168.1.105',
      target_host: '192.168.1.120',
      target_service: 'SMB',
      success: true,
      access_gained: '获得目标主机的 SYSTEM 权限',
      timestamp: '2024-05-20 16:20:00',
      notes: '使用窃取的数据库密码通过 PsExec 成功登录到域成员服务器',
    },
  ],
};

// ==================== 9. 敏感数据 ====================
export const mockSensitiveData = [
  {
    id: 'DATA-CONFIG-001',
    type: 'config',
    session_id: 'SESS-SHELL-001',
    location: '192.168.1.105, C:\\app\\config\\database.yml',
    content_summary: '包含多个内部应用和生产数据库的明文连接字符串',
    significance: '高',
    files: ['database.yml', 'connection.php'],
    extracted_data: ['prod_db:10.0.0.5:sa:P@ssw0rd!'],
    discovered_date: '2024-05-20',
    notes: '这些凭证可用于进一步渗透核心生产网络',
  },
];

// ==================== 10. 密码破解数据 ====================
export const mockPasswordCracking = [
  {
    session_id: 'SESS-SHELL-001',
    target_hashes: ['$NT$...hash1...', '$NT$...hash2...'],
    hash_type: 'NTLM',
    attempts: [
      {
        tool: 'john',
        command: 'john --format=nt --wordlist=rockyou.txt hashes.txt',
        wordlist: 'rockyou.txt',
        rules: ['best64'],
        time_spent: '2h',
        cracked_count: 1,
        cracked: [
          {
            hash: '$NT$...hash1...',
            password: 'Summer2024!',
            user: 'jdoe',
          },
        ],
      },
    ],
    timestamp: '2024-05-21',
    notes: '成功破解域用户 jdoe 的密码',
  },
];

// ==================== 11. 工具命令数据 ====================
export const mockToolCommands = [
  {
    phase: '信息收集',
    tool: 'nmap',
    version: '7.80',
    command: 'nmap -sV -p- -T4 93.184.216.34',
    output_file: 'nmap_scan_example_com.txt',
    parameters: { '-sV': '版本探测', '-p-': '全端口扫描' },
    timestamp: '2024-05-19',
    notes: '发现开放端口 22, 80, 443',
  },
  {
    phase: '漏洞利用',
    tool: 'git-dumper',
    version: 'latest',
    command: 'git-dumper https://example.com/.git/ ./example_git/',
    output_file: './example_git/',
    parameters: {},
    timestamp: '2024-05-20',
    notes: '成功下载泄露的 git 仓库',
  },
  {
    phase: '密码破解',
    tool: 'john',
    version: '1.9.0',
    command: 'john --format=nt --wordlist=rockyou.txt hashes.txt',
    output_file: 'john_output.txt',
    parameters: { '--format': 'nt', '--wordlist': 'rockyou.txt' },
    timestamp: '2024-05-21',
    notes: '破解 NTLM 哈希',
  },
];

// ==================== 12. 网络拓扑数据 ====================
export const mockTopology = {
  segments: [
    {
      name: 'DMZ',
      network: '93.184.216.0/24',
      hosts: [
        {
          ip: '93.184.216.34',
          hostname: 'example.com',
          role: 'Web 服务器',
          services: ['HTTP', 'HTTPS', 'SSH'],
          compromised: false,
          session_id: '',
        },
      ],
    },
    {
      name: '内部网络 - 办公',
      network: '192.168.1.0/24',
      hosts: [
        {
          ip: '192.168.1.105',
          hostname: 'internal-db',
          role: '数据库服务器',
          services: ['MySQL'],
          compromised: true,
          session_id: 'SESS-SHELL-001',
        },
        {
          ip: '192.168.1.120',
          hostname: 'HR-PC-01',
          role: '域成员工作站',
          services: ['SMB', 'RDP'],
          compromised: true,
          session_id: 'SESS-MOVE-001',
        },
      ],
    },
  ],
  connections: [
    {
      from: '192.168.1.105',
      to: '192.168.1.120',
      protocol: 'TCP',
      port: 445,
      discovered_by: '端口扫描和横向移动',
    },
  ],
};

// ==================== 13. 密码字典数据 ====================
export const mockWordlists = {
  usernames: ['admin', 'root', 'db_user', 'jdoe', 'asmith', 'backup'],
  passwords: ['EncryptedPassword123', 'P@ssw0rd', 'Summer2024!', 'CompanyName2024'],
  common_strings: ['ExampleCorp', 'Example', 'EC', '2024', 'Summer'],
  generated_files: ['example_corp_wordlist.txt', 'example_corp_rule.rule'],
};

// ==================== 旧版兼容数据 ====================
export const mockAssets = [
  { id: 'asset-001', type: 'host', host: '192.168.1.1', port: null, service: null, os: 'Linux', mac: '00:11:22:33:44:55', discoveredAt: '2024-01-15T09:15:00Z' },
  { id: 'asset-002', type: 'host', host: '192.168.1.10', port: null, service: null, os: 'Windows Server 2019', mac: '00:11:22:33:44:56', discoveredAt: '2024-01-15T09:16:00Z' },
  { id: 'asset-003', type: 'service', host: '192.168.1.1', port: 80, service: 'http', banner: 'nginx/1.18.0', discoveredAt: '2024-01-15T09:20:00Z' },
  { id: 'asset-004', type: 'service', host: '192.168.1.1', port: 443, service: 'https', banner: 'nginx/1.18.0', discoveredAt: '2024-01-15T09:20:00Z' },
  { id: 'asset-005', type: 'web', url: 'https://example.com', title: 'Example Corp', tech: ['React', 'Bootstrap'], discoveredAt: '2024-01-15T09:30:00Z' },
];

export const mockSubAgents = [
  {
    id: 'agent-001',
    name: '侦察代理',
    type: 'reconnaissance',
    description: '负责信息收集和资产发现',
    status: 'completed',
    taskCount: 15,
    successRate: 98,
  },
  {
    id: 'agent-002',
    name: '漏洞扫描代理',
    type: 'vulnerability_scanner',
    description: '负责自动化漏洞扫描和验证',
    status: 'running',
    taskCount: 8,
    successRate: 95,
  },
  {
    id: 'agent-003',
    name: '凭证破解代理',
    type: 'cracker',
    description: '负责密码爆破和凭证验证',
    status: 'pending',
    taskCount: 3,
    successRate: 85,
  },
];

// ==================== 模拟任务统计 ====================
export const mockTaskStats = {
  reconnaissance: {
    domains: 2,
    ipAddresses: 3,
    whoisInfo: 1,
  },
  services: 4,
  webApplications: 2,
  vulnerabilities: {
    total: 2,
    critical: 1,
    high: 1,
    medium: 0,
    low: 0,
  },
  credentials: {
    total: 2,
    valid: 2,
    invalid: 0,
  },
  exploitation: {
    sessions: 1,
    successful: 1,
  },
  privilegeEscalation: {
    total: 1,
    successful: 1,
  },
  lateralMovement: {
    pivoting: 1,
    movement: 1,
    successful: 1,
  },
  sensitiveData: 1,
  passwordCracking: {
    total: 1,
    cracked: 1,
  },
  toolCommands: 3,
  networkTopology: {
    segments: 2,
    hosts: 3,
    compromised: 2,
  },
};

// ==================== 模拟聊天记录 ====================
export const mockMessages = [
  {
    id: 'msg-001',
    type: 'system_message',
    content: '任务已启动，开始执行渗透测试...',
    timestamp: '2024-01-15T09:00:00Z',
  },
  {
    id: 'msg-002',
    type: 'assistant_message',
    content: '好的，我将开始对目标 example.com 进行全面的渗透测试。首先进行信息收集和资产发现。',
    timestamp: '2024-01-15T09:00:05Z',
  },
  {
    id: 'msg-003',
    type: 'subagent_message',
    agentName: '侦察代理',
    subAgentType: 'reconnaissance',
    content: '已完成域名信息收集，发现 2 个域名和 3 个 IP 地址。',
    data: { domainsFound: 2, ipsFound: 3 },
    timestamp: '2024-01-15T09:15:00Z',
  },
  {
    id: 'msg-004',
    type: 'tool_call',
    toolName: 'Nmap',
    command: 'nmap -sV -p- -T4 93.184.216.34',
    params: { targets: ['93.184.216.34'], version: true },
    status: 'completed',
    timestamp: '2024-01-15T09:10:00Z',
  },
  {
    id: 'msg-005',
    type: 'tool_result',
    toolName: 'Nmap',
    output: 'PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 7.6p1\n80/tcp open  http    nginx 1.18.0\n443/tcp open  https   nginx 1.18.0',
    executionTime: 45000,
    timestamp: '2024-01-15T09:15:00Z',
  },
  {
    id: 'msg-006',
    type: 'subagent_message',
    agentName: '漏洞扫描代理',
    subAgentType: 'vulnerability_scanner',
    content: '发现 Git 源代码泄露漏洞，严重程度：高。',
    data: { vulnerabilitiesFound: 1 },
    timestamp: '2024-01-15T09:50:00Z',
  },
];

/**
 * 模拟 API 延迟
 */
const simulateDelay = (ms = 500) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Mock 任务服务
 */
export const mockTaskService = {
  async getAllTasks(params = {}) {
    await simulateDelay(300);
    let tasks = [...mockTasks];
    if (params.status) {
      tasks = tasks.filter((t) => t.status === params.status);
    }
    return tasks;
  },

  async getTaskById(taskId) {
    await simulateDelay(200);
    const task = mockTasks.find((t) => t.id === taskId);
    if (!task) throw new Error('Task not found');
    return task;
  },

  async createTask(taskData) {
    await simulateDelay(500);
    const newTask = {
      ...taskData,
      id: generateTimestampId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    mockTasks.push(newTask);
    return newTask;
  },

  async deleteTask(taskId) {
    await simulateDelay(200);
    const index = mockTasks.findIndex((t) => t.id === taskId);
    if (index === -1) throw new Error('Task not found');
    mockTasks.splice(index, 1);
    return { success: true };
  },

  async startTask(taskId) {
    await simulateDelay(300);
    const task = mockTasks.find((t) => t.id === taskId);
    if (!task) throw new Error('Task not found');
    task.status = 'running';
    task.updatedAt = new Date().toISOString();
    return task;
  },

  async stopTask(taskId) {
    await simulateDelay(300);
    const task = mockTasks.find((t) => t.id === taskId);
    if (!task) throw new Error('Task not found');
    task.status = 'completed';
    task.updatedAt = new Date().toISOString();
    return task;
  },

  async updateTask(taskId, taskData) {
    await simulateDelay(300);
    const task = mockTasks.find((t) => t.id === taskId);
    if (!task) throw new Error('Task not found');
    Object.assign(task, taskData, { updatedAt: new Date().toISOString() });
    return task;
  },
};

/**
 * Mock 信息服务 - 支持 13 个核心信息模块
 */
export const mockInfoService = {
  // 统计
  async getTaskStats(taskId) {
    await simulateDelay(300);
    console.log('📊 [Mock] getTaskStats:', taskId, '返回数据:', testData.stats);
    return testData.stats;
  },

  // 侦察阶段
  async getReconnaissance(taskId) {
    await simulateDelay(400);
    console.log('🔍 [Mock] getReconnaissance:', taskId, '返回数据:', testData.reconnaissance);
    return testData.reconnaissance;
  },

  async getServices(taskId) {
    await simulateDelay(300);
    console.log('🌐 [Mock] getServices:', taskId, '返回数据:', testData.services);
    return testData.services;
  },

  async getWebApplications(taskId) {
    await simulateDelay(300);
    console.log('🕸️ [Mock] getWebApplications:', taskId, '返回数据:', testData.webApplications);
    return testData.webApplications;
  },

  // 攻击阶段
  async getVulnerabilities(taskId) {
    await simulateDelay(300);
    console.log('⚠️ [Mock] getVulnerabilities:', taskId, '返回数据:', testData.vulnerabilities);
    return testData.vulnerabilities;
  },

  async createVulnerability(taskId, vulnData) {
    await simulateDelay(300);
    const newVuln = {
      ...vulnData,
      id: `VULN-${String(mockVulnerabilities.length + 1).padStart(3, '0')}`,
      status: vulnData.status || 'new',
      discovered_date: new Date().toISOString().split('T')[0],
    };
    mockVulnerabilities.push(newVuln);
    return newVuln;
  },

  async getCredentials(taskId) {
    await simulateDelay(300);
    console.log('🔑 [Mock] getCredentials:', taskId, '返回数据:', testData.credentials);
    return testData.credentials;
  },

  async getExploitation(taskId) {
    await simulateDelay(300);
    console.log('💉 [Mock] getExploitation:', taskId, '返回数据:', testData.exploitation);
    return testData.exploitation;
  },

  async getPrivilegeEscalation(taskId) {
    await simulateDelay(300);
    console.log('⬆️ [Mock] getPrivilegeEscalation:', taskId, '返回数据:', testData.privilegeEscalation);
    return testData.privilegeEscalation;
  },

  async getLateralMovement(taskId) {
    await simulateDelay(300);
    console.log('↔️ [Mock] getLateralMovement:', taskId, '返回数据:', testData.lateralMovement);
    return testData.lateralMovement;
  },

  // 成果阶段
  async getSensitiveData(taskId) {
    await simulateDelay(300);
    console.log('📁 [Mock] getSensitiveData:', taskId, '返回数据:', testData.sensitiveData);
    return testData.sensitiveData;
  },

  async getPasswordCracking(taskId) {
    await simulateDelay(300);
    console.log('🔓 [Mock] getPasswordCracking:', taskId, '返回数据:', testData.passwordCracking);
    return testData.passwordCracking;
  },

  async getWordlists(taskId) {
    await simulateDelay(300);
    console.log('📚 [Mock] getWordlists:', taskId, '返回数据:', testData.wordlists);
    return testData.wordlists;
  },

  // 辅助信息
  async getToolCommands(taskId) {
    await simulateDelay(300);
    console.log('🛠️ [Mock] getToolCommands:', taskId, '返回数据:', testData.toolCommands);
    return testData.toolCommands;
  },

  async getTopology(taskId) {
    await simulateDelay(300);
    console.log('🗺️ [Mock] getTopology:', taskId, '返回数据:', testData.topology);
    return testData.topology;
  },

  // 旧版兼容
  async getTaskInfo(taskId) {
    await simulateDelay(300);
    console.log('📋 [Mock] getTaskInfo:', taskId);
    return { summary: testData.stats };
  },

  async getAssets(taskId) {
    await simulateDelay(300);
    console.log('📦 [Mock] getAssets:', taskId);
    return mockAssets;
  },

  async getNetworkTopology(taskId) {
    return this.getTopology(taskId);
  },

  async getToolHistory(taskId) {
    return this.getToolCommands(taskId);
  },

  async getSubAgents(taskId) {
    await simulateDelay(300);
    console.log('🤖 [Mock] getSubAgents:', taskId, '返回数据:', mockSubAgents);
    return mockSubAgents;
  },
};

/**
 * Mock WebSocket 消息
 */
let messageIndex = 0;
export const getMockWebSocketMessages = () => {
  const messages = [...mockMessages];
  return messages[messageIndex++ % messages.length];
};

export const resetMockMessages = () => {
  messageIndex = 0;
};
