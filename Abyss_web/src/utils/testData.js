/**
 * 测试数据 - 模拟后端 API 返回的完整关键信息数据
 * 基于 RESTful API 设计文档中的示例数据
 */

// 模拟 /api/tasks/{taskId}/stats 接口返回
export const mockStatsResponse = {
  success: true,
  data: {
    reconnaissance: {
      domains: 1,
      ipAddresses: 2,
      whoisInfo: 1
    },
    services: 3,
    webApplications: 2,
    vulnerabilities: {
      total: 1,
      critical: 0,
      high: 1,
      medium: 0,
      low: 0
    },
    credentials: {
      total: 1,
      valid: 1,
      invalid: 0
    },
    exploitation: {
      sessions: 1,
      successful: 1
    },
    privilegeEscalation: {
      total: 1,
      successful: 1
    },
    lateralMovement: {
      pivoting: 1,
      movement: 1,
      successful: 1
    },
    sensitiveData: 1,
    passwordCracking: {
      total: 1,
      cracked: 1
    },
    toolCommands: 2,
    networkTopology: {
      segments: 2,
      hosts: 3,
      compromised: 2
    }
  }
};

// 模拟 /api/tasks/{taskId}/reconnaissance 接口返回
export const mockReconnaissanceResponse = {
  success: true,
  data: {
    domains: [
      {
        domain: "example.com",
        subdomains: ["www", "mail", "blog", "admin", "dev"],
        ips: ["93.184.216.34"],
        notes: "主域名解析到一个共享 IP，子域名通过证书透明度日志和 DNS 爆破发现"
      }
    ],
    ipAddresses: [
      {
        ip: "93.184.216.34",
        hostname: "example.com",
        is_alive: true,
        os: "Linux (疑似 Ubuntu 20.04)",
        mac: "N/A",
        notes: "TTL 值为 64，推测为 Linux 系统"
      },
      {
        ip: "192.168.1.105",
        hostname: "internal-db.example.com",
        is_alive: true,
        os: "Windows Server 2019",
        mac: "00:50:56:89:AB:CD",
        notes: "内部网络发现的数据库服务器，MAC 地址识别为 VMware 虚拟机"
      }
    ],
    whoisInfo: [
      {
        target: "example.com",
        registrar: "Example Registrar Inc.",
        emails: ["admin@example.com", "hostmaster@example.com"],
        nameservers: ["ns1.example.com", "ns2.example.com"],
        created_date: "2000-01-01",
        expiry_date: "2025-01-01"
      }
    ]
  }
};

// 模拟 /api/tasks/{taskId}/services 接口返回
export const mockServicesResponse = {
  success: true,
  data: [
    {
      ip: "93.184.216.34",
      hostname: "example.com",
      port: 22,
      protocol: "tcp",
      state: "open",
      service: "ssh",
      version: "OpenSSH 7.6p1 Ubuntu 4ubuntu0.5",
      banner: "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.5",
      cpe: "cpe:/a:openbsd:openssh:7.6",
      notes: "支持密码和密钥登录，未发现高危漏洞"
    },
    {
      ip: "93.184.216.34",
      hostname: "example.com",
      port: 80,
      protocol: "tcp",
      state: "open",
      service: "http",
      version: "nginx 1.18.0",
      banner: "",
      cpe: "cpe:/a:nginx:nginx:1.18.0",
      notes: "重定向到 https://example.com"
    },
    {
      ip: "93.184.216.34",
      hostname: "example.com",
      port: 443,
      protocol: "tcp",
      state: "open",
      service: "https",
      version: "nginx 1.18.0",
      banner: "",
      cpe: "cpe:/a:nginx:nginx:1.18.0",
      notes: "主站点"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/web-applications 接口返回
export const mockWebApplicationsResponse = {
  success: true,
  data: [
    {
      url: "https://example.com",
      ip: "93.184.216.34",
      port: 443,
      https: true,
      status_code: 200,
      server: "nginx/1.18.0",
      title: "Example Corp - Official Site",
      technologies: ["jQuery", "Bootstrap", "Google Analytics"],
      frameworks: ["React"],
      cms: "Custom",
      login_panel: false,
      directories: ["/images", "/css", "/js", "/api", "/backup"],
      files: ["/robots.txt", "/sitemap.xml", "/.git/HEAD"],
      parameters: ["id", "page", "user"],
      headers: {"Server": "nginx/1.18.0", "X-Powered-By": "Express"},
      notes: "发现/.git/目录泄露，可能包含源代码"
    },
    {
      url: "https://admin.example.com/login",
      ip: "93.184.216.34",
      port: 443,
      https: true,
      status_code: 200,
      server: "nginx/1.18.0",
      title: "Admin Login",
      technologies: [],
      frameworks: [],
      cms: "",
      login_panel: true,
      directories: [],
      files: [],
      parameters: ["username", "password", "csrf_token"],
      headers: {},
      notes: "管理后台登录页面，存在 CSRF token"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/vulnerabilities 接口返回
export const mockVulnerabilitiesResponse = {
  success: true,
  data: [
    {
      id: "VULN-001",
      name: "Git 源代码泄露",
      severity: "high",
      type: "信息泄露",
      status: "confirmed",
      affected: {
        target: "93.184.216.34",
        url: "https://example.com/.git/",
        parameter: "N/A",
        component: "Git",
        version: "N/A"
      },
      description: "Web 根目录下的 .git 文件夹被公开访问，导致项目源代码泄露。",
      impact: "攻击者可以下载完整的源代码，分析其中的业务逻辑、数据库连接字符串、API 密钥等敏感信息，可能导致更严重的攻击。",
      poc: "使用 git-dumper 工具成功下载了整个 .git 目录。",
      evidence: "成功获取到 database.php 文件，其中包含数据库连接凭证。",
      cve: "N/A",
      cwe: "CWE-540",
      cvss: 7.5,
      remediation: "删除 Web 目录下的 .git 文件夹，或配置 Web 服务器（如 Nginx、Apache）阻止对 .git 目录的访问。",
      references: ["https://github.com/arthaud/git-dumper"],
      discovered_date: "2024-05-20",
      discovered_by: "张安全",
      notes: "泄露的代码中包含数据库地址为 192.168.1.105，用户名为 db_user，密码为 EncryptedPassword123"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/credentials 接口返回
export const mockCredentialsResponse = {
  success: true,
  data: [
    {
      id: "CRED-DB-001",
      type: "database",
      status: "valid",
      target: {
        service: "mysql",
        host: "192.168.1.105",
        port: 3306,
        domain: ""
      },
      auth: {
        username: "db_user",
        password: "EncryptedPassword123",
        hash: "",
        hash_type: "",
        private_key: "",
        certificate: ""
      },
      source: "从泄露的源代码 database.php 文件中提取",
      discovered_date: "2024-05-20",
      notes: "该凭证用于连接内部数据库服务器 192.168.1.105"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/exploitation 接口返回
export const mockExploitationResponse = {
  success: true,
  data: {
    sessions: [
      {
        id: "SESS-SHELL-001",
        vuln_id: "VULN-001",
        target: "192.168.1.105",
        exploit_used: {
          name: "MySQL 弱口令/凭证复用",
          tool: "mysql client",
          command: "mysql -h 192.168.1.105 -u db_user -p",
          payload: "SELECT 'Hello World' INTO OUTFILE '/tmp/test.txt';"
        },
        access: {
          shell_type: "SQL Shell",
          ip: "192.168.1.105",
          port: 3306,
          user: "db_user",
          privileges: "SELECT, INSERT, UPDATE, DELETE, FILE"
        },
        timestamp: "2024-05-20 14:30:00",
        notes: "利用泄露的数据库凭证成功登录内部 MySQL 服务器，具有 FILE 权限，可用于写入文件。"
      }
    ]
  }
};

// 模拟 /api/tasks/{taskId}/privilege-escalation 接口返回
export const mockPrivilegeEscalationResponse = {
  success: true,
  data: [
    {
      session_id: "SESS-SHELL-001",
      host: "192.168.1.105",
      initial_user: "db_user",
      initial_privileges: "数据库用户，FILE 权限",
      target_user: "SYSTEM",
      method: "通过 MySQL 的 FILE 权限向启动目录写入 webshell",
      exploit_name: "MySQL UDF 提权",
      exploit_file: "raptor_udf2.c",
      command: "gcc -g -c raptor_udf2.c; ...; mysql -u db_user -p < foo.sql",
      success: true,
      final_user: "SYSTEM",
      final_privileges: "Windows 系统权限",
      timestamp: "2024-05-20 15:45:00",
      notes: "通过 MySQL UDF 提权，成功获得 Windows Server 2019 的 SYSTEM shell。"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/lateral-movement 接口返回
export const mockLateralMovementResponse = {
  success: true,
  data: {
    pivoting: [
      {
        session_id: "SESS-SHELL-001",
        pivot_type: "端口转发",
        local_port: 1080,
        remote_host: "192.168.1.1",
        remote_port: 3389,
        command: "netsh interface portproxy add v4tov4 ...",
        accessible_networks: ["192.168.1.0/24", "10.0.0.0/8"],
        notes: "通过已攻陷的数据库服务器建立端口转发，使其作为跳板机访问内部网络。"
      }
    ],
    movement: [
      {
        session_id: "SESS-SHELL-001",
        method: "PsExec",
        credentials_id: "CRED-DB-001",
        source_host: "192.168.1.105",
        target_host: "192.168.1.120",
        target_service: "SMB",
        success: true,
        access_gained: "获得目标主机的 SYSTEM 权限",
        timestamp: "2024-05-20 16:20:00",
        notes: "使用窃取的数据库密码（在多台机器上复用）通过 PsExec 成功登录到域成员服务器 192.168.1.120"
      }
    ]
  }
};

// 模拟 /api/tasks/{taskId}/sensitive-data 接口返回
export const mockSensitiveDataResponse = {
  success: true,
  data: [
    {
      id: "DATA-CONFIG-001",
      type: "config",
      session_id: "SESS-SHELL-001",
      location: "192.168.1.105, C:\\app\\config\\database.yml",
      content_summary: "包含多个内部应用和生产数据库的明文连接字符串",
      significance: "高",
      files: ["database.yml", "connection.php"],
      extracted_data: ["prod_db:10.0.0.5:sa:P@ssw0rd!"],
      discovered_date: "2024-05-20",
      notes: "这些凭证可用于进一步渗透核心生产网络。"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/password-cracking 接口返回
export const mockPasswordCrackingResponse = {
  success: true,
  data: [
    {
      session_id: "SESS-SHELL-001",
      target_hashes: ["$NT$...hash1...", "$NT$...hash2..."],
      hash_type: "NTLM",
      attempts: [
        {
          tool: "john",
          command: "john --format=nt --wordlist=rockyou.txt hashes.txt",
          wordlist: "rockyou.txt",
          rules: ["best64"],
          time_spent: "2h",
          cracked_count: 1,
          cracked: [
            {
              hash: "$NT$...hash1...",
              password: "Summer2024!",
              user: "jdoe"
            }
          ]
        }
      ],
      timestamp: "2024-05-21",
      notes: "成功破解域用户 jdoe 的密码，该密码符合公司密码策略，但仍被字典命中。"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/wordlists 接口返回
export const mockWordlistsResponse = {
  success: true,
  data: {
    usernames: ["admin", "root", "db_user", "jdoe", "asmith", "backup"],
    passwords: ["EncryptedPassword123", "P@ssw0rd", "Summer2024!", "CompanyName2024"],
    common_strings: ["ExampleCorp", "Example", "EC", "2024", "Summer"],
    generated_files: ["example_corp_wordlist.txt", "example_corp_rule.rule"]
  }
};

// 模拟 /api/tasks/{taskId}/tool-commands 接口返回
export const mockToolCommandsResponse = {
  success: true,
  data: [
    {
      phase: "信息收集",
      tool: "nmap",
      version: "7.80",
      command: "nmap -sV -p- -T4 93.184.216.34",
      output_file: "nmap_scan_example_com.txt",
      parameters: {"-sV": "版本探测", "-p-": "全端口扫描"},
      timestamp: "2024-05-19",
      notes: "发现开放端口 22, 80, 443"
    },
    {
      phase: "漏洞利用",
      tool: "git-dumper",
      version: "latest",
      command: "git-dumper https://example.com/.git/ ./example_git/",
      output_file: "./example_git/",
      parameters: {},
      timestamp: "2024-05-20",
      notes: "成功下载泄露的 git 仓库"
    }
  ]
};

// 模拟 /api/tasks/{taskId}/topology 接口返回
export const mockTopologyResponse = {
  success: true,
  data: {
    segments: [
      {
        name: "DMZ",
        network: "93.184.216.0/24",
        hosts: [
          {
            ip: "93.184.216.34",
            hostname: "example.com",
            role: "Web 服务器",
            services: ["HTTP", "HTTPS", "SSH"],
            compromised: false,
            session_id: ""
          }
        ]
      },
      {
        name: "内部网络 - 办公",
        network: "192.168.1.0/24",
        hosts: [
          {
            ip: "192.168.1.105",
            hostname: "internal-db",
            role: "数据库服务器",
            services: ["MySQL"],
            compromised: true,
            session_id: "SESS-SHELL-001"
          },
          {
            ip: "192.168.1.120",
            hostname: "HR-PC-01",
            role: "域成员工作站",
            services: ["SMB", "RDP"],
            compromised: true,
            session_id: "SESS-MOVE-001"
          }
        ]
      }
    ],
    connections: [
      {
        from: "192.168.1.105",
        to: "192.168.1.120",
        protocol: "TCP",
        port: 445,
        discovered_by: "端口扫描和横向移动"
      }
    ]
  }
};

// 完整的测试数据包
export const completeTestData = {
  stats: mockStatsResponse,
  reconnaissance: mockReconnaissanceResponse,
  services: mockServicesResponse,
  webApplications: mockWebApplicationsResponse,
  vulnerabilities: mockVulnerabilitiesResponse,
  credentials: mockCredentialsResponse,
  exploitation: mockExploitationResponse,
  privilegeEscalation: mockPrivilegeEscalationResponse,
  lateralMovement: mockLateralMovementResponse,
  sensitiveData: mockSensitiveDataResponse,
  passwordCracking: mockPasswordCrackingResponse,
  wordlists: mockWordlistsResponse,
  toolCommands: mockToolCommandsResponse,
  topology: mockTopologyResponse
};

// 提取 data 字段的辅助函数（模拟响应拦截器的行为）
export function extractData(response) {
  if (response && typeof response === 'object') {
    if (response.success !== undefined && response.data !== undefined) {
      return response.data;
    }
  }
  return response;
}

// 获取所有测试数据（已提取 data 字段）
export function getExtractedTestData() {
  const result = {};
  for (const [key, value] of Object.entries(completeTestData)) {
    result[key] = extractData(value);
  }
  return result;
}
