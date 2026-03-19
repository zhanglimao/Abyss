from flask import Flask, jsonify, request
from flask_cors import CORS
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from task import TaskManager, TaskStatus
from datetime import datetime
import yaml
import logging

app = Flask(__name__)
CORS(app)  # 启用 CORS 支持

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.CRITICAL + 1)

# 加载关键信息文件
KEY_INFO_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'key_information', 'key_infomation.yaml')


def load_key_information():
    """加载关键信息 YAML 文件"""
    if os.path.exists(KEY_INFO_PATH):
        with open(KEY_INFO_PATH, 'r', encoding='utf-8') as f:
            try:
                data = yaml.safe_load(f)
            except yaml.YAMLError as e:
                print(f"Error loading YAML file: {e}")
                return {}
            # 如果文件为空或只包含空结构，返回空字典
            if data is None:
                return {}
            return data
    return {}


def _is_empty_item(item):
    """检查列表项是否为空项（递归检查所有值都是空字符串、空列表、空字典、False 或 0）"""
    if isinstance(item, dict):
        for value in item.values():
            if _is_empty_value(value):
                continue
            return False
        return True
    return False


def _is_empty_value(value):
    """递归检查值是否为空"""
    if value in (None, '', False, 0):
        return True
    if isinstance(value, list):
        # 空列表或只包含空项的列表都视为空
        if len(value) == 0:
            return True
        # 检查列表中是否所有项都是空的
        return all(_is_empty_item(item) if isinstance(item, dict) else _is_empty_value(item) for item in value)
    if isinstance(value, dict):
        return _is_empty_item(value)
    return False


def _filter_empty_items(items):
    """过滤掉空项列表"""
    if not isinstance(items, list):
        return items or []
    return [item for item in items if not _is_empty_item(item)]


@app.route('/')
def index():
    """欢迎页面"""
    return jsonify({
        "message": "Welcome to PT Test RESTful API",
        "endpoints": [
            "GET /api/health - 健康检查",
            "GET /api/tasks/{taskId}/info - 获取任务关键信息",
            "GET /api/tasks/{taskId}/stats - 获取任务统计信息",
            "GET /api/tasks/{taskId}/detail?type={type} - 获取任务详细信息"
        ]
    })


@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "service": "pt_test-restful"
    })

@app.route('/api/tasks/<task_id>/stats', methods=['GET'])
def get_task_stats(task_id):
    """获取任务统计信息"""
    key_info = load_key_information()

    # 统计 reconnaissance
    domains_count = 0
    ip_addresses_count = 0
    whois_info_count = 0

    if key_info.get('reconnaissance', {}).get('domains'):
        domains_count = len(_filter_empty_items(key_info['reconnaissance']['domains']))
    if key_info.get('reconnaissance', {}).get('ip_addresses'):
        ip_addresses_count = len(_filter_empty_items(key_info['reconnaissance']['ip_addresses']))
    if key_info.get('reconnaissance', {}).get('whois_info'):
        whois_info_count = len(_filter_empty_items(key_info['reconnaissance']['whois_info']))

    # 统计 services
    services_count = len(_filter_empty_items(key_info.get('services', [])))

    # 统计 web applications
    web_applications_count = len(_filter_empty_items(key_info.get('web_applications', [])))

    # 统计 vulnerabilities
    vulnerabilities_list = _filter_empty_items(key_info.get('vulnerabilities', []))
    vuln_critical = sum(1 for v in vulnerabilities_list if v.get('severity') == 'critical')
    vuln_high = sum(1 for v in vulnerabilities_list if v.get('severity') == 'high')
    vuln_medium = sum(1 for v in vulnerabilities_list if v.get('severity') == 'medium')
    vuln_low = sum(1 for v in vulnerabilities_list if v.get('severity') == 'low')

    # 统计 credentials
    credentials_list = _filter_empty_items(key_info.get('credentials', []))
    cred_valid = sum(1 for c in credentials_list if c.get('status') == 'valid')
    cred_invalid = sum(1 for c in credentials_list if c.get('status') == 'invalid')

    # 统计 exploitation
    sessions_list = _filter_empty_items(key_info.get('exploitation', {}).get('sessions', []))
    # 过滤掉只有空字段的 session（与详情保持一致）
    sessions_list = [s for s in sessions_list if s.get('id') or s.get('target') or s.get('exploit_used')]
    sessions_successful = len(sessions_list)  # 假设所有 session 都是成功的

    # 统计 privilege escalation
    priv_esc_list = _filter_empty_items(key_info.get('privilege_escalation', []))
    priv_esc_successful = sum(1 for p in priv_esc_list if p.get('success', False))

    # 统计 lateral movement
    pivoting_list = _filter_empty_items(key_info.get('lateral_movement', {}).get('pivoting', []))
    movement_list = _filter_empty_items(key_info.get('lateral_movement', {}).get('movement', []))
    movement_successful = sum(1 for m in movement_list if m.get('success', False))

    # 统计 sensitive data
    sensitive_data_count = len(_filter_empty_items(key_info.get('sensitive_data', [])))

    # 统计 password cracking
    password_cracking_list = _filter_empty_items(key_info.get('password_cracking', []))
    password_cracking_total = len(password_cracking_list)
    password_cracked = sum(
        len(pc.get('attempts', [{}])[0].get('cracked', [])) if pc.get('attempts') else 0
        for pc in password_cracking_list
    )

    # 统计 tool commands
    tool_commands_count = len(_filter_empty_items(key_info.get('tool_commands', [])))

    # 统计 network topology
    segments_list = _filter_empty_items(key_info.get('network_topology', {}).get('segments', []))
    network_hosts = sum(len(seg.get('hosts', [])) for seg in segments_list)
    network_compromised = sum(
        sum(1 for h in seg.get('hosts', []) if h.get('compromised', False))
        for seg in segments_list
    )

    return jsonify({
        "success": True,
        "data": {
            "reconnaissance": {
                "domains": domains_count,
                "ipAddresses": ip_addresses_count,
                "whoisInfo": whois_info_count
            },
            "services": services_count,
            "webApplications": web_applications_count,
            "vulnerabilities": {
                "total": len(vulnerabilities_list),
                "critical": vuln_critical,
                "high": vuln_high,
                "medium": vuln_medium,
                "low": vuln_low
            },
            "credentials": {
                "total": len(credentials_list),
                "valid": cred_valid,
                "invalid": cred_invalid
            },
            "exploitation": {
                "sessions": len(sessions_list),
                "successful": sessions_successful
            },
            "privilegeEscalation": {
                "total": len(priv_esc_list),
                "successful": priv_esc_successful
            },
            "lateralMovement": {
                "pivoting": len(pivoting_list),
                "movement": len(movement_list),
                "successful": movement_successful
            },
            "sensitiveData": sensitive_data_count,
            "passwordCracking": {
                "total": password_cracking_total,
                "cracked": password_cracked
            },
            "toolCommands": tool_commands_count,
            "networkTopology": {
                "segments": len(segments_list),
                "hosts": network_hosts,
                "compromised": network_compromised
            }
        }
    })


@app.route('/api/tasks/<task_id>/detail', methods=['GET'])
def get_task_detail(task_id):
    """获取任务详细信息，根据 type 参数返回对应的模块数据"""
    module_type = request.args.get('type')
    
    if not module_type:
        return jsonify({
            "success": False,
            "error": "Missing required query parameter: type"
        }), 400
    
    key_info = load_key_information()
    
    # 模块类型映射
    module_handlers = {
        'reconnaissance': lambda: get_reconnaissance_detail(key_info),
        'services': lambda: get_services_detail(key_info),
        'webApplications': lambda: get_web_applications_detail(key_info),
        'vulnerabilities': lambda: get_vulnerabilities_detail(key_info),
        'credentials': lambda: get_credentials_detail(key_info),
        'exploitation': lambda: get_exploitation_detail(key_info),
        'privilegeEscalation': lambda: get_privilege_escalation_detail(key_info),
        'lateralMovement': lambda: get_lateral_movement_detail(key_info),
        'sensitiveData': lambda: get_sensitive_data_detail(key_info),
        'passwordCracking': lambda: get_password_cracking_detail(key_info),
        'wordlists': lambda: get_wordlists_detail(key_info),
        'toolCommands': lambda: get_tool_commands_detail(key_info),
        'topology': lambda: get_topology_detail(key_info),
    }
    
    if module_type not in module_handlers:
        valid_types = ', '.join(module_handlers.keys())
        return jsonify({
            "success": False,
            "error": f"Invalid type parameter. Valid values: {valid_types}"
        }), 400
    
    data = module_handlers[module_type]()
    
    return jsonify({
        "success": True,
        "data": data
    })


def get_reconnaissance_detail(key_info):
    """获取信息收集详情"""
    recon = key_info.get('reconnaissance', {})

    domains = []
    for d in _filter_empty_items(recon.get('domains', [])):
        domains.append({
            "domain": d.get('domain', ''),
            "subdomains": d.get('subdomains', []),
            "ips": d.get('ips', []),
            "notes": d.get('notes', '')
        })

    ip_addresses = []
    for ip in _filter_empty_items(recon.get('ip_addresses', [])):
        ip_addresses.append({
            "ip": ip.get('ip', ''),
            "hostname": ip.get('hostname', ''),
            "isAlive": ip.get('is_alive', False),
            "os": ip.get('os', ''),
            "mac": ip.get('mac', ''),
            "notes": ip.get('notes', '')
        })

    whois_info = []
    for w in _filter_empty_items(recon.get('whois_info', [])):
        whois_info.append({
            "target": w.get('target', ''),
            "registrar": w.get('registrar', ''),
            "emails": w.get('emails', []),
            "nameservers": w.get('nameservers', []),
            "createdDate": w.get('created_date', ''),
            "expiryDate": w.get('expiry_date', '')
        })

    return {
        "domains": domains,
        "ipAddresses": ip_addresses,
        "whoisInfo": whois_info
    }


def get_services_detail(key_info):
    """获取端口服务详情"""
    services = []
    for s in _filter_empty_items(key_info.get('services', [])):
        services.append({
            "ip": s.get('ip', ''),
            "hostname": s.get('hostname', ''),
            "port": s.get('port', 0),
            "protocol": s.get('protocol', ''),
            "state": s.get('state', ''),
            "service": s.get('service', ''),
            "version": s.get('version', ''),
            "banner": s.get('banner', ''),
            "cpe": s.get('cpe', ''),
            "notes": s.get('notes', '')
        })
    return services


def get_web_applications_detail(key_info):
    """获取 Web 应用详情"""
    web_apps = []
    for w in _filter_empty_items(key_info.get('web_applications', [])):
        web_apps.append({
            "url": w.get('url', ''),
            "status_code": w.get('status_code', 0),
            "title": w.get('title', ''),
            "technologies": w.get('technologies', [])
        })
    return web_apps


def get_vulnerabilities_detail(key_info):
    """获取漏洞详情"""
    vulns = []
    for v in _filter_empty_items(key_info.get('vulnerabilities', [])):
        vulns.append({
            "id": v.get('id', ''),
            "name": v.get('name', ''),
            "severity": v.get('severity', ''),
            "description": v.get('description', ''),
            "cvss": v.get('cvss', 0)
        })
    return vulns


def get_credentials_detail(key_info):
    """获取凭证详情"""
    creds = []
    for c in _filter_empty_items(key_info.get('credentials', [])):
        creds.append({
            "type": c.get('type', ''),
            "target": c.get('target', {}),
            "auth": c.get('auth', {}),
            "status": c.get('status', '')
        })
    return creds


def get_exploitation_detail(key_info):
    """获取漏洞利用详情"""
    sessions = []
    for s in _filter_empty_items(key_info.get('exploitation', {}).get('sessions', [])):
        # 过滤掉只有空字段的 session（至少需要有 id 或其他关键字段）
        if not s.get('id') and not s.get('target') and not s.get('exploit_used'):
            continue
        sessions.append({
            "id": s.get('id', ''),
            "target": s.get('target', ''),
            "exploit_used": s.get('exploit_used', {}).get('name', '') if s.get('exploit_used') else '',
            "access": s.get('access', {})
        })
    return sessions


def get_privilege_escalation_detail(key_info):
    """获取权限提升详情"""
    priv_esc = []
    for p in _filter_empty_items(key_info.get('privilege_escalation', [])):
        priv_esc.append({
            "host": p.get('host', ''),
            "initial_user": p.get('initial_user', ''),
            "final_user": p.get('final_user', ''),
            "method": p.get('method', '')
        })
    return priv_esc


def get_lateral_movement_detail(key_info):
    """获取横向移动详情"""
    lateral = key_info.get('lateral_movement', {})

    pivoting = []
    for p in _filter_empty_items(lateral.get('pivoting', [])):
        pivoting.append({
            "session_id": p.get('session_id', ''),
            "pivot_type": p.get('pivot_type', ''),
            "local_port": p.get('local_port', 0),
            "remote_host": p.get('remote_host', ''),
            "remote_port": p.get('remote_port', 0),
            "accessible_networks": p.get('accessible_networks', [])
        })

    movement = []
    for m in _filter_empty_items(lateral.get('movement', [])):
        movement.append({
            "session_id": m.get('session_id', ''),
            "method": m.get('method', ''),
            "source_host": m.get('source_host', ''),
            "target_host": m.get('target_host', ''),
            "success": m.get('success', False),
            "access_gained": m.get('access_gained', '')
        })

    return {
        "pivoting": pivoting,
        "movement": movement
    }


def get_sensitive_data_detail(key_info):
    """获取敏感数据详情"""
    sensitive = []
    for s in _filter_empty_items(key_info.get('sensitive_data', [])):
        sensitive.append({
            "type": s.get('type', ''),
            "location": s.get('location', ''),
            "content_summary": s.get('content_summary', '')
        })
    return sensitive


def get_password_cracking_detail(key_info):
    """获取密码破解详情"""
    cracking = []
    for c in _filter_empty_items(key_info.get('password_cracking', [])):
        cracking.append({
            "hash_type": c.get('hash_type', ''),
            "attempts": c.get('attempts', [])
        })
    return cracking


def get_wordlists_detail(key_info):
    """获取密码字典详情"""
    wordlists = key_info.get('wordlists', {})
    return {
        "usernames": wordlists.get('usernames', []),
        "passwords": wordlists.get('passwords', [])
    }


def get_tool_commands_detail(key_info):
    """获取工具命令详情"""
    commands = []
    for c in _filter_empty_items(key_info.get('tool_commands', [])):
        commands.append({
            "tool": c.get('tool', ''),
            "command": c.get('command', ''),
            "phase": c.get('phase', ''),
            "timestamp": c.get('timestamp', '')
        })
    return commands


def get_topology_detail(key_info):
    """获取网络拓扑详情"""
    topology = key_info.get('network_topology', {})

    segments = []
    for seg in _filter_empty_items(topology.get('segments', [])):
        hosts = []
        for h in seg.get('hosts', []):
            hosts.append({
                "ip": h.get('ip', ''),
                "hostname": h.get('hostname', ''),
                "role": h.get('role', ''),
                "services": h.get('services', []),
                "compromised": h.get('compromised', False)
            })
        segments.append({
            "name": seg.get('name', ''),
            "network": seg.get('network', ''),
            "hosts": hosts
        })

    connections = []
    for conn in _filter_empty_items(topology.get('connections', [])):
        connections.append({
            "from": conn.get('from', ''),
            "to": conn.get('to', ''),
            "protocol": conn.get('protocol', ''),
            "port": conn.get('port', 0)
        })

    return {
        "segments": segments,
        "connections": connections
    }


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
