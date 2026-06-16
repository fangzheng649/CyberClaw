# 第三章 方案实现

## 3.1 网络感知引擎实现

感知层的核心目标是构建完整的网络资产画像：网络中存在什么设备，设备是什么类型、运行什么服务、存在什么暴露面。CyberScan感知引擎协调nmap-scan、device-config和simulation三个感知类MCP服务器，完成设备发现到设备清单构建的自动化流程。本节依次展开nmap扫描引擎封装、IoT指纹识别算法实现、自主设备发现流水线和默认密码检测四个子模块的具体实现方案。

> **【图3-1】IoT设备指纹识别效果图** — 展示nmap扫描+IoT指纹识别的运行截图：左侧为扫描结果列表（IP/端口/服务/Banner），右侧为指纹识别结果（设备类型/厂商/置信度/凭证状态）。新绘。

### 3.1.1 nmap扫描引擎封装

nmap-scan MCP服务器封装python-nmap库，通过FastMCP（Python 3.10+）框架暴露为MCP工具接口。服务器注册六个工具函数：network_scan负责全网设备发现，host_discovery负责主机存活检测，service_detection负责深度服务版本探测，vuln_scan负责NSE漏洞脚本扫描，iot_fingerprint负责IoT设备指纹识别，default_credential_check负责默认密码探测。各工具通过MCP协议的JSON-RPC 2.0消息格式经stdio管道与Agent通信。

**四种扫描模式的技术实现。** ICMP Ping扫描通过nmap的-sn参数发送ICMP Echo Request报文并等待Echo Reply响应判断主机存活状态，适用于常规主机发现但可能被设备防火墙策略阻断。TCP SYN扫描通过-sS参数向目标端口发送TCP SYN报文，根据返回的SYN-ACK（端口开放）或RST（端口关闭）判断端口状态，采用半开连接方式仅完成TCP三次握手的前两步即中断连接，可绕过部分ICMP过滤规则。UDP扫描通过-sU参数向目标端口发送UDP探测报文，根据返回的ICMP Port Unreachable消息判断端口状态，用于检测DNS（53端口）、SNMP（161端口）等仅运行在UDP协议上的IoT管理服务。ARP扫描通过-PR参数在同网段内发送ARP Request广播，由于工作在数据链路层不受IP层防火墙规则影响，在同网段场景下检测可靠性最高且速度最快。

**异步执行与安全限制。** python-nmap封装层通过asyncio实现异步执行，避免同步阻塞导致Agent的ReAct循环在Observation阶段长时间等待而触发超时中断。扫描引擎设置MAX_TARGETS=256的安全限制，防止单次扫描任务消耗过多系统资源。CyberAgent根据目标网段特征自动选择最优扫描组合——同网段优先ARP扫描，跨网段组合TCP SYN与ICMP——用户也可通过自然语言指定扫描策略，例如“用ARP模式扫描192.168.1.0/24网段”。扫描28台设备的目标网段可在30秒内完成。

**TOON序列化集成。** 所有nmap-scan工具的返回结果经toon_serializer模块自动进行TOON序列化后返回给Agent，解码失败时安全回退至JSON格式。封装nmap而非自研扫描引擎的设计决策基于三方面考量：nmap服务指纹库覆盖超过11,000种签名、NSE脚本生态成熟（vuln、exploit、default-login等类别），且经过25年以上持续迭代；python-nmap封装层提供标准化参数接口和TOON统一输出格式，使Agent可通过MCP协议调用扫描能力而无需构造命令行参数。

**表3-1 nmap-scan MCP服务器工具清单**

| 工具名称 | 功能 | 核心参数 | 输出 |
|:------:|:---:|:------:|:---:|
| network_scan | 全网设备发现 | target(网段), scan_type | hosts_found, devices[] |
| host_discovery | 主机存活检测 | target, method(arp/icmp) | alive_hosts[] |
| service_detection | 服务版本探测 | target, ports | services[] with banner |
| vuln_scan | NSE漏洞脚本 | target, scripts | vulnerabilities[] |
| iot_fingerprint | IoT指纹识别 | target | devices[] with type/vendor/confidence |
| default_credential_check | 默认密码检测 | target, vendor | weak_credentials[] |

### 3.1.2 IoT指纹识别算法实现

iot_fingerprint工具将MAC OUI匹配、服务Banner解析和端口组合模式识别三个维度的结果进行加权融合，输出设备类型分类、厂商信息和置信度评分。本节展开每个维度的具体实现算法。

**第一维度——MAC OUI数据库匹配。** 工具从nmap扫描结果中提取目标设备的MAC地址前三字节（OUI，Organizationally Unique Identifier），查询本地维护的IEEE OUI数据库（ieee-oui.txt）推断设备制造商。当OUI指向知名IoT品牌（如Hikvision、Dahua、Axis）时赋予较高的置信度权重；当OUI指向通用芯片制造商（如Realtek、MediaTek）时赋予较低的权重，因为这些通用芯片被广泛用于各类IoT终端，OUI仅能确定芯片来源而无法区分终端设备类型。

**第二维度——服务Banner解析。** 工具从service_detection的输出中提取各服务的banner信息，应用预定义的正则表达式规则集进行匹配。HTTP banner解析提取title标签内容、Server响应头和WWW-Authenticate字段；SSH banner解析提取SSH协议版本字符串（如"SSH-2.0-OpenSSH_8.2"表示标准SSH服务，"SSH-2.0-dropbear_2020.81"表示嵌入式IoT设备常用的轻量SSH实现）；RTSP banner解析提取Server字段（如"Hikvision-IPCamera"直接标识摄像头设备）。Banner解析维度直接包含设备品牌和型号标识信息，在三个维度中赋予最高的置信度权重（0.45）。

**第三维度——端口组合模式识别。** 工具分析目标设备开放的端口集合，与预定义的22条JSON启发式规则进行匹配。摄像头设备典型开放HTTP（80端口）和RTSP（554端口）的组合；门禁系统典型开放HTTP（80端口）、HTTPS（443端口）和管理端口（8080端口）；工控设备开放Modbus TCP（502端口）和S7comm（102端口）等工业协议的标志性端口。端口组合维度赋予中等置信度权重（0.35）。

**第四维度——综合加权判定。** 三维度加权融合公式为 Score(T) = 0.20 · S_OUI(T) + 0.45 · S_Banner(T) + 0.35 · S_Port(T)。当综合得分超过0.6时输出设备类型判定；低于0.6时触发深度分析模式，追加SNMP sysDescr查询和Nmap NSE脚本扫描。该融合策略具有容错能力——即使某一维度信号缺失（如HTTP title为空），其余维度仍能提供有效的识别依据。最终输出包含设备类型分类、厂商信息和置信度评分（0至1.0），以TOON格式返回给Agent。

> **【图3-2】IoT指纹识别四维度融合算法流程图** — 展示三层输入（MAC OUI/Banner/端口）→权重分配→融合评分→阈值判定的完整流程，标注三个权重值和0.6阈值。复用初赛文档图3-2，更新为三维度+综合判定结构。

### 3.1.3 自主设备发现流水线

discovery_service实现网络中新增IoT设备的自动识别和动态建档。发现流水线采用三层Fallback策略：优先使用scapy ARP扫描（arp-scan）获取局域网设备列表，ARP扫描工作在数据链路层不受IP层防火墙影响，在局域网场景下速度最快、准确率最高；若ARP不可用则降级为Nmap快速扫描（TCP SYN常用端口）；若前两种主动扫描均不可用，则从拓扑数据库加载已知设备信息（拓扑数据库在系统启动时从初始配置种子引导，运行时持续通过周期扫描和邻居协议自动更新）。

发现流水线按2.2.5节设计的六阶段流水线实现（设备创建→厂商识别→类型推断→属性填充→拓扑关联→事件通知），在实现层面补充三个关键技术细节：

**厂商识别的多源融合。** identify_vendor函数按MAC OUI前缀匹配19家IoT厂商库（ieee-oui.txt），对匹配不到的设备降级为hostname正则匹配（camera/sensor/plug/router等模式），再降级为端口特征映射（554→camera、1883→server、502→plc）。三层优先级确保即使MAC被通用芯片商注册，仍能通过端口特征准确识别设备类型。

**scan_service周期扫描集成。** 设备发现服务集成在后端的scan_service中，系统启动时读取初始子网配置（或通过SCAN_SUBNET环境变量覆盖），以可配置的间隔（默认300秒，SCAN_INTERVAL环境变量）持续执行周期性扫描。每轮扫描完成后，discovery_service将新发现的设备与已知设备列表进行差异比较——新出现的设备触发完整的六阶段建档流水线（设备创建→厂商识别→类型推断→属性填充→拓扑关联→事件通知），已消失的设备标记为离线状态。增量更新机制确保系统拓扑视图始终与实际网络状态同步，新接入网络的IoT设备在下一个扫描周期内即可被自动感知并纳入安全监控范围。

**动态拓扑维护机制。** 系统采用“种子配置+动态发现”双驱动的拓扑维护策略。初始配置文件提供网络子网定义、已知设备列表（IP/MAC/类型/厂商/位置坐标/交换机端口映射）和连接关系作为启动种子。系统运行后，拓扑信息通过三条路径持续更新：（1）周期性ARP/nmap扫描发现新设备并自动注册；（2）通过SSH查询交换机MAC地址表和CDP/LLDP邻居信息，动态构建和更新设备-端口映射关系；（3）MQTT和Syslog事件中发现的新设备标识（如新出现的源IP）自动触发发现流程。三条路径的更新结果合并写入统一的拓扑数据库，消除了静态配置文件无法反映网络变化的局限性。新设备从接入网络到被系统感知的延迟不超过一个扫描周期（默认300秒）。

### 3.1.4 默认密码检测实现

default_credential_check工具对目标设备的登录服务尝试常见默认凭证组合，将凭证安全状态纳入设备资产画像。工具内置IoT设备常见默认密码库，包含两类凭证来源：通用默认组合（admin/admin、root/root、admin/12345、guest/guest等，约50组常见组合）和厂商特定组合，根据iot_fingerprint识别的厂商信息从厂商凭证子库中优先提取该厂商的已知默认凭证（如Hikvision设备的12345/12345、Dahua设备的admin/888888等，覆盖20余个主流IoT厂商共约70组厂商特定凭证）。

对于Telnet和SSH服务，工具封装hydra暴力破解引擎使用凭证字典进行自动化登录尝试，通过线程池并发探测控制单次扫描耗时低于10秒；对于HTTP管理界面，工具构造HTTP POST登录请求并尝试默认凭证组合，根据HTTP响应状态码（302重定向至管理页面为登录成功）和响应内容判断登录是否成功。检测结果输出三种状态：安全、使用默认密码（输出具体凭证组合）和无法检测。默认密码检测属于三级权限中的只读操作，Agent可自主执行而无需用户确认。

---

## 3.2 多源数据采集实现

CyberSense引擎协调syslog-collector、snmp-collector、cve-intel、security-baseline、flow-analyzer和traffic-analyzer六个检测类MCP服务器，采集设备日志、漏洞情报、安全基线和网络流量四路异构数据。本节展开每路数据源的采集协议和解析实现。

> **【图3-3】多源数据采集架构实现图** — 展示五个采集器的实际实现：Syslog(asyncio UDP Server) / SNMP(pysnmp) / MQTT(paho-mqtt) / IPFIX(自定义UDP解析器) / Suricata(eve.json文件监控)，各自连接到后端collector_service的广播机制。新绘。

### 3.2.1 Syslog采集器

syslog-collector MCP服务器基于asyncio DatagramProtocol实现UDP 514端口的异步监听，接收IoT设备发送的RFC 5424格式Syslog消息。服务器提供六个工具函数：syslog_start_receiver启动UDP监听，syslog_stop_receiver停止监听，syslog_get_status获取运行状态，syslog_query查询历史告警，syslog_get_message获取单条告警详情，syslog_get_severity_counts统计各级别告警数量。

**解析与去重机制。** parse_raw解析函数提取severity（Emergency至Debug共八级）、facility（设施类型）、timestamp（时间戳）、source_ip（发送设备IP）、hostname（设备主机名）和message（事件描述）六个核心字段。系统设计哈希去重机制避免重复告警——对每条消息的(source_ip + severity + message_prefix)计算哈希值，相同哈希在60秒冷却窗口内不重复记录。令牌桶限流机制防止告警风暴——当单台设备在10秒内产生超过50条告警时，后续告警聚合为一条摘要记录，避免系统过载。

### 3.2.2 SNMP Trap采集器

snmp-collector MCP服务器基于pysnmp库实现UDP 162端口的SNMP Trap监听，支持SNMP v1、v2c和v3三个版本。服务器提供六个工具函数：snmp_start_trap_receiver启动Trap监听，snmp_stop_trap_receiver停止监听，snmp_get_receiver_status获取接收器状态，snmp_get_traps查询历史Trap记录，snmp_get_trap_detail获取单条Trap详情，snmp_get_trap_counts统计各类Trap数量。

**SNMP v3安全认证处理。** SNMP v3相比v1/v2c增加了基于用户的安全模型（USM），提供认证和加密两项安全能力。snmp-collector在处理v3 Trap时，首先通过预配置的USM用户凭证（authKey和privKey）验证消息的HMAC-SHA认证摘要，确认消息未被篡改；然后使用AES-128算法解密加密的Scoped PDU数据部分。认证失败的消息记录为security_event并丢弃，避免伪造Trap干扰安全分析。v1和v2c版本通过community string进行简单的明文认证，适用于隔离管理网络环境。

**Trap OID解码与语义映射。** decode_trap工具实现两层OID映射机制：第一层为标准Enterprise OID映射，预定义关键Trap OID映射表涵盖linkDown（1.3.6.1.6.3.1.1.5.3，接口down事件）、linkUp（1.3.6.1.6.3.1.1.5.4，接口up事件）、authenticationFailure（1.3.6.1.6.3.1.1.5.5，认证失败）和coldStart（1.3.6.1.6.3.1.1.5.1，设备重启）等标准Trap；第二层为厂商私有OID映射，针对华为（1.3.6.1.4.1.2011）、Cisco（1.3.6.1.4.1.9）和H3C（1.3.6.1.4.1.25506）等主流厂商的私有MIB定义，将设备温度告警、电源异常、风扇故障等厂商特定事件映射为统一的安全事件格式。映射失败时保留原始OID作为事件标识，供后续人工分析。

**Trap与Syslog的互补采集。** SNMP Trap与Syslog形成互补关系：Syslog偏重设备应用层日志事件（登录失败、配置变更、服务启停），SNMP Trap偏重设备协议层状态变化（接口up/down、CPU阈值越限、内存异常）。两路数据的采集器独立运行，通过各自的事件总线推送至CyberSense关联分析引擎。当Syslog检测到登录失败事件且SNMP Trap同时报告对应设备的接口状态变化时，CyberSense将两路事件进行时间关联（5秒窗口），提升攻击判定的置信度。

### 3.2.3 MQTT监控器

mqtt_service基于paho-mqtt v2库实现MQTT协议监控，订阅IoT设备通信的MQTT主题（默认订阅"cyberclaw/#"通配主题），检测三类异常行为。**异常发布率检测**——维护每台设备的发布计数器（publish_count），滑动窗口60秒内单台设备发布超过100条消息触发疑似数据外泄告警（threshold=100, window=60s），告警通过set_broadcast推送至3D HUD。**未授权主题订阅检测**——维护主题白名单（从拓扑数据库中加载已注册设备的合法MQTT client_id和授权订阅主题），检测非预期设备订阅敏感主题（如配置下发主题"cmd/+"）的行为。**异常载荷检测**——检查MQTT消息载荷大小，单条超过10KB的异常大载荷标记为可疑（可能包含窃取的数据或恶意固件包）。

### 3.2.4 IPFIX/NetFlow流量采集器

flow-analyzer MCP服务器实现自定义的UDP接收器，解析NetFlow v5、v9和IPFIX（v10）三种格式的流量元数据。服务器提供七个工具函数，覆盖接收器管理、流记录查询、单条流详情、主机排行（top_talkers）和模板管理等功能。

**模板缓存机制。** NetFlow v9和IPFIX采用动态模板机制——路由器在发送流记录前先发送模板定义（Template Record），接收器缓存模板后按模板解析后续数据流。flow-analyzer维护模板缓存字典（template_id → field_definitions），处理模板刷新和超时淘汰。当收到未知模板ID的流记录时，记录为raw_data等待模板到达后回溯解析。

**异常流量检测。** detect_anomaly工具执行三类攻击行为检测：C2回连检测通过分析对外连接的目的IP集中度和连接频率识别C2（Command and Control）行为；横向扫描检测通过检测短时间内大量不同目的IP与固定端口（23/Telnet和2323）的流量模式识别Mirai等恶意软件的扩散行为；DDoS参与检测通过识别设备向单一目标发送大量出站流量判断是否参与分布式拒绝服务攻击。

### 3.2.5 Suricata IDS事件监控

suricata_service实现Suricata IDS的事件集成。服务监控Suricata输出的eve.json文件（JSON Lines格式），实时提取IDS告警事件。文件监控采用增量读取策略——记录上次读取的文件偏移量（file_offset），每2秒检查一次文件大小变化，仅读取offset之后的新增内容，解析后更新offset，避免重复处理。解析逻辑提取eve.json中的alert类型事件，核心字段包括：timestamp（时间戳，ISO 8601格式）、src_ip/src_port（源地址）、dest_ip/dest_port（目的地址）、alert.signature（规则签名，如"ET TELNET Attempted Telnet Login"）、alert.severity（严重级别，1=critical、2=high、3=medium）、alert.category（攻击类别，如"Attempted Administrator Privilege Gain"）。告警事件经severity级别过滤（默认仅转发severity ≤ 3的告警）后，通过set_broadcast推送至前端3D HUD和Chat通道，同时在设备列表中查找匹配的目标设备更新其安全状态。Suricata的集成使CyberClaw获得基于签名的专业IDS检测能力，与traffic-analyzer的行为检测形成互补。

---

## 3.3 智能检测引擎实现

### 3.3.1 CVE漏洞查询与缓存

cve-intel MCP服务器通过httpx异步HTTP客户端对接NVD（National Vulnerability Database）REST API v2.0，为检测阶段提供漏洞情报数据。NVD由美国国家标准与技术研究院（NIST）维护，覆盖已知CVE漏洞超过20万条。服务器提供四个工具函数：search_cve按关键词搜索，get_cve按CVE编号查询详情，search_by_cpe按CPE标识符查询，check_device_vulns按设备信息综合查询。

**CPE 2.3自动构造算法。** CyberScan感知阶段输出的设备资产清单包含device_type、vendor和firmware_version三个字段。CyberSense接收资产清单后，自动将设备信息映射为CPE 2.3格式字符串。例如一台Hikvision摄像头固件版本2.1.2被映射为"cpe:2.3:a:hikvision:ip_camera_firmware:2.1.2:*:*:*:*:*:*:*"。CPE构造算法处理三类边界情况：厂商名称中的空格和特殊字符规范化（如"D-Link"→"d_link"）、固件版本号的多段式处理（如"v2.1.2-build2024"→"2.1.2"）、缺失字段的通配符填充。

**SQLite缓存与API限流策略。** cve-intel在SQLite数据库中缓存已查询的CVE结果，缓存键为CPE字符串，缓存有效期为5分钟（短缓存周期确保漏洞数据时效性）。Agent查询CVE时先查本地缓存，缓存命中且未过期则直接返回（响应时间从1-2秒降至毫秒级）；缓存未命中则调用NVD API并将结果写入缓存。当批量查询触发NVD API的429状态码（Too Many Requests）时，cve-intel自动进入指数退避重试策略（初始等待2秒，每次翻倍，最大60秒），优先返回缓存中的近似结果供Agent进行初步推理，待限流窗口结束后补充查询精确数据。

### 3.3.2 安全基线审计实现

security-baseline MCP服务器基于CIS（Center for Internet Security）安全基线标准，对IoT设备配置进行系统化合规性检查。服务器提供四个工具函数：check_baseline执行完整基线审计，list_rules列出所有检查规则，get_profiles获取审计配置文件，quick_audit执行快速合规检查。

**四种审计Profile。** 服务器内置四种安全Profile，针对不同设备类型定制检查规则集：（1）iot-default——通用IoT设备基线，覆盖所有基础检查项；（2）network-device——网络设备基线，增加路由协议和ACL检查；（3）camera-specific——摄像头专用基线，增加RTSP认证和视频流加密检查；（4）critical-infra——关键基础设施基线，采用最严格的检查标准。四种Profile共涵盖53条详细安全规则。

**规则分类与权重体系。** 53条检查规则按安全影响分为三个权重等级：Critical级规则（权重3.0）包含默认密码检测、Telnet服务开放、管理接口无认证等直接影响设备可被攻陷的高危配置项；Warning级规则（权重2.0）包含SNMP默认community、HTTP未升级HTTPS、固件版本过旧等中等风险配置项；Info级规则（权重1.0）包含DNS配置、NTP同步、日志级别设置等运维规范类检查项。合规评分算法基于加权扣分制——初始满分100分，每条违规规则按其权重从总分中扣减（Critical违规扣15分，Warning违规扣8分，Info违规扣3分），最终得分下限为0分。该加权机制确保高危配置缺陷对合规评分的影响远大于运维规范类问题，引导运维人员优先修复高风险项。

**并发扫描优化。** 基线审计对目标设备的检查涉及多个TCP端口的连接探测。为避免串行探测导致审计耗时长，security-baseline采用concurrent.futures.ThreadPoolExecutor实现并发端口扫描，线程池大小根据目标设备数量动态调整（min(设备数×2, 32)）。每个端口扫描使用TCP connect方式（socket.connect_ex），设置3秒超时避免阻塞。审计结果输出合规评分（0-100）和不合规项清单，清单中每条违规项包含规则ID、检查描述、当前配置状态、修复建议和风险等级，支持按设备类型和网段维度聚合分析。

### 3.3.3 深度流量分析与IoC提取

traffic-analyzer MCP服务器封装tshark（Wireshark命令行版本）进行深度包检测（DPI）。服务器提供四个工具函数：start_capture启动实时抓包（通过subprocess调用tshark -i指定接口 -w指定输出文件），get_capture_result获取抓包结果（解析tshark输出的JSON格式报文摘要），extract_ioc提取威胁指标，analyze_flow分析流量模式。

**IoC提取的六维检测。** extract_ioc工具执行六类威胁指标提取：（1）可疑端口检测——检测13种危险端口（23/Telnet、2323/Mirai变种、4444/Metasploit默认监听、6667/IRC-C2信道、6668-6670/IRC变种等）的通信行为，当设备与外部IP建立这些端口的连接时标记为可疑；（2）DNS异常检测——匹配DGA（域名生成算法）特征域名（长度超过20字符的随机子域名、高熵值域名）和已知恶意TLD（.tk、.ml、.ga等免费域名），同时检测DNS查询频率异常（单设备每分钟超过50次查询）；（3）C2心跳检测——分析固定间隔的对外连接模式，通过滑动窗口统计连接时间间隔的标准差，当标准差小于阈值（间隔波动<10%）且持续时间超过5分钟时判定为C2心跳行为（如每隔30秒向同一外部IP的HTTPS心跳）；（4）横向移动检测——检测短时间（60秒窗口）内的多目标同端口扫描行为，当单台设备向超过20个不同IP的相同端口（23或2323）发起连接时标记为横向扩散；（5）数据外泄检测——识别大量出站数据传输，通过NetFlow记录统计单条流的出站字节数，超过10MB的异常上传标记为可疑外泄，同时检查目标IP是否在已知可信IP白名单中；（6）恶意载荷检测——分析Telnet和HTTP协议中的命令注入特征（wget/curl/chmod 777/busybox等关键字）和恶意脚本下载行为（从可疑URL下载.sh/.bin文件的HTTP GET请求）。六维检测的输出为结构化的IoC列表，每条IoC包含类型、置信度评分（基于匹配规则的严格程度计算）和原始报文摘要。

### 3.3.4 ReAct七轮推理实现

本节以摄像头Cam-08（IP地址192.168.10.108）遭受Mirai僵尸网络感染为例，展示anomaly-detect Skill完整的ReAct七轮推理过程。

> **【图3-4】CyberAgent ReAct七轮推理数据流示意图** — 横向七列对应七轮推理，每列展示Thought（思考气泡）→Action（工具图标）→Observation（结果卡片）。底部标注高风险路径（走完全部7轮）和低风险路径（3-4轮快速判定）的分支点。复用初赛文档图3-3。

**表3-2 anomaly-detect Skill完整调用链**

| 轮次 | 推理阶段 | 调用工具 | 输入参数 | Observation结果 |
|:---:|:------:|:------:|:------:|:------:|
| 1 | 读取告警上下文 | attack-timeline/get_timeline | target_ip=192.168.10.108 | 12次登录失败，源IP 192.168.10.200 |
| 2 | 扫描设备暴露面 | nmap-scan/network_scan | target=192.168.10.108 | 端口23(Telnet)/80(HTTP)/554(RTSP)开放 |
| 3 | 关联已知漏洞 | cve-intel/check_device_vulns | vendor=Hikvision, version=2.1.2 | CVE-2024-XXXX, CVSS 9.8, RCE |
| 4 | 检查配置合规 | security-baseline/check_baseline | target=192.168.10.108 | 基线不合规：Telnet开放+默认密码 |
| 5 | 分析网络流量 | flow-analyzer/ipfix_query_flows | target_ip=192.168.10.108 | 扫描150+个IP的23/2323端口 |
| 6 | 提取攻击指标 | traffic-analyzer/extract_ioc | target=192.168.10.108 | C2回连203.0.113.50:443 |
| 7 | 综合判定 | CyberAgent推理 | 全部证据 | Mirai感染，置信度0.94，建议立即隔离 |

**动态策略调整。** 基于证据充分性的动态分析策略相比固定流程的SOAR方案，在保证分析深度的同时避免了不必要的工具调用开销。在高风险路径中，当CVE查询返回CVSS ≥ 9.0的高危漏洞或flow-analyzer发现异常流量时，Agent不跳过任何步骤，依次执行全部7轮ReAct迭代；在低风险路径中，当CVE查询未发现高危漏洞且NetFlow未检测到异常流量时，Agent跳过第5-6轮的深度流量分析，仅执行3-4轮迭代后输出低风险判定。

---

## 3.4 自动响应引擎实现

### 3.4.1 多厂商设备隔离实现

auto-response MCP服务器封装IsolationService实现设备隔离，提供六个工具函数：isolate_device隔离设备、restore_device恢复隔离、block_ip封禁IP、unblock_ip解封IP、get_response_status查询响应状态、get_response_history获取响应历史。

> **【图3-5】双重隔离策略实现流程图** — 上半部分展示iptables隔离路径：检测WSL环境→构造iptables命令→双向DROP规则→规则写入内存字典；下半部分展示SSH交换机隔离路径：查询拓扑数据库获取设备-端口映射（优先MAC表动态查询，回退至初始配置）→netmiko建立SSH连接→执行厂商CLI命令→保存配置。新绘。

**iptables本地防火墙隔离。** IsolationService的_isolate_iptables方法通过Linux iptables在FORWARD链双向插入DROP规则。系统自动检测运行环境——在Windows部署场景下通过"wsl -e"前缀执行iptables命令，在Linux环境直接执行。每条规则在插入前先通过iptables -C检查是否已存在，避免重复执行导致规则冗余。隔离规则维护在内存字典_iptables_rules中（device_ip → rule_description），隔离时创建条目、恢复时删除条目。

**SSH交换机端口隔离。** _isolate_ssh方法通过netmiko库建立SSH连接至可管理交换机，执行对应厂商的CLI命令关闭目标设备所在端口。设备IP到交换机端口的映射关系通过多源融合自动获取——_load_device_ports函数首先通过SSH查询交换机MAC地址表（show mac address-table address XX:XX:XX:XX:XX:XX）按MAC地址动态发现设备与端口的对应关系，同时结合CDP/LLDP邻居信息和初始拓扑配置进行交叉验证，构建“设备IP → {switch_ip, port_name, device_name}”的映射字典。当动态查询成功时，结果同时回写拓扑数据库，使后续隔离操作可直接复用而无需重复查询。厂商命令模板的具体对照见第二章表2-2。

端口映射查找首先通过SSH执行show mac address-table address XX:XX:XX:XX:XX:XX命令按MAC地址查询交换机MAC地址表，若无结果则降级查询CDP/LLDP邻居信息。命令执行通过netmiko的ConnectHandler建立连接（device_type参数根据设备指纹自动选择huawei/cisco_ios/h3c），设置conn_timeout=10秒和timeout=30秒的超时保护。每条命令执行前通过-C参数检查是否已存在（避免重复下发），命令执行后自动验证（通过send_command读取接口状态确认administratively down）。

**策略降级机制。** 当iptables不可用且SSH连接失败时，系统降级为record_only模式——将隔离意图记录至审计日志但不执行实际操作，避免在不可控环境下造成误操作。auto-response MCP服务器的所有操作结果均持久化至SQLite数据库，支持跨会话的响应历史查询。

**表3-3 auto-response MCP服务器工具清单**

| 工具名称 | 功能 | 隔离方式 | 审计记录 |
|:------:|:---:|:------:|:------:|
| isolate_device | 设备隔离 | iptables+SSH双模式 | action_id(UUID) |
| restore_device | 恢复隔离 | 逆向操作 | 关联原action_id |
| block_ip | IP封禁 | iptables DROP规则 | 封禁源/目的IP |
| unblock_ip | 解封IP | iptables规则删除 | 解封时间戳 |
| get_response_status | 查询活跃操作 | — | 活跃隔离动作列表 |
| get_response_history | 获取历史记录 | — | 全部操作历史 |

### 3.4.2 事件驱动自动响应实现

NotificationBridge是CyberClaw事件驱动架构的核心枢纽，采用NetAlertX风格的通知管道设计。桥接器接收来自多个事件源的安全事件，经过去重、持久化和发布后，通过WebSocket实时推送至3D安全HUD。

**事件处理流水线。** NotificationBridge的_send方法实现三阶段处理流程：（1）去重检查——基于“section:title:MAC”构造去重键，300秒冷却窗口内相同事件不重复发送，去重记录维护在内存字典中（dedup_key → last_send_time），每轮清理周期自动淘汰过期条目；（2）SQLite持久化——通知记录写入cyberclaw_notifications表（status='new'），包含GUID、分区类型、标题、内容、严重级别、设备MAC/IP和附加数据（JSON格式），表结构设计包含created_at时间戳索引和status状态索引，支持按时间范围和状态高效查询；（3）多通道发布——通过webhook/ntfy等渠道发送通知，同时通过WebSocket广播至前端。三个阶段串行执行，任一阶段失败不影响后续阶段——例如SQLite写入失败时通知仍通过WebSocket推送，确保前端告警的实时性。

**设备状态变更通知。** on_device_status_change方法在设备安全状态发生FSM转换时触发，自动构建包含旧状态、新状态、设备信息和变更原因的通知消息，severity根据目标状态映射（attacked→critical、vulnerable→high、isolated→warning等）。通知消息的附加数据（extra字段）包含设备IP、设备类型、状态变更时间戳和触发事件的简要描述，供前端3D HUD展示状态转换动画。on_intrusion_detected方法在检测到入侵行为时触发，构建包含攻击类型、置信度、影响范围和建议响应策略的紧急通知，severity固定为critical，触发全通道推送——同时通过ntfy、webhook、WebSocket和Chat四个通道发送，确保安全人员在最短时间内收到告警。

### 3.4.3 配置审计与ACL冲突检测

config-audit MCP服务器提供四个工具函数：audit_config执行设备配置审计，check_acl_conflicts检测ACL冲突，compare_configs对比两份配置，get_audit_report获取审计报告。

**设备配置审计实现。** audit_config工具通过paramiko库建立SSH连接获取设备当前运行配置（execute_command读取running-config或display current-configuration），结合nmap服务扫描结果，从三个维度检测配置问题：（1）不安全协议检测——识别Telnet（23端口）、FTP（21端口）的开放使用，检查设备配置中是否启用了no service tcp-small-servers等加固命令；（2）弱认证检测——检查SNMP community string是否为默认值（public/private），检查SSH是否启用v2版本（ip ssh version 2），检查HTTP管理是否升级为HTTPS（ip http secure-server）；（3）管理接口暴露检测——检查管理端口（22/80/443/8080）的ACL访问控制配置，判断是否暴露于非管理网段。审计结果以结构化的total_findings和各项违规详情返回，每条违规项包含配置路径、当前值、期望值和修复命令。

**ACL冲突检测算法。** check_acl_conflicts工具实现三种规则冲突检测算法，输入为设备ACL规则列表（按序号排序），输出为冲突报告。冲突规则（Contradictory Rules）检测将每条ACL规则解析为{source, destination, port, protocol, action}五元组，通过双重循环比较所有规则对——当两条规则的源/目的/端口/协议字段完全相同但action字段相反时标记为冲突，例如“permit tcp any host 192.168.1.1 eq 23”与“deny tcp any host 192.168.1.1 eq 23”构成冲突。重叠规则（Overlapping Rules）检测识别两条规则匹配相同流量范围造成冗余——当规则A的匹配范围是规则B的子集且两者action相同时，规则B永远不会被匹配到，标记为重叠冗余。影子规则（Shadowed Rules）检测识别被高优先级规则完全覆盖而永远不会生效的规则——ACL按序号从上到下匹配，当高序号规则的匹配范围完全包含低序号规则的范围时，低序号规则成为影子规则。三种检测结果按严重程度排序（冲突>影子>重叠），供运维人员优先处理高风险冲突。

### 3.4.4 四步安全响应流程实现

> **【图3-6】四步安全响应流程实现图** — 横向四步流程图，每步内展示具体实现细节：Step1(get_baseline: ping+port_scan+interface_status) → Step2(isolate: iptables+SSH) → Step3(verify: ping不可达+port scan验证) → Step4(rollback: 逆向操作+二次验证)。新绘。

**步骤一：基线采集。** 在执行任何隔离操作之前，采集目标设备的当前状态快照，为后续回滚提供恢复依据。基线采集内容包括：通过ping测试记录当前网络连通性，通过快速端口扫描记录当前开放端口列表，通过device-config获取交换机接口当前状态。每次响应操作生成唯一的action_id（UUID格式），关联本次操作的全部信息。

**步骤二：隔离执行。** 根据响应策略选择隔离方式：设备被攻击时同时执行iptables DROP规则和SSH交换机端口关闭；仅封禁攻击源IP时执行iptables DROP。执行顺序为先iptables封禁（即时生效）再SSH端口关闭（需建立连接），确保即使SSH连接失败iptables已先行生效提供保护。所有操作通过attack-timeline的record_event工具实时写入审计日志。

**步骤三：效果验证。** verify_isolation在隔离操作完成后自动执行双重验证：ping目标设备检测网络可达性（预期不可达），TCP端口扫描确认所有端口无响应。采用双重验证的设计考量在于：部分IoT设备不响应ICMP Echo Request，仅ping可能产生假阳性，追加端口扫描可确认隔离的物理效果。两项均符合预期则标记验证成功；任一项不符合预期则标记验证失败并自动触发回滚。

**步骤四：自动回滚。** rollback工具根据action_id查询基线快照数据，逆向执行隔离操作——iptables规则删除、SSH端口恢复（no shutdown）。回滚后重新执行验证确认恢复成功。若回滚操作本身也失败（如SSH连接中断），系统标记为rollback_failed并通过Chat通道紧急通知用户。

---

## 3.5 攻防复盘引擎实现

### 3.5.1 攻击时间线持久化

attack-timeline MCP服务器使用SQLite数据库持久化安全事件时间线。服务器提供四个工具函数：record_event记录安全事件，get_timeline获取攻击时间线，analyze_root_cause执行根因分析，generate_report生成事件报告。

**八种事件类型。** CyberReview定义了覆盖安全闭环全部四个阶段的八种标准化事件类型。感知阶段记录scan_started和scan_completed事件；检测阶段记录vuln_found、alert_received和attack_detected事件；响应阶段记录response_executed和device_isolated事件；复盘阶段记录verified事件。每个事件的数据结构包含event_type（事件类型）、timestamp（时间戳）、source（来源引擎）、severity（严重级别）和details（事件详情，JSON格式）五个标准字段。

**事件记录机制。** record_event采用被动调用机制——由其他MCP工具在完成关键操作后主动调用，而非轮询。时间线查询支持两种维度：按时间范围查询（start_time和end_time），适用于安全事件整体回顾；按设备维度查询（target_ip），适用于单台设备的安全状况追踪。时间线数据同时从主数据库的security_events表读取安全事件，确保与前端展示一致。

### 3.5.2 根因分析算法实现

> **【图3-7】根因分析四步算法流程图** — 纵向四步流程：Step1入口识别（attack_detected锚点回溯24h）→ Step2扩散路径DAG → Step3薄弱环节统计（CIS基线违规率>50%）→ Step4改进建议生成。每步输入输出用箭头标注。复用初赛文档图3-5。

analyze_root_cause工具执行四步根因分析算法：

**第一步：入口识别。** 从时间线中定位第一个attack_detected事件，以其timestamp为锚点，向前检索24小时时间窗口内的所有alert_received和vuln_found事件。通过源IP聚合将相关事件关联至同一攻击链，确定攻击的初始入口。

**第二步：扩散路径追溯。** 从attack_detected事件开始，查找后续的流量异常记录，分析被感染设备对外扫描的目标IP列表，追溯攻击的横向扩散路径。扩散路径以有向无环图（DAG）结构组织——节点为受影响设备，边为攻击传播方向，边的权重为攻击利用的漏洞或手法。

**第三步：防御薄弱环节识别。** 交叉分析基线审计结果，按CIS基线各检查项的维度统计违规率。当某项规则的违规率超过50%时标记为“系统性缺陷”（表明问题并非个别设备配置疏忽，而是存在系统性的安全策略缺失），优先生成修复建议。

**第四步：改进建议生成。** 基于根因分析结果生成具体、可操作的防御策略建议。每条建议包含优先级（urgent/high/medium/low）、目标对象（网段或设备类型）和具体操作三个属性。

### 3.5.3 安全报告自动生成

generate_report工具支持三种报告类型的自动生成：（1）incident报告——聚焦单次安全事件，包含攻击时间线、影响范围和处置记录；（2）review报告——侧重防御体系整体评估，包含根因分析和改进建议；（3）compliance报告——面向合规审计场景，汇总安全基线达标率和不合规项清单。

**报告数据采集与结构化。** 报告生成过程分三步执行。第一步，根据报告类型从attack-timeline数据库中查询相关事件数据——incident报告查询指定时间范围内的全部事件记录，review报告查询最近30天的所有attack_detected和response_executed事件，compliance报告查询全部设备的最近一次基线审计结果。第二步，将原始事件数据格式化为结构化的报告上下文——时间线事件按时间戳排序构建攻击链，基线审计结果按设备类型和网段维度聚合，根因分析结论按优先级排序。第三步，将结构化上下文注入DeepSeek LLM的系统提示词，指示LLM按预设的报告模板生成自然语言报告正文。

**报告模板与输出格式。** 三种报告类型各自遵循结构化的报告模板。incident报告模板包含六个章节：事件概述（攻击时间、持续时间、影响设备数）、攻击时间线（按时间轴展开各阶段事件）、影响范围评估（受影响设备清单、数据泄露风险评估）、处置记录（自动响应操作和人工干预记录）、根因分析结论和后续加固建议。review报告模板包含五个章节：安全态势总览（安全事件统计趋势、设备状态分布）、攻击模式分析（近期攻击类型统计、高频攻击入口）、防御效能评估（自动响应成功率、平均响应时间）、根因分析摘要和改进建议优先级列表。compliance报告模板包含四个章节：合规总览（全网合规评分分布、达标率百分比）、按设备类型统计（各类设备的平均评分和主要违规项）、按检查规则统计（违规率最高的规则Top-10）和修复计划（按优先级排列的修复任务清单）。报告由CyberAgent自动生成后通过Chat通道返回给用户，支持后续追问和报告内容调整。

---

## 3.6 AI决策与编排层实现

### 3.6.1 MCP工具动态加载机制

mcp_tool_service实现了12个MCP服务器的运行时动态加载和统一工具注册。系统启动时读取_MCP_REGISTRY_DEF注册表（定义每个服务器的文件名和框架类型），通过importlib动态加载服务器模块并提取工具函数。

**两种加载模式。** 9个FastMCP服务器的加载流程为：importlib.spec_from_file_location加载模块→获取mcp实例→通过_tool_manager._tools反射提取工具函数名→从模块中获取对应的可调用函数。3个底层协议服务器（syslog-collector、snmp-collector、flow-analyzer）使用底层mcp.server.Server框架实现，直接对接真实网络协议——syslog-collector基于asyncio DatagramProtocol监听UDP 514端口的Syslog报文，snmp-collector基于pysnmp库监听UDP 162端口的SNMP Trap报文，flow-analyzer基于自定义UDP解析器接收NetFlow/IPFIX流记录。三者的工具函数直接操作协议数据，通过统一的TOON序列化接口返回结构化结果。动态加载机制使新增MCP服务器无需修改任何加载代码——只需编写服务器文件并更新注册表即可自动发现和注册。

### 3.6.2 意图识别与工具编排

意图编排器通过INTENT_TOOL_MAP定义15个正则模式到MCP工具的映射规则。match_intent函数对用户消息进行正则匹配，最多触发3个意图组以避免系统过载。每个意图组可包含1-3个工具调用，通过asyncio.gather并行执行。

**并行编排示例。** 用户输入“扫描网络”匹配“扫描|scan|检查|发现”模式，同时触发nmap-scan/network_scan和nmap-scan/iot_fingerprint两个工具并行执行。用户输入“审计”同时触发config-audit/audit_config和config-audit/check_acl_conflicts。并行执行将串行的多工具调用耗时压缩为单次最慢工具的耗时。

**结果智能摘要。** _summarize_tool函数根据不同工具返回数据的特征字段（hosts_found/total_cves/devices_audited/iocs_found等）自动生成人类可读的步骤描述。format_tool_results_for_llm函数将工具结果格式化为结构化的上下文文本，标注每条结果的执行状态（成功/失败），列表数据超过10条时截断并附加总数，单条结果文本限制2000字符防止上下文溢出。

### 3.6.3 DeepSeek大模型集成

chat API端点实现了完整的AI对话流程：用户消息到达后，首先通过_parse_timer_intent检查是否为定时任务意图（支持“5分钟后”“明天9点”等中文时间表达），若是则调度延迟执行。对于常规消息，execute_intent执行意图匹配和工具调用，构建包含系统提示词、对话历史和工具结果的完整消息列表，调用DeepSeek API获取LLM响应。

**系统提示词设计。** _build_system_prompt动态构建系统提示词，注入当前环境上下文（设备数量、设备类型分布、安全状态统计、近24小时事件数）。提示词内置9条严格的行为规则：如实反映工具执行失败结果、按CVSS评分准确评估风险等级、禁止在无数据时编造结论、隔离操作须生成确认卡片等。提示词还定义了隔离确认卡片的HTML模板格式——当用户请求隔离操作时，LLM直接在回复中嵌入HTML按钮卡片，前端解析后渲染为可交互的确认界面。

**对话历史管理。** 聊天历史持久化至data/chat_history.json文件，采用500条滑动窗口——新消息追加写入，超出上限时淘汰最早的消息。对话历史同时通过GET /api/chat/history端点暴露给前端，支持会话恢复。

### 3.6.4 三层记忆系统实现

**Layer 1 短期记忆。** 基于chat_history.json的对话滑动窗口（上限500条），存储完整的用户-Agent交互历史。_load_chat_history在模块加载时读取历史文件，_save_chat_history在每次对话后异步写入，确保重启后对话上下文不丢失。

**Layer 2 工作记忆。** 基于AnalysisStep结构化对象，跟踪当前安全分析任务的执行状态。_build_steps_from_results函数将MCP工具执行结果转化为结构化的分析步骤列表——每步包含工具名称、摘要描述和详细数据（限制500字符），供前端展示分析进度。工作记忆保障多轮对话的上下文连贯性——用户先问“扫描网络”再追问“那台摄像头有什么漏洞”时，Agent通过对话历史自动将“那台摄像头”解析为第一轮扫描结果中的具体设备。

**Layer 3 长期记忆。** 基于向量数据库（ChromaDB）的知识持久化引擎，存储设备历史安全状态变更、攻击模式知识图谱和安全决策记录。ChromaDB以collection为单位组织知识——cyberclaw_device_history collection存储设备安全状态时序数据（每次状态变更记录设备IP、旧状态、新状态、触发原因和时间戳），cyberclaw_attack_patterns collection存储历史攻击模式（攻击类型、入口向量、扩散路径、利用的漏洞和防御建议），cyberclaw_decisions collection存储安全决策记录（威胁判定结论、置信度、响应动作和验证结果）。

写入流程：根因分析完成后，analyze_root_cause的结果经toon_serializer压缩后，通过ChromaDB的add接口写入对应collection，每条记录自动生成embedding向量（采用all-MiniLM-L6-v2模型，384维）。检索流程：当用户发起安全查询时，Agent通过ChromaDB的query接口进行向量相似度搜索（余弦相似度，默认返回top-5最相关记录），从长期记忆中检索相关的历史分析结论，辅助当前推理决策。例如当检测到新的Mirai变种攻击时，Agent可从长期记忆中检索历史Mirai攻击的处置记录，参考其响应策略和效果验证结果。

根因分析生成的改进建议同时写入长期记忆和security_scheduler的配置——在下一轮感知扫描时，CyberAgent通过语义检索加载与目标网段匹配的改进建议，据此调整扫描策略（提升优先扫描网段的排序权重、将改进建议中的检查项追加为优先检测项）。这一机制使四阶段闭环从线性流水线升级为具备持续进化能力的循环结构。

### 3.6.5 多Agent协作实现

CyberClaw的多Agent协作在代码层面通过mcp_tool_service的意图-工具映射表实现专业化分工。三个Agent角色的调用逻辑如下：

**ScanAgent感知编排。** 当match_intent匹配到"扫描|scan|发现"模式时，并行触发nmap-scan/network_scan和nmap-scan/iot_fingerprint两个工具（asyncio.gather并发执行），工具返回结果经_build_steps_from_results转化为结构化分析步骤。这对应ScanAgent的感知专家角色——两个工具调用封装在同一意图组中，确保设备发现和指纹识别同时完成。

**AnalyzeAgent检测编排。** "漏洞|CVE"模式触发cve-intel/check_device_vulns，"基线|审计"模式同时触发config-audit/audit_config和config-audit/check_acl_conflicts（两工具并行），"流量|异常"模式同时触发traffic-analyzer/extract_ioc和traffic-analyzer/analyze_flow（两工具并行）。match_intent最多匹配3个意图组，每个意图组1-3个工具，通过asyncio.gather实现AnalyzeAgent的多源检测并行编排。

**ResponseAgent响应编排。** "隔离|封禁"模式触发auto-response/get_response_status查询当前隔离状态，同时触发nmap-scan/iot_fingerprint获取目标设备信息。用户确认隔离操作后，Chat API生成确认卡片HTML，前端渲染可交互按钮，用户点击后调用auto-response/isolate_device执行实际隔离。

三种编排模式在代码中的体现：串行编排通过用户多轮对话自然实现（先扫描→再分析→再响应）；并行编排通过asyncio.gather在同一意图组内实现；条件分支通过LLM推理结果中的建议动作触发后续意图匹配实现。

> **【图3-8】多Agent协作编排流程图** — 中心为OrchestrAgent（match_intent调度器），展示三个Agent角色的工具调用关系：ScanAgent→nmap+device-config、AnalyzeAgent→cve+baseline+traffic+flow、ResponseAgent→auto-response+config-audit。标注asyncio.gather并行执行点。新绘。

### 3.6.6 TOON序列化实现

toon_serializer模块实现TOON（Tabular Object Oriented Notation）序列化格式，在MCP工具返回表格类数据时自动编码。serialize_response函数首先生成JSON格式作为基准，然后尝试通过toon.dumps()进行TOON编码。两个版本的token数量通过_len/4_启发式估算，计算节省百分比。TOON编码失败时自动回退至JSON格式，设置fallback_used标志，确保兼容性——解码失败不会导致工具调用失败。

所有MCP服务器的返回结果均经过toon_serializer处理，对Agent透明。Token计数和成本计算通过SessionLedger进行会话级累计追踪，提供按工具的token使用明细，并通过format_footer输出每次交互的token消耗摘要。

---

## 3.7 3D安全HUD实现

3D安全HUD是CyberClaw面向运维人员的核心交互界面，负责将后端安全引擎产生的结构化安全数据实时转化为三维空间中的视觉元素。前端代码规模达3,700+行（main.js 1,667行 + chat/main.js 2,000行），基于Three.js v0.170 + GSAP v3.12构建。

### 3.7.1 Three.js渲染管线

3D场景采用EffectComposer五通道串行后处理管线：RenderPass（基础渲染）→ UnrealBloomPass（辉光效果，阈值0.6、强度0.7、半径0.4）→ VignetteShader（暗角效果）→ GlitchPass（故障特效，默认关闭，攻击事件时激活0.5秒）→ OutputPass（色彩校正输出）。

**设备几何体映射。** 每种IoT设备类型映射到独特的3D几何体——路由器为八面体（OctahedronGeometry）、交换机为长方体（2.2×0.6×1.4）、摄像头为圆锥体（底面0.7、高1.2）、传感器为四面体、充电桩为圆柱体、服务器为高长方体（1.2×1.8×0.8）、网关为圆环体，共9种设备几何体。

**渲染层次设计。** 每台设备渲染为三层叠加效果：底层为暗色实体Mesh底座加自发光状态色（MeshStandardMaterial.emissive），中层为70%透明度的线框外壳（wireframe mode），顶层为状态色光环底座（TorusGeometry）。三层渲染确保设备在不同视角和背景下均清晰可辨。场景环境包含600粒子星空（带相位闪烁）、三层脉冲光环（自定义ShaderMaterial）和160×40网格地面。

> **【图3-9】3D安全HUD渲染管线架构图** — 展示五通道后处理管线的连接关系，每通道标注参数配置。附九种设备几何体的渲染效果缩略图。新绘。

### 3.7.2 设备状态实时映射

设备安全状态通过STATUS_COLORS和STATUS_GLOW两个常量表映射到3D视觉属性：

**表3-4 设备安全状态FSM视觉映射**

| FSM状态 | 颜色(HEX) | 发光强度 | 视觉效果 | GSAP动画 |
|:------:|:--------:|:-------:|:-------:|:-------:|
| secure | #00FF88 | 0.15 | 绿色线框+微弱呼吸 | 静态 |
| scanning | #00BBFF | 0.35 | 蓝色脉冲+扫描波 | RingGeometry扩散 |
| vulnerable | #FFAA00 | 0.55 | 橙色振荡+警告光 | 摆动+发光增强 |
| attacked | #FF2244 | 0.90 | 红色闪烁+攻击光束 | 脉冲+Glitch特效 |
| isolated | #5A6E88 | 0.08 | 灰色护盾+降透明 | 缩小至0.7+护盾包裹 |

updateDeviceStatus函数通过GSAP实现0.8秒的平滑状态过渡——emissive颜色渐变、发光强度调整。attacked状态附加脉冲缩放动画（1.08倍反复2次）并触发全局GlitchPass故障特效；isolated状态将设备缩小至0.7倍并叠加二十面体线框护盾（spawnShield函数，IcosahedronGeometry细分度1，GSAP back.out弹性缓动）。状态转换遵循“不降级”原则——已标记attacked的设备不会被后续事件降级为vulnerable或scanning。

### 3.7.3 攻防特效实现

**攻击光束。** fireAttackBeam函数创建设备间的攻击视觉效果——使用CatmullRomCurve3生成30段贝塞尔平滑路径，渲染双层管道：内核管道（TubeGeometry半径0.12）渲染攻击颜色，外层发光管道（半径0.35）产生辉光扩散。动画时序通过GSAP timeline控制：淡入0.3秒→保持1.5秒→淡出0.8秒。

**扫描波纹。** triggerScanWave函数从扫描源向目标设备发射同心环动画——RingGeometry初始缩放0.1，2秒内GSAP缩放至30倍并同步渐隐透明度，直观展示扫描范围。

**防御护盾。** spawnShield函数为隔离设备叠加二十面体线框护盾——IcosahedronGeometry（细分度1，产生20个三角面片）+ MeshBasicMaterial线框模式，GSAP弹性缩放动画（back.out缓动系数1.5）从0缩放至1.2倍后回弹至1.0倍，持续旋转动画维持防护状态的视觉提示。

**Raycaster交互。** 3D场景支持鼠标拾取——每3帧执行一次Raycaster检测（性能优化），hover时增强设备发光强度+0.2并提升线框不透明度至100%，点击时相机平滑过渡至目标设备。

### 3.7.4 HUD面板与交互

前端界面采用五标签页架构：Chat（AI对话）、Dashboard（安全趋势图表）、Devices（设备列表）、Events（安全事件）和Automate（自动化任务管理）。

**Dashboard安全态势仪表盘。** Dashboard标签页提供全网安全态势的可视化概览，包含四个核心图表区域。安全事件趋势图采用ECharts堆叠面积图，横轴为时间（支持1小时/6小时/24小时/7天四档切换），纵轴为事件数量，按severity级别分色堆叠（critical红色、high橙色、warning黄色、info蓝色），直观展示告警爆发的时间分布。设备状态分布饼图实时展示全网设备的FSM状态占比（secure/scanning/vulnerable/attacked/isolated），中心显示设备总数，外围环形图按状态着色。协议流量柱状图展示网络流量的协议维度分布（TCP/UDP/ICMP/其他），按采集周期刷新。安全评分仪表盘展示全网综合合规评分（0-100），基于所有设备的基线审计评分加权平均计算，数值低于60时仪表盘变红触发告警。

**Devices设备列表页。** 设备列表页展示全网设备的结构化清单，采用DataTables组件实现，支持按IP地址、设备类型、厂商、安全状态等多维度搜索和排序。列表每行展示设备核心属性（IP/MAC/类型/厂商/状态/合规评分），安全状态列使用与3D场景一致的五色编码（绿/蓝/橙/红/灰）。支持批量操作——勾选多台设备后可批量执行扫描、基线审计或隔离操作。筛选栏提供快捷过滤按钮（仅显示受攻击设备、仅显示不合规设备、仅显示离线设备等）。

**Events安全事件页。** 安全事件页以时间倒序展示所有安全事件，支持按事件类型（scan_started/vuln_found/attack_detected/response_executed/device_isolated等八种类型）和severity级别过滤。每条事件展示时间戳、事件类型标签、关联设备IP、事件摘要和severity级别指示器。点击事件行展开详细视图，显示完整的JSON格式事件数据和关联的MCP工具调用记录。

**Automate自动化任务页。** 自动化任务页分为两个区域：采集器状态监控区和调度任务管理区。采集器状态监控区展示各数据源采集器的运行状态（运行中/已停止/错误），包含启动时间、已采集事件数和最近一条事件时间。调度任务管理区展示SecurityScheduler中已注册的所有定时任务列表，支持新建任务（选择任务模板或自定义Cron表达式）、编辑任务参数、手动触发执行和删除任务。

**设备详情面板。** 点击3D场景中的设备节点或列表中的设备行，弹出多维信息面板，包含六个信息区：基础信息（IP/MAC/类型/厂商/固件版本）、开放端口列表（端口号/协议/Banner，带危险等级着色——Telnet红色、SSH绿色、HTTP黄色）、CVE漏洞信息（CVE编号/CVSS评分/描述/利用状态）、合规评分进度条（基于基线审计结果，0-100分，低于60分红色告警）、连接设备列表（通过CDP/LLDP发现的邻居设备，可点击跳转至对应设备详情）和最近安全事件时间线（该设备最近20条事件的紧凑时间轴）。

**跨页面状态同步。** HUD页面和Chat页面通过localStorage + BroadcastChannel双通道实现状态同步——设备状态变更、告警列表、扫描结果、合规数据等关键状态同时写入localStorage，页面刷新后自动恢复。BroadcastChannel用于实时推送跨标签页事件，确保任意页面的操作即时反映到其他页面。同步机制包含版本号校验（每次状态写入递增version字段），接收端通过比较版本号丢弃乱序的过期更新，防止状态回退。

---

## 3.8 调度与通知系统实现

### 3.8.1 安全任务调度器

SecurityScheduler基于croniter库实现灵活的安全任务调度系统，支持三种调度模式：interval（固定间隔，单位秒）、cron（标准5字段Cron表达式，由croniter解析）和once（指定时间一次性执行，执行后自动标记为completed并从调度循环中移除）。

**任务生命周期管理。** 每个ScheduledTask对象维护独立的执行状态（next_run时间戳、last_run时间戳、运行计数、上次执行结果）。_run_loop方法在后台异步循环中以1秒精度检查所有任务的next_run时间，到期则调用对应的任务执行函数并更新状态——interval模式计算next_run = current_time + interval_seconds，cron模式通过croniter.next()获取下一个执行时间点，once模式执行后标记为completed。任务执行采用asyncio.create_task实现异步非阻塞——多个任务同时到期时并发执行，互不阻塞。任务配置持久化至config/scheduler.json文件，格式为JSON数组，每个元素包含task_id、name、schedule（mode+参数）、enabled（是否启用）和last_result（最近执行结果摘要）。支持运行时通过RESTful API动态添加（POST /api/scheduler/tasks）、修改（PUT /api/scheduler/tasks/{id}）和删除（DELETE /api/scheduler/tasks/{id}）任务，修改立即生效无需重启服务。系统内置5个预设安全巡检任务模板——每日端口扫描（interval:86400，全网nmap扫描）、每日CVE更新（interval:86400，全设备CVE查询）、每周基线审计（cron:0 2 * * 1，每周一凌晨2点基线检查）、每月合规报告（cron:0 3 1 * *，每月1号凌晨3点生成compliance报告）和每日流量异常检测（interval:3600，每小时检测一次异常流量）。

### 3.8.2 多通道通知系统

通知系统提供四通道告警推送能力：

**ntfy推送通道。** 通过ntfy开源推送服务向移动端发送告警通知。通知系统按severity级别配置不同的ntfy topic实现告警分级推送——critical级别推送至cyberclaw-urgent紧急通道（移动端启用声音和振动提醒），high级别推送至cyberclaw-alert告警通道（移动端静默通知），warning和info级别推送至cyberclaw-info信息通道（移动端不提醒，仅在通知栏展示）。推送消息包含标题（事件类型+设备IP）、正文（事件摘要+severity级别）和点击跳转链接（指向CyberClaw前端对应设备页面）。ntfy连接采用HTTPS加密传输，支持Basic Auth认证防止未授权订阅。

**Webhook集成通道。** 支持HMAC-SHA256签名验证的Webhook推送，与企业IM（钉钉、飞书、企业微信）集成。每次Webhook请求在HTTP Header中携带X-CyberClaw-Signature签名（ HMAC-SHA256(webhook_secret, request_body)）和时间戳（X-CyberClaw-Timestamp），接收端验证签名的一致性和时间戳的时效性（60秒窗口）确认通知来源可信。Webhook负载采用各IM平台的消息卡片格式——钉钉使用Markdown卡片、飞书使用Interactive卡片、企业微信使用Text-Mentioned格式，确保告警在各平台上的最佳展示效果。Webhook URL和密钥通过环境变量配置，支持同时配置多个目标实现多部门分发。

**WebSocket广播通道。** 实时推送至3D安全HUD进行可视化展示。广播消息采用类型化JSON格式，包含25+种消息类型，覆盖攻击链事件（attack_detected/lateral_movement/c2_detected）、MCP工具事件（tool_started/scan_result/cve_result/baseline_result）、实时数据流（syslog_event/snmp_trap/mqtt_message/suricata_alert）和心跳同步（heartbeat）。前端通过消息类型映射表自动将收到的消息分发至对应的处理函数——设备状态更新类消息触发updateDeviceStatus，攻击动画类消息触发fireAttackBeam/triggerScanWave，工具结果类消息更新对应的面板数据。

**Chat内嵌通道。** 在自然语言对话通道中生成告警摘要，将结构化的安全事件转化为运维人员可理解的自然语言描述。告警摘要包含事件概要（设备IP+攻击类型+严重级别）、关键证据（异常端口/CVE编号/流量特征）和建议操作（隔离/封禁/继续观察）。定时任务执行结果通过Chat通道反馈给用户，格式为“⏰ 定时任务结果：{消息}”。Chat通道的告警同时追加至对话历史，用户可在后续对话中追问告警详情（如“刚才那个摄像头告警详细分析一下”）。

**告警去重与升级机制。** 通知系统实现两级告警控制策略。告警去重基于“设备IP+事件类型”构造去重键，300秒时间窗口内相同设备的重复告警合并为一条（后续重复计数递增但不触发新通知），有效防止Mirai扫描等批量攻击产生数百条重复告警导致告警疲劳。告警升级针对持续未处理的critical告警——15分钟后若该告警仍为unresolved状态，自动提升通知范围从单通道（仅WebSocket）扩展至全部通道（WebSocket+ntfy+webhook+Chat），30分钟后仍为unresolved则触发二次升级，将告警摘要推送至值班人员手机ntfy紧急通道。升级策略通过notification_config中的escalation_rules配置，支持按severity和事件类型自定义升级规则。

### 3.8.3 端到端攻击链验证——Mirai僵尸网络场景

为验证CyberClaw各安全引擎在实际攻击场景下的协同工作能力，系统实现了完整的Mirai僵尸网络攻击链端到端验证场景。Mirai是IoT安全领域最具代表性的僵尸网络——2016年其首次爆发即感染超过60万台IoT设备，发起的DDoS攻击导致Twitter、Netflix、Reddit等大量主流网站瘫痪，后续变种（Mozi、HinataBot等）至今仍是IoT网络的首要威胁。选择Mirai作为验证场景基于三方面考量：（1）攻击链完整覆盖CyberClaw四阶段闭环——侦察→检测→响应→复盘；（2）利用的漏洞类型（默认密码、Telnet暴露、未修补CVE）正是IoT设备最普遍的安全缺陷；（3）横向扩散机制可充分检验多设备关联分析和批量响应能力。

ScenarioService支持Demo和Live两种运行模式，两种模式共享同一套设备状态管理和3D动画触发逻辑，区别在于事件来源——Demo模式从预设的55步攻击脚本按时间线播放，Live模式从数据库的security_events表实时读取真实安全事件。

**Demo模式——全链路脚本化验证。** Demo模式按预设时间线播放55步攻击脚本，将完整攻击链压缩至约90秒内完成演示。脚本覆盖10个阶段、涉及19台IoT设备（8台摄像头、1台NVR、4台交换机、2台路由器、2台服务器、1台网关和1台充电桩），每步包含事件类型、源/目标设备、severity级别和事件描述。十个阶段的详细流程如下：

> **【图3-10】Mirai攻击链端到端验证时间线** — 横向时间轴展示10个攻击阶段，每阶段内标注：阶段名称、涉及的MCP工具、设备FSM状态转换和3D动画效果。底部标注两行对应关系：上行映射到CyberClaw四阶段闭环（感知→检测→响应→复盘），下行标注关键MCP工具调用。新绘。

**阶段一：初始态势**（1步，耗时3秒）。系统启动完成，展示智能园区视频监控网络的全貌——19台设备全部处于secure（绿色）状态，18条网络链路正常连接。3D场景呈现宁静的安全态势基线。

**阶段二：网络侦察**（6步，耗时18秒）。外部攻击者从IP 10.0.1.1发起端口扫描，依次探测cam_entrance（入口摄像头）、cam_parking（停车场摄像头）、cam_lobby（大堂摄像头）、cam_elevator（电梯摄像头）、cam_corridor（走廊摄像头）、cam_server_room（机房摄像头）和nvr_main（网络录像机）7台设备。每步触发triggerScanWave扫描波纹动画——RingGeometry从攻击源向目标设备扩散，2秒内缩放至30倍并同步渐隐。7台被扫描设备的状态从secure（绿色）转换为scanning（蓝色脉冲）。此阶段验证CyberScan感知引擎的网络扫描检测能力。

**阶段三：漏洞发现**（6步，耗时17.5秒）。CyberSense关联分析引擎对扫描结果执行CVE查询，发现三组高危漏洞：CVE-2021-36260（CVSS 9.8，Hikvision命令注入漏洞，影响cam_entrance/cam_parking/cam_corridor/cam_server_room/cam_rooftop 5台Hikvision摄像头）、CVE-2021-33044（CVSS 9.8，Dahua身份认证绕过漏洞，影响cam_lobby/cam_elevator 2台Dahua摄像头）、弱密码问题（NVR使用admin/12345默认凭据）。7台存在漏洞的设备状态从scanning（蓝色）转换为vulnerable（橙色振荡+警告光），3D场景中设备开始GSAP摆动动画并增强发光强度。此阶段验证cve-intel的CPE自动构造和CVE查询能力，以及security-baseline的默认密码检测。

**阶段四：暴力破解**（1步，耗时4秒）。攻击者利用默认凭据admin/12345通过Telnet暴力破解cam_entrance（入口摄像头）。事件类型为bruteforce，severity为critical。3D场景中从攻击者IP到cam_entrance之间触发fireAttackBeam攻击光束——CatmullRomCurve3生成30段贝塞尔弧形路径，内核管道渲染红色攻击流，外层管道产生辉光扩散，淡入0.3秒→保持1.5秒→淡出0.8秒。同时触发全局GlitchPass故障特效0.5秒（全屏RGB偏移和扫描线闪烁），制造高优先级告警的视觉冲击。此阶段验证traffic-analyzer的暴力破解检测和NotificationBridge的实时告警推送。

**阶段五：首次感染**（1步，耗时3秒）。攻击者向cam_entrance植入Mirai恶意程序，设备被僵尸网络控制。cam_entrance状态从vulnerable（橙色）转换为attacked（红色闪烁），发光强度升至0.90，GSAP脉冲缩放动画1.08倍反复2次。NotificationBridge的on_intrusion_detected方法触发全通道告警——WebSocket推送至3D HUD、ntfy推送至运维人员手机、webhook推送至企业IM。此阶段验证auto-response的攻击事件触发机制。

**阶段六：横向扩散**（7步，耗时23秒）。Mirai蠕虫从已感染设备向网络中其他设备扩散。扩散路径覆盖完整的有向无环图：cam_entrance→cam_parking（利用CVE-2021-36260同品牌漏洞）、cam_entrance→cam_lobby（利用CVE-2021-33044）、cam_lobby→cam_corridor（同品牌横向移动）、cam_entrance→nvr_main（利用共享默认密码）。每步横向移动触发fireAttackBeam攻击光束（橙色，区别于初始攻击的红色），连接源设备和目标设备。6台受感染设备依次转换为attacked（红色）状态。此阶段验证flow-analyzer的横向扫描检测能力——detect_anomaly工具检测到短时间内大量不同目的IP与固定端口23/2323的流量模式，识别Mirai扩散行为。

**阶段七：C2通信检测**（2步，耗时5.5秒）。受感染设备cam_entrance向C2服务器185.220.101.34:443（Tor出口节点）发送心跳回连，cam_parking同时向外发送DNS查询。事件类型为c2_detected，traffic-analyzer的C2心跳检测算法识别出固定间隔的对外连接模式。3D场景中受感染设备向外部IP发射紫色攻击光束（颜色与横向扩散的橙色和初始攻击的红色区分），直观展示数据外泄通道。此阶段验证IoC提取的C2心跳检测（连接间隔标准差<10%判定）和数据外泄检测（目标IP不在可信白名单中）。

**阶段八：AI综合分析**（1步，耗时4秒）。CyberAgent完成ReAct推理，输出分析结论：“Mirai僵尸网络感染——6台设备受控（含NVR），置信度96%”。分析过程串联了攻击时间线回溯（attack-timeline/get_timeline）、设备暴露面扫描（nmap-scan/network_scan）、CVE漏洞关联（cve-intel/check_device_vulns）、基线合规检查（security-baseline/check_baseline）、网络流量分析（flow-analyzer/ipfix_query_flows）和IoC提取（traffic-analyzer/extract_ioc）六个MCP工具的调用结果。Chat通道同时展示AI分析步骤进度条，供运维人员追踪推理过程。

**阶段九：自动隔离响应**（6步，耗时13.5秒）。根据CyberAgent的建议，系统依次隔离6台受感染设备。每步事件类型为device_isolated，auto-response MCP服务器执行iptables DROP规则封禁受感染设备的网络流量。受隔离设备状态从attacked（红色）转换为isolated（灰色），3D场景中每台设备触发spawnShield防御护盾——IcosahedronGeometry二十面体线框护盾通过GSAP back.out弹性缓动从0缩放至1.2倍后回弹至1.0倍，持续旋转动画维持防护状态的视觉提示。同时设备整体缩小至0.7倍表示离线状态。此阶段验证IsolationService的iptables隔离执行、效果验证（ping不可达+端口扫描确认）和attack-timeline的响应记录。

**阶段十：威胁清除与复盘**（1步，耗时3秒）。全部受感染设备完成隔离，CyberAgent生成Mirai攻击时间线报告，包含完整的攻击链还原、根因分析结论（入口为cam_entrance使用默认密码被暴力破解）和改进建议（全网禁用默认密码、关闭Telnet服务、部署CVE补丁）。改进建议写入长期记忆，在下一轮感知扫描时优先检查全网默认密码和Telnet服务状态，实现“每轮闭环都比上一轮更精准”的自适应安全能力。

**表3-5 Mirai攻击链各阶段与系统模块对应关系**

| 攻击阶段 | 步数 | 闭环阶段 | 核心MCP工具 | FSM转换 | 3D动画 |
|:------:|:---:|:------:|:---------:|:------:|:-----:|
| 初始态势 | 1 | — | — | all→secure | 无 |
| 网络侦察 | 6 | 感知 | nmap-scan | secure→scanning | 扫描波纹（蓝色扩散环） |
| 漏洞发现 | 6 | 检测 | cve-intel/security-baseline | scanning→vulnerable | 橙色振荡+发光增强 |
| 暴力破解 | 1 | 检测 | traffic-analyzer | vulnerable→attacked | 红色攻击光束+Glitch特效 |
| 首次感染 | 1 | 响应 | auto-response | vulnerable→attacked | 全通道告警+脉冲闪烁 |
| 横向扩散 | 7 | 检测 | flow-analyzer | 多台→attacked | 橙色攻击光束（设备间） |
| C2通信 | 2 | 检测 | traffic-analyzer | — | 紫色外泄光束 |
| AI分析 | 1 | 检测 | CyberAgent(6工具) | — | Chat分析进度条 |
| 自动隔离 | 6 | 响应 | auto-response | attacked→isolated | 灰色护盾+缩小 |
| 威胁清除 | 1 | 复盘 | attack-timeline | — | 报告生成 |

**Live模式——真实事件实时映射。** Live模式面向生产环境部署场景，每2秒从数据库security_events表读取最新安全事件，通过SEV_TO_FSM映射表将事件severity转换为设备FSM状态：critical和high级别映射为attacked（红色），warning级别映射为vulnerable（橙色），info级别映射为scanning（蓝色）。事件到达后实时更新3D场景中对应设备的安全状态和视觉效果。Live模式遵循“不降级”原则——已标记attacked的设备不会被后续低severity事件降级，确保高危状态的持续可见性。Live模式的事件来源包括Syslog告警、SNMP Trap、Suricata IDS告警和MQTT异常等全部五路数据采集通道，与Demo模式共享同一套_update_device_status状态更新和3D动画触发逻辑，确保演示效果与生产行为一致。

**Demo与Live模式的协同价值。** Demo模式用于系统功能验证、安全培训和竞赛演示——55步脚本在90秒内完整展示四阶段安全闭环的全部能力，每一步的事件类型、设备状态和3D动画效果均可预期和复现。Live模式用于生产环境实时监控——真实安全事件驱动3D可视化，运维人员通过3D场景直觉感知全网安全态势，无需查阅文字告警列表。两种模式的共享架构确保演示场景中展示的所有能力在Live模式下均由相同的代码路径实现，不存在“演示专用”的特殊逻辑。

---

## 本章小结

本章从实现层面详细阐述了CyberClaw各核心模块的具体方案。网络感知引擎通过python-nmap封装实现四种扫描模式，结合三维度加权融合的IoT指纹识别算法、自主设备发现流水线和动态拓扑维护机制，实现全网设备的自动化发现和实时资产画像构建。多源数据采集层实现五路异构数据（Syslog/SNMP/MQTT/IPFIX/Suricata）的并行采集，配合CVE漏洞查询的CPE自动构造和SQLite缓存策略、CIS基线审计的53条规则和加权评分算法、深度流量分析的六维IoC检测和ReAct七轮推理的多源关联检测，构成完整的智能检测能力。自动响应引擎通过iptables+SSH双重隔离策略实现多厂商设备隔离，配合事件驱动的NotificationBridge三阶段处理流水线、配置审计的ACL三重冲突检测算法和四步安全响应流程，实现从检测到处置的秒级响应。AI决策层通过MCP工具动态加载、正则意图匹配编排和DeepSeek大模型集成实现智能安全分析，结合三层记忆架构、多Agent协作机制和TOON序列化优化。3D安全HUD基于Three.js五通道后处理管线和9种设备几何体映射，配合五标签页仪表盘和六维设备详情面板，实现沉浸式安全态势感知。调度与通知系统支持croniter驱动的三种调度模式和四通道告警推送，配合两级告警控制策略。最后以Mirai僵尸网络攻击链为案例，通过10个阶段55步攻击脚本的端到端验证，展示了CyberClaw四阶段安全闭环（感知→检测→响应→复盘）在全系统层面的协同工作能力。
