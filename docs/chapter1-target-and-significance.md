# 第一章 目标问题与意义价值

## 1.1 问题背景

### 1.1.1 国家战略与政策驱动

物联网（IoT）安全已从技术议题上升为国家安全战略的重要组成部分。近年来，从国家法律法规到国际标准框架，IoT安全治理体系正在加速构建，政策驱动效应日益显著。

**中国网络安全法律体系全面升级。** 2025年10月28日，全国人大常委会通过《网络安全法》修订版，于2026年1月1日正式施行[1]。这是该法自2017年实施以来的首次重大修订，核心变化体现在三个方面：一是将人工智能安全首次纳入法律框架，明确AI系统的安全评估与备案要求、AI生成内容的可追溯性要求，以及针对AI驱动网络攻击的防御要求；二是法律责任大幅升级，罚款金额大幅提升（最高可达上一年度营业额的5%），建立分级处罚机制；三是明确34类网络安全产品必须经过安全认证或检测，未经认证不得销售[2]。

在数据安全层面，《数据安全法》要求对IoT感知数据实行分类分级保护，覆盖数据收集、存储、传输、使用的全生命周期。2024年9月，国务院审议通过《网络数据安全管理条例》，标志数据安全法律体系进一步完善。在关键基础设施保护层面，《关键信息基础设施安全保护条例》将涉及IoT设备的能源、交通、金融、智慧城市等基础设施纳入保护范畴，要求运营者建立健全安全保护制度、定期开展风险评估和应急演练[3]。

**等级保护2.0标准构建IoT安全技术基线。** GB/T 22239-2019标准采用"安全通用要求+安全扩展要求"的框架结构，其中物联网安全扩展要求针对感知层提出了专门的技术要求，涵盖感知节点物理防护、感知网接入控制与入侵防范、感知节点和网关节点设备安全、抗数据重放以及数据融合处理完整性和一致性保护等关键控制点[4]。这一标准为IoT安全防护提供了可操作的技术基线。

**产业政策与战略规划持续加码。** 工信部2024年4月发布《工业互联网安全分类分级管理办法》（工信部网安〔2024〕68号），将联网工业企业分为三类、安全等级分为三级，建立"自主定级→定级核查→分级防护→符合性评测→安全整改"五步工作流程[5]。"十五五"规划明确提出"基于人工智能等技术实现对网络攻击路径的预测与自动化防御"，"形成行业级智慧安全体系"，为AI Agent框架驱动的IoT安全平台提供了明确的政策环境和发展机遇[6]。

**国际层面同步加速立法进程。** 欧盟《网络弹性法案》（Cyber Resilience Act, CRA）于2024年12月10日正式生效，这是全球首部针对所有含数字元素产品（包括IoT设备）的全面安全法规，要求制造商在产品规划阶段即落实"安全即设计"原则，涵盖15项关键安全要求，2027年12月全面执行[7]。美国《IoT网络安全改进法》自2020年生效以来持续推进，NIST发布SP 800-183"物网络"基础框架，并持续推进SP 800-213系列和IR 8259修订版，将IoT安全视角从"设备"扩展为"完整产品系统"[8]。美国国会问责局（GAO）2025年报告显示，联邦机构在IoT安全合规方面仍存在不足，6个机构获得部分豁免，反映出IoT安全治理的紧迫性和复杂性[9]。

> **【图片位置1-1】** 建议绘制"IoT安全政策法规体系图"：以时间线形式展示2019-2026年关键政策法规的发布节点，分为中国（上）和国际（下）两条线，标注各法规与IoT安全的关联度。可复用初赛文档图1-1的结构并更新内容。

---

### 1.1.2 IoT安全威胁态势

IoT设备规模的爆发式增长与安全防护能力的严重滞后，正在形成日益严峻的威胁态势。

**设备规模持续攀升，攻击面急剧扩大。** 据IoT Analytics统计，2025年全球IoT设备连接数达到211亿台，同比增长14%，预计2030年将达390亿台（年复合增长率13.2%）[10]。中国拥有超过80亿台IoT设备，2025年市场规模达4.55万亿元人民币，产业链企业超32万家[11]。然而，IoT设备平均每台存在约25个安全漏洞[12]，98%的IoT设备流量未经加密传输，大量设备使用默认密码、缺乏固件更新、未实施网络隔离，构成庞大的攻击面。

**DDoS攻击进入Tbps时代，僵尸网络工业化运营。** 从2016年Mirai的1.1 Tbps到2025年的31.4 Tbps，DDoS攻击峰值带宽在十年间增长超过28倍[13]。2024年10月，Mirai变种发动5.6 Tbps攻击，控制超过13,000台IoT设备[14]。2024年末出现的Aisuru/TurboMirai僵尸网络DDoS能力达20+ Tbps，攻击量同比暴增700%[15]。2025年全年Cloudflare共缓解4,710万次DDoS攻击，同比增长121%[16]。BadBox 2.0通过供应链攻击植入后门，导致约1,000万台Android/IoT设备沦陷，影响220多个国家[17]。僵尸网络已从Mirai的单一DDoS工具演变为集DDoS攻击、代理服务、加密挖矿、数据窃取于一体的工业化犯罪平台。

**AI武器化加速攻防失衡。** 87%的安全专家观察到AI驱动威胁的持续增长[18]。SonicWall报告显示，2024年IoT恶意软件攻击同比增长124%，新增未知恶意软件变种超过21万个[19]。AI驱动的攻击在2024至2025年间增长1200%[20]，恶意机器人流量占全球互联网流量的37%[21]。2025年，每个家庭平均每日遭受29次IoT攻击尝试，是2024年的3倍[22]。更为严峻的是，AI攻击速度已超过人类防御能力，Booz Allen Hamilton报告指出，AI驱动的网络攻击已全面超越人类驱动的防御响应速度[23]。

**行业安全事件率居高不下。** 75%的企业在2025年遭遇IoT安全事件，相比2024年的50%大幅上升[24]。制造业安全事件率达85%，充电桩行业为82%[25]。Kaspersky监测数据显示，21.9%的工业控制系统（ICS）计算机在2025年第一季度遭受恶意软件攻击[26]。OT勒索软件攻击同比增长46%[27]，IoMT（医疗物联网）安全事件平均成本高达1,000万美元[28]。

> **【图片位置1-2】** 建议绘制"IoT安全威胁态势全景图"：左侧为重大安全事件时间线（2016年Mirai→2024年5.6Tbps→2025年TurboMirai 31.4Tbps→BadBox 2.0），右侧包含两个子图——(a)全球IoT设备连接数增长曲线（2020-2030预测，标注211亿/390亿），(b)DDoS攻击峰值带宽演变柱状图。可复用初赛文档图1-1~1-3的布局并更新数据。

---

### 1.1.3 核心痛点分析

从重大安全事件、行业态势数据以及政策要求中，可以提炼出当前IoT安全面临的五大核心痛点。这些痛点不仅反映了技术层面的挑战，更揭示了IoT安全防护体系的系统性缺陷。

**表1-1 IoT安全五大核心痛点**

| 痛点 | 核心问题描述 | 量化数据支撑 |
|:----:|:---------:|:---------:|
| "看不到" | 大量IoT设备处于"影子IT"状态，企业无法掌握网络中存在哪些设备及其安全状态 | 每台IoT设备平均25个漏洞[12]，98%流量未加密 |
| "管不住" | 安全工具各自为战，无法实现多源数据关联和协同分析 | 典型安全事件响应需在5+个工具间切换，流程耗时2-3小时 |
| "来不及" | 传统人工响应流程需数小时到数天，而攻击横向扩散速度极快 | Mirai感染全网<10分钟，BadBox 2.0千万级设备沦陷 |
| "人才缺" | IoT安全需要网络安全、IoT协议、AI算法等多领域复合型人才 | 全国网络安全人才缺口达数百万，中小企业安全团队平均不足3人 |
| "工具缺" | 市场缺乏真正能落地的AI驱动IoT安全工具 | 中小企业被入侵率是大型企业的4倍[29]，IoT安全部署率不足5% |

从本质上看，这五大痛点形成了一条恶性因果链："看不到"导致设备失管，"管不住"造成分析碎片化，"来不及"使防御始终被动，而"人才缺"和"工具缺"则从供给侧限制了破局的可能。打破这一恶性循环，需要构建一个能够实现"感知-检测-响应-复盘"全链路自动化的AI驱动安全平台。

---

## 1.2 国内外研究现状

### 1.2.1 传统IDS/IPS系统及其局限

传统入侵检测与防御系统（IDS/IPS）如Snort、Suricata基于固定规则库进行特征匹配，在传统IT网络环境中发挥了重要作用，但在IoT场景下暴露出三个根本性局限。

**检测机制落后于攻击演进。** Snort采用单线程架构，仅能利用单个CPU核心，在高流量IoT环境下性能严重受限[30]。Suricata虽支持多线程，但仍以规则/签名检测为主，面对零日攻击和变种恶意软件无能为力。学术研究表明，基于机器学习的入侵检测模型在部署数周后，准确率会下降12-40个百分点[31]。NDSS 2025的研究进一步指出，基于被动网络数据的机器学习方法在IoT设备识别中存在显著局限，模型泛化能力不足[32]。

**缺乏IoT协议支持与资源适配能力。** IoT环境通信协议多样化（MQTT、CoAP、Zigbee、LoRaWAN、Modbus、OPC-UA），传统IDS规则库覆盖严重不足。同时，IoT设备计算存储资源有限，无法部署重量级检测Agent，传统IDS难以直接适配。

**缺乏上下文理解与关联分析能力。** 传统IDS只能单点告警，无法理解攻击上下文，无法将端口扫描、异常流量、CVE漏洞等多源信息进行关联分析。典型的安全事件响应流程——Syslog异常告警（5分钟）→Nmap端口扫描（15分钟）→NVD查询CVE（30分钟）→安全专家人工判断（1-2小时），整个流程耗时2-3小时[33]，而此时攻击往往已完成横向扩散。

### 1.2.2 商业IoT安全平台

当前IoT安全市场已形成以Armis、Claroty、Nozomi Networks为代表的第一梯队。Gartner 2025年魔力象限（MQ）将这三家同时列为CPS（网络物理系统）保护平台"领导者"[34]。

Armis采用无代理SaaS架构，通过被动流量分析实现设备发现和风险评估，拥有超过60亿设备画像，覆盖约20%全球联网设备。Claroty（含Medigate医疗IoT安全）提供云+本地双模式部署，Team82研究团队已披露550+CPS漏洞，在医疗IoT安全领域连续四年KLAS最佳（2026年得分92.1/100）[35]。Nozomi Networks保护1.15亿工业/IoT资产，12,000+安装点，Gartner Peer Insights评分4.9/5.0（247条评价）[36]。

然而，现有商业平台存在三大共性缺陷：（1）**成本门槛极高**——所有头部厂商均不公开定价，企业年费通常从六位数起步，大型部署可达七位数，中小企业安全预算通常仅5-10万美元，形成难以逾越的门槛[37]；（2）**响应能力不足**——主要功能集中在检测和告警，对攻击的自动隔离、配置回滚等响应措施支持有限，Armis和Claroty均缺乏真正的自动隔离闭环能力；（3）**封闭生态策略**——无法与企业现有的Nmap、Nessus、Zabbix等工具实现数据互通和协同分析，形成安全信息孤岛。

> **【图片位置1-4】** 建议绘制"商业IoT安全平台能力对比雷达图"：六个维度（资产发现、威胁检测、AI分析、自动响应、开放性、成本可控），Armis/Claroty/Nozomi/CyberClaw四条曲线。CyberClaw在AI分析和自动响应维度突出。可升级初赛文档图1-6为雷达图形式。

### 1.2.3 AI Agent与MCP协议生态

近年来，大语言模型（LLM）在网络安全领域的应用研究呈现爆发式增长。Shi等人的系统性文献综述分析了300余篇相关文献，覆盖25种LLM和10余个网络安全子领域[38]。IEEE Security & Privacy Magazine 2025年专题探讨了LLM在网络安全合规与弹性方面的新机遇[39]。

**LLM驱动安全自动化成为前沿热点。** Deng等人在USENIX Security 2024发表的PentestGPT提出迭代式LLM提示-执行-反馈循环，实现自主渗透测试[40]。ACM 2024年发表的CTAR提出了从威胁分析到自动响应的完整LLM流水线[41]。2025年，AWS Security Blog发布了生产级多Agent渗透测试架构[42]，学术界则提出了基于任务树约束LLM Agent推理以减少幻觉的方法[43]。在安全日志分析领域，RAG增强的LLM框架被用于从多源日志中收集和分析安全事件证据[44]。然而，上述研究多聚焦于LLM的单任务能力，缺乏多工具编排的标准化框架。MCP协议的出现为这一瓶颈提供了技术解法。

**MCP协议为AI Agent安全工具集成提供标准化路径。** MCP（Model Context Protocol）是AI Agent与外部工具之间的开源标准协议，采用JSON-RPC 2.0通信机制，实现工具即插即用。截至2026年，MCP月度SDK下载量已超过9,700万次，社区贡献的服务器超过5,800个[45]，被称为"有史以来采用最快的协议之一"。然而，学术研究也指出MCP生态面临安全威胁挑战，Hou等人的论文全面分析了MCP的生态格局、安全风险与未来方向[46]。在IoT安全领域，MCP生态仍存在明显空白——缺乏专门针对IoT安全的MCP服务器，现有安全工具尚未官方支持MCP协议。CyberClaw项目正是填补这一空白的探索实践。

### 1.2.4 现有方案综合对比

基于以上分析，本文从检测能力、AI分析、自动响应、设备发现、可视化、开放性、成本可控性七个维度，对现有主流方案进行综合对比。

**表1-2 现有IoT安全方案七维度综合对比**

| 对比维度 | Snort/Suricata | Armis | Claroty | Nozomi | CyberClaw |
|:------:|:----:|:----:|:----:|:----:|:----:|
| 检测能力 | 规则匹配，IoT覆盖不足 | 被动流量+行为分析 | 深度协议解析+威胁检测 | AI异常检测 | 多源关联+ReAct推理 |
| AI分析 | 无 | 行为基线异常检测 | 威胁检测 | AI/ML异常检测 | LLM多源关联+推理 |
| 自动响应 | 仅IPS阻断 | 仅告警建议 | 仅告警建议 | 仅告警建议 | 分级自动隔离+验证回滚 |
| 设备发现 | 无 | 60亿+设备画像 | 深度资产发现 | 实时资产清单 | 多模式扫描+指纹识别 |
| 可视化 | 日志文本 | 2D仪表盘 | 2D拓扑 | 2D仪表盘 | 3D安全态势HUD |
| 开放性 | 开源 | 封闭SaaS | 封闭SaaS | 封闭SaaS | 开源+MCP标准化 |
| 成本 | 免费 | 企业级(六位数/年) | 企业级(六位数/年) | 企业级(六位数/年) | 开源/低成本部署 |

从对比中可以清晰看出：传统开源工具（Snort/Suricata）缺乏IoT适配能力和AI分析能力；商业平台（Armis/Claroty/Nozomi）虽然检测能力强大，但成本高昂、生态封闭、自动响应能力有限。CyberClaw通过MCP协议标准化集成12个安全工具服务器（约100个安全工具），结合LLM的多源关联分析能力和ReAct推理循环，在开放性、AI分析深度、自动响应闭环和3D可视化方面实现了差异化创新。

---

## 1.3 项目目标与意义

### 1.3.1 项目目标

CyberClaw面向IoT安全"看不到、管不住、来不及、人才缺、工具缺"五大核心痛点，旨在构建一个"感知→检测→响应→复盘"全链路智能闭环的IoT安全自动化平台。具体目标包括：

（1）**全链路安全自动化**：基于12个MCP安全工具服务器（约100个安全工具），实现从网络扫描、设备发现、漏洞检测、攻击分析到自动隔离响应的完整闭环，将安全事件响应时间从"小时级"缩短到"秒级"。

（2）**AI驱动的多源关联检测**：利用大语言模型（LLM）同时编排Nmap端口扫描、NVD CVE漏洞库、Syslog事件监听、SNMP Trap告警、安全基线审计等多源安全工具，通过ReAct推理循环实现多源数据关联分析和综合判断。

（3）**事件驱动的主动防御**：构建"安全事件→策略评估→置信度计算→分级响应"的事件驱动自动响应架构，支持iptables、SSH交换机、ACL等多种隔离方式，覆盖华为VRP、Cisco IOS、H3C Comware等多厂商设备，实现"基线采集→隔离执行→效果验证→自动回滚"的四步安全响应流程。

（4）**降低安全防护门槛**：通过自然语言交互界面，将安全运维门槛从"安全专家"降低到"会用自然语言提问"，使中小企业也能拥有AI级别的网络安全防护能力。

### 1.3.2 理论意义

**（1）探索LLM+安全工具的多源关联检测方法论。** CyberClaw探索了如何让大语言模型有效编排多个安全工具，实现智能化的多源关联分析。提出了"事件触发→工具编排→多源关联→综合判断"的AI分析流程，探索了LLM在安全领域的Prompt工程最佳实践。在IoT专用SOAR（安全编排自动化与响应）领域，学术研究仍存在明显空白[47]，CyberClaw的实践为AI Agent在安全自动化领域提供了可复制的技术范式。

**（2）验证MCP协议在安全自动化场景的适用性。** 安全场景对协议提出特殊要求：实时性（秒级延迟）、可靠性（不能因协议故障导致安全防护失效）、审计性（所有操作需留下不可篡改审计日志）。CyberClaw验证了MCP JSON-RPC 2.0通信机制在安全场景下的性能表现，构建了包含12个专业安全MCP服务器、约100个安全工具的IoT安全MCP工具集群，填补了MCP生态在IoT安全领域的空白。

**（3）提出TOON序列化优化策略。** 针对LLM Agent上下文窗口有限的问题，CyberClaw设计了TOON（Tabular Object Oriented Notation）序列化格式，在安全数据传输中实现40-60%的token节省，为AI Agent在资源受限场景下的高效运行提供了优化策略。

### 1.3.3 实践价值

**（1）让中小企业拥有AI级网络安全防护能力。** 商业IoT安全平台年费高达十万美元至百万美元级别，中小企业被入侵率是大型企业的4倍[29]，IoT安全部署率不足5%。CyberClaw基于开源架构构建，通过复用企业现有网络工具（Nmap、Suricata等），避免重复采购；采用自然语言交互界面，降低使用门槛。这使得中小企业也能拥有"AI安全分析师"级别的防护能力。

**（2）将安全运维门槛从"安全专家"降低到"自然语言交互"。** 传统安全运维需要熟练使用Nmap、Wireshark等工具，理解TCP/IP协议栈、防火墙规则，掌握CVE漏洞库和应急响应流程。CyberClaw通过自然语言交互，用户只需提问"帮我分析一下网络的安全状况"，AI即可自动完成扫描、分析、报告全流程，从根本上缓解安全人才短缺问题。

**（3）提供可验证的虚实结合安全测试环境。** 结合GNS3网络仿真和Docker IoT容器，构建从攻击发起到自动隔离的端到端验证环境，支持Mirai等典型攻击场景的可重复演示，确保技术方案的有效性和可验证性。

---

## 参考文献

[1] 全国人大常委会. 《中华人民共和国网络安全法》修订版. 2025年10月28日通过, 2026年1月1日施行.

[2] 国家网信办. 《网络安全法》修订全文. https://www.cac.gov.cn/2025-12/29/c_1768735112911946.htm

[3] 国务院. 《关键信息基础设施安全保护条例》. 2021年9月1日施行. http://xzfg.moj.gov.cn/law/detail?LawID=683

[4] 全国信息安全标准化技术委员会. GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求. 2019年12月1日实施.

[5] 工业和信息化部. 《工业互联网安全分类分级管理办法》(工信部网安〔2024〕68号). 2024年4月11日.

[6] 中央网信办. 锚定网络强国战略目标 扎实推进"十五五"时期网信工作. 2026年3月. https://www.cac.gov.cn/2026-03/17/c_1775482046495737.htm

[7] European Commission. Cyber Resilience Act (Regulation EU 2024/2847). 2024年12月10日生效. https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act

[8] NIST. SP 800-183 "Networks of Things". 2016年7月. https://csrc.nist.gov/pubs/sp/800/183/final

[9] U.S. Government Accountability Office. GAO-25-107179: IoT Cybersecurity. 2025. https://www.gao.gov/products/gao-25-107179

[10] IoT Analytics. State of IoT — Spring 2025: Number of Connected IoT Devices Growing 14% to 21.1 Billion Globally. https://iot-analytics.com/number-connected-iot-devices/

[11] 中商产业研究院. 2025年中国物联网行业市场前景预测及投资研究报告. https://www.5iot.com/newsinfo/8739625.html

[12] ACM Digital Library. IoT Device Security Assessment. https://dl.acm.org/doi/10.1145/3727166.3727189

[13] NETSCOUT. ASERT Threat Summary: TurboMirai Botnet DDoS Attack Report. https://www.netscout.com/blog/asert/asert-threat-summary-aisuru-and-related-turbomirai-botnet-ddos

[14] The Hacker News. Mirai Botnet Launches Record 5.6 Tbps DDoS Attack with 13,000+ IoT Devices. 2024年10月29日.

[15] Krebs on Security. Feds Disrupt IoT Botnets Behind Huge DDoS Attacks. 2026年3月. https://krebsonsecurity.com/2026/03/feds-disrupt-iot-botnets-behind-huge-ddos-attacks/

[16] Cloudflare. DDoS Threat Report Q4 2025: 47.1M DDoS Attacks Mitigated in 2025. https://blog.cloudflare.com/ddos-threat-report-2025-q4/

[17] FBI. Alert: Home Internet-Connected Devices Facilitate Criminal Activity (BadBox 2.0). 2025. https://www.fbi.gov/investigate/cyber/alerts/2025/home-internet-connected-devices-facilitate-criminal-activity

[18] Darktrace. State of AI Cybersecurity 2026: 87% of Security Professionals Are Seeing More AI-Driven Threats. https://www.darktrace.com/blog/state-of-ai-cybersecurity-2026

[19] SonicWall. 2025 Cyber Threat Report: IoT Malware Attacks Up 124%. https://www.sonicwall.com/2025-cyber-threat-report

[20] SonicWall. 2026 Cyber Protect Report: AI-Driven Attacks Surge 1200%. https://www.sonicwall.com/2026-cyber-protect-report

[21] SonicWall. 2026 Cyber Protect Report: Malicious Bot Traffic Reaches 37% of Internet Traffic.

[22] Bitdefender & NETGEAR. 2025 IoT Security Threat Report. https://www.netgear.com/hub/network/security/iot-threat-report-25/

[23] Booz Allen Hamilton. AI-Driven Cyberattacks Outpace Human-Driven Defenses Across Critical Infrastructure. 2025. https://industrialcyber.co/ai/booz-allen-warns-ai-driven-cyberattacks-outpace-human-driven-defenses-across-critical-infrastructure/

[24] Eseye. 2025 IoT State of the Nation Report. https://www.eseye.com/resources/

[25] Eseye. EV Charge Point Security Under Fire: 82% Businesses Breached. https://www.eseye.com/resources/blogs/ev-charge-point-security-under-fire-82-businesses-breached/

[26] Kaspersky ICS CERT. KSB 2025 ICS CERT Trends and Predictions. https://lp.kaspersky.com/global/ksb2025-ics-cert-trends-and-predictions/

[27] DeepStrike. IoT Hacking Statistics 2025. https://deepstrike.io/blog/iot-hacking-statistics

[28] DeepStrike. IoMT安全事件平均成本1000万美元. IoT Hacking Statistics 2025.

[29] Total Assure. Small Business Cybersecurity Statistics 2026. https://totalassure.com/blog/small-business-cybersecurity-statistics

[30] Stamus Networks. Suricata vs Snort: IDS Performance Comparison. https://www.stamus-networks.com/suricata-vs-snort

[31] arXiv. Evaluating Machine Learning Models on CICIDS2017 Dataset. https://arxiv.org/html/2506.19877v1

[32] NDSS 2025. Evaluating ML-Based IoT Device Identification Using Passive Network Data. https://www.ndss-symposium.org/wp-content/uploads/2025-118-paper.pdf

[33] IBM Security. Cost of a Data Breach Report 2025: Average Incident Response Time Analysis.

[34] Gartner. Magic Quadrant for Cyber-Physical Systems Protection Platforms. 2025.

[35] Claroty. Medigate Wins Best in KLAS for Healthcare IoT Security Four Years in a Row. https://claroty.com/blog/medigate-by-claroty-wins-best-in-klas-for-healthcare-iot-security-four-years-in-a-row

[36] Nozomi Networks. Named a Leader in Forrester Wave IoT Security Q3 2025. https://www.nozominetworks.com/press-release/nozomi-networks-named-a-leader-in-forrester-wave-iot-security

[37] PeerSpot. Armis vs Claroty Pricing Comparison. https://www.peerspot.com/products/comparisons/armis-centrix-for-ot-iot-security_vs_claroty-platform

[38] Shi J, Wang Z, et al. Large Language Models for Cyber Security: A Systematic Literature Review. ACM Computing Surveys, 2024. https://arxiv.org/abs/2405.04760

[39] IEEE Security & Privacy Magazine. LLMs for Cybersecurity: New Opportunities. Vol.23(5), 2025.

[40] Deng X, Liu Z, et al. PentestGPT: Evaluating and Harnessing LLMs for Automated Penetration Testing. USENIX Security 2024. https://www.usenix.org/system/files/usenixsecurity24-deng.pdf

[41] CTAR: A Novel LLM Approach of Cybersecurity Threat Analysis and Response. ACM, 2024. https://dl.acm.org/doi/10.1145/3755881.3755888

[42] AWS Security Blog. Inside AWS Security Agent: A Multi-Agent Architecture for Automated Penetration Testing. 2025.

[43] Guided Reasoning in LLM-Driven Penetration Testing Using Task Trees. arXiv, 2025. https://arxiv.org/html/2509.07939v1

[44] ACM. Retrieval-Augmented LLMs for Security Incident Analysis. 2025. https://dl.acm.org/doi/full/10.1145/3786335.3813136

[45] Digital Applied/MarsDevs. MCP Ecosystem Statistics: 97M+ Monthly Downloads. https://www.digitalapplied.com/blog/mcp-97-million-downloads-model-context-protocol-mainstream

[46] Hou X, et al. Model Context Protocol (MCP): Landscape, Security Threats, and Future Directions. 2025. https://xinyi-hou.github.io/files/hou2025mcp_1.pdf

[47] IEEE Xplore. Towards Smarter Security Orchestration and Automatic Response for IoT/CPS. 2024. https://ieeexplore.ieee.org/document/10475827/
