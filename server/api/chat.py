import re
from fastapi import APIRouter
from ..models.schemas import ChatRequest, ChatResponse

router = APIRouter(prefix="/api/chat", tags=["chat"])

RESPONSES = {
    r"扫描|scan": "好的，我来启动网络扫描。当前网络中有 15 台 IoT 设备，我将执行全面端口扫描和指纹识别。",
    r"漏洞|vuln": "正在检查已知漏洞数据库。目前检测到 2 个高风险 CVE 需要关注。",
    r"报告|report": "正在生成安全评估报告，包含网络拓扑、设备清单、漏洞摘要和修复建议。",
    r"攻击|attack|mirai": "检测到 Mirai 僵尸网络攻击迹象。建议立即隔离受感染设备并分析攻击路径。",
    r"隔离|isolat": "准备执行设备隔离操作。这是一个高风险操作，需要人工确认。",
}

_chat_history: list[dict] = []


@router.post("")
async def chat(req: ChatRequest) -> ChatResponse:
    reply = "我是 CyberAgent，您的 IoT 安全分析助手。请告诉我您需要什么帮助？"
    for pattern, response in RESPONSES.items():
        if re.search(pattern, req.message, re.IGNORECASE):
            reply = response
            break
    _chat_history.append({"role": "user", "content": req.message})
    _chat_history.append({"role": "assistant", "content": reply})
    return ChatResponse(reply=reply)


@router.get("/history")
async def chat_history():
    return {"history": _chat_history}
